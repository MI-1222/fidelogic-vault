//! `unlock` の対話モードを、実行ファイルで確かめる統合テスト。
//!
//! コマンドをパイプから渡すテストは、制御端末の無いプロセスで実行する。
//! 端末での操作は、標準入出力をすべて疑似端末にして実行する。

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use common::entry_vault::{EntryVault, credential, spawn_without_terminal};
use common::{Options, PASSWORD, Redirect, Session, TIMEOUT, TestResult};
use fidelogic_cli::sys::storage::{VaultLock, VaultPath};

const UNLOCKED: &str = "解錠しました。";
const LOCKED: &str = "施錠しました。";
const IDLE_LOCKED: &str = "無操作の時間が上限に達したため、施錠しました。";
const COMMAND_PROMPT: &str = "fidelogic> ";

/// 子の出力の 1 本を、行ごとに受け取る。
struct Lines {
    receiver: Receiver<String>,
    seen: Vec<String>,
}

impl Lines {
    fn new(source: impl Read + Send + 'static) -> Self {
        let (sender, receiver) = channel();
        thread::spawn(move || {
            for line in BufReader::new(source).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            receiver,
            seen: Vec::new(),
        }
    }

    /// `text` を含む行が届くまで待つ。
    fn expect(&mut self, text: &str) -> TestResult {
        loop {
            let line = self.receiver.recv_timeout(TIMEOUT).map_err(|error| {
                format!("{text} が出力されませんでした ({error}): {:?}", self.seen)
            })?;
            let found = line.contains(text);
            self.seen.push(line);
            if found {
                return Ok(());
            }
        }
    }

    /// 出力の終端まで読み、全行を返す。
    fn finish(mut self) -> Vec<String> {
        while let Ok(line) = self.receiver.recv_timeout(TIMEOUT) {
            self.seen.push(line);
        }
        self.seen
    }
}

/// コマンドをパイプから渡す対話モード。
struct Piped {
    child: Child,
    input: Option<ChildStdin>,
    output: Lines,
    errors: Lines,
}

/// 終了した対話モードの結果。
struct Ended {
    status: Option<i32>,
    output: Vec<String>,
    errors: Vec<String>,
}

impl Piped {
    /// 起動して、解錠の案内が出るまで待つ。
    fn start(target: &EntryVault, extra: &[&str]) -> Result<Self, Box<dyn std::error::Error>> {
        let mut args = vec![
            "unlock",
            "--vault",
            target.vault_text()?,
            "--password-file",
            target.password_file_text()?,
        ];
        args.extend_from_slice(extra);
        Self::attach(spawn_without_terminal(&args)?)
    }

    /// 起動した対話モードにつなぎ、解錠の案内が出るまで待つ。
    fn attach(mut child: Child) -> Result<Self, Box<dyn std::error::Error>> {
        let input = child.stdin.take();
        let output = Lines::new(child.stdout.take().ok_or("子の標準出力がありません。")?);
        let errors = Lines::new(
            child
                .stderr
                .take()
                .ok_or("子の標準エラー出力がありません。")?,
        );
        let mut session = Self {
            child,
            input,
            output,
            errors,
        };
        session.errors.expect(UNLOCKED)?;
        Ok(session)
    }

    fn send(&mut self, line: &[u8]) -> TestResult {
        let input = self.input.as_mut().ok_or("入力は閉じています。")?;
        input.write_all(line)?;
        input.write_all(b"\n")?;
        Ok(input.flush()?)
    }

    /// 入力を閉じずに、プロセスの終了を待つ。
    fn wait(mut self) -> Result<Ended, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + TIMEOUT;
        let status = loop {
            if let Some(status) = self.child.try_wait()? {
                break status.code();
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                return Err("対話モードが終了しません。".into());
            }
            thread::sleep(Duration::from_millis(5));
        };
        Ok(Ended {
            status,
            output: self.output.finish(),
            errors: self.errors.finish(),
        })
    }

    /// 入力を閉じて、プロセスの終了を待つ。
    fn close(mut self) -> Result<Ended, Box<dyn std::error::Error>> {
        drop(self.input.take());
        self.wait()
    }
}

impl Ended {
    fn assert_last_error(&self, status: i32, message: &str) {
        assert_eq!(
            self.status,
            Some(status),
            "終了コードの確認に失敗: {:?}",
            self.errors
        );
        assert!(
            self.errors
                .last()
                .is_some_and(|line| line.contains(message)),
            "最後の出力の確認に失敗: {:?}",
            self.errors
        );
    }
}

#[test]
fn test_piped_commands_run_until_end_of_input() -> TestResult {
    let target = EntryVault::new(&[credential(2, "bravo"), credential(1, "alpha one")])?;
    let before = target.contents()?;
    let mut session = Piped::start(&target, &[])?;
    let long_line = vec![b'a'; 4097];
    for line in [
        &b"list"[..],
        b"",
        b"get alpha one --field password",
        b"unknown",
        b"get missing",
        b"set bravo",
        b"delete bravo",
        &long_line,
        b"get \xff",
        b"get bravo",
        b"help",
    ] {
        session.send(line)?;
    }
    // 終端の無い最後の行も実行する。
    session
        .input
        .as_mut()
        .ok_or("入力は閉じています。")?
        .write_all(b"get bravo --field username")?;
    let ended = session.close()?;

    assert_eq!(ended.status, Some(0), "終了に失敗: {:?}", ended.errors);
    let output = ended.output.join("\n");
    assert!(output.starts_with(
        "alpha one\tuser-of-alpha one\thttps://1.example\n\
         bravo\tuser-of-bravo\thttps://2.example\n\
         password-of-alpha one\n\
         タイトル: bravo\n"
    ));
    assert!(output.contains("パスワード: ********"));
    assert!(output.contains("lock, exit"));
    assert!(output.contains("クリップボードマネージャー"));
    assert!(output.ends_with("\nuser-of-bravo"), "出力: {output}");
    assert!(!output.contains(COMMAND_PROMPT));
    let errors = ended.errors.join("\n");
    assert!(
        !errors.contains(COMMAND_PROMPT),
        "端末でない入力に案内を出さないことの確認に失敗。"
    );
    let expected = [
        "知らないコマンドです。",
        "指定されたエントリがありません。",
        "この操作には端末が必要です。",
        "この操作には端末が必要です。",
        "コマンドの行が長すぎます。",
        "コマンドの行が UTF-8 ではありません。",
        LOCKED,
    ];
    let reported: Vec<_> = ended.errors.iter().skip(1).collect();
    assert_eq!(reported.len(), expected.len(), "失敗の表示の数: {errors}");
    for (line, message) in reported.iter().zip(expected) {
        assert!(line.contains(message), "{message} の順の確認に失敗: {line}");
    }
    assert!(target.contents()? == before);
    Ok(())
}

#[test]
fn test_lock_and_exit_stop_before_later_commands() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    for command in [&b"lock"[..], b"exit"] {
        let mut session = Piped::start(&target, &[])?;
        session.send(command)?;
        // 続きの行は、読み込まれていても実行しない。
        let _ = session.send(b"list");
        let ended = session.wait()?;
        assert_eq!(ended.status, Some(0));
        assert!(ended.output.is_empty(), "実行した出力: {:?}", ended.output);
        assert!(ended.errors.last().is_some_and(|line| line == LOCKED));
    }
    Ok(())
}

#[test]
fn test_each_command_reads_the_latest_vault() -> TestResult {
    let target = EntryVault::new(&[credential(1, "first")])?;
    let mut session = Piped::start(&target, &[])?;
    session.send(b"list")?;
    session.output.expect("first")?;
    // 同じ世代の内容の置き換えと、世代の進行を取り込む。
    for (epoch, title) in [(1, "same-epoch"), (9, "later-epoch")] {
        target.overwrite(epoch, &[credential(2, title)])?;
        session.send(b"list")?;
        session.output.expect(title)?;
    }
    assert_eq!(session.close()?.status, Some(0));
    Ok(())
}

#[test]
fn test_rewound_epoch_ends_the_session() -> TestResult {
    // 開始時の世代より古い内容と、途中で確認した世代より古い内容の両方を検知する。
    for (initial, seen, rewound) in [(3, None, 2), (1, Some(5), 4)] {
        let target = EntryVault::new(&[credential(1, "a")])?;
        target.overwrite(initial, &[credential(1, "a")])?;
        let mut session = Piped::start(&target, &[])?;
        if let Some(epoch) = seen {
            target.overwrite(epoch, &[credential(1, "seen")])?;
            session.send(b"list")?;
            session.output.expect("seen")?;
        }
        target.overwrite(rewound, &[credential(1, "old")])?;
        session.send(b"list")?;
        let ended = session.wait()?;
        ended.assert_last_error(1, "世代が以前に読み込んだものより古い");
        assert!(!ended.output.iter().any(|line| line.contains("old")));
    }
    Ok(())
}

#[test]
fn test_replaced_key_ends_the_session() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let other = EntryVault::new(&[credential(2, "other")])?;
    let mut session = Piped::start(&target, &[])?;
    fs::write(&target.vault, other.contents()?)?;
    session.send(b"list")?;
    let ended = session.wait()?;
    ended.assert_last_error(3, "Vault の解錠に失敗しました。");
    assert!(ended.output.is_empty());
    Ok(())
}

#[test]
fn test_missing_vault_and_held_lock_keep_the_session() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let mut session = Piped::start(&target, &[])?;
    let moved = target.directory.path("moved");
    fs::rename(&target.vault, &moved)?;
    session.send(b"list")?;
    session
        .errors
        .expect("指定されたパスに Vault がありません。")?;
    fs::rename(&moved, &target.vault)?;

    let lock = VaultLock::try_acquire(VaultPath::resolve(&target.vault)?)?;
    session.send(b"list")?;
    session.errors.expect("他の処理が Vault を使用中です。")?;
    drop(lock);

    session.send(b"list")?;
    session.output.expect("user-of-a")?;
    // コマンドの実行の後は、ロックを解放している。
    session.send(b"get missing")?;
    session.errors.expect("指定されたエントリがありません。")?;
    drop(VaultLock::try_acquire(VaultPath::resolve(&target.vault)?)?);
    assert_eq!(session.close()?.status, Some(0));
    Ok(())
}

/// ディスプレイの無い環境では、コピーの失敗を表示して続けること。
#[cfg(target_os = "linux")]
#[test]
fn test_clip_failure_keeps_the_session() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let mut session = Piped::start(&target, &[])?;
    session.send(b"get a --clip password")?;
    session.errors.expect("クリップボードを利用できません。")?;
    session.send(b"list")?;
    session.output.expect("user-of-a")?;
    let ended = session.close()?;
    assert_eq!(ended.status, Some(0));
    assert!(
        !ended
            .output
            .iter()
            .any(|line| line.contains("password-of-a"))
    );
    Ok(())
}

/// 対話モードの `--clip` が指定の項目をコピーし、対話モードを続けること。
#[test]
#[ignore = "クリップボードを上書きする。ディスプレイのある環境で明示して実行する。"]
fn test_session_clip_copies_the_field_on_a_display() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let child = common::entry_vault::spawn_with_display(&[
        "unlock",
        "--vault",
        target.vault_text()?,
        "--password-file",
        target.password_file_text()?,
    ])?;
    let mut session = Piped::attach(child)?;
    session.send(b"get a --clip totp")?;
    session
        .output
        .expect("TOTP をクリップボードにコピーしました。")?;
    assert_eq!(arboard::Clipboard::new()?.get_text()?, "totp-of-a");
    session.send(b"list")?;
    session.output.expect("user-of-a")?;
    let ended = session.close()?;
    assert_eq!(ended.status, Some(0), "終了に失敗: {:?}", ended.errors);
    assert!(!ended.output.iter().any(|line| line.contains("totp-of-a")));
    Ok(())
}

#[test]
fn test_signals_end_the_session_with_interrupted_status() -> TestResult {
    let target = EntryVault::new(&[])?;
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        let session = Piped::start(&target, &[])?;
        let child = i32::try_from(session.child.id())?;
        // SAFETY: 起動した子へシグナルを送るだけで、メモリを参照しない。
        if unsafe { libc::kill(child, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        session.wait()?.assert_last_error(130, "中断");
    }
    Ok(())
}

#[test]
fn test_idle_session_locks_after_the_timeout() -> TestResult {
    let target = EntryVault::new(&[])?;
    let started = Instant::now();
    let session = Piped::start(&target, &["--idle-timeout", "1"])?;
    let ended = session.wait()?;
    assert!(
        started.elapsed() >= Duration::from_secs(1),
        "上限より前に施錠しないことの確認に失敗。"
    );
    assert_eq!(ended.status, Some(0));
    assert!(ended.errors.last().is_some_and(|line| line == IDLE_LOCKED));
    Ok(())
}

/// コマンドを受け取るたびに、無操作の時間を測り直すこと。
#[test]
fn test_activity_restarts_the_idle_timeout() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let mut session = Piped::start(&target, &["--idle-timeout", "3"])?;
    let started = Instant::now();
    for _ in 0..4 {
        thread::sleep(Duration::from_millis(1200));
        session.send(b"list")?;
        session.output.expect("user-of-a")?;
    }
    assert!(started.elapsed() > Duration::from_secs(3));
    let ended = session.wait()?;
    assert_eq!(ended.status, Some(0));
    assert!(ended.errors.last().is_some_and(|line| line == IDLE_LOCKED));
    Ok(())
}

/// 結果を書けない場合は、施錠して終了し、後のコマンドを実行しないこと。
#[test]
fn test_output_failure_ends_the_session() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let mut child = spawn_without_terminal(&[
        "unlock",
        "--vault",
        target.vault_text()?,
        "--password-file",
        target.password_file_text()?,
    ])?;
    drop(child.stdout.take());
    let mut input = child.stdin.take().ok_or("子の標準入力がありません。")?;
    let mut errors = Lines::new(
        child
            .stderr
            .take()
            .ok_or("子の標準エラー出力がありません。")?,
    );
    errors.expect(UNLOCKED)?;
    input.write_all(b"list\n")?;
    errors.expect("標準出力への書き込みに失敗しました。")?;
    // 入力を閉じなくても終了する。
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status.code();
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err("対話モードが終了しません。".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status, Some(1));
    Ok(())
}

#[test]
fn test_wrong_password_does_not_start_the_session() -> TestResult {
    let target = EntryVault::new(&[])?;
    fs::write(&target.password_file, b"wrong")?;
    let output = common::entry_vault::run_without_terminal(
        &[
            "unlock",
            "--vault",
            target.vault_text()?,
            "--password-file",
            target.password_file_text()?,
        ],
        b"list\n",
    )?;
    common::entry_vault::assert_process_failure(&output, 3, "Vault の解錠に失敗しました。");
    Ok(())
}

/// 標準入出力を端末にして起動し、パスワードを入力する。
fn terminal(target: &EntryVault, extra: &[&str]) -> Result<Session, Box<dyn std::error::Error>> {
    let mut args = vec!["unlock", "--vault", target.vault_text()?];
    args.extend_from_slice(extra);
    let options = Options {
        redirect: Redirect::Terminal,
        ..Options::default()
    };
    let mut session = Session::spawn(&args, &options)?;
    session.answer("マスターパスワード: ", PASSWORD)?;
    Ok(session)
}

/// `count` 回目の入力の案内を待って、コマンドを入力する。
fn command(session: &mut Session, count: usize, line: &str) -> TestResult {
    session.wait_for_screen(COMMAND_PROMPT, count)?;
    session.type_input(format!("{line}\r").as_bytes())
}

#[test]
fn test_interactive_session_edits_entries() -> TestResult {
    let target = EntryVault::new(&[credential(1, "existing")])?;
    let epoch = target.epoch()?;
    let mut session = terminal(&target, &[])?;
    command(&mut session, 1, "set added entry")?;
    session.answer("ユーザー名 (", "Typed-User")?;
    session.answer("パスワード (", "typed-secret")?;
    session.answer("もう一度入力してください: ", "typed-secret")?;
    session.answer("URL (", "")?;
    session.answer("otpauth URI (", "")?;
    session.answer("メモ (1 行)", "")?;
    command(&mut session, 2, "list")?;
    session.wait_for_screen("added entry\ttyped-user", 1)?;
    assert!(
        !session.pty.text().contains("typed-secret"),
        "入力した秘密を表示しないことの確認に失敗。"
    );
    command(&mut session, 3, "get added entry --field password")?;
    session.wait_for_screen("typed-secret\r\n", 1)?;
    command(&mut session, 4, "delete existing")?;
    session.answer("y/N", "y")?;
    session.wait_for_screen("エントリを削除しました: existing", 1)?;
    // 続けて保存した後も、自分の保存を巻き戻しと扱わない。
    command(&mut session, 5, "delete added entry")?;
    session.wait_for_screen("y/N", 2)?;
    session.type_input(b"n\r")?;
    command(&mut session, 6, "list")?;
    command(&mut session, 7, "exit")?;
    let outcome = session.finish()?;
    assert_eq!(outcome.status, 0, "終了に失敗: {}", outcome.screen);
    assert!(outcome.screen.contains(LOCKED));
    assert!(outcome.screen.contains("削除に同意しなかったため"));
    assert_eq!(target.epoch()?, epoch + 2);
    let titles: Vec<_> = target
        .credentials()?
        .into_iter()
        .map(|credential| credential.title)
        .collect();
    assert_eq!(titles, [Some("added entry".to_owned())]);
    Ok(())
}

/// 対話モードで保存した後は、保存前の世代へ戻された内容も、巻き戻しとして検知すること。
#[test]
fn test_own_save_advances_the_rollback_baseline() -> TestResult {
    for saving in ["set a", "delete a"] {
        let target = EntryVault::new(&[credential(1, "a")])?;
        let original = target.contents()?;
        let mut session = terminal(&target, &[])?;
        command(&mut session, 1, saving)?;
        if saving == "set a" {
            session.answer("ユーザー名 (", "changed")?;
            for prompt in ["パスワード (", "URL (", "otpauth URI (", "メモ (1 行)"] {
                session.answer(prompt, "")?;
            }
        } else {
            session.answer("y/N", "y")?;
        }
        session.wait_for_screen(COMMAND_PROMPT, 2)?;
        fs::write(&target.vault, &original)?;
        session.type_input(b"list\r")?;
        let outcome = session.finish()?;
        assert_eq!(
            outcome.status, 1,
            "{saving} の後の巻き戻しの検知に失敗: {}",
            outcome.screen
        );
        assert!(
            outcome
                .screen
                .contains("世代が以前に読み込んだものより古い")
        );
    }
    Ok(())
}

#[test]
fn test_end_of_input_cancels_a_field_but_ends_the_session_at_the_prompt() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let before = target.contents()?;
    let mut session = terminal(&target, &[])?;
    command(&mut session, 1, "set a")?;
    session.wait_for_screen("ユーザー名 (", 1)?;
    session.type_input(b"\x04")?;
    session.wait_for_screen("エントリを保存しませんでした。", 1)?;
    session.wait_for_screen(COMMAND_PROMPT, 2)?;
    session.type_input(b"\x04")?;
    let outcome = session.finish()?;
    assert_eq!(outcome.status, 0, "終了に失敗: {}", outcome.screen);
    assert!(outcome.screen.contains(LOCKED));
    assert!(target.contents()? == before);
    Ok(())
}

#[test]
fn test_interrupt_at_any_prompt_ends_the_session() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let before = target.contents()?;
    for (line, prompt) in [
        (None, COMMAND_PROMPT),
        (Some("set a"), "ユーザー名 ("),
        (Some("delete a"), "y/N"),
    ] {
        let mut session = terminal(&target, &[])?;
        if let Some(line) = line {
            command(&mut session, 1, line)?;
        }
        session.wait_for_screen(prompt, 1)?;
        // 端末の `Ctrl+C` が `SIGINT` になる。
        session.type_input(b"\x03")?;
        let outcome = session.finish()?;
        assert_eq!(
            outcome.status, 130,
            "{prompt} の中断に失敗: {}",
            outcome.screen
        );
    }
    assert!(target.contents()? == before);
    Ok(())
}

#[test]
fn test_idle_timeout_applies_to_every_prompt() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let before = target.contents()?;
    for (line, prompt) in [
        (None, COMMAND_PROMPT),
        (Some("set a"), "ユーザー名 ("),
        (Some("delete a"), "y/N"),
    ] {
        let mut session = terminal(&target, &["--idle-timeout", "1"])?;
        if let Some(line) = line {
            command(&mut session, 1, line)?;
        }
        session.wait_for_screen(prompt, 1)?;
        // 端末属性の復元は、`finish` が確かめる。
        let outcome = session.finish()?;
        assert_eq!(
            outcome.status, 0,
            "{prompt} の施錠に失敗: {}",
            outcome.screen
        );
        assert!(
            outcome.screen.contains(IDLE_LOCKED),
            "{prompt} の施錠の表示に失敗: {}",
            outcome.screen
        );
        assert!(!outcome.screen.contains("fidelogic-cli: "));
        // 施錠の後は、ロックを解放している。
        drop(VaultLock::try_acquire(VaultPath::resolve(&target.vault)?)?);
    }
    assert!(target.contents()? == before);
    Ok(())
}
