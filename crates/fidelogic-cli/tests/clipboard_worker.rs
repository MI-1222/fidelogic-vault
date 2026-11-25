//! クリップボードのワーカー (`__clipboard-worker`) を、実行ファイルを起動して確かめる統合テスト。
//!
//! 通常の実行では、クリップボードに書き込む前に失敗する場合だけを確かめる。
//! 開発者のクリップボードを上書きしないためである。
//!
//! 実際にコピーして 30 秒後の消去を確かめるテストは `#[ignore]` にしている。
//! ディスプレイのある環境 (X11 なら Xvfb など) で、次のように明示して実行する。
//!
//! ```text
//! cargo test -p fidelogic-cli --test clipboard_worker -- --ignored --test-threads=1
//! ```

use std::io::{Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use fidelogic_cli::sys::clipboard::{
    CLEAR_DELAY, ClipboardError, HistoryPolicy, MAX_TEXT_LEN, WORKER_SUBCOMMAND, copy_via_worker,
    reap_finished_workers,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// ワーカーが失敗して終了するまでの上限。成功してしまった場合に 30 秒待たないようにする。
const FAILURE_TIMEOUT: Duration = Duration::from_secs(10);

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_fidelogic-cli"))
}

/// ワーカーを起動し、`input` を標準入力に書いて閉じ、終了を待つ。
///
/// [`FAILURE_TIMEOUT`] を過ぎても終了しない場合は、子を終了させてエラーを返す。
fn run_worker(input: &[u8], remove_display: bool) -> Result<Output, Box<dyn std::error::Error>> {
    let mut command = Command::new(binary());
    command
        .arg(WORKER_SUBCOMMAND)
        .arg("--exclude-from-history")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if remove_display {
        command.env_remove("DISPLAY").env_remove("WAYLAND_DISPLAY");
    }
    let mut child = command.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        // 上限を超える入力では、ワーカーが先に終了して書き込みが失敗することがある。
        let _ = stdin.write_all(input);
    }
    let started = Instant::now();
    while child.try_wait()?.is_none() {
        if started.elapsed() > FAILURE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("ワーカーが時間内に終了しなかったため失敗しました。".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(child.wait_with_output()?)
}

#[test]
fn test_invalid_input_fails_with_one_status_byte() -> TestResult {
    let too_long = vec![b'a'; MAX_TEXT_LEN + 1];
    for input in [&b""[..], &[0xff, 0xfe, 0xfd][..], &too_long[..]] {
        let output = run_worker(input, false)?;
        assert_eq!(
            output.status.code(),
            Some(1),
            "長さ {} の入力の終了コードの確認に失敗。",
            input.len()
        );
        assert_eq!(
            output.stdout.len(),
            1,
            "応答が 1 バイトであることの確認に失敗: {:?}",
            output.stdout
        );
        // 失敗の内容は標準エラー出力に 1 行で書く (親は標準エラー出力を捨てる)。
        let stderr = String::from_utf8(output.stderr)?;
        assert!(stderr.starts_with("fidelogic-cli: "), "{stderr}");
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
    }
    Ok(())
}

/// 疑似端末のプログラム側の記述子を開く。利用者側は呼び出し側が保持する。
fn open_pty() -> Result<(OwnedFd, OwnedFd), Box<dyn std::error::Error>> {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: 2 つの出力先は有効で、名前、端末属性、窓の大きさには null を渡す。
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: `openpty` が成功した直後の記述子で、所有者は他に無い。
    Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
}

/// 利用者が端末から直接起動した場合 (標準入力が端末) は、入力を読まずに拒否する。
#[test]
fn test_worker_rejects_terminal_input() -> TestResult {
    let (_master, slave) = open_pty()?;
    let mut child = Command::new(binary())
        .arg(WORKER_SUBCOMMAND)
        .stdin(Stdio::from(slave))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    while child.try_wait()?.is_none() {
        if started.elapsed() > FAILURE_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("端末からの入力を拒否せずに待ち続けたため失敗しました。".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 1, "{:?}", output.stdout);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains(&ClipboardError::InvalidInput.to_string()),
        "{stderr}"
    );
    Ok(())
}

#[test]
fn test_copy_rejects_empty_and_too_long_text_without_spawning() {
    // 存在しない実行ファイルを指定しても、起動の前に長さで拒否する。
    let missing = Path::new("/nonexistent/fidelogic-cli");
    assert_eq!(
        copy_via_worker(missing, "", HistoryPolicy::Exclude),
        Err(ClipboardError::Empty)
    );
    let too_long = "a".repeat(MAX_TEXT_LEN + 1);
    assert_eq!(
        copy_via_worker(missing, &too_long, HistoryPolicy::Exclude),
        Err(ClipboardError::TooLong)
    );
}

#[test]
fn test_copy_reports_spawn_failure() {
    let missing = Path::new("/nonexistent/fidelogic-cli");
    assert!(matches!(
        copy_via_worker(missing, "s3cret", HistoryPolicy::Exclude),
        Err(ClipboardError::Os { errno, .. }) if errno == libc::ENOENT
    ));
}

/// テスト用の一時ディレクトリ。破棄時に削除する。
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "fidelogic-cli-clipboard-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// ワーカーの代わりに起動するシェルスクリプトを作り、パスを返す。
///
/// ファイルの書き込みは別のプロセスに任せる。テストのプロセスが書き込み用の記述子を持つと、
/// 並行するテストが起動した子に記述子が引き継がれ、実行が `ETXTBSY` で失敗することがある。
fn write_script(directory: &TempDir, body: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = directory.0.join("fake-worker.sh");
    let mut writer = Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 700 \"$1\"", "sh"])
        .arg(&path)
        .stdin(Stdio::piped())
        .spawn()?;
    writer
        .stdin
        .take()
        .ok_or("標準入力の取得に失敗。")?
        .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())?;
    if !writer.wait()?.success() {
        return Err("スクリプトの作成に失敗。".into());
    }
    Ok(path)
}

/// [`copy_via_worker`] を別のスレッドで呼び、[`FAILURE_TIMEOUT`] を過ぎても戻らなければ失敗にする。
///
/// 親が入力を閉じない欠陥などがあると、呼び出しは戻らない。テストを止めずに失敗させる。
fn copy_within_timeout(
    program: &Path,
    text: &str,
    policy: HistoryPolicy,
) -> Result<Result<(), ClipboardError>, Box<dyn std::error::Error>> {
    let (sender, receiver) = mpsc::channel();
    let program = program.to_path_buf();
    let text = text.to_owned();
    std::thread::spawn(move || {
        let _ = sender.send(copy_via_worker(&program, &text, policy));
    });
    receiver
        .recv_timeout(FAILURE_TIMEOUT)
        .map_err(|_| "ワーカーの起動元が時間内に戻らなかったため失敗しました。".into())
}

/// 親は、引数・カレントディレクトリ・プロセスグループ・秘密を、決められた形でワーカーに渡す。
#[test]
fn test_parent_starts_worker_with_expected_arguments_and_input() -> TestResult {
    let directory = TempDir::new()?;
    let output = directory.0.display();
    let script = write_script(
        &directory,
        &format!(
            "printf '%s\\n' \"$@\" > '{output}/args'\n\
             pwd > '{output}/cwd'\n\
             cat > '{output}/input'\n\
             echo $$ > '{output}/pid'\n\
             printf '\\001'\n\
             exec sleep 10"
        ),
    )?;
    let secret = "s".repeat(MAX_TEXT_LEN);

    copy_within_timeout(&script, &secret, HistoryPolicy::Exclude)??;

    let pid: libc::pid_t = std::fs::read_to_string(directory.0.join("pid"))?
        .trim()
        .parse()?;
    // SAFETY: 整数引数だけで、プロセスグループの ID を読み取る。
    let group = unsafe { libc::getpgid(pid) };
    // SAFETY: このテストが起動した子を終了させて回収する。状態の出力先には null を渡す。
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, core::ptr::null_mut(), 0);
    }
    assert_eq!(group, pid, "新しいプロセスグループでの起動の確認に失敗。");
    assert_eq!(
        std::fs::read_to_string(directory.0.join("args"))?,
        "__clipboard-worker\n--exclude-from-history\n"
    );
    assert_eq!(std::fs::read_to_string(directory.0.join("cwd"))?, "/\n");
    assert_eq!(std::fs::read_to_string(directory.0.join("input"))?, secret);
    Ok(())
}

/// プロセスが存在するか (回収していないゾンビを含む) を返す。
fn process_exists(pid: libc::pid_t) -> bool {
    // SAFETY: シグナル 0 は送信せず、対象の有無だけを調べる。
    unsafe { libc::kill(pid, 0) == 0 }
}

/// コピーに成功する偽のワーカーを起動し、その PID を返す。応答の後は `after_reply` を実行する。
fn start_fake_worker(
    directory: &TempDir,
    after_reply: &str,
) -> Result<libc::pid_t, Box<dyn std::error::Error>> {
    let output = directory.0.display();
    let script = write_script(
        directory,
        &format!("cat > /dev/null\necho $$ > '{output}/pid'\nprintf '\\001'\n{after_reply}"),
    )?;
    copy_within_timeout(&script, "s3cret", HistoryPolicy::Allow)??;
    Ok(std::fs::read_to_string(directory.0.join("pid"))?
        .trim()
        .parse()?)
}

/// 終了したワーカーは回収し、実行中のワーカーは待たずに残すこと。
#[test]
fn test_reap_collects_only_finished_workers() -> TestResult {
    let running_directory = TempDir::new()?;
    let running = start_fake_worker(&running_directory, "exec sleep 10")?;
    let finished_directory = TempDir::new()?;
    let finished = start_fake_worker(&finished_directory, "exit 0")?;
    assert!(
        process_exists(finished),
        "回収の前に子プロセスが残ることの確認に失敗。"
    );

    let started = Instant::now();
    while process_exists(finished) {
        assert!(
            started.elapsed() < FAILURE_TIMEOUT,
            "終了したワーカーの回収に失敗。"
        );
        reap_finished_workers();
        std::thread::sleep(Duration::from_millis(20));
    }
    let still_running = process_exists(running);
    // SAFETY: このテストが起動した子を終了させるだけで、メモリを参照しない。
    unsafe {
        libc::kill(running, libc::SIGKILL);
    }
    assert!(still_running, "実行中のワーカーを残すことの確認に失敗。");
    Ok(())
}

/// 親は、ワーカーの応答をエラーに変換する。応答が無い場合は `WorkerFailed` になる。
#[test]
fn test_parent_maps_worker_status() -> TestResult {
    let cases = [
        ("printf '\\002'", ClipboardError::InvalidInput),
        ("printf '\\003'", ClipboardError::MemoryLockFailed),
        ("printf '\\004'", ClipboardError::Unavailable),
        ("printf '\\005'", ClipboardError::CopyFailed),
        ("printf '\\006'", ClipboardError::WorkerFailed),
        ("exit 0", ClipboardError::WorkerFailed),
    ];
    for (reply, expected) in cases {
        let directory = TempDir::new()?;
        // 入力を読み切ってから応答し、親の書き込みが失敗しないようにする。
        let script = write_script(&directory, &format!("cat > /dev/null\n{reply}"))?;
        assert_eq!(
            copy_within_timeout(&script, "s3cret", HistoryPolicy::Allow)?,
            Err(expected),
            "{reply} の変換の確認に失敗。"
        );
    }
    Ok(())
}

/// ワーカーは、秘密を読み込む前にプロセス硬化を適用する。
///
/// 入力を閉じずに待たせ、その間の `RLIMIT_CORE` を `/proc` で読み取る。クリップボードには触れない。
#[cfg(target_os = "linux")]
#[test]
fn test_worker_is_hardened_while_waiting_for_input() -> TestResult {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` は書き込み可能な有効な構造体であり、呼び出しの間は生存している。
    if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } != 0 {
        return Err("親プロセスの RLIMIT_CORE の取得に失敗。".into());
    }
    let before = limit.rlim_max.min(1 << 20);
    if before == 0 {
        println!("スキップ: 親プロセスの RLIMIT_CORE が 0 のため、変更前の状態を再現できない。");
        return Ok(());
    }

    let mut command = Command::new(binary());
    command
        .arg(WORKER_SUBCOMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setrlimit` は非同期シグナルセーフであり、ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: before,
                rlim_max: before,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn()?;
    let path = format!("/proc/{}/limits", child.id());
    let started = Instant::now();
    let mut observed = String::new();
    let mut hardened = false;
    while !hardened && started.elapsed() < FAILURE_TIMEOUT {
        observed = std::fs::read_to_string(&path)?
            .lines()
            .find(|line| line.starts_with("Max core file size"))
            .unwrap_or_default()
            .to_owned();
        // 列は、名前の 4 語に続いて、ソフト上限、ハード上限、単位である。
        let columns: Vec<&str> = observed.split_whitespace().collect();
        hardened = columns.get(4..6) == Some(&["0", "0"][..]);
        std::thread::sleep(Duration::from_millis(20));
    }
    // 空の入力でワーカーを終了させる。
    drop(child.stdin.take());
    child.wait()?;
    assert!(hardened, "ワーカーの硬化の確認に失敗: {observed}");
    Ok(())
}

/// ディスプレイの無い Linux では、クリップボードに接続できないことを報告する。
#[cfg(target_os = "linux")]
#[test]
fn test_worker_without_display_reports_unavailable() -> TestResult {
    let output = run_worker(b"s3cret", true)?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout.len(), 1, "{:?}", output.stdout);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        stderr.contains(&ClipboardError::Unavailable.to_string()),
        "{stderr}"
    );

    if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        println!("スキップ: ディスプレイがあるため、親からの起動は確かめない。");
        return Ok(());
    }
    assert_eq!(
        copy_via_worker(binary(), "s3cret", HistoryPolicy::Exclude),
        Err(ClipboardError::Unavailable)
    );
    Ok(())
}

/// コピーした内容を読み取る。
fn clipboard_text() -> Result<String, arboard::Error> {
    arboard::Clipboard::new()?.get_text()
}

/// 直接起動したワーカーが、コピーの成功を応答するまで待つ。
fn wait_until_copied(worker: &mut std::process::Child) -> TestResult {
    let mut status = [0u8; 1];
    worker
        .stdout
        .as_mut()
        .ok_or("標準出力の取得に失敗。")?
        .read_exact(&mut status)?;
    assert_eq!(status, [1], "コピーの応答の確認に失敗。");
    Ok(())
}

/// 待機中に `SIGTERM` を受けたワーカーは、30 秒を待たずに消去して終了する。
#[test]
#[ignore = "クリップボードを上書きする。ディスプレイのある環境で明示して実行する。"]
fn test_sigterm_ends_wait_and_clears() -> TestResult {
    let secret = format!("fidelogic-test-sigterm-{}", std::process::id());
    let mut worker = Command::new(binary())
        .arg(WORKER_SUBCOMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = worker.stdin.take() {
        stdin.write_all(secret.as_bytes())?;
    }
    wait_until_copied(&mut worker)?;
    assert_eq!(clipboard_text()?, secret);

    let pid = libc::pid_t::try_from(worker.id())?;
    // SAFETY: このテストが起動し、まだ回収していない子にシグナルを送る。
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let started = Instant::now();
    let exit = loop {
        if let Some(exit) = worker.try_wait()? {
            break exit;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = worker.kill();
            let _ = worker.wait();
            return Err("SIGTERM で待機を切り上げなかったため失敗しました。".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    // シグナルによる強制終了ではなく、消去の処理を経た正常終了である。
    assert_eq!(exit.code(), Some(0), "{exit:?}");
    assert_ne!(clipboard_text().unwrap_or_default(), secret);
    Ok(())
}

/// 実際にコピーし、内容が変わらなければ 30 秒後に消去されることを確かめる。
#[test]
#[ignore = "クリップボードを上書きし、30 秒以上かかる。ディスプレイのある環境で明示して実行する。"]
fn test_copied_text_is_cleared_after_delay() -> TestResult {
    let secret = format!("fidelogic-test-{}", std::process::id());
    copy_via_worker(binary(), &secret, HistoryPolicy::Exclude)?;
    assert_eq!(
        clipboard_text()?,
        secret,
        "コピーした内容の読み取りに失敗。"
    );

    std::thread::sleep(CLEAR_DELAY + Duration::from_secs(2));
    let remaining = clipboard_text().unwrap_or_default();
    assert_ne!(remaining, secret, "30 秒後の消去に失敗。");
    Ok(())
}

/// 待機中に利用者が別の内容をコピーした場合は、その内容を消さないことを確かめる。
#[test]
#[ignore = "クリップボードを上書きし、30 秒以上かかる。ディスプレイのある環境で明示して実行する。"]
fn test_replaced_text_survives_delay() -> TestResult {
    let secret = format!("fidelogic-test-secret-{}", std::process::id());
    let replacement = format!("fidelogic-test-user-{}", std::process::id());
    let copied_at = Instant::now();
    copy_via_worker(binary(), &secret, HistoryPolicy::Exclude)?;

    // 利用者のコピーを、別のプロセスとして模す (Linux では所有者が別のプロセスになる)。
    // 2 つ目も 30 秒後に自分の内容を消すため、最初の消去の時刻と十分に離して起動する。
    std::thread::sleep(Duration::from_secs(5));
    let mut owner = Command::new(binary())
        .arg(WORKER_SUBCOMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = owner.stdin.take() {
        stdin.write_all(replacement.as_bytes())?;
    }
    wait_until_copied(&mut owner)?;
    assert_eq!(clipboard_text()?, replacement);

    // 最初のワーカーの消去の時刻 (2 秒の余裕を見る) を過ぎても、置き換えた内容が残る。
    let check_at = CLEAR_DELAY + Duration::from_secs(2);
    std::thread::sleep(check_at.saturating_sub(copied_at.elapsed()));
    let remaining = clipboard_text().unwrap_or_default();
    let _ = owner.kill();
    let _ = owner.wait();
    assert_eq!(
        remaining, replacement,
        "置き換えた内容が残ることの確認に失敗。"
    );
    Ok(())
}
