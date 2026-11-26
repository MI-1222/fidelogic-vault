//! `list`, `get`, `set`, `delete`, `export` を、実行ファイルで確かめる統合テスト。
//!
//! 端末が要る操作は疑似端末で、端末が要らない操作は制御端末の無いプロセスで実行する。

mod common;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use common::entry_vault::{
    EntryVault, assert_process_failure, credential, run_without_terminal, write_private,
};
use common::fixture::{Tamper, write_fixture, write_vault};
use common::{
    Options, PASSWORD, Session, TempDir, TestResult, assert_failure, mode_of, read_vault, text,
};
use fidelogic_cli::sys::storage::{VaultLock, VaultPath};
use fidelogic_core::{Credential, SecretVec, TlvRecord, UnknownField};

const PASSWORD_PROMPT: &str = "マスターパスワード: ";
const USERNAME_PROMPT: &str = "ユーザー名 (空の Enter で";
const PASSWORD_FIELD_PROMPT: &str = "パスワード (空の Enter で";
const REPEAT_PROMPT: &str = "もう一度入力してください: ";
const URL_PROMPT: &str = "URL (空の Enter で";
const TOTP_PROMPT: &str = "otpauth URI (空の Enter で";
const NOTES_PROMPT: &str = "メモ (1 行) (空の Enter で";
const DELETE_PROMPT: &str = "削除します。元に戻せません。";
const EXPORT_PROMPT: &str = "平文を書き出します。";
const EXPORT_WARNING: &str = "暗号化していない平文で、すべてのパスワードを含みます。";
const AUTHENTICATION_FAILED: &str = "Vault の解錠に失敗しました。";

/// 端末で実行ファイルを起動し、マスターパスワードを入力する。
fn start(args: &[&str]) -> Result<Session, Box<dyn std::error::Error>> {
    let mut session = Session::spawn(args, &Options::default())?;
    session.answer(PASSWORD_PROMPT, PASSWORD)?;
    Ok(session)
}

/// `set` の項目の問いに順に答える。パスワードが空でなければ、再入力にも同じ値を答える。
fn answer_fields(session: &mut Session, answers: [&str; 5]) -> TestResult {
    let [username, password, url, totp, notes] = answers;
    session.answer(USERNAME_PROMPT, username)?;
    session.answer(PASSWORD_FIELD_PROMPT, password)?;
    if !password.is_empty() {
        session.answer(REPEAT_PROMPT, password)?;
    }
    session.answer(URL_PROMPT, url)?;
    session.answer(TOTP_PROMPT, totp)?;
    session.answer(NOTES_PROMPT, notes)
}

/// 各項目の値を、`username`, `password`, `url`, `totp`, `notes` の順に返す。
fn field_values(credential: &Credential) -> [Option<String>; 5] {
    let secret = |value: &Option<SecretVec>| {
        value
            .as_ref()
            .map(|value| String::from_utf8_lossy(value.as_slice()).into_owned())
    };
    [
        secret(&credential.username),
        secret(&credential.password),
        credential.url.clone(),
        secret(&credential.totp),
        secret(&credential.notes),
    ]
}

fn all(values: [&str; 5]) -> [Option<String>; 5] {
    values.map(|value| Some(value.to_owned()))
}

#[test]
fn test_set_adds_an_entry_with_canonical_values() -> TestResult {
    let target = EntryVault::new(&[credential(1, "other")])?;
    let before = read_vault(&target.vault)?;
    let args = ["set", "--vault", target.vault_text()?, "new site"];
    let mut session = start(&args)?;
    answer_fields(
        &mut session,
        [
            "Alice",
            "typed\u{3000}secret",
            "https://new.example",
            "TYPED-SEED",
            "typed memo",
        ],
    )?;
    let outcome = session.finish()?;

    assert_eq!(outcome.status, 0, "追加に失敗: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains("エントリを追加しました: new site"),
        "結果の表示の確認に失敗: {}",
        outcome.stdout
    );
    for secret in ["Alice", "typed", "TYPED-SEED", "https://new.example"] {
        assert!(
            !outcome.screen.contains(secret),
            "入力を表示しないことの確認に失敗: {secret}"
        );
    }
    assert_eq!(target.epoch()?, before.header.epoch_id + 1);
    target.assert_preserved(&before)?;
    let added = target.credential("new site")?;
    assert_eq!(
        field_values(&added),
        all([
            "alice",
            "typed secret",
            "https://new.example",
            "TYPED-SEED",
            "typed memo"
        ])
    );
    assert_ne!(added.entry_id, [0; 16]);
    assert!(
        added
            .created_at
            .is_some_and(|created| created > 1_700_000_000)
    );
    assert_eq!(added.created_at, added.updated_at);
    let other = target.credential("other")?;
    assert_eq!(field_values(&other), field_values(&credential(1, "other")));
    assert_eq!(other.updated_at, Some(200));
    assert_eq!(target.credentials()?.len(), 2);
    Ok(())
}

/// すべての項目を省略した新しいエントリは、タイトルと日時だけで保存すること。
#[test]
fn test_set_adds_an_entry_with_a_title_only() -> TestResult {
    let target = EntryVault::new(&[])?;
    let epoch = target.epoch()?;
    let mut session = start(&["set", "--vault", target.vault_text()?, "title only"])?;
    answer_fields(&mut session, ["", "", "", "", ""])?;
    let outcome = session.finish()?;

    assert_eq!(outcome.status, 0, "追加に失敗: {}", outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains("エントリを追加しました: title only"),
        "結果の表示の確認に失敗: {}",
        outcome.stdout
    );
    assert_eq!(target.epoch()?, epoch + 1);
    let added = target.credential("title only")?;
    assert_eq!(field_values(&added), [None, None, None, None, None]);
    assert!(added.created_at.is_some() && added.created_at == added.updated_at);
    Ok(())
}

#[test]
fn test_set_updates_only_the_entered_fields() -> TestResult {
    let mut original = credential(1, "site");
    original.unknown_fields.push(UnknownField {
        tag: 42,
        value: SecretVec::from_slice(b"future field"),
    });
    let target = EntryVault::new(&[original, credential(2, "other")])?;
    let before = read_vault(&target.vault)?;
    let args = ["set", "--vault", target.vault_text()?, "site"];
    let mut session = start(&args)?;
    answer_fields(&mut session, ["", "rotated", "", "", ""])?;
    let outcome = session.finish()?;

    assert_eq!(outcome.status, 0, "更新に失敗: {}", outcome.stderr);
    assert!(outcome.stdout.contains("エントリを更新しました: site"));
    assert_eq!(target.epoch()?, before.header.epoch_id + 1);
    target.assert_preserved(&before)?;
    let updated = target.credential("site")?;
    assert_eq!(
        field_values(&updated),
        all([
            "user-of-site",
            "rotated",
            "https://1.example",
            "totp-of-site",
            "notes-of-site"
        ])
    );
    assert_eq!(updated.entry_id, [1; 16]);
    assert_eq!(updated.created_at, Some(100));
    assert!(updated.updated_at.is_some_and(|time| time > 200));
    assert!(
        matches!(
            updated.unknown_fields.as_slice(),
            [field] if field.tag == 42 && field.value.as_slice() == b"future field"
        ),
        "未知のフィールドの保持の確認に失敗。"
    );
    let order: Vec<_> = target
        .credentials()?
        .iter()
        .map(|credential| credential.entry_id[0])
        .collect();
    assert_eq!(order, [1, 2], "記録順の保持の確認に失敗。");
    Ok(())
}

#[test]
fn test_set_without_changes_does_not_save() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let before = target.contents()?;
    let mut session = start(&["set", "--vault", target.vault_text()?, "site"])?;
    answer_fields(&mut session, ["", "", "", "", ""])?;
    let outcome = session.finish()?;
    assert_eq!(outcome.status, 0, "終了に失敗: {}", outcome.stderr);
    assert!(outcome.stdout.contains("変更はありません: site"));
    assert!(target.contents()? == before, "保存しないことの確認に失敗。");
    Ok(())
}

/// 4 KiB を超える複数行のメモ。末尾の改行を含む。
fn long_notes() -> String {
    let body: String = (0..120)
        .map(|index| format!("line {index:03} abcdefghijklmnopqrstuvwxyz 0123456789\n"))
        .collect();
    format!("-----BEGIN KEY-----\n{body}-----END KEY-----\n")
}

#[test]
fn test_long_notes_round_trip_from_file_and_standard_input() -> TestResult {
    let notes = long_notes();
    assert!(notes.len() > 4096);
    for from_standard_input in [false, true] {
        let target = EntryVault::new(&[])?;
        let notes_file = target.directory.path("key");
        fs::write(&notes_file, &notes)?;
        let mut args = vec![
            "set",
            "--vault",
            target.vault_text()?,
            "ssh key",
            "--password-file",
            target.password_file_text()?,
        ];
        let mut options = Options::default();
        if from_standard_input {
            args.push("--notes-stdin");
            options.stdin = Some(notes.as_bytes());
        } else {
            args.extend(["--notes-file", text(&notes_file)?]);
        }
        let mut session = Session::spawn(&args, &options)?;
        // メモは尋ねないため、TOTP の問いで終わる。
        session.answer(USERNAME_PROMPT, "")?;
        session.answer(PASSWORD_FIELD_PROMPT, "")?;
        session.answer(URL_PROMPT, "")?;
        session.answer(TOTP_PROMPT, "")?;
        let outcome = session.finish()?;
        assert_eq!(outcome.status, 0, "追加に失敗: {}", outcome.stderr);
        assert!(!outcome.screen.contains(NOTES_PROMPT));

        // 制御端末の無いプロセスで、保存したバイト列のまま取り出せる。
        let output = run_without_terminal(
            &[
                "get",
                "--vault",
                target.vault_text()?,
                "ssh key",
                "--field",
                "notes",
                "--password-file",
                target.password_file_text()?,
            ],
            b"",
        )?;
        assert_eq!(output.status.code(), Some(0));
        assert!(
            output.stdout == notes.as_bytes(),
            "メモの往復に失敗 (標準入力: {from_standard_input})。"
        );
        assert!(output.stderr.is_empty());
    }
    Ok(())
}

#[test]
fn test_set_rejects_invalid_notes_without_saving() -> TestResult {
    let target = EntryVault::new(&[])?;
    let before = target.contents()?;
    let empty = target.directory.path("empty");
    let large = target.directory.path("large");
    let binary = target.directory.path("binary");
    fs::write(&empty, b"")?;
    fs::write(&large, vec![b'a'; 65_537])?;
    fs::write(&binary, [0xff, 0xfe])?;
    let missing = target.directory.path("missing");
    let directory = target.directory.path(".");
    for (path, message) in [
        (&empty, "メモの入力が空です。"),
        (&large, "メモが上限の 65536 バイトを超えています。"),
        (&binary, "メモ に使用できない文字"),
        (&missing, "メモのファイルを開く処理に失敗しました"),
        (&directory, "メモのファイルが通常のファイルではありません。"),
    ] {
        let session = start(&[
            "set",
            "--vault",
            target.vault_text()?,
            "x",
            "--notes-file",
            text(path)?,
        ])?;
        let outcome = session.finish()?;
        assert_failure(&outcome, 1, message);
        assert!(target.contents()? == before);
    }
    Ok(())
}

#[test]
fn test_set_accepts_notes_at_the_limit() -> TestResult {
    let target = EntryVault::new(&[])?;
    let path = target.directory.path("limit");
    fs::write(&path, vec![b'a'; 65_536])?;
    let mut session = start(&[
        "set",
        "--vault",
        target.vault_text()?,
        "x",
        "--notes-file",
        text(&path)?,
    ])?;
    session.answer(USERNAME_PROMPT, "")?;
    session.answer(PASSWORD_FIELD_PROMPT, "")?;
    session.answer(URL_PROMPT, "")?;
    session.answer(TOTP_PROMPT, "")?;
    let outcome = session.finish()?;
    assert_eq!(outcome.status, 0, "追加に失敗: {}", outcome.stderr);
    assert_eq!(
        target.credential("x")?.notes.map(|notes| notes.len()),
        Some(65_536)
    );
    Ok(())
}

#[test]
fn test_set_input_errors_leave_the_vault_unchanged() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let before = target.contents()?;
    let args = ["set", "--vault", target.vault_text()?, "site"];

    // 2 回のパスワードの不一致。
    let mut session = start(&args)?;
    session.answer(USERNAME_PROMPT, "")?;
    session.answer(PASSWORD_FIELD_PROMPT, "one")?;
    session.answer(REPEAT_PROMPT, "two")?;
    assert_failure(
        &session.finish()?,
        1,
        "入力した 2 つのパスワードが一致しません。",
    );

    // 使用できない文字。
    let mut session = start(&args)?;
    session.answer(USERNAME_PROMPT, "a\u{7}b")?;
    assert_failure(&session.finish()?, 1, "ユーザー名 に使用できない文字");

    // 上限を超える行。
    let mut session = start(&args)?;
    session.answer(USERNAME_PROMPT, "")?;
    session.answer(PASSWORD_FIELD_PROMPT, "")?;
    session.answer(URL_PROMPT, &"a".repeat(1025))?;
    assert_failure(&session.finish()?, 1, "URL が、端末から入力できる上限");

    // 空の行での入力の終わり。
    let mut session = start(&args)?;
    session.answer(USERNAME_PROMPT, "bob")?;
    session.wait_for_screen(PASSWORD_FIELD_PROMPT, 1)?;
    session.type_input(b"\x04")?;
    assert_failure(
        &session.finish()?,
        1,
        "入力が途中で終了したため、エントリを保存しませんでした。",
    );

    assert!(
        target.contents()? == before,
        "Vault を変えないことの確認に失敗。"
    );
    Ok(())
}

#[test]
fn test_interrupted_set_leaves_the_vault_unchanged() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let before = target.contents()?;
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let mut session = start(&["set", "--vault", target.vault_text()?, "site"])?;
        session.answer(USERNAME_PROMPT, "bob")?;
        session.wait_for_screen(PASSWORD_FIELD_PROMPT, 1)?;
        session.send_signal(signal)?;
        assert_failure(&session.finish()?, 130, "中断");
        assert!(target.contents()? == before);
    }
    Ok(())
}

/// 入力と確認を待つ間に外部の処理が書き換えた場合は、保存しないこと。
#[test]
fn test_set_does_not_overwrite_an_external_change() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let mut session = start(&["set", "--vault", target.vault_text()?, "site"])?;
    session.wait_for_screen(USERNAME_PROMPT, 1)?;
    target.overwrite(7, &[credential(2, "external")])?;
    let external = target.contents()?;
    answer_fields(&mut session, ["bob", "", "", "", ""])?;
    assert_failure(&session.finish()?, 1, "別の処理で変更されたため");
    assert!(target.contents()? == external);
    Ok(())
}

/// タイトルの誤り、端末の無い環境、誤ったパスワード、他の処理のロックで、Vault を変えないこと。
#[test]
fn test_set_is_rejected_before_prompting() -> TestResult {
    let target = EntryVault::new(&[credential(1, "twin"), credential(2, "twin")])?;
    let before = target.contents()?;
    let vault = target.vault_text()?;
    let password_file = target.password_file_text()?;

    for title in ["", "a\u{1b}[31m", "a\nb"] {
        let session = Session::spawn(&["set", "--vault", vault, title], &Options::default())?;
        let outcome = session.finish()?;
        assert_failure(&outcome, 1, "エントリのタイトルに");
        assert!(!outcome.screen.contains(PASSWORD_PROMPT));
    }

    let session = start(&["set", "--vault", vault, "twin"])?;
    assert_failure(&session.finish()?, 1, "同じタイトルのエントリが複数ある");

    let mut session = Session::spawn(&["set", "--vault", vault, "x"], &Options::default())?;
    session.answer(PASSWORD_PROMPT, "wrong password")?;
    assert_failure(&session.finish()?, 3, AUTHENTICATION_FAILED);

    let output = run_without_terminal(
        &[
            "set",
            "--vault",
            vault,
            "x",
            "--password-file",
            password_file,
        ],
        b"",
    )?;
    assert_process_failure(&output, 1, "この操作には端末が必要です。");

    let lock = VaultLock::try_acquire(VaultPath::resolve(&target.vault)?)?;
    let session = Session::spawn(&["set", "--vault", vault, "x"], &Options::default())?;
    assert_failure(&session.finish()?, 1, "他の処理が Vault を使用中です。");
    drop(lock);

    assert!(target.contents()? == before);
    Ok(())
}

#[test]
fn test_list_shows_sorted_entries_without_secrets() -> TestResult {
    let mut hostile = credential(3, "zz\u{1b}]0;evil");
    hostile.username = Some(SecretVec::from_slice(b"line1\nline2"));
    hostile.url = None;
    let target = EntryVault::new(&[credential(2, "bravo"), hostile, credential(1, "alpha")])?;
    let before = target.contents()?;
    let output = run_without_terminal(
        &[
            "list",
            "--vault",
            target.vault_text()?,
            "--password-file",
            target.password_file_text()?,
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "alpha\tuser-of-alpha\thttps://1.example\n\
         bravo\tuser-of-bravo\thttps://2.example\n\
         zz\\u{1b}]0;evil\tline1\\nline2\t\n"
    );
    assert!(target.contents()? == before);
    Ok(())
}

/// 読み取りだけのサブコマンドは、入力と同意を待つ間にロックを保持せず、
/// 内容を変えるサブコマンドは保持すること。
#[test]
fn test_lock_is_held_only_while_a_change_is_pending() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let vault = target.vault_text()?;
    let acquire = || -> Result<bool, Box<dyn std::error::Error>> {
        Ok(VaultLock::try_acquire(VaultPath::resolve(&target.vault)?).is_ok())
    };
    for args in [
        &["list", "--vault", vault][..],
        &["get", "--vault", vault, "a"],
        &["export", "--vault", vault, "--stdout"],
    ] {
        let mut session = Session::spawn(args, &Options::default())?;
        session.wait_for_screen(PASSWORD_PROMPT, 1)?;
        assert!(acquire()?, "{args:?} のロックの解放に失敗。");
        session.send_signal(libc::SIGINT)?;
        assert_eq!(session.finish()?.status, 130);
    }
    for (args, prompt) in [
        (&["set", "--vault", vault, "a"][..], USERNAME_PROMPT),
        (&["delete", "--vault", vault, "a"], DELETE_PROMPT),
    ] {
        let mut session = start(args)?;
        session.wait_for_screen(prompt, 1)?;
        assert!(!acquire()?, "{args:?} のロックの保持に失敗。");
        session.send_signal(libc::SIGINT)?;
        assert_eq!(session.finish()?.status, 130);
    }
    Ok(())
}

#[test]
fn test_list_from_a_terminal_and_empty_vault() -> TestResult {
    let target = EntryVault::new(&[])?;
    let outcome = start(&["list", "--vault", target.vault_text()?])?.finish()?;
    assert_eq!(outcome.status, 0, "一覧に失敗: {}", outcome.stderr);
    assert!(outcome.stdout.is_empty() && outcome.stderr.is_empty());
    Ok(())
}

#[test]
fn test_get_outputs_summary_field_and_errors() -> TestResult {
    let mut partial = credential(2, "partial");
    partial.totp = None;
    let target = EntryVault::new(&[credential(1, "site"), partial])?;
    let before = target.contents()?;
    let get = |arguments: &[&str], stdin: &[u8]| {
        let mut args = vec!["get", "--vault", target.vault_text()?, "--password-stdin"];
        args.extend_from_slice(arguments);
        run_without_terminal(&args, stdin)
    };
    let password = format!("{PASSWORD}\n");

    let output = get(&["site"], password.as_bytes())?;
    assert_eq!(output.status.code(), Some(0));
    let summary = String::from_utf8(output.stdout)?;
    assert!(summary.contains("ユーザー名: user-of-site\n"));
    assert!(summary.contains("パスワード: ********\n"));
    assert!(
        !summary.contains("password-of-site")
            && !summary.contains("totp-of-site")
            && !summary.contains("notes-of-site"),
        "秘密を伏せることの確認に失敗: {summary}"
    );

    for (field, expected) in [
        ("password", "password-of-site"),
        ("username", "user-of-site"),
        ("url", "https://1.example"),
        ("totp", "totp-of-site"),
        ("notes", "notes-of-site"),
    ] {
        let output = get(&["site", "--field", field], password.as_bytes())?;
        assert_eq!(output.status.code(), Some(0), "{field} の取り出しに失敗。");
        assert_eq!(
            output.stdout,
            expected.as_bytes(),
            "{field} の値の確認に失敗。"
        );
    }

    for (arguments, message) in [
        (&["missing"][..], "指定されたエントリがありません。"),
        (
            &["partial", "--field", "totp"],
            "指定された項目は設定されていません。",
        ),
        (
            &["partial", "--clip", "totp"],
            "指定された項目は設定されていません。",
        ),
    ] {
        assert_process_failure(&get(arguments, password.as_bytes())?, 1, message);
    }
    // 誤ったパスワードは、対象のエントリの有無によらず同じ出力にする。
    for title in ["site", "missing"] {
        assert_process_failure(&get(&[title], b"wrong\n")?, 3, AUTHENTICATION_FAILED);
    }
    assert!(target.contents()? == before);
    Ok(())
}

/// ディスプレイの無い環境では、コピーに失敗して、値を出力しないこと。
///
/// macOS ではクリップボードが常に使え、開発者の内容を上書きするため、実行しない。
#[cfg(target_os = "linux")]
#[test]
fn test_get_clip_without_a_display_fails_without_printing() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let output = run_without_terminal(
        &[
            "get",
            "--vault",
            target.vault_text()?,
            "site",
            "--clip",
            "password",
            "--password-file",
            target.password_file_text()?,
        ],
        b"",
    )?;
    assert_process_failure(&output, 1, "クリップボードを利用できません。");
    Ok(())
}

#[test]
fn test_reading_commands_reject_tampered_vaults_alike() -> TestResult {
    let cases: [(&str, Tamper); 4] = [
        ("世代の改ざん", |vault| vault.header.epoch_id += 1),
        ("エントリの削除", |vault| {
            vault.records.remove(1);
        }),
        ("レコードの入れ替え", |vault| {
            vault.records.swap(1, 2)
        }),
        ("暗号スイートの改ざん", |vault| {
            vault.header.suite_id = 0x7f
        }),
    ];
    for (name, tamper) in cases {
        let target = EntryVault::new(&[credential(1, "a"), credential(2, "b")])?;
        let mut vault = read_vault(&target.vault)?;
        tamper(&mut vault);
        write_vault(&target.vault, &vault)?;
        let vault = target.vault_text()?;
        let password = target.password_file_text()?;
        for args in [
            &["list"][..],
            &["get", "a"],
            &["delete", "a", "--yes"],
            &["export", "--stdout", "--confirm-plaintext"],
        ] {
            let mut full = args.to_vec();
            full.extend(["--vault", vault, "--password-file", password]);
            let output = run_without_terminal(&full, b"")?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(
                stderr, "fidelogic-cli: Vault の解錠に失敗しました。\n",
                "{name}の {args:?} の出力の確認に失敗。"
            );
            assert_eq!(
                output.status.code(),
                Some(3),
                "{name}の終了コードの確認に失敗。"
            );
            assert!(output.stdout.is_empty());
        }
    }
    Ok(())
}

/// 認証に成功しても、クレデンシャルとして解釈できないエントリがあれば中止すること。
#[test]
fn test_entries_that_are_not_credentials_are_reported() -> TestResult {
    let directory = TempDir::new()?;
    let vault = directory.path("vault.fvl");
    write_fixture(&vault, false)?;
    let password = directory.path("password");
    write_private(&password, PASSWORD.as_bytes())?;
    let output = run_without_terminal(
        &[
            "list",
            "--vault",
            text(&vault)?,
            "--password-file",
            text(&password)?,
        ],
        b"",
    )?;
    assert_process_failure(&output, 1, "解釈できないエントリ");
    Ok(())
}

#[test]
fn test_delete_removes_one_entry_after_consent() -> TestResult {
    let target = EntryVault::new(&[
        credential(1, "keep"),
        credential(2, "drop me"),
        credential(3, "also keep"),
    ])?;
    let before = read_vault(&target.vault)?;
    for answer in ["y", "YES"] {
        let title = if answer == "y" { "drop me" } else { "keep" };
        let mut session = start(&["delete", "--vault", target.vault_text()?, title])?;
        session.answer("y/N", answer)?;
        let outcome = session.finish()?;
        assert_eq!(outcome.status, 0, "削除に失敗: {}", outcome.stderr);
        assert!(
            outcome
                .screen
                .contains(&format!("エントリ「{title}」を{DELETE_PROMPT}")),
            "対象を示すことの確認に失敗: {}",
            outcome.screen
        );
        assert!(
            outcome
                .stdout
                .contains(&format!("エントリを削除しました: {title}"))
        );
    }
    assert_eq!(target.epoch()?, before.header.epoch_id + 2);
    target.assert_preserved(&before)?;
    let titles: Vec<_> = target
        .credentials()?
        .into_iter()
        .map(|credential| credential.title)
        .collect();
    assert_eq!(titles, [Some("also keep".to_owned())]);
    Ok(())
}

#[test]
fn test_delete_is_declined_or_interrupted_without_saving() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let before = target.contents()?;
    let args = ["delete", "--vault", target.vault_text()?, "site"];
    for answer in ["n", "ye", "yy"] {
        let mut session = start(&args)?;
        session.answer("y/N", answer)?;
        assert_failure(&session.finish()?, 1, "削除に同意しなかったため");
    }
    let mut session = start(&args)?;
    session.wait_for_screen("y/N", 1)?;
    session.type_input(b"\x04")?;
    assert_failure(&session.finish()?, 1, "削除に同意しなかったため");

    let mut session = start(&args)?;
    session.wait_for_screen("y/N", 1)?;
    session.send_signal(libc::SIGINT)?;
    assert_failure(&session.finish()?, 130, "中断");

    // 対象が無い場合は、同意を求めない。
    let session = start(&["delete", "--vault", target.vault_text()?, "missing"])?;
    let outcome = session.finish()?;
    assert_failure(&outcome, 1, "指定されたエントリがありません。");
    assert!(!outcome.screen.contains("y/N"));

    assert!(target.contents()? == before);
    Ok(())
}

#[test]
fn test_delete_with_yes_needs_no_terminal() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site"), credential(2, "other")])?;
    let output = run_without_terminal(
        &[
            "delete",
            "--vault",
            target.vault_text()?,
            "site",
            "--yes",
            "--password-file",
            target.password_file_text()?,
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "エントリを削除しました: site\n"
    );
    assert_eq!(target.credentials()?.len(), 1);

    // 同意を求める実行は、端末が無ければ中止する。
    let before = target.contents()?;
    let output = run_without_terminal(&["delete", "--vault", target.vault_text()?, "other"], b"")?;
    assert_process_failure(&output, 1, "この操作には端末が必要です。");
    assert!(target.contents()? == before);
    Ok(())
}

/// 書き出した JSON が、全エントリの秘密を含むこと。
fn assert_exported(json: &str) {
    assert!(json.starts_with("{\n  \"format\": \"fidelogic-vault-export\",\n"));
    assert!(json.ends_with("]\n}\n"));
    for title in ["a", "b"] {
        for (key, value) in [
            ("title", title.to_owned()),
            ("password", format!("password-of-{title}")),
            ("totp", format!("totp-of-{title}")),
            ("notes", format!("notes-of-{title}")),
        ] {
            assert!(
                json.contains(&format!("\"{key}\": \"{value}\"")),
                "{title} の {key} の書き出しに失敗: {json}"
            );
        }
    }
}

#[test]
fn test_export_to_standard_output_and_file_without_terminal() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a"), credential(2, "b")])?;
    let before = target.contents()?;
    let vault = target.vault_text()?;
    let password = target.password_file_text()?;

    let output = run_without_terminal(
        &[
            "export",
            "--vault",
            vault,
            "--stdout",
            "--confirm-plaintext",
            "--password-file",
            password,
        ],
        b"",
    )?;
    assert_eq!(output.status.code(), Some(0));
    assert_exported(&String::from_utf8(output.stdout)?);
    let warning = String::from_utf8(output.stderr)?;
    assert!(
        warning.contains(EXPORT_WARNING),
        "警告の表示に失敗: {warning}"
    );

    let destination = target.directory.path("dump.json");
    let args = [
        "export",
        "--vault",
        vault,
        "--output",
        text(&destination)?,
        "--confirm-plaintext",
        "--password-file",
        password,
    ];
    let output = run_without_terminal(&args, b"")?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8(output.stdout)?,
        format!("書き出しました: {}\n", destination.display())
    );
    assert!(String::from_utf8(output.stderr)?.contains(EXPORT_WARNING));
    assert_eq!(mode_of(&destination)?, 0o600);
    assert_exported(&fs::read_to_string(&destination)?);

    // 既存のファイルは上書きせず、パスワードを読む前に中止する。
    fs::write(&destination, b"keep")?;
    let output = run_without_terminal(&args, b"")?;
    assert_process_failure(&output, 1, "書き出し先にファイルがすでに存在する");
    assert_eq!(fs::read(&destination)?, b"keep");
    assert!(target.contents()? == before);
    Ok(())
}

/// 書き出せない場合は、ファイルを残さないこと。
#[test]
fn test_export_failures_leave_no_file() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let vault = target.vault_text()?;
    let destination = target.directory.path("dump.json");
    let missing_parent = target.directory.path("missing/dump.json");
    let wrong = target.directory.path("wrong");
    write_private(&wrong, b"wrong")?;
    let dangling = target.directory.path("dangling");
    std::os::unix::fs::symlink(target.directory.path("nowhere"), &dangling)?;
    // 出力先の確認は解錠より前のため、誤ったパスワードでも、出力先の失敗になる。
    let cases: [(&Path, &Path, i32, &str); 5] = [
        (&destination, &wrong, 3, AUTHENTICATION_FAILED),
        (&missing_parent, &target.password_file, 1, "失敗しました"),
        (&target.vault, &wrong, 1, "すでに存在する"),
        (&target.vault, &target.password_file, 1, "すでに存在する"),
        (&dangling, &wrong, 1, "すでに存在する"),
    ];
    let names = target.directory.names()?;
    for (output_path, password, status, message) in cases {
        let output = run_without_terminal(
            &[
                "export",
                "--vault",
                vault,
                "--output",
                text(output_path)?,
                "--confirm-plaintext",
                "--password-file",
                text(password)?,
            ],
            b"",
        )?;
        assert_process_failure(&output, status, message);
    }
    let mut expected = names;
    // 解錠に進んだ実行は、ロックファイルを作る。
    expected.push("vault.fvl.lock".to_owned());
    expected.sort();
    expected.dedup();
    assert_eq!(target.directory.names()?, expected);
    Ok(())
}

#[test]
fn test_export_asks_for_consent_on_a_terminal() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a"), credential(2, "b")])?;
    let destination = target.directory.path("dump.json");
    let args = [
        "export",
        "--vault",
        target.vault_text()?,
        "--output",
        text(&destination)?,
    ];
    for answer in ["n", ""] {
        let mut session = start(&args)?;
        session.answer(EXPORT_PROMPT, answer)?;
        let outcome = session.finish()?;
        assert_eq!(outcome.status, 1);
        assert!(
            outcome.stderr.contains(EXPORT_WARNING)
                && outcome.stderr.contains("同意しなかったため"),
            "警告と中止の表示の確認に失敗: {}",
            outcome.stderr
        );
        assert!(!destination.exists());
    }
    let mut session = start(&args)?;
    session.wait_for_screen(EXPORT_PROMPT, 1)?;
    session.send_signal(libc::SIGINT)?;
    assert_eq!(session.finish()?.status, 130);
    assert!(!destination.exists());

    let mut session = start(&args)?;
    session.answer(EXPORT_PROMPT, "y")?;
    let outcome = session.finish()?;
    assert_eq!(outcome.status, 0, "書き出しに失敗: {}", outcome.stderr);
    assert!(outcome.stderr.contains(EXPORT_WARNING));
    assert_exported(&fs::read_to_string(&destination)?);

    let output = run_without_terminal(
        &["export", "--vault", target.vault_text()?, "--stdout"],
        b"",
    )?;
    assert_process_failure(&output, 1, "この操作には端末が必要です。");
    Ok(())
}

/// 端末からパスワードを入力する場合も、`--confirm-plaintext` を指定すれば同意を求めないこと。
#[test]
fn test_export_confirmation_flag_skips_the_prompt_on_a_terminal() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a"), credential(2, "b")])?;
    let destination = target.directory.path("dump.json");
    let session = start(&[
        "export",
        "--vault",
        target.vault_text()?,
        "--output",
        text(&destination)?,
        "--confirm-plaintext",
    ])?;
    let outcome = session.finish()?;

    assert_eq!(outcome.status, 0, "書き出しに失敗: {}", outcome.stderr);
    assert!(
        !outcome.screen.contains(EXPORT_PROMPT),
        "同意を求めないことの確認に失敗: {}",
        outcome.screen
    );
    assert!(outcome.stderr.contains(EXPORT_WARNING));
    assert_exported(&fs::read_to_string(&destination)?);
    Ok(())
}

/// `get --clip` が、実行ファイルからワーカーを起動して指定の項目をコピーし、消去を待たずに終了すること。
#[test]
#[ignore = "クリップボードを上書きする。ディスプレイのある環境で明示して実行する。"]
fn test_get_clip_copies_the_field_on_a_display() -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    for (field, label, value) in [
        ("password", "パスワード", "password-of-site"),
        ("username", "ユーザー名", "user-of-site"),
    ] {
        let started = Instant::now();
        let child = common::entry_vault::spawn_with_display(&[
            "get",
            "--vault",
            target.vault_text()?,
            "site",
            "--clip",
            field,
            "--password-file",
            target.password_file_text()?,
        ])?;
        // 出力の終端まで待つ。ワーカーが出力の記述子を引き継ぐと、消去まで戻らない。
        let output = child.wait_with_output()?;
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "{field} のコピーで、消去を待たないことの確認に失敗。"
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "{field} のコピーに失敗: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout)?,
            format!("{label} をクリップボードにコピーしました。30 秒後に消去します。\n")
        );
        assert_eq!(arboard::Clipboard::new()?.get_text()?, value);
    }
    Ok(())
}

/// 読み手の居ない標準出力への書き出しは、出力の失敗になること。
#[test]
fn test_export_to_a_closed_pipe_fails() -> TestResult {
    let target = EntryVault::new(&[credential(1, "a")])?;
    let mut child = common::entry_vault::spawn_without_terminal(&[
        "export",
        "--vault",
        target.vault_text()?,
        "--stdout",
        "--confirm-plaintext",
        "--password-stdin",
    ])?;
    // 書き出しの前に読み手を閉じる。パスワードは、閉じた後に渡す。
    drop(child.stdout.take());
    let mut stdin = child.stdin.take().ok_or("子の標準入力がありません。")?;
    std::io::Write::write_all(&mut stdin, PASSWORD.as_bytes())?;
    drop(stdin);
    let output = child.wait_with_output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8(output.stderr)?.contains("標準出力への書き込みに失敗しました。"));
    Ok(())
}

/// 読み手が止まった出力先への書き出しは、1 回の中断のシグナルで終了すること。
#[test]
fn test_interrupt_stops_a_blocked_export() -> TestResult {
    // パイプのバッファに収まらない大きさにする。
    let entries: Vec<Credential> = (1..=4)
        .map(|id| {
            let mut entry = credential(id, &format!("large {id}"));
            entry.notes = Some(SecretVec::from_slice(&vec![b'a'; 60_000]));
            entry
        })
        .collect();
    let target = EntryVault::new(&entries)?;
    let mut child = common::entry_vault::spawn_without_terminal(&[
        "export",
        "--vault",
        target.vault_text()?,
        "--stdout",
        "--confirm-plaintext",
        "--password-file",
        target.password_file_text()?,
    ])?;
    let mut output = child.stdout.take().ok_or("子の標準出力がありません。")?;
    // 書き出しの開始を確かめた後は読まず、子の書き込みを停止させる。
    std::io::Read::read_exact(&mut output, &mut [0u8; 1])?;
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait()?.is_none(),
        "書き込みが停止することの確認に失敗。"
    );
    let process = i32::try_from(child.id())?;
    // SAFETY: 起動した子へシグナルを送るだけで、メモリを参照しない。
    if unsafe { libc::kill(process, libc::SIGINT) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status.code();
        }
        if Instant::now() > deadline {
            child.kill()?;
            return Err("中断のシグナルで終了しません。".into());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(status, Some(130));
    Ok(())
}

/// 追加と削除を続けても、TLV のレコードが増え続けないこと。
#[test]
fn test_deleting_shrinks_the_records() -> TestResult {
    let target = EntryVault::new(&[])?;
    let entry_records = |path: &Path| -> Result<usize, Box<dyn std::error::Error>> {
        Ok(read_vault(path)?
            .records
            .iter()
            .filter(|record| matches!(record, TlvRecord::Entry(_)))
            .count())
    };
    let empty = entry_records(&target.vault)?;
    let mut session = start(&["set", "--vault", target.vault_text()?, "x"])?;
    answer_fields(&mut session, ["u", "p", "", "", ""])?;
    assert_eq!(session.finish()?.status, 0);
    assert!(entry_records(&target.vault)? > empty);
    let session = start(&["delete", "--vault", target.vault_text()?, "x", "--yes"])?;
    assert_eq!(session.finish()?.status, 0);
    assert_eq!(entry_records(&target.vault)?, empty);
    Ok(())
}
