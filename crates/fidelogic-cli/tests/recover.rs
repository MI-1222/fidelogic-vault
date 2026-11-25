//! `recover` サブコマンドの統合テスト。
//!
//! 実行ファイルを疑似端末で起動する仕組みと、テスト用の Vault は `common` にある。

mod common;

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use common::fixture::*;
use common::*;
use fidelogic_cli::recovery_code::RecoveryCode;
use fidelogic_cli::sys::random::fill_random;
use fidelogic_cli::sys::storage::{VaultLock, VaultPath};
use fidelogic_core::{Argon2Params, Argon2idSlotPayload, Vault};

const CODE_PROMPT: &str = "リカバリーコード (入力は表示されません): ";

const AUTHENTICATION_FAILED: &str = "Vault の解錠に失敗しました。";

/// テスト用の Vault を持つ一時ディレクトリ。
struct Setup {
    dir: TempDir,
    vault: PathBuf,
    /// 実行前の内容。
    before: Vault,
}

impl Setup {
    fn new() -> Result<Self, Box<dyn Error>> {
        let dir = TempDir::new()?;
        let vault = dir.path("vault.fvl");
        let before = write_fixture(&vault, true)?;
        Ok(Self { dir, vault, before })
    }

    /// `recover --vault <PATH>` に `extra` を加えて起動する。
    fn spawn(&self, extra: &[&str], options: &Options<'_>) -> Result<Session, Box<dyn Error>> {
        let mut args = vec!["recover", "--vault", text(&self.vault)?];
        args.extend_from_slice(extra);
        Session::spawn(&args, options)
    }

    /// 実行前の DEK。
    fn dek(&self) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(dek_by_password(&self.before, PASSWORD).ok_or("実行前の解錠に失敗。")?)
    }

    /// Vault ファイルが実行前から変わっていないこと。
    fn assert_unchanged(&self) -> TestResult {
        let expected =
            fidelogic_core::serialize(&self.before).map_err(|error| format!("{error}"))?;
        assert!(
            fs::read(&self.vault)? == expected,
            "Vault を変えないことの確認に失敗。"
        );
        Ok(())
    }
}

/// 古いコードと、新しいパスワードを入力し、表示された新しいコードを返す。
fn enter_code_and_password(session: &mut Session) -> Result<String, Box<dyn Error>> {
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    displayed_code(&session.pty.text())
}

fn confirm(session: &mut Session, code: &str) -> TestResult {
    session.type_input(format!("{}\r", suffix(code)?).as_bytes())
}

fn assert_success(outcome: &Outcome) {
    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
}

/// パスワードを再設定し、Slot 2 以外の、作り直さないスロットを変えていないこと。
fn assert_password_reset(setup: &Setup) -> Result<Vault, Box<dyn Error>> {
    let dek = setup.dek()?;
    let after = assert_updated(&setup.vault, &dek)?;
    assert_eq!(slot_ids(&after), slot_ids(&setup.before));
    assert_eq!(dek_by_password(&after, NEW_PASSWORD), Some(dek));
    assert_eq!(dek_by_password(&after, PASSWORD), None);
    assert_eq!(dek_by_prf(&after), Some(dek), "Slot 1 の解錠に失敗。");
    for slot_id in [1, UNKNOWN_SLOT_ID] {
        assert!(
            slot(&after, slot_id) == slot(&setup.before, slot_id),
            "スロット {slot_id} を変えないことの確認に失敗。"
        );
    }
    let params = Argon2idSlotPayload::from_slot_entry(slot(&after, 0).ok_or("Slot 0")?)
        .map_err(|error| format!("{error}"))?
        .params;
    assert_eq!(params.m_cost(), Argon2Params::for_native().m_cost());
    Ok(after)
}

#[test]
fn test_recover_resets_password_and_reissues_code() -> TestResult {
    let setup = Setup::new()?;
    let mut session = setup.spawn(&[], &Options::default())?;
    // 小文字と、空白の区切りでも読み取ること。
    let typed = OLD_CODE.to_lowercase().replace('-', " ");
    session.answer(CODE_PROMPT, &typed)?;
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    setup.assert_unchanged()?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(
        outcome
            .stdout
            .contains("マスターパスワードを再設定しました")
    );
    assert!(
        outcome
            .stdout
            .contains("新しいリカバリーコードを有効にしました")
    );
    assert!(!outcome.stdout.contains(&code));
    for secret in [typed.as_str(), NEW_PASSWORD] {
        assert!(
            !outcome.screen.contains(secret),
            "入力が表示されないことの確認に失敗。"
        );
    }
    assert_ne!(code, OLD_CODE);
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(setup.dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    let after = assert_password_reset(&setup)?;
    assert_eq!(dek_by_code(&after, &code), Some(setup.dek()?));
    assert_eq!(dek_by_code(&after, OLD_CODE), None);
    Ok(())
}

#[test]
fn test_recover_keeps_code_when_requested() -> TestResult {
    let setup = Setup::new()?;
    let password_file = setup.dir.path("password");
    fs::write(&password_file, format!("{NEW_PASSWORD}\n"))?;
    fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600))?;
    let extra = [
        "--keep-recovery-code",
        "--password-file",
        text(&password_file)?,
    ];
    let mut session = setup.spawn(&extra, &Options::default())?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert!(!outcome.stdout.contains("新しいリカバリーコード"));
    let after = assert_password_reset(&setup)?;
    assert!(slot(&after, 2) == slot(&setup.before, 2));
    assert_eq!(dek_by_code(&after, OLD_CODE), Some(setup.dek()?));
    Ok(())
}

#[test]
fn test_recover_writes_html_kit_with_password_from_standard_input() -> TestResult {
    let setup = Setup::new()?;
    let kit = setup.dir.path("kit.html");
    let input = format!("{NEW_PASSWORD}\n");
    let options = Options {
        stdin: Some(input.as_bytes()),
        ..Options::default()
    };
    let extra = ["--password-stdin", "--kit-html", text(&kit)?];
    let mut session = setup.spawn(&extra, &options)?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(outcome.stdout.contains("リカバリーキットを書き出しました"));
    assert_eq!(mode_of(&kit)?, 0o600);
    assert_eq!(fs::read_to_string(&kit)?.matches(&code).count(), 1);
    let after = assert_password_reset(&setup)?;
    assert_eq!(dek_by_code(&after, &code), Some(setup.dek()?));
    Ok(())
}

/// 引き継いだ記述子から新しいパスワードを読む場合も、端末では新しいパスワードを求めないこと。
#[test]
fn test_recover_reads_new_password_from_inherited_descriptor() -> TestResult {
    let setup = Setup::new()?;
    let password_source = setup.dir.path("password");
    fs::write(&password_source, format!("{NEW_PASSWORD}\n"))?;
    let options = Options {
        redirect: Redirect::DescriptorThreeFrom(&password_source),
        ..Options::default()
    };
    let extra = ["--keep-recovery-code", "--password-fd", "3"];
    let mut session = setup.spawn(&extra, &options)?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_password_reset(&setup)?;
    Ok(())
}

#[test]
fn test_recover_succeeds_with_small_memory_lock_limit() -> TestResult {
    let setup = Setup::new()?;
    let options = Options {
        memlock_limit: Some(64 * 1024),
        ..Options::default()
    };
    let mut session = setup.spawn(&[], &options)?;
    let code = enter_code_and_password(&mut session)?;
    confirm(&mut session, &code)?;
    assert_success(&session.finish()?);
    assert_password_reset(&setup)?;
    Ok(())
}

/// 保存の後に結果を書き込めない場合は失敗を報告し、更新した Vault と HTML を残すこと。
#[test]
fn test_recover_output_failure_after_save_keeps_vault_and_kit() -> TestResult {
    let setup = Setup::new()?;
    let kit = setup.dir.path("kit.html");
    let options = Options {
        redirect: Redirect::BrokenStdout,
        ..Options::default()
    };
    let mut session = setup.spawn(&["--kit-html", text(&kit)?], &options)?;
    let code = enter_code_and_password(&mut session)?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "標準出力への書き込みに失敗しました");
    assert!(fs::read_to_string(&kit)?.contains(&code));
    let after = assert_password_reset(&setup)?;
    assert_eq!(dek_by_code(&after, &code), Some(setup.dek()?));
    Ok(())
}

/// コードの入力の段階で失敗する場合は、新しいパスワードを求めず、Vault を変えないこと。
fn assert_code_failure(
    input: impl FnOnce(&mut Session) -> TestResult,
    status: i32,
    message: &str,
) -> TestResult {
    let setup = Setup::new()?;
    let mut session = setup.spawn(&[], &Options::default())?;
    session.wait_for_screen(CODE_PROMPT, 1)?;
    input(&mut session)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, status, message);
    assert!(
        !outcome.screen.contains(NEW_PASSWORD_PROMPT),
        "新しいパスワードを求めないことの確認に失敗: {}",
        outcome.screen
    );
    assert_eq!(setup.dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    setup.assert_unchanged()
}

#[test]
fn test_wrong_recovery_code_fails_as_authentication_failure() -> TestResult {
    let other = RecoveryCode::generate(fill_random)?;
    let other = other.grouped()?;
    let line = [other.as_slice(), b"\r"].concat();
    assert_code_failure(
        |session| session.type_input(&line),
        3,
        AUTHENTICATION_FAILED,
    )
}

#[test]
fn test_malformed_recovery_code_is_reported_as_input_error() -> TestResult {
    let bad_checksum = OLD_CODE.replace("00014", "00015");
    let too_long = "0".repeat(2000);
    let cases = [
        (bad_checksum.as_str(), "チェックサムが一致しません"),
        ("FL000", "30 文字で指定してください"),
        ("", "30 文字で指定してください"),
        (too_long.as_str(), "30 文字で指定してください"),
    ];
    for (line, message) in cases {
        assert_code_failure(
            |session| session.type_input(format!("{line}\r").as_bytes()),
            1,
            message,
        )?;
    }
    Ok(())
}

#[test]
fn test_abort_during_recovery_code_input() -> TestResult {
    assert_code_failure(
        |session| session.type_input(b"\x04"),
        1,
        "リカバリーコードの入力が途中で終了しました",
    )?;
    assert_code_failure(|session| session.type_input(b"FL0\x03"), 130, "中断")
}

/// 改ざんされた Vault は、誤ったコードと同じ出力にし、新しいパスワードを求める前に中止すること。
#[test]
fn test_tampered_vault_fails_as_authentication_failure() -> TestResult {
    let tamper: [(&str, Tamper); 4] = [
        ("エントリのレコードの欠損", |vault| {
            vault.records.remove(1);
        }),
        ("世代の改ざん", |vault| vault.header.epoch_id += 1),
        ("Slot 2 の削除", |vault| {
            vault.slots.retain(|slot| slot.slot_id() != 2);
        }),
        ("Slot 2 の重複", |vault| {
            let duplicated: Vec<_> = vault
                .slots
                .iter()
                .filter(|slot| slot.slot_id() == 2)
                .cloned()
                .collect();
            vault.slots.extend(duplicated);
        }),
    ];
    for (name, change) in tamper {
        let mut setup = Setup::new()?;
        change(&mut setup.before);
        write_vault(&setup.vault, &setup.before)?;
        let mut session = setup.spawn(&[], &Options::default())?;
        session.answer(CODE_PROMPT, OLD_CODE)?;
        let outcome = session.finish()?;

        assert_failure(&outcome, 3, AUTHENTICATION_FAILED);
        assert!(
            !outcome.screen.contains(NEW_PASSWORD_PROMPT),
            "{name}の拒否の時期の確認に失敗。"
        );
        setup.assert_unchanged()?;
    }
    Ok(())
}

/// 末尾の再入力が一致しない間は Vault を変えず、描き直して、一致した場合に保存すること。
#[test]
fn test_wrong_confirmation_keeps_vault_until_it_matches() -> TestResult {
    let setup = Setup::new()?;
    let mut session = setup.spawn(&[], &Options::default())?;
    let code = enter_code_and_password(&mut session)?;
    session.type_input(b"UUUUU\r")?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 2)?;
    setup.assert_unchanged()?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(outcome.screen.contains("一致しません。"));
    let after = assert_password_reset(&setup)?;
    assert_eq!(dek_by_code(&after, &code), Some(setup.dek()?));
    Ok(())
}

#[test]
fn test_disallowed_new_password_keeps_vault() -> TestResult {
    let setup = Setup::new()?;
    let mut session = setup.spawn(&[], &Options::default())?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.answer(NEW_PASSWORD_PROMPT, "a\tb")?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "使用できない文字");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    setup.assert_unchanged()
}

#[test]
fn test_mismatched_new_passwords_keep_vault() -> TestResult {
    let setup = Setup::new()?;
    let mut session = setup.spawn(&[], &Options::default())?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "2 つのパスワードが一致しません");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    setup.assert_unchanged()
}

/// コードの再入力の前に中止した場合は、Vault を変えず、HTML を残さないこと。
#[test]
fn test_abort_during_confirmation_keeps_vault() -> TestResult {
    type Abort = fn(&mut Session) -> TestResult;
    let cases: [(Abort, i32, &str); 3] = [
        (|session| session.type_input(b"\x03"), 130, "中断"),
        (|session| session.send_signal(libc::SIGTERM), 130, "中断"),
        (
            |session| session.type_input(b"\x04"),
            1,
            "リカバリーコードの控えを確認できないため",
        ),
    ];
    for (abort, status, message) in cases {
        let setup = Setup::new()?;
        let kit = setup.dir.path("kit.html");
        let mut session = setup.spawn(&["--kit-html", text(&kit)?], &Options::default())?;
        let code = enter_code_and_password(&mut session)?;
        abort(&mut session)?;
        let outcome = session.finish()?;

        assert_failure(&outcome, status, message);
        assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
        assert_eq!(setup.dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
        setup.assert_unchanged()?;
    }
    Ok(())
}

/// 確認の間に Vault が書き換えられた場合は上書きせず、表示したコードが使えないことを警告すること。
#[test]
fn test_vault_changed_during_confirmation_is_not_replaced() -> TestResult {
    let setup = Setup::new()?;
    let kit = setup.dir.path("kit.html");
    let mut session = setup.spawn(&["--kit-html", text(&kit)?], &Options::default())?;
    let code = enter_code_and_password(&mut session)?;
    fs::write(&setup.vault, b"changed by another program")?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_eq!(outcome.status, 1, "{}", outcome.stderr);
    assert!(outcome.stdout.is_empty());
    let lines: Vec<&str> = outcome.stderr.lines().collect();
    let [warning, error] = lines.as_slice() else {
        return Err(format!("エラー出力の行数の確認に失敗: {}", outcome.stderr).into());
    };
    assert!(
        warning.starts_with("fidelogic-cli: 警告: ")
            && warning.contains("表示したリカバリーコードは使えません"),
        "警告の確認に失敗: {warning}"
    );
    assert!(
        error.contains("別の処理で変更されたため"),
        "エラーの確認に失敗: {error}"
    );
    assert_eq!(fs::read(&setup.vault)?, b"changed by another program");
    assert_eq!(setup.dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

/// コードを再発行しない場合に保存を中止しても、コードについての警告を出さないこと。
#[test]
fn test_save_failure_without_new_code_has_no_code_warning() -> TestResult {
    let setup = Setup::new()?;
    let mut session = setup.spawn(&["--keep-recovery-code"], &Options::default())?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.wait_for_screen(REPEAT_PASSWORD_PROMPT, 1)?;
    // 保存の直前の入力を待つ間に、ロックに従わない処理が Vault を書き換える。
    fs::write(&setup.vault, b"changed by another program")?;
    session.type_input(format!("{NEW_PASSWORD}\r").as_bytes())?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "別の処理で変更されたため");
    assert_eq!(fs::read(&setup.vault)?, b"changed by another program");
    Ok(())
}

/// 秘密の入力より前に失敗する場合は、何も入力を求めないこと。
fn assert_rejected_before_input(args: &[&str], status: i32, message: &str) -> TestResult {
    let outcome = Session::spawn(args, &Options::default())?.finish()?;
    assert_failure(&outcome, status, message);
    assert!(
        !outcome.screen.contains(CODE_PROMPT),
        "入力を求めないことの確認に失敗: {}",
        outcome.screen
    );
    Ok(())
}

#[test]
fn test_missing_vault_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    assert_rejected_before_input(
        &["recover", "--vault", text(&vault)?],
        1,
        "指定されたパスに Vault がありません",
    )?;
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_unparsable_vault_fails_as_authentication_failure() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    fs::write(&vault, b"not a vault")?;
    assert_rejected_before_input(
        &["recover", "--vault", text(&vault)?],
        3,
        AUTHENTICATION_FAILED,
    )?;
    assert_eq!(fs::read(&vault)?, b"not a vault");
    Ok(())
}

#[test]
fn test_existing_kit_destination_is_rejected() -> TestResult {
    let setup = Setup::new()?;
    let kit = setup.dir.path("kit.html");
    fs::write(&kit, b"existing")?;
    // Vault とロックファイルも、出力先にできない。
    let lock_file = setup.dir.path("vault.fvl.lock");
    for destination in [&kit, &setup.vault, &lock_file] {
        assert_rejected_before_input(
            &[
                "recover",
                "--vault",
                text(&setup.vault)?,
                "--kit-html",
                text(destination)?,
            ],
            1,
            "出力先にファイルがすでに存在するため",
        )?;
    }
    assert_eq!(fs::read(&kit)?, b"existing");
    setup.assert_unchanged()
}

#[test]
fn test_unwritable_kit_destination_fails_before_display() -> TestResult {
    let setup = Setup::new()?;
    let kit = setup.dir.path("missing").join("kit.html");
    let mut session = setup.spawn(&["--kit-html", text(&kit)?], &Options::default())?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, NEW_PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "出力先のファイルの作成に失敗しました");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    setup.assert_unchanged()
}

#[test]
fn test_locked_vault_is_rejected_without_waiting() -> TestResult {
    let setup = Setup::new()?;
    let lock = VaultLock::try_acquire(VaultPath::resolve(&setup.vault)?)?;
    assert_rejected_before_input(
        &["recover", "--vault", text(&setup.vault)?],
        1,
        "他の処理が Vault を使用中です",
    )?;
    drop(lock);
    setup.assert_unchanged()
}

/// 端末の無い環境では、入力元の指定があっても中止し、ファイルに触れないこと。
#[test]
fn test_recover_requires_controlling_terminal() -> TestResult {
    let setup = Setup::new()?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"));
    command
        .args(["recover", "--vault", text(&setup.vault)?])
        .args(["--password-stdin", "--keep-recovery-code"])
        .stdin(Stdio::null());
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setsid` は非同期シグナルセーフである。新しいセッションは制御端末を持たない。
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "fidelogic-cli: この操作には端末が必要です。端末から実行してください。\n"
    );
    assert_eq!(setup.dir.names()?, ["vault.fvl"]);
    setup.assert_unchanged()
}
