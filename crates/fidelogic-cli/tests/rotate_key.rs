//! `rotate-key` サブコマンドの統合テスト。
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
use fidelogic_core::{Argon2Params, Argon2idSlotPayload, CipherSuiteId, Vault};

const CURRENT_PASSWORD_PROMPT: &str = "現在のマスターパスワード: ";

const PRF_PROMPT: &str = "(y/N、入力は表示されません): ";

const AUTHENTICATION_FAILED: &str = "Vault の解錠に失敗しました。";

const PRF_DROPPED: &str = "WebAuthn PRF のスロットを破棄しました";

/// テスト用の Vault を持つ一時ディレクトリ。
struct Setup {
    dir: TempDir,
    vault: PathBuf,
    /// 実行前の内容。
    before: Vault,
}

impl Setup {
    fn new(prf_slot: bool) -> Result<Self, Box<dyn Error>> {
        let dir = TempDir::new()?;
        let vault = dir.path("vault.fvl");
        let before = write_fixture(&vault, prf_slot)?;
        Ok(Self { dir, vault, before })
    }

    /// `rotate-key --vault <PATH>` に `extra` を加えて起動する。
    fn spawn(&self, extra: &[&str], options: &Options<'_>) -> Result<Session, Box<dyn Error>> {
        let mut args = vec!["rotate-key", "--vault", text(&self.vault)?];
        args.extend_from_slice(extra);
        Session::spawn(&args, options)
    }

    /// 実行前の DEK。
    fn dek(&self) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(dek_by_password(&self.before, PASSWORD).ok_or("実行前の解錠に失敗。")?)
    }

    /// 現在のパスワードを含むファイルを作る。
    fn password_file(&self) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.dir.path("password");
        fs::write(&path, format!("{PASSWORD}\n"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
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

fn enter_new_password(session: &mut Session) -> TestResult {
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, NEW_PASSWORD)
}

/// 再入力の案内を待ち、表示されたコードを返す。
fn read_code(session: &mut Session) -> Result<String, Box<dyn Error>> {
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

fn assert_unchanged_slots(before: &Vault, after: &Vault, slot_ids: &[u8]) {
    for &slot_id in slot_ids {
        assert!(
            slot(before, slot_id).is_some() && slot(after, slot_id) == slot(before, slot_id),
            "スロット {slot_id} を変えないことの確認に失敗。"
        );
    }
}

#[test]
fn test_kek_only_changes_password_and_keeps_other_slots() -> TestResult {
    for extra in [&[][..], &["--kek-only"]] {
        let setup = Setup::new(true)?;
        let mut session = setup.spawn(extra, &Options::default())?;
        session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
        enter_new_password(&mut session)?;
        let outcome = session.finish()?;

        assert_success(&outcome);
        assert!(outcome.stdout.contains("鍵を更新しました"));
        assert!(!outcome.stdout.contains("新しいリカバリーコード"));
        assert!(!outcome.stdout.contains(PRF_DROPPED));
        assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
        assert!(!outcome.screen.contains(PRF_PROMPT));
        for secret in [PASSWORD, NEW_PASSWORD] {
            assert!(
                !outcome.screen.contains(secret),
                "入力が表示されないことの確認に失敗。"
            );
        }
        let dek = setup.dek()?;
        let after = assert_updated(&setup.vault, &dek)?;
        assert_eq!(slot_ids(&after), slot_ids(&setup.before));
        assert_unchanged_slots(&setup.before, &after, &[1, 2, UNKNOWN_SLOT_ID]);
        assert_eq!(dek_by_password(&after, NEW_PASSWORD), Some(dek));
        assert_eq!(dek_by_password(&after, PASSWORD), None);
        assert_eq!(dek_by_code(&after, OLD_CODE), Some(dek));
        assert_eq!(dek_by_prf(&after), Some(dek));
        assert_eq!(setup.dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    }
    Ok(())
}

#[test]
fn test_new_recovery_code_reissues_slot_two_and_keeps_dek() -> TestResult {
    let setup = Setup::new(true)?;
    let password_file = setup.password_file()?;
    let kit = setup.dir.path("kit.html");
    let extra = [
        "--new-recovery-code",
        "--password-file",
        text(&password_file)?,
        "--kit-html",
        text(&kit)?,
    ];
    let mut session = setup.spawn(&extra, &Options::default())?;
    // 現在のパスワードは入力元から読み、新しいパスワードは端末で読む。
    enter_new_password(&mut session)?;
    let code = read_code(&mut session)?;
    setup.assert_unchanged()?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(!outcome.screen.contains(CURRENT_PASSWORD_PROMPT));
    assert!(
        outcome
            .stdout
            .contains("新しいリカバリーコードを有効にしました")
    );
    assert!(outcome.stdout.contains("リカバリーキットを書き出しました"));
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(mode_of(&kit)?, 0o600);
    assert_eq!(fs::read_to_string(&kit)?.matches(&code).count(), 1);
    let dek = setup.dek()?;
    let after = assert_updated(&setup.vault, &dek)?;
    assert_eq!(slot_ids(&after), slot_ids(&setup.before));
    assert_unchanged_slots(&setup.before, &after, &[1, UNKNOWN_SLOT_ID]);
    assert_eq!(dek_by_password(&after, NEW_PASSWORD), Some(dek));
    assert_eq!(dek_by_code(&after, &code), Some(dek));
    assert_eq!(dek_by_code(&after, OLD_CODE), None);
    Ok(())
}

/// `--full-dek` の後の Vault を検査し、新しい DEK を返す。
fn assert_dek_replaced(setup: &Setup, code: &str) -> TestResult {
    let after = read_vault(&setup.vault)?;
    let dek = dek_by_password(&after, NEW_PASSWORD).ok_or("新しいパスワードでの解錠に失敗。")?;
    assert_ne!(dek, setup.dek()?, "DEK を作り直すことの確認に失敗。");
    let after = assert_updated(&setup.vault, &dek)?;
    assert_eq!(slot_ids(&after), [0, 2, UNKNOWN_SLOT_ID]);
    assert_unchanged_slots(&setup.before, &after, &[UNKNOWN_SLOT_ID]);
    assert_eq!(dek_by_code(&after, code), Some(dek));
    assert_eq!(dek_by_code(&after, OLD_CODE), None);
    assert_eq!(dek_by_password(&after, PASSWORD), None);
    assert_eq!(dek_by_prf(&after), None);
    Ok(())
}

#[test]
fn test_full_dek_without_prf_slot_does_not_ask() -> TestResult {
    let setup = Setup::new(false)?;
    let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    enter_new_password(&mut session)?;
    let code = read_code(&mut session)?;
    confirm(&mut session, &code)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(outcome.stdout.contains("DEK を更新し"));
    assert!(!outcome.stdout.contains(PRF_DROPPED));
    assert!(!outcome.screen.contains(PRF_PROMPT));
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_dek_replaced(&setup, &code)
}

#[test]
fn test_full_dek_drops_prf_slot_after_consent() -> TestResult {
    for answer in ["y", "Y", "yes"] {
        let setup = Setup::new(true)?;
        let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
        session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
        session.answer(PRF_PROMPT, answer)?;
        enter_new_password(&mut session)?;
        let code = read_code(&mut session)?;
        confirm(&mut session, &code)?;
        let outcome = session.finish()?;

        assert_success(&outcome);
        assert!(outcome.stdout.contains(PRF_DROPPED));
        assert_dek_replaced(&setup, &code)?;
    }
    Ok(())
}

#[test]
fn test_full_dek_keeps_vault_when_prf_removal_is_declined() -> TestResult {
    let too_long = "y".repeat(2000);
    let cases: [(&[u8], i32, &str); 6] = [
        (b"n\r", 1, "PRF のスロットを破棄しないため"),
        (b"\r", 1, "PRF のスロットを破棄しないため"),
        (b"yy\r", 1, "PRF のスロットを破棄しないため"),
        (b"\x04", 1, "PRF のスロットを破棄しないため"),
        (b"y\x03", 130, "中断"),
        (too_long.as_bytes(), 1, "PRF のスロットを破棄しないため"),
    ];
    for (input, status, message) in cases {
        let setup = Setup::new(true)?;
        let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
        session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
        session.wait_for_screen(PRF_PROMPT, 1)?;
        session.type_input(input)?;
        if input.len() >= too_long.len() {
            session.type_input(b"\r")?;
        }
        let outcome = session.finish()?;

        assert_failure(&outcome, status, message);
        assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
        setup.assert_unchanged()?;
    }
    Ok(())
}

#[test]
fn test_full_dek_with_password_source_requires_drop_flag() -> TestResult {
    let input = format!("{PASSWORD}\n");
    for source in ["--password-file", "--password-stdin", "--password-fd"] {
        let setup = Setup::new(true)?;
        let password_file = setup.password_file()?;
        let mut extra = vec!["--full-dek", source];
        let mut options = Options::default();
        match source {
            "--password-file" => extra.push(text(&password_file)?),
            "--password-fd" => {
                extra.push("3");
                options.redirect = Redirect::DescriptorThreeFrom(&password_file);
            }
            _ => options.stdin = Some(input.as_bytes()),
        }
        let outcome = setup.spawn(&extra, &options)?.finish()?;

        assert_failure(&outcome, 1, "`--drop-prf-slot` を指定してください");
        assert!(
            !outcome.screen.contains(PRF_PROMPT) && !outcome.screen.contains(NEW_PASSWORD_PROMPT),
            "{source} の拒否の時期の確認に失敗。"
        );
        setup.assert_unchanged()?;
    }
    Ok(())
}

/// 引き継いだ記述子から現在のパスワードを読み、新しいパスワードは端末で読むこと。
#[test]
fn test_current_password_is_read_from_inherited_descriptor() -> TestResult {
    let setup = Setup::new(false)?;
    let password_file = setup.password_file()?;
    let options = Options {
        redirect: Redirect::DescriptorThreeFrom(&password_file),
        ..Options::default()
    };
    let mut session = setup.spawn(&["--password-fd", "3"], &options)?;
    enter_new_password(&mut session)?;
    let outcome = session.finish()?;

    assert_success(&outcome);
    assert!(!outcome.screen.contains(CURRENT_PASSWORD_PROMPT));
    let dek = setup.dek()?;
    let after = assert_updated(&setup.vault, &dek)?;
    assert_eq!(dek_by_password(&after, NEW_PASSWORD), Some(dek));
    Ok(())
}

#[test]
fn test_drop_prf_slot_flag_skips_consent() -> TestResult {
    for from_terminal in [true, false] {
        let setup = Setup::new(true)?;
        let input = format!("{PASSWORD}\n");
        let mut extra = vec!["--full-dek", "--drop-prf-slot"];
        let mut options = Options::default();
        if !from_terminal {
            extra.push("--password-stdin");
            options.stdin = Some(input.as_bytes());
        }
        let mut session = setup.spawn(&extra, &options)?;
        if from_terminal {
            session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
        }
        enter_new_password(&mut session)?;
        let code = read_code(&mut session)?;
        confirm(&mut session, &code)?;
        let outcome = session.finish()?;

        assert_success(&outcome);
        assert!(!outcome.screen.contains(PRF_PROMPT));
        assert!(outcome.stdout.contains(PRF_DROPPED));
        assert_dek_replaced(&setup, &code)?;
    }
    Ok(())
}

/// XChaCha20-Poly1305 以外の暗号スイートの Vault も、スイートを変えずに更新できること。
#[test]
fn test_full_dek_keeps_cipher_suite() -> TestResult {
    let mut setup = Setup::new(false)?;
    setup.before = write_fixture_with_suite(&setup.vault, false, CipherSuiteId::Aes256GcmSiv)?;
    let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    enter_new_password(&mut session)?;
    let code = read_code(&mut session)?;
    confirm(&mut session, &code)?;
    assert_success(&session.finish()?);

    let after = read_vault(&setup.vault)?;
    assert_eq!(after.header.suite_id, CipherSuiteId::Aes256GcmSiv.as_u8());
    assert_dek_replaced(&setup, &code)
}

/// 再発行したコードで、続けて `recover` を実行できること。
#[test]
fn test_reissued_code_recovers_vault() -> TestResult {
    let setup = Setup::new(false)?;
    let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    enter_new_password(&mut session)?;
    let code = read_code(&mut session)?;
    confirm(&mut session, &code)?;
    assert_success(&session.finish()?);

    let args = [
        "recover",
        "--vault",
        text(&setup.vault)?,
        "--keep-recovery-code",
    ];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.answer("リカバリーコード (入力は表示されません): ", &code)?;
    session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    assert_success(&session.finish()?);

    let after = read_vault(&setup.vault)?;
    assert_eq!(after.header.epoch_id, FIXTURE_EPOCH + 2);
    assert_eq!(
        dek_by_password(&after, PASSWORD),
        dek_by_code(&after, &code)
    );
    assert!(dek_by_code(&after, &code).is_some());
    Ok(())
}

/// 解錠に失敗する場合は、新しいパスワードを求めず、Vault を変えないこと。
#[test]
fn test_unlock_failures_share_output() -> TestResult {
    let cases: [(&str, &str, Tamper); 5] = [
        ("誤ったパスワード", "wrong password", |_| {}),
        ("エントリのレコードの欠損", PASSWORD, |vault| {
            vault.records.remove(1);
        }),
        ("世代の改ざん", PASSWORD, |vault| {
            vault.header.epoch_id += 1
        }),
        ("Slot 0 の削除", PASSWORD, |vault| {
            vault.slots.retain(|slot| slot.slot_id() != 0);
        }),
        ("Slot 0 の重複", PASSWORD, |vault| {
            let duplicated: Vec<_> = vault
                .slots
                .iter()
                .filter(|slot| slot.slot_id() == 0)
                .cloned()
                .collect();
            vault.slots.extend(duplicated);
        }),
    ];
    for (name, password, change) in cases {
        for extra in [&[][..], &["--full-dek"]] {
            let mut setup = Setup::new(true)?;
            change(&mut setup.before);
            write_vault(&setup.vault, &setup.before)?;
            let mut session = setup.spawn(extra, &Options::default())?;
            session.answer(CURRENT_PASSWORD_PROMPT, password)?;
            let outcome = session.finish()?;

            assert_failure(&outcome, 3, AUTHENTICATION_FAILED);
            assert!(
                !outcome.screen.contains(NEW_PASSWORD_PROMPT)
                    && !outcome.screen.contains(PRF_PROMPT),
                "{name}の拒否の時期の確認に失敗。"
            );
            setup.assert_unchanged()?;
        }
    }
    Ok(())
}

/// 現在と同じパスワードを入力した場合も、Slot 0 を現在の鍵導出パラメータで作り直すこと。
#[test]
fn test_same_password_recreates_password_slot() -> TestResult {
    let setup = Setup::new(false)?;
    let mut session = setup.spawn(&[], &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    assert_success(&session.finish()?);

    let dek = setup.dek()?;
    let after = assert_updated(&setup.vault, &dek)?;
    assert_eq!(dek_by_password(&after, PASSWORD), Some(dek));
    let payload = |vault: &Vault| -> Result<Argon2idSlotPayload, Box<dyn Error>> {
        let slot = slot(vault, 0).ok_or("Slot 0 がありません。")?;
        Ok(Argon2idSlotPayload::from_slot_entry(slot).map_err(|error| format!("{error}"))?)
    };
    let (old, new) = (payload(&setup.before)?, payload(&after)?);
    assert!(
        old.salt != new.salt && old.nonce != new.nonce,
        "ソルトとノンスを作り直すことの確認に失敗。"
    );
    assert_eq!(new.params.m_cost(), Argon2Params::for_native().m_cost());
    assert_ne!(old.params.m_cost(), new.params.m_cost());
    Ok(())
}

/// 入力元の指定がある場合も、誤ったパスワードは端末の入力と同じ出力にすること。
#[test]
fn test_wrong_password_from_any_source_fails_as_authentication_failure() -> TestResult {
    const WRONG_LINE: &str = "wrong password\n";
    for source in ["--password-file", "--password-stdin", "--password-fd"] {
        let setup = Setup::new(false)?;
        let password_file = setup.password_file()?;
        fs::write(&password_file, WRONG_LINE)?;
        let mut extra = vec![source];
        let mut options = Options::default();
        match source {
            "--password-file" => extra.push(text(&password_file)?),
            "--password-fd" => {
                extra.push("3");
                options.redirect = Redirect::DescriptorThreeFrom(&password_file);
            }
            _ => options.stdin = Some(WRONG_LINE.as_bytes()),
        }
        let outcome = setup.spawn(&extra, &options)?.finish()?;

        assert_failure(&outcome, 3, AUTHENTICATION_FAILED);
        assert!(
            !outcome.screen.contains(NEW_PASSWORD_PROMPT),
            "{source} の拒否の時期の確認に失敗。"
        );
        setup.assert_unchanged()?;
    }
    Ok(())
}

#[test]
fn test_disallowed_new_password_keeps_vault() -> TestResult {
    let setup = Setup::new(false)?;
    let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(NEW_PASSWORD_PROMPT, "a\tb")?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "使用できない文字");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    setup.assert_unchanged()
}

#[test]
fn test_mismatched_new_passwords_keep_vault() -> TestResult {
    let setup = Setup::new(false)?;
    let mut session = setup.spawn(&["--full-dek"], &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(NEW_PASSWORD_PROMPT, NEW_PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "2 つのパスワードが一致しません");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    setup.assert_unchanged()
}

#[test]
fn test_interrupt_during_confirmation_keeps_vault() -> TestResult {
    let setup = Setup::new(false)?;
    let kit = setup.dir.path("kit.html");
    let extra = ["--full-dek", "--kit-html", text(&kit)?];
    let mut session = setup.spawn(&extra, &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    enter_new_password(&mut session)?;
    let code = read_code(&mut session)?;
    session.type_input(b"\x03")?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 130, "中断");
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(setup.dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    setup.assert_unchanged()
}

/// 確認の間に Vault が書き換えられた場合は上書きせず、表示したコードが使えないことを警告すること。
#[test]
fn test_vault_changed_during_full_dek_confirmation_is_not_replaced() -> TestResult {
    let setup = Setup::new(false)?;
    let kit = setup.dir.path("kit.html");
    let extra = ["--full-dek", "--kit-html", text(&kit)?];
    let mut session = setup.spawn(&extra, &Options::default())?;
    session.answer(CURRENT_PASSWORD_PROMPT, PASSWORD)?;
    enter_new_password(&mut session)?;
    let code = read_code(&mut session)?;
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
    assert!(!kit.exists(), "HTML を残さないことの確認に失敗。");
    Ok(())
}

#[test]
fn test_unparsable_vault_fails_as_authentication_failure() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    fs::write(&vault, b"not a vault")?;
    let args = ["rotate-key", "--vault", text(&vault)?];
    let outcome = Session::spawn(&args, &Options::default())?.finish()?;

    assert_failure(&outcome, 3, AUTHENTICATION_FAILED);
    assert!(!outcome.screen.contains(CURRENT_PASSWORD_PROMPT));
    assert_eq!(fs::read(&vault)?, b"not a vault");
    Ok(())
}

/// 端末の無い環境では、すべての指定がそろっていても中止し、ファイルに触れないこと。
#[test]
fn test_rotate_key_requires_controlling_terminal() -> TestResult {
    let setup = Setup::new(true)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"));
    command
        .args(["rotate-key", "--vault", text(&setup.vault)?])
        .args(["--full-dek", "--drop-prf-slot", "--password-stdin"])
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

#[test]
fn test_missing_vault_and_existing_kit_are_rejected_before_input() -> TestResult {
    let setup = Setup::new(false)?;
    let kit = setup.dir.path("kit.html");
    fs::write(&kit, b"existing")?;
    let missing = setup.dir.path("missing.fvl");
    let cases: [(Vec<&str>, &str); 2] = [
        (
            vec!["rotate-key", "--vault", text(&missing)?],
            "指定されたパスに Vault がありません",
        ),
        (
            vec![
                "rotate-key",
                "--vault",
                text(&setup.vault)?,
                "--full-dek",
                "--kit-html",
                text(&kit)?,
            ],
            "出力先にファイルがすでに存在するため",
        ),
    ];
    for (args, message) in cases {
        let outcome = Session::spawn(&args, &Options::default())?.finish()?;
        assert_failure(&outcome, 1, message);
        assert!(!outcome.screen.contains(CURRENT_PASSWORD_PROMPT));
    }
    assert!(!missing.exists());
    setup.assert_unchanged()
}
