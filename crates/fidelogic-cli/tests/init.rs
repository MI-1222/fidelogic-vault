//! `init` サブコマンドの統合テスト。
//!
//! 実行ファイルを疑似端末で起動する仕組みは `common` にある。

mod common;

use std::error::Error;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use common::*;
use fidelogic_cli::sys::storage::{VaultLock, VaultPath};
use fidelogic_core::{
    Argon2Params, Argon2idSlotPayload, KekSlots, LockedBuffer, SlotStatus, VaultEngine,
};

/// `mlock` の可否を調べる子プロセスであることを示す環境変数の名前。
const PROBE_MARKER: &str = "FIDELOGIC_CLI_INIT_MEMLOCK_PROBE";

/// 調べた子プロセスで、`mlock` に成功したことを示す出力。
const PROBE_LOCKED: &str = "init-probe:locked";

/// 調べた子プロセスで、`mlock` に失敗したことを示す出力。
const PROBE_REFUSED: &str = "init-probe:refused";

fn engine() -> VaultEngine {
    VaultEngine::new(KekSlots::new(
        SlotStatus::Valid,
        SlotStatus::Unset,
        SlotStatus::Valid,
    ))
}

/// 作成された Vault を、パスワードと、表示されたリカバリーコードのそれぞれで解錠できること。
fn assert_vault_unlocks(path: &Path, password: &str, code: &str) -> TestResult {
    let vault = read_vault(path)?;
    assert_eq!(vault.header.epoch_id, 1);
    // 作成した Vault が、ネイティブ向けの鍵導出パラメータを使うこと。
    let password_slot = vault.slots.first().ok_or("Slot 0 がありません。")?;
    let params = Argon2idSlotPayload::from_slot_entry(password_slot)
        .map_err(|error| format!("{error}"))?
        .params;
    let expected = Argon2Params::for_native();
    assert_eq!(
        (params.m_cost(), params.t_cost(), params.p_cost()),
        (expected.m_cost(), expected.t_cost(), expected.p_cost()),
        "鍵導出パラメータの確認に失敗。"
    );
    engine()
        .unlock_vault_with_password(&vault, password.as_bytes())
        .map_err(|error| format!("パスワードでの解錠に失敗: {error}"))?;
    engine()
        .unlock_vault_with_recovery_code(&vault, code.as_bytes())
        .map_err(|error| format!("リカバリーコードでの解錠に失敗: {error}"))?;
    assert!(
        engine()
            .unlock_vault_with_password(&vault, b"wrong password")
            .is_err(),
        "誤ったパスワードの拒否に失敗。"
    );
    Ok(())
}

#[test]
fn test_init_creates_vault_after_confirmation() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let mut session = Session::spawn(&["init", "--vault", text(&vault)?], &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    assert_eq!(
        dir.names()?,
        ["vault.fvl.lock"],
        "確認の前に Vault を作らないことの確認に失敗。"
    );
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    assert!(outcome.stdout.contains("Vault を作成しました"));
    assert!(!outcome.stdout.contains(&code));
    assert!(
        !outcome.screen.contains(PASSWORD),
        "パスワードが表示されないことの確認に失敗。"
    );
    // コードの全体に含まれる分の他に、再入力した末尾が表示されないこと。
    assert_eq!(
        outcome.screen.matches(suffix(&code)?).count(),
        1,
        "再入力が表示されないことの確認に失敗。"
    );
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    assert_eq!(mode_of(&vault)?, 0o600);
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

#[test]
fn test_init_writes_html_kit_with_password_file() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let password_file = dir.path("password");
    fs::write(&password_file, format!("{PASSWORD}\n"))?;
    fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600))?;
    let args = [
        "init",
        "--vault",
        text(&vault)?,
        "--kit-html",
        text(&kit)?,
        "--password-file",
        text(&password_file)?,
    ];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    assert!(
        !vault.exists() && kit.exists(),
        "確認の前の状態の確認に失敗。"
    );
    // 小文字と、区切りの `-` と空白を含む形でも、確認を通ること。
    let spaced: String = suffix(&code)?
        .to_lowercase()
        .chars()
        .flat_map(|symbol| [symbol, ' ', '-'])
        .collect();
    session.type_input(format!(" {spaced}\r").as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert!(outcome.stdout.contains("リカバリーキットを書き出しました"));
    assert_eq!(mode_of(&kit)?, 0o600);
    let html = fs::read_to_string(&kit)?;
    assert_eq!(
        html.matches(&code).count(),
        1,
        "HTML のコードの確認に失敗。"
    );
    assert!(html.contains(WARNING));
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

#[test]
fn test_init_accepts_relative_paths() -> TestResult {
    let dir = TempDir::new()?;
    let options = Options {
        current_dir: Some(&dir.0),
        ..Options::default()
    };
    let args = ["init", "--vault", "vault.fvl", "--kit-html", "kit.html"];
    let mut session = Session::spawn(&args, &options)?;
    let code = session.enter_password_and_read_code()?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    // 親ディレクトリの同期の失敗は、警告として標準エラー出力に出る。
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    assert_eq!(dir.names()?, ["kit.html", "vault.fvl", "vault.fvl.lock"]);
    assert_vault_unlocks(&dir.path("vault.fvl"), PASSWORD, &code)
}

#[test]
fn test_init_reads_password_from_standard_input() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    // 全角の空白は ASCII の空白に正準化する。
    let input = format!("{}\n", PASSWORD.replace(' ', "\u{3000}"));
    let options = Options {
        stdin: Some(input.as_bytes()),
        ..Options::default()
    };
    let args = ["init", "--vault", text(&vault)?, "--password-stdin"];
    let mut session = Session::spawn(&args, &options)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 引き継いだ記述子から読む場合も、本体が開く端末やロックファイルと取り違えずに作成できること。
#[test]
fn test_init_reads_password_from_inherited_descriptor() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let password_source = dir.path("password");
    fs::write(&password_source, format!("{PASSWORD}\n"))?;
    let options = Options {
        redirect: Redirect::DescriptorThreeFrom(&password_source),
        ..Options::default()
    };
    let args = ["init", "--vault", text(&vault)?, "--password-fd", "3"];
    let mut session = Session::spawn(&args, &options)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

#[test]
fn test_wrong_confirmation_redraws_kit_and_asks_again() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let mut session = Session::spawn(&["init", "--vault", text(&vault)?], &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    let too_long = "A".repeat(2000);
    for (attempt, wrong) in ["UUUUU", "", too_long.as_str()].into_iter().enumerate() {
        session.type_input(format!("{wrong}\r").as_bytes())?;
        session.wait_for_screen(CONFIRMATION_PROMPT, attempt + 2)?;
        assert!(
            !vault.exists(),
            "不一致で Vault を作らないことの確認に失敗。"
        );
    }
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert_eq!(outcome.screen.matches("一致しません。").count(), 3);
    assert_eq!(
        outcome.screen.matches(&code).count(),
        4,
        "同じコードの描き直しの確認に失敗。"
    );
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 作成の後に結果を書き込めない場合は失敗を報告し、作成した Vault と HTML を残すこと。
#[test]
fn test_output_failure_after_creation_keeps_vault_and_kit() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let options = Options {
        redirect: Redirect::BrokenStdout,
        ..Options::default()
    };
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &options)?;
    let code = session.enter_password_and_read_code()?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "標準出力への書き込みに失敗しました");
    assert_eq!(dir.names()?, ["kit.html", "vault.fvl", "vault.fvl.lock"]);
    assert!(fs::read_to_string(&kit)?.contains(&code));
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 再入力の前に中止した場合は、Vault も HTML も残さず、画面を消去して元の画面に戻ること。
fn assert_abort_during_confirmation(
    abort: impl FnOnce(&mut Session) -> TestResult,
    status: i32,
    message: &str,
) -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    abort(&mut session)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, status, message);
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(
        dir.names()?,
        ["vault.fvl.lock"],
        "中止後のファイルの確認に失敗。"
    );
    Ok(())
}

#[test]
fn test_interrupt_key_during_confirmation_leaves_nothing() -> TestResult {
    assert_abort_during_confirmation(|session| session.type_input(b"\x03"), 130, "中断")
}

#[test]
fn test_termination_signal_during_confirmation_leaves_nothing() -> TestResult {
    assert_abort_during_confirmation(|session| session.send_signal(libc::SIGTERM), 130, "中断")
}

#[test]
fn test_end_of_input_during_confirmation_leaves_nothing() -> TestResult {
    assert_abort_during_confirmation(
        |session| session.type_input(b"\x04"),
        1,
        "リカバリーコードの控えを確認できないため",
    )
}

#[test]
fn test_vault_created_during_confirmation_is_not_replaced() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    // ロックに従わない処理が、確認の間にファイルを作る。
    fs::write(&vault, b"created by another program")?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "ファイルがすでに存在するため");
    assert_eq!(fs::read(&vault)?, b"created by another program");
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

/// パスワードの入力の段階で失敗する場合は、リカバリーキットを表示せず、ファイルを作らないこと。
fn assert_password_failure(
    input: impl FnOnce(&mut Session) -> TestResult,
    status: i32,
    message: &str,
) -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    input(&mut session)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, status, message);
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_mismatched_passwords_create_nothing() -> TestResult {
    assert_password_failure(
        |session| {
            session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
            session.answer(REPEAT_PASSWORD_PROMPT, &PASSWORD.to_uppercase())
        },
        1,
        "2 つのパスワードが一致しません",
    )
}

#[test]
fn test_disallowed_password_creates_nothing() -> TestResult {
    assert_password_failure(
        |session| session.answer(NEW_PASSWORD_PROMPT, "a\tb"),
        1,
        "使用できない文字",
    )
}

#[test]
fn test_empty_password_creates_nothing() -> TestResult {
    assert_password_failure(
        |session| session.answer(NEW_PASSWORD_PROMPT, ""),
        1,
        "パスワードが空です",
    )
}

#[test]
fn test_interrupt_during_password_input_creates_nothing() -> TestResult {
    assert_password_failure(
        |session| {
            session.wait_for_screen(NEW_PASSWORD_PROMPT, 1)?;
            session.type_input(b"partial\x03")
        },
        130,
        "中断",
    )
}

/// パスワードの入力より前に失敗する場合は、何も入力を求めないこと。
fn assert_rejected_before_password(args: &[&str], message: &str) -> TestResult {
    let outcome = Session::spawn(args, &Options::default())?.finish()?;
    assert_failure(&outcome, 1, message);
    assert!(
        !outcome.screen.contains(NEW_PASSWORD_PROMPT),
        "入力を求めないことの確認に失敗: {}",
        outcome.screen
    );
    Ok(())
}

#[test]
fn test_existing_vault_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    fs::write(&vault, b"existing")?;
    assert_rejected_before_password(
        &["init", "--vault", text(&vault)?],
        "ファイルがすでに存在するため",
    )?;
    assert_eq!(fs::read(&vault)?, b"existing");
    Ok(())
}

#[test]
fn test_existing_kit_destination_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    fs::write(&kit, b"existing")?;
    assert_rejected_before_password(
        &["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?],
        "出力先にファイルがすでに存在するため",
    )?;
    assert_eq!(fs::read(&kit)?, b"existing");
    assert_eq!(dir.names()?, ["kit.html", "vault.fvl.lock"]);
    Ok(())
}

/// 出力先がディレクトリ、または参照先の無いシンボリックリンクの場合も、パスワードを読み込む前に拒否すること。
#[test]
fn test_kit_destination_with_other_entry_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let target = dir.path("target");
    let link = dir.path("link.html");
    std::os::unix::fs::symlink(&target, &link)?;
    let directory = dir.path("directory");
    fs::create_dir(&directory)?;
    for kit in [&link, &directory] {
        assert_rejected_before_password(
            &["init", "--vault", text(&vault)?, "--kit-html", text(kit)?],
            "出力先にファイルがすでに存在するため",
        )?;
    }
    assert!(
        fs::symlink_metadata(&link)?.file_type().is_symlink() && !target.exists(),
        "リンクと参照先を変えないことの確認に失敗。"
    );
    assert_eq!(dir.names()?, ["directory", "link.html", "vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_locked_vault_is_rejected_without_waiting() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let lock = VaultLock::try_acquire(VaultPath::resolve(&vault)?)?;
    assert_rejected_before_password(
        &["init", "--vault", text(&vault)?],
        "他の処理が Vault を使用中です",
    )?;
    drop(lock);
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_kit_destination_equal_to_vault_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    // 異なる表記で、同じファイルを指定する。
    let kit = dir.0.join(".").join("vault.fvl");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "出力先が Vault のパスと重なっています");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_unwritable_kit_destination_fails_before_display() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("missing").join("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "出力先のファイルの作成に失敗しました");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

/// 非特権の環境の標準的な上限 (64 KiB) でも、鍵導出と秘密のバッファの確保が両立すること。
#[test]
fn test_init_succeeds_with_small_memory_lock_limit() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let options = Options {
        memlock_limit: Some(64 * 1024),
        ..Options::default()
    };
    let mut session = Session::spawn(&["init", "--vault", text(&vault)?], &options)?;
    let code = session.enter_password_and_read_code()?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 子プロセスの中で、`mlock` できるかを報告する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_probe_memory_lock() -> TestResult {
    if std::env::var_os(PROBE_MARKER).is_none() {
        return Ok(());
    }
    let report = if LockedBuffer::<1>::zero_strict().is_ok() {
        PROBE_LOCKED
    } else {
        PROBE_REFUSED
    };
    writeln!(std::io::stdout(), "\n{report}")?;
    Ok(())
}

/// `RLIMIT_MEMLOCK` を 0 にしたプロセスで、`mlock` が失敗する環境かを返す。
///
/// 検査する実行ファイルの振る舞いに依存しないよう、テストバイナリを子プロセスとして再実行して調べる。
/// `CAP_IPC_LOCK` を持つプロセスなどは、上限を 0 にしても `mlock` が成功する。
fn memory_lock_can_be_refused() -> Result<bool, Box<dyn Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "child_probe_memory_lock",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE_MARKER, "1");
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setrlimit` は非同期シグナルセーフで、ヒープ確保などは行わない。
    unsafe {
        command.pre_exec(|| set_memory_lock_limit(0));
    }
    let output = command.output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let reported = |report: &str| stdout.lines().any(|line| line == report);
    match (reported(PROBE_REFUSED), reported(PROBE_LOCKED)) {
        (true, false) if output.status.success() => Ok(true),
        (false, true) if output.status.success() => Ok(false),
        _ => Err(format!("mlock の可否の確認に失敗しました: {stdout}").into()),
    }
}

/// 秘密のバッファを `mlock` できない場合は、入力を求めずに中止すること。
///
/// 上の上限のテストが、上限を実際に適用していることの対照でもある。
/// 上限を 0 にしても `mlock` が成功する環境では、スキップする。
#[test]
fn test_init_fails_closed_without_memory_lock() -> TestResult {
    if !memory_lock_can_be_refused()? {
        writeln!(
            std::io::stderr(),
            "スキップ: この環境では mlock の失敗を再現できません。"
        )?;
        return Ok(());
    }
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let options = Options {
        memlock_limit: Some(0),
        ..Options::default()
    };
    let outcome = Session::spawn(&["init", "--vault", text(&vault)?], &options)?.finish()?;

    assert_failure(&outcome, 1, "メモリロックに失敗しました");
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

/// 端末の無い環境では、入力元の指定があっても作成せず、ファイルに触れないこと。
#[test]
fn test_init_requires_controlling_terminal() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let mut command = Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"));
    command
        .args(["init", "--vault", text(&vault)?, "--password-stdin"])
        .args(["--kit-html", text(&kit)?])
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
    assert!(
        dir.names()?.is_empty(),
        "ファイルに触れないことの確認に失敗。"
    );
    Ok(())
}
