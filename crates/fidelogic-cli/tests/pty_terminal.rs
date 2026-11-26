//! 端末で秘密を入力する間のエコーの抑止と、`SIGINT` による中断の後の端末の復元を、実行ファイルで確かめる統合テスト。
//!
//! 入力を表示せずに読み込む問いごとに、次を確かめる。
//!
//! - 入力中は端末のエコーと行入力モードが無効で、入力した内容が画面に出ない。
//! - `Ctrl+C` と、他のプロセスからの `SIGINT` で中断すると、終了コード 130 で終わり、端末属性が元に戻る。
//! - 中断の時点で読み残していた入力は、後続のシェルに渡らない。
//! - 中断した場合は、ファイルを作らず、既存の Vault を変えない。

mod common;

use std::fs;
use std::os::fd::AsRawFd;
use std::time::Duration;

use common::entry_vault::{EntryVault, credential};
use common::fixture::{NEW_PASSWORD, OLD_CODE, write_fixture};
use common::{
    CONFIRMATION_PROMPT, ENTER_ALTERNATE_SCREEN, KIT_HEADING, LEAVE_ALTERNATE_SCREEN,
    NEW_PASSWORD_PROMPT, Options, Outcome, PASSWORD, REPEAT_PASSWORD_PROMPT, Redirect, Session,
    TempDir, TestResult, assert_code_only_on_alternate_screen, attributes, displayed_code, text,
};

const PASSWORD_PROMPT: &str = "マスターパスワード: ";
const CURRENT_PASSWORD_PROMPT: &str = "現在のマスターパスワード: ";
const CODE_PROMPT: &str = "リカバリーコード (入力は表示されません): ";
const USERNAME_PROMPT: &str = "ユーザー名 (空の Enter で";
const PASSWORD_FIELD_PROMPT: &str = "パスワード (空の Enter で";
const URL_PROMPT: &str = "URL (空の Enter で";
const TOTP_PROMPT: &str = "otpauth URI (空の Enter で";
const NOTES_PROMPT: &str = "メモ (1 行) (空の Enter で";
/// 同意を求める問いの、共通の末尾。
const CONSENT_PROMPT: &str = "(y/N、入力は表示されません): ";
const COMMAND_PROMPT: &str = "fidelogic> ";

/// 中断の前に入力する内容。実行ファイルが読み込んでから中断する。
const TYPED: &str = "typed-before-interrupt";

/// 中断と同時に端末に届き、実行ファイルが読み込まない内容。
const UNREAD: &str = "unread-at-interrupt";

/// 端末で順に答える操作。
#[derive(Debug, Clone, Copy)]
enum Step {
    /// 入力を表示しない問いと、その答え。中断を試す対象である。
    Hidden(&'static str, &'static str),
    /// 対話モードのコマンドの入力。入力は表示される。
    Command(&'static str),
}

/// `SIGINT` の起こし方。
#[derive(Debug, Clone, Copy)]
enum Interrupt {
    /// 端末の `Ctrl+C`。端末がシグナルを生成する。
    Key,
    /// 他のプロセスからのシグナル。
    Signal,
}

/// `steps` の `target` 番目の問いが表示されるまで進める。
///
/// 問いは画面に 1 回目に現れた時点で待つ。同じ文言の問いを 2 回以上通る列は扱えない。
fn advance(
    args: &[&str],
    redirect: Redirect<'_>,
    steps: &[Step],
    target: usize,
) -> Result<Session, Box<dyn std::error::Error>> {
    let options = Options {
        redirect,
        ..Options::default()
    };
    let mut session = Session::spawn(args, &options)?;
    for (index, step) in steps.iter().enumerate().take(target + 1) {
        match *step {
            Step::Hidden(prompt, _) if index == target => session.wait_for_screen(prompt, 1)?,
            Step::Hidden(prompt, answer) => session.answer(prompt, answer)?,
            Step::Command(line) => {
                session.answer(COMMAND_PROMPT, line)?;
                // 表示される入力は画面に現れる。画面の内容でエコーを判定できることの確認を兼ねる。
                session.wait_for_screen(line, 1)?;
            }
        }
    }
    Ok(session)
}

/// 問いの表示中は端末のエコーと行入力モードが無効で、入力した内容が画面に出ないこと。
fn assert_input_is_hidden(session: &mut Session, context: &str) -> TestResult {
    // 起動前から無効な端末では、以降の確認が意味を持たない。
    assert_eq!(
        session.initial.c_lflag & (libc::ECHO | libc::ICANON),
        libc::ECHO | libc::ICANON,
        "{context}: 起動前の端末のエコーと行入力モードの確認に失敗。"
    );
    let during = attributes(session.pty.slave.as_raw_fd())?;
    assert_eq!(
        during.c_lflag & (libc::ECHO | libc::ECHONL | libc::ICANON),
        0,
        "{context}: 入力中のエコーと行入力モードの無効化に失敗。"
    );
    assert_ne!(
        during.c_lflag & libc::ISIG,
        0,
        "{context}: 入力中のシグナル生成の有効化に失敗。"
    );

    session.type_input(TYPED.as_bytes())?;
    // 中断のキーは端末の出力を捨てることがあるため、エコーが届く時間を置いて、中断の前に調べる。
    std::thread::sleep(Duration::from_millis(100));
    session.pty.drain_screen()?;
    assert!(
        !session.pty.text().contains(TYPED),
        "{context}: 入力が表示されないことの確認に失敗。"
    );
    Ok(())
}

/// 読み込まれていない入力がある状態で、`SIGINT` を起こす。
///
/// 実行ファイルを停止している間に入力とシグナルを届けてから再開する。
/// 停止せずに届けると、読み残しの入力が端末属性の復元より後に届き、後続のシェルに渡ることがある。
fn interrupt_with_unread_input(session: &mut Session, interrupt: Interrupt) -> TestResult {
    session.send_signal(libc::SIGSTOP)?;
    std::thread::sleep(Duration::from_millis(50));
    match interrupt {
        // 端末はシグナルを生成する前の入力を捨てるため、読み残しはキーの後ろに置く。
        Interrupt::Key => session.type_input(format!("\x03{UNREAD}").as_bytes())?,
        Interrupt::Signal => {
            session.type_input(UNREAD.as_bytes())?;
            session.send_signal(libc::SIGINT)?;
        }
    }
    // 入力が端末に届くのを待ってから再開する。
    std::thread::sleep(Duration::from_millis(50));
    session.send_signal(libc::SIGCONT)
}

/// 終了コード 130 で、エラー出力の最後の行が中断を示すこと。
///
/// 端末での実行 ([`Redirect::Terminal`]) は、エラー出力も画面に出る。
/// それ以外の実行は、標準出力が空であることも確かめる。
/// 警告を先に書くサブコマンドがあるため、エラー出力の行数は限らない。
fn assert_interrupted(outcome: &Outcome, redirect: Redirect<'_>, context: &str) {
    assert_eq!(
        outcome.status, 130,
        "{context}: 終了コードの確認に失敗: {}{}",
        outcome.stderr, outcome.screen
    );
    let errors = if matches!(redirect, Redirect::Terminal) {
        &outcome.screen
    } else {
        assert!(
            outcome.stdout.is_empty(),
            "{context}: 標準出力が空ではありません。"
        );
        &outcome.stderr
    };
    assert!(
        errors
            .lines()
            .last()
            .is_some_and(|line| line.starts_with("fidelogic-cli: ") && line.contains("中断")),
        "{context}: 中断のエラー出力の確認に失敗: {errors}"
    );
    assert!(
        !errors.contains(TYPED) && !errors.contains(UNREAD),
        "{context}: 入力をエラー出力に含めないことの確認に失敗。"
    );
}

/// `steps` の入力を表示しない問いのそれぞれで中断し、端末の状態と `assert_unchanged` を確かめる。
fn assert_interrupts_restore_terminal(
    args: &[&str],
    redirect: Redirect<'_>,
    steps: &[Step],
    assert_unchanged: impl Fn() -> TestResult,
) -> TestResult {
    for (target, step) in steps.iter().enumerate() {
        let Step::Hidden(prompt, _) = step else {
            continue;
        };
        for interrupt in [Interrupt::Key, Interrupt::Signal] {
            let context = format!("{args:?} の「{prompt}」での {interrupt:?}");
            let mut session = advance(args, redirect, steps, target)?;
            assert_input_is_hidden(&mut session, &context)?;
            interrupt_with_unread_input(&mut session, interrupt)?;
            // 端末属性が起動前と同じ (エコーと行入力モードが有効) であることは、終了の処理が確かめる。
            let (outcome, following) = session.finish_with_following_input()?;

            // 読み残しは画面にも出ることがあるため、原因が分かるように先に確かめる。
            assert_eq!(following, "", "{context}: 読み残した入力の破棄に失敗。");
            assert_interrupted(&outcome, redirect, &context);
            assert!(
                !outcome.screen.contains(TYPED) && !outcome.screen.contains(UNREAD),
                "{context}: 中断の後も入力が表示されないことの確認に失敗: {}",
                outcome.screen
            );
            if let Some(entered) = outcome.screen.rfind(ENTER_ALTERNATE_SCREEN) {
                assert!(
                    outcome.screen[entered..].contains(LEAVE_ALTERNATE_SCREEN),
                    "{context}: 代替画面からの復帰に失敗。"
                );
            }
            if outcome.screen.contains(KIT_HEADING) {
                let code = displayed_code(&outcome.screen)?;
                assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
            }
            assert_unchanged()?;
        }
    }
    Ok(())
}

#[test]
fn test_init_prompts_restore_terminal_after_interrupt() -> TestResult {
    let directory = TempDir::new()?;
    let vault = directory.path("vault.fvl");
    let kit = directory.path("kit.html");
    assert_interrupts_restore_terminal(
        &["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?],
        Redirect::None,
        &[
            Step::Hidden(NEW_PASSWORD_PROMPT, PASSWORD),
            Step::Hidden(REPEAT_PASSWORD_PROMPT, PASSWORD),
            Step::Hidden(CONFIRMATION_PROMPT, ""),
        ],
        || {
            assert_eq!(
                directory.names()?,
                ["vault.fvl.lock"],
                "中断後のファイルの確認に失敗。"
            );
            Ok(())
        },
    )
}

/// 全スロットを持つ Vault を作り、鍵を更新するサブコマンドの各問いで中断する。
fn assert_key_update_interrupts(
    command: &str,
    extra: &[&str],
    prf_slot: bool,
    steps: &[Step],
) -> TestResult {
    let directory = TempDir::new()?;
    let vault = directory.path("vault.fvl");
    let kit = directory.path("kit.html");
    write_fixture(&vault, prf_slot)?;
    let before = fs::read(&vault)?;
    let mut args = vec![command, "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    args.extend_from_slice(extra);
    assert_interrupts_restore_terminal(&args, Redirect::None, steps, || {
        assert!(
            fs::read(&vault)? == before,
            "Vault を変えないことの確認に失敗。"
        );
        assert_eq!(
            directory.names()?,
            ["vault.fvl", "vault.fvl.lock"],
            "中断後のファイルの確認に失敗。"
        );
        Ok(())
    })
}

#[test]
fn test_recover_prompts_restore_terminal_after_interrupt() -> TestResult {
    assert_key_update_interrupts(
        "recover",
        &[],
        false,
        &[
            Step::Hidden(CODE_PROMPT, OLD_CODE),
            Step::Hidden(NEW_PASSWORD_PROMPT, NEW_PASSWORD),
            Step::Hidden(REPEAT_PASSWORD_PROMPT, NEW_PASSWORD),
            Step::Hidden(CONFIRMATION_PROMPT, ""),
        ],
    )
}

#[test]
fn test_rotate_key_prompts_restore_terminal_after_interrupt() -> TestResult {
    assert_key_update_interrupts(
        "rotate-key",
        &["--full-dek"],
        true,
        &[
            Step::Hidden(CURRENT_PASSWORD_PROMPT, PASSWORD),
            Step::Hidden(CONSENT_PROMPT, "y"),
            Step::Hidden(NEW_PASSWORD_PROMPT, NEW_PASSWORD),
            Step::Hidden(REPEAT_PASSWORD_PROMPT, NEW_PASSWORD),
            Step::Hidden(CONFIRMATION_PROMPT, ""),
        ],
    )
}

/// エントリを 1 件持つ Vault に対する操作の各問いで中断する。
///
/// `extra` は、`--vault` の指定より後ろの引数である。
fn assert_entry_command_interrupts(
    command: &str,
    extra: &[&str],
    redirect: Redirect<'_>,
    steps: &[Step],
) -> TestResult {
    let target = EntryVault::new(&[credential(1, "site")])?;
    let before = target.contents()?;
    let mut args = vec![command, "--vault", target.vault_text()?];
    args.extend_from_slice(extra);
    assert_interrupts_restore_terminal(&args, redirect, steps, || {
        assert!(
            target.contents()? == before,
            "Vault を変えないことの確認に失敗。"
        );
        assert_eq!(
            target.directory.names()?,
            ["password", "vault.fvl", "vault.fvl.lock"],
            "中断後のファイルの確認に失敗。"
        );
        Ok(())
    })
}

#[test]
fn test_reading_command_prompts_restore_terminal_after_interrupt() -> TestResult {
    for (command, extra) in [("list", &[][..]), ("get", &["site"])] {
        assert_entry_command_interrupts(
            command,
            extra,
            Redirect::None,
            &[Step::Hidden(PASSWORD_PROMPT, "")],
        )?;
    }
    Ok(())
}

#[test]
fn test_consent_prompts_restore_terminal_after_interrupt() -> TestResult {
    for (command, extra) in [("delete", &["site"][..]), ("export", &["--stdout"])] {
        assert_entry_command_interrupts(
            command,
            extra,
            Redirect::None,
            &[
                Step::Hidden(PASSWORD_PROMPT, PASSWORD),
                Step::Hidden(CONSENT_PROMPT, ""),
            ],
        )?;
    }
    Ok(())
}

#[test]
fn test_set_prompts_restore_terminal_after_interrupt() -> TestResult {
    assert_entry_command_interrupts(
        "set",
        &["added"],
        Redirect::None,
        &[
            Step::Hidden(PASSWORD_PROMPT, PASSWORD),
            Step::Hidden(USERNAME_PROMPT, "user"),
            Step::Hidden(PASSWORD_FIELD_PROMPT, "field-secret"),
            Step::Hidden(REPEAT_PASSWORD_PROMPT, "field-secret"),
            Step::Hidden(URL_PROMPT, ""),
            Step::Hidden(TOTP_PROMPT, ""),
            Step::Hidden(NOTES_PROMPT, ""),
        ],
    )
}

#[test]
fn test_session_prompts_restore_terminal_after_interrupt() -> TestResult {
    assert_entry_command_interrupts(
        "unlock",
        &[],
        Redirect::Terminal,
        &[
            Step::Hidden(PASSWORD_PROMPT, PASSWORD),
            Step::Command("set added"),
            Step::Hidden(USERNAME_PROMPT, "user"),
            Step::Hidden(PASSWORD_FIELD_PROMPT, "field-secret"),
            Step::Hidden(REPEAT_PASSWORD_PROMPT, "field-secret"),
            Step::Hidden(URL_PROMPT, ""),
            Step::Hidden(TOTP_PROMPT, ""),
            Step::Hidden(NOTES_PROMPT, ""),
        ],
    )?;
    assert_entry_command_interrupts(
        "unlock",
        &[],
        Redirect::Terminal,
        &[
            Step::Hidden(PASSWORD_PROMPT, PASSWORD),
            Step::Command("delete site"),
            Step::Hidden(CONSENT_PROMPT, ""),
        ],
    )
}
