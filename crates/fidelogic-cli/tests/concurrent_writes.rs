//! 同じ Vault への同時の書き込みと、古いスナップショットでの上書きの統合テスト。
//!
//! Vault を扱うサブコマンドは、ロックを待たずに失敗する。同時の書き込みは、利用者が実行し直す場合と同じく、
//! ロックの競合で失敗した操作をテスト側でやり直す。

mod common;

use std::fs;
use std::sync::mpsc::channel;
use std::time::{Duration, Instant};

use common::entry_vault::{EntryVault, credential, run_without_terminal};
use common::{Options, Session, TIMEOUT, TestResult, assert_failure, read_vault};
use fidelogic_cli::sys::storage::{VaultLock, VaultPath};

/// 同時に書き込むプロセスの数。
const WRITERS: u8 = 10;

/// ロックの競合で失敗した場合のメッセージ。
const LOCKED: &str = "他の処理が Vault を使用中です。";

/// 端末から読み込むマスターパスワードのプロンプト。
const PASSWORD_PROMPT: &str = "マスターパスワード: ";

/// やり直すまでの間隔。
const RETRY_INTERVAL: Duration = Duration::from_millis(5);

/// 端末を使わずにエントリを削除し、成功するか、ロックの競合以外で失敗するまで繰り返す。
///
/// # Args
///
/// - `on_rejected`: ロックの競合で失敗するたびに呼ぶ処理。
///
/// # Errors
///
/// ロックの競合以外の失敗と、時間内に成功しないこと。
fn delete_until_saved(
    vault: &str,
    password_file: &str,
    title: &str,
    mut on_rejected: impl FnMut(),
) -> Result<(), String> {
    let args = [
        "delete",
        "--vault",
        vault,
        title,
        "--yes",
        "--password-file",
        password_file,
    ];
    let deadline = Instant::now() + TIMEOUT;
    loop {
        let output = run_without_terminal(&args, b"").map_err(|error| error.to_string())?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        match output.status.code() {
            Some(0) if stderr.is_empty() => return Ok(()),
            Some(1) if stderr.contains(LOCKED) => on_rejected(),
            code => return Err(format!("{title} の削除に失敗しました ({code:?}): {stderr}")),
        }
        if Instant::now() > deadline {
            return Err(format!("{title} の削除が時間内に終わりませんでした。"));
        }
        std::thread::sleep(RETRY_INTERVAL);
    }
}

/// 10 プロセスの書き込みが直列になり、更新の消失と世代の競合が起きないこと。
#[test]
fn test_concurrent_writers_advance_the_epoch_one_by_one() -> TestResult {
    let titles: Vec<String> = (0..WRITERS)
        .map(|index| format!("writer-{index}"))
        .collect();
    let mut entries = vec![credential(u8::MAX, "keep")];
    entries.extend((1..).zip(&titles).map(|(id, title)| credential(id, title)));
    let target = EntryVault::new(&entries)?;
    let before = read_vault(&target.vault)?;
    let before_bytes = target.contents()?;
    let vault = target.vault_text()?;
    let password_file = target.password_file_text()?;

    // 全部の書き込みが 1 回以上拒否されるまでロックを保持し、解放の後に競合させる。
    let lock = VaultLock::try_acquire(VaultPath::resolve(&target.vault)?)?;
    let (sender, first_rejections) = channel();
    std::thread::scope(|scope| -> TestResult {
        let writers: Vec<_> = titles
            .iter()
            .map(|title| {
                let mut sender = Some(sender.clone());
                scope.spawn(move || {
                    delete_until_saved(vault, password_file, title, || {
                        // 受け手は、全部の書き込みの終了まで生存する。
                        if let Some(sender) = sender.take() {
                            let _ = sender.send(());
                        }
                    })
                })
            })
            .collect();
        drop(sender);
        // 拒否されずに終了した書き込みがある場合は、送り手がなくなった時点で失敗する。
        let all_rejected = (0..WRITERS).try_for_each(|_| first_rejections.recv_timeout(TIMEOUT));
        let held_bytes = target.contents();
        // 失敗した場合も、書き込みのスレッドが終了できるように、先に解放する。
        drop(lock);
        for writer in writers {
            writer
                .join()
                .map_err(|_| "書き込みのスレッドが異常終了しました。")??;
        }
        all_rejected
            .map_err(|error| format!("ロックの保持中の拒否の確認に失敗しました: {error}"))?;
        assert!(
            held_bytes? == before_bytes,
            "ロックの保持中の Vault の維持に失敗。"
        );
        Ok(())
    })?;

    assert_eq!(
        target.epoch()?,
        before.header.epoch_id + u64::from(WRITERS),
        "世代の直列化の確認に失敗。"
    );
    let remaining: Vec<_> = target
        .credentials()?
        .into_iter()
        .map(|credential| credential.title)
        .collect();
    assert_eq!(
        remaining,
        [Some("keep".to_owned())],
        "更新の消失が起きたため失敗しました。"
    );
    target.assert_preserved(&before)?;
    assert_eq!(
        target.directory.names()?,
        ["password", "vault.fvl", "vault.fvl.lock"]
    );
    Ok(())
}

/// 読み込みから保存までの間に、ロックに従わない処理が古いスナップショットで上書きした場合は、
/// 巻き戻しとして中止し、上書きされた内容を変えないこと。
#[test]
fn test_older_snapshot_written_during_a_command_is_a_rollback() -> TestResult {
    let target = EntryVault::new(&[credential(1, "removed"), credential(2, "site")])?;
    let snapshot = target.contents()?;
    delete_until_saved(
        target.vault_text()?,
        target.password_file_text()?,
        "removed",
        || {},
    )?;

    let mut session = Session::spawn(
        &["delete", "--vault", target.vault_text()?, "site"],
        &Options::default(),
    )?;
    session.answer(PASSWORD_PROMPT, common::PASSWORD)?;
    // 同意の問いの表示は、Vault の読み込みと解錠が済んだことを示す。
    session.wait_for_screen("y/N", 1)?;
    fs::write(&target.vault, &snapshot)?;
    session.answer("y/N", "y")?;
    assert_failure(
        &session.finish()?,
        1,
        "Vault の世代が以前に読み込んだものより古いため",
    );

    assert!(
        target.contents()? == snapshot,
        "上書きされた内容を変えないことの確認に失敗。"
    );
    assert_eq!(
        target.directory.names()?,
        ["password", "vault.fvl", "vault.fvl.lock"]
    );
    Ok(())
}
