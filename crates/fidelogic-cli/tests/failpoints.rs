//! 失敗点で停止させた実行ファイルの統合テスト。保存の途中で強制終了した場合と、起動直後の保護を扱う。
//!
//! 実行ファイルを失敗点で停止させ、停止中の状態を調べてから `SIGKILL` を送る。
//! 失敗点は、フィーチャー `test-hooks` を有効にしたデバッグビルドにだけ含まれる。
//! それ以外のビルドでは、失敗点を指定しても停止しないことを確かめる。

mod common;

/// 停止する失敗点の名前を指定する環境変数。
const VARIABLE: &str = "FIDELOGIC_CLI_FAILPOINT";

/// 失敗点が有効なビルドのテスト。
#[cfg(all(feature = "test-hooks", debug_assertions))]
mod enabled {
    use std::error::Error;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::path::PathBuf;
    use std::process::{Child, ChildStderr, Command};
    use std::sync::mpsc::{Receiver, channel};

    use fidelogic_cli::sys::storage::{StorageError, VaultLock, VaultPath};
    use fidelogic_core::Vault;

    use super::VARIABLE;
    use super::common::entry_vault::{
        EntryVault, credential, run_without_terminal, spawn_prepared,
    };
    use super::common::{TIMEOUT, TestResult, mode_of, read_vault};

    /// 削除するエントリと、残すエントリを持つ Vault を作る。
    fn target() -> Result<EntryVault, Box<dyn Error>> {
        EntryVault::new(&[credential(1, "drop"), credential(2, "keep")])
    }

    /// 端末を使わずに `drop` を削除する引数。保存まで進む操作として使う。
    fn delete_args(target: &EntryVault) -> Result<[&str; 7], Box<dyn Error>> {
        Ok([
            "delete",
            "--vault",
            target.vault_text()?,
            "drop",
            "--yes",
            "--password-file",
            target.password_file_text()?,
        ])
    }

    /// 失敗点で停止している実行ファイル。
    ///
    /// 破棄すると標準入力が閉じ、停止中の子は終了する。
    struct Halted {
        child: Child,
        /// 子の標準エラー出力の行。
        lines: Receiver<String>,
    }

    impl Halted {
        /// 実行ファイルを起動し、失敗点 `point` で停止するまで待つ。
        fn spawn(
            args: &[&str],
            point: &str,
            prepare: impl FnOnce(&mut Command),
        ) -> Result<Self, Box<dyn Error>> {
            let mut child = spawn_prepared(args, |command| {
                command.env(VARIABLE, point);
                prepare(command);
            })?;
            let stderr: ChildStderr = child
                .stderr
                .take()
                .ok_or("子の標準エラー出力がありません。")?;
            let (sender, lines) = channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    if sender.send(line).is_err() {
                        break;
                    }
                }
            });
            let halted = Self { child, lines };
            let line = halted
                .next_line()
                .map_err(|error| format!("{point} で停止しませんでした: {error}"))?;
            assert_eq!(
                line,
                format!("failpoint:{point}"),
                "停止の通知の確認に失敗。"
            );
            Ok(halted)
        }

        /// 子の標準エラー出力の次の 1 行を待つ。
        fn next_line(&self) -> Result<String, Box<dyn Error>> {
            Ok(self.lines.recv_timeout(TIMEOUT)?)
        }

        /// `SIGKILL` で終了させ、シグナルによる終了であることを確かめる。
        fn kill(mut self) -> TestResult {
            // `Child::kill` は `SIGKILL` を送るため、子の `Drop` は実行されない。
            self.child.kill()?;
            let status = self.child.wait()?;
            assert_eq!(
                status.signal(),
                Some(libc::SIGKILL),
                "`SIGKILL` による終了の確認に失敗: {status:?}"
            );
            Ok(())
        }
    }

    /// 一時ディレクトリに残る一時ファイルを返す。
    fn temp_files(target: &EntryVault) -> Result<Vec<PathBuf>, Box<dyn Error>> {
        Ok(target
            .directory
            .names()?
            .into_iter()
            .filter(|name| name.starts_with(".vault.fvl.") && name.ends_with(".tmp"))
            .map(|name| target.directory.path(&name))
            .collect())
    }

    fn titles(target: &EntryVault) -> Result<Vec<Option<String>>, Box<dyn Error>> {
        Ok(target
            .credentials()?
            .into_iter()
            .map(|credential| credential.title)
            .collect())
    }

    /// 停止中はロックを保持し、強制終了の後も Vault が直前の世代のまま解錠できて、次の保存が通ること。
    fn assert_survives_kill(point: &str) -> TestResult {
        let target = target()?;
        let before_bytes = target.contents()?;
        let before: Vault = read_vault(&target.vault)?;
        let args = delete_args(&target)?;

        let halted = Halted::spawn(&args, point, |_| {})?;
        assert!(
            target.contents()? == before_bytes,
            "{point}: 停止中の Vault の維持に失敗。"
        );
        assert_eq!(
            VaultLock::try_acquire(VaultPath::resolve(&target.vault)?).err(),
            Some(StorageError::Locked),
            "{point}: 停止中のロックの保持の確認に失敗。"
        );
        let other = run_without_terminal(&args, b"")?;
        assert_eq!(
            other.status.code(),
            Some(1),
            "{point}: 停止中の他の処理の拒否に失敗。"
        );
        assert!(String::from_utf8_lossy(&other.stderr).contains("他の処理が Vault を使用中です。"));
        let temporary = temp_files(&target)?;
        // 一時ファイルの内容は、停止中に読んでおく。
        let temporary_length = match temporary.as_slice() {
            [] => {
                assert_eq!(point, "after-lock", "{point}: 一時ファイルがありません。");
                None
            }
            [path] => {
                assert_ne!(
                    point, "after-lock",
                    "ロックの直後に一時ファイルがあります。"
                );
                assert_eq!(mode_of(path)?, 0o600, "{point}: 一時ファイルの権限が不正。");
                if point == "before-rename" {
                    assert_eq!(
                        read_vault(path)?.header.epoch_id,
                        before.header.epoch_id + 1,
                        "改名の直前の一時ファイルが、次の世代の完全な Vault ではありません。"
                    );
                } else {
                    assert!(
                        read_vault(path).is_err(),
                        "書き込み途中の一時ファイルが、完全な Vault として解析できます。"
                    );
                }
                Some(fs::metadata(path)?.len())
            }
            many => return Err(format!("{point}: 一時ファイルが複数あります: {many:?}").into()),
        };
        halted.kill()?;

        assert!(
            target.contents()? == before_bytes,
            "{point}: 強制終了の後の Vault の維持に失敗。"
        );
        assert_eq!(target.epoch()?, before.header.epoch_id);
        assert_eq!(
            titles(&target)?,
            [Some("drop".to_owned()), Some("keep".to_owned())],
            "{point}: 強制終了の後の解錠と復号に失敗。"
        );
        assert_eq!(temp_files(&target)?, temporary);

        // ロックは解放され、残った一時ファイルは次の保存を妨げない。
        let output = run_without_terminal(&args, b"")?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{point}: 強制終了の後の保存に失敗: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(target.epoch()?, before.header.epoch_id + 1);
        assert_eq!(titles(&target)?, [Some("keep".to_owned())]);
        target.assert_preserved(&before)?;
        assert_eq!(
            temp_files(&target)?,
            temporary,
            "{point}: 次の保存が、一時ファイルを増減させました。"
        );

        // 同じ操作で保存する内容の長さは一定のため、停止した位置を長さで確かめられる。
        if let Some(length) = temporary_length {
            let complete = u64::try_from(target.contents()?.len())?;
            let expected = if point == "before-rename" {
                complete
            } else {
                complete / 2
            };
            assert_eq!(length, expected, "{point}: 一時ファイルの長さが不正。");
        }
        Ok(())
    }

    #[test]
    fn test_kill_after_lock_keeps_the_vault() -> TestResult {
        assert_survives_kill("after-lock")
    }

    #[test]
    fn test_kill_during_temp_file_write_keeps_the_vault() -> TestResult {
        assert_survives_kill("partial-temp-write")
    }

    #[test]
    fn test_kill_before_rename_keeps_the_vault() -> TestResult {
        assert_survives_kill("before-rename")
    }

    /// 引数の解析を始める時点で、実行ファイルにプロセス硬化が適用されていること。
    #[test]
    fn test_hardening_is_applied_before_arguments_are_parsed() -> TestResult {
        // 硬化前の上限を 0 以外にする。親のハード上限が 0 の場合は、再現できない。
        let mut parent = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `parent` は書き込み可能な有効な構造体であり、呼び出しの間は生存している。
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut parent) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let initial = parent.rlim_max.min(1 << 20);
        if initial == 0 {
            let _ = std::io::Write::write_all(
                &mut std::io::stderr(),
                "親プロセスの RLIMIT_CORE が 0 のため、RLIMIT_CORE の変更は確かめずに続けます。\n"
                    .as_bytes(),
            );
        }
        // 停止位置は引数の解析の入口にある。解析に失敗する引数を使い、サブコマンドの処理に依存せずに確かめる。
        let halted = Halted::spawn(&["--no-such-option"], "before-args", |command| {
            // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
            // `setrlimit` と `umask` は非同期シグナルセーフで、ヒープ確保などは行わない。
            unsafe {
                command.pre_exec(move || {
                    libc::umask(0o022);
                    let limit = libc::rlimit {
                        rlim_cur: initial,
                        rlim_max: initial,
                    };
                    if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        })?;
        let expected = if cfg!(target_os = "linux") {
            "protections:core=0,0 umask=0077 dumpable=0"
        } else {
            "protections:core=0,0 umask=0077"
        };
        assert_eq!(
            halted.next_line()?,
            expected,
            "引数の解析より前の硬化の確認に失敗。"
        );
        halted.kill()
    }
}

/// 失敗点を含まないビルドのテスト。
#[cfg(not(all(feature = "test-hooks", debug_assertions)))]
mod disabled {
    use super::VARIABLE;
    use super::common::TestResult;
    use super::common::entry_vault::{EntryVault, credential, spawn_prepared};

    /// 失敗点の名前の一覧。
    const FAILPOINTS: [&str; 4] = [
        "before-args",
        "after-lock",
        "partial-temp-write",
        "before-rename",
    ];

    #[test]
    fn test_failpoint_variable_is_ignored() -> TestResult {
        for point in FAILPOINTS {
            let target = EntryVault::new(&[credential(1, "drop")])?;
            let args = [
                "delete",
                "--vault",
                target.vault_text()?,
                "drop",
                "--yes",
                "--password-file",
                target.password_file_text()?,
            ];
            let mut child = spawn_prepared(&args, |command| {
                command.env(VARIABLE, point);
            })?;
            // 停止する欠陥がある場合は、入力の終端で終了し、終了コードの確認が失敗する。
            drop(child.stdin.take());
            let output = child.wait_with_output()?;
            assert_eq!(
                output.status.code(),
                Some(0),
                "{point} の指定を無視することの確認に失敗: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(output.stderr.is_empty());
        }
        Ok(())
    }
}
