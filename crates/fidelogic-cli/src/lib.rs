//! # fidelogic-cli
//!
//! Fidelogic Vault のローカル運用および暗号鍵ライフサイクル管理を行うネイティブ CLI ツール。
//!
//! ## Overview
//!
//! ファイルシステム上に永続化された暗号化ストレージ (Vault) の作成、スロット構成の更新 (Argon2id パスワード、
//! リカバリーコード)、機密エントリの格納と取り出しを、コマンドラインから実行する。
//! WebAuthn PRF のスロットは保持と破棄だけを行い、登録と解錠はできない。
//!
//! | サブコマンド | 内容 | モジュール |
//! | :-- | :-- | :-- |
//! | `init` | Vault を作成してリカバリーキットを表示する | [`init`] |
//! | `unlock` | 解錠して、対話モードでエントリを操作する | [`unlock`] |
//! | `list` | エントリの一覧を表示する | [`list`] |
//! | `get` | エントリの表示、項目の出力、クリップボードへのコピー | [`get`] |
//! | `set` | エントリの追加と更新 | [`set`] |
//! | `delete` | エントリの削除 | [`delete`] |
//! | `export` | 全エントリを平文の JSON で書き出す | [`export`] |
//! | `recover` | リカバリーコードで解錠し、マスターパスワードを再設定する | [`recover`] |
//! | `rotate-key` | スロットの鍵、または DEK を更新する | [`rotate_key`] |
//! | `__clipboard-worker` | クリップボードへのコピーが内部で起動する隠しサブコマンド | [`sys::clipboard`] |
//!
//! 実行ファイル (`main.rs`) は [`run`] を呼ぶだけの薄い入口であり、処理の本体はこのライブラリに置く。
//! これにより、統合テストから各処理を直接呼び出せる。
//!
//! ## 処理の流れ
//!
//! 1. [`sys::process::harden_process`] でプロセスを硬化する。失敗したら、引数を読まずに終了する。
//! 2. [`args::parse`] で引数を解析する。`--help` / `--version` は表示して終了する。
//! 3. サブコマンドを実行する。
//! 4. 失敗した場合は、標準エラー出力に `fidelogic-cli: <メッセージ>` を 1 行で書き、[`exit::ExitCategory`] の終了コードで終了する。
//!
//! ## エラー出力と終了コード
//!
//! | 終了コード | 意味 |
//! | --: | :-- |
//! | 0 | 成功 (`--help`, `--version` を含む) |
//! | 1 | 一般の失敗 |
//! | 2 | 引数の誤り |
//! | 3 | 認証の失敗 |
//! | 130 | シグナルによる中断 |
//!
//! 誤ったパスワード、未設定のスロット、改ざんされたファイルは、すべて終了コード 3 と同じメッセージになる。
//! 変換は [`error::CliError::from_unlock_error`] が行う。
//!
//! ## ネイティブ環境におけるセキュリティアーキテクチャ
//!
//! - **プロセス硬化 (実装済み)**: [`run`] は引数の解析より前に [`sys::process::harden_process`] を実行し、
//!   コアダンプの抑止、`umask(0077)`、デバッガーのアタッチ拒否を適用する。
//! - **秘密を引数と環境変数で受け取らない (実装済み)**: パスワードなどを値として受け取る引数を設けない ([`args`])。
//! - **端末と非対話の入力 (実装済み)**: 制御端末ではエコーを止めて読み込み、
//!   中断のシグナルを受けた場合は端末属性を戻して秘密を消去する ([`secret_input::read_password`], [`sys::signal`])。
//!   読み込んだパスワードは、PRECIS の `OpaqueString` プロファイルをコアの実装の範囲で適用してから使う ([`password`])。
//! - **OS 依存処理の境界**: OS の API の呼び出しと、OS を判別する条件付きコンパイルは [`sys`] の配下に閉じ込める。
//!   それ以外のモジュールは OS に依存しない。
//! - **排他制御 (実装済み)**: 名前を変えないサイドカー `<vault>.lock` に排他ロックを掛ける
//!   ([`sys::storage::VaultLock`])。ロックを取得しないプログラムによる読み書きは防げない。
//! - **アトミックな作成と保存 (実装済み)**: 一時ファイルへの書き込み、永続化、改名、親ディレクトリの同期の順で書く。
//!   `init` は、既存のファイルを置き換えない改名で作成する ([`sys::storage::create_vault_file_atomically`])。
//! - **世代の二重検証 (実装済み)**: Vault を保存するサブコマンドは、保存の直前にディスク上の Vault を読み直し、
//!   読み込み時と異なれば中止する ([`vault_file::save_vault`])。対話モードは、世代が戻った場合に終了する。
//! - **鍵の更新 (実装済み)**: 利用者がリカバリーコードを控えたことを確認するまで Vault を書き換えず、
//!   スロットの更新と全エントリの再暗号化を 1 回の保存で置き換える ([`rekey`], [`recover`], [`rotate_key`])。
//! - **クリップボード (実装済み)**: 秘密のコピーは、自分自身を起動したワーカープロセスが行い、
//!   30 秒後に、内容が変わっていなければ消去する。秘密のフィールドは履歴からの除外を指定する ([`sys::clipboard`])。
//!   除外の指定を無視するクリップボードマネージャーには防御できない。
//! - **平文の出力 (実装済み)**: 復号した値は、バッファを持たない出力先に書く ([`sys::tty::standard_output`])。
//!   `export` は警告を表示して同意を求める ([`export`])。出力した後の値は、受け取った側が管理する。
//! - **対話モード (実装済み)**: DEK を保持してコマンドを受け付け、`lock`、入力の終端、中断、
//!   無操作の時間の上限で消去して終了する ([`unlock`])。
//! - **リカバリーコード (実装済み)**: 128 bit の乱数にチェックサムを付けた、30 文字のコードを作る
//!   ([`recovery_code::RecoveryCode`])。乱数は OS から取得する ([`sys::random::fill_random`])。
//!   発行するサブコマンドは端末の代替画面に表示し、末尾の再入力を確認してから Vault を書き込む ([`init`], [`recovery_kit`])。
//!   `recover` は、入力されたコードのチェックサムを鍵導出より前に検証する。
//! - **メモリ保護 (一部実装)**: パスワードの入力バッファとリカバリーコードは `fidelogic_core` の `LockedBuffer` に置き、
//!   `mlock` (スワップアウト抑止) に失敗した場合は処理を中止する。
//!   DEK、正準化したパスワード、復号したエントリ、鍵導出の作業領域は `mlock` せず、破棄時に消去する。
//! - **プロファイル連携**: [`fidelogic_core`] を `profile-vault` でリンクしている。
//!   暗号処理とゼロ消去はコアが担う。
//!
//! ## 対応環境
//!
//! POSIX 環境 (macOS / Linux) のみを対象とする。それ以外の環境では [`sys`] がコンパイルを拒否する。

#![deny(unsafe_code)]

pub mod args;
pub mod delete;
mod display;
pub mod entry_ops;
mod entry_session;
pub mod error;
pub mod exit;
pub mod export;
mod export_json;
mod failpoint;
pub mod get;
pub mod init;
mod interaction;
mod key_update;
pub mod list;
pub mod password;
pub mod recover;
pub mod recovery_code;
pub mod recovery_kit;
pub mod rekey;
mod repl_command;
pub mod rotate_key;
pub mod secret_input;
pub mod set;
pub mod sys;
pub mod unlock;
pub mod vault_file;

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;
use std::time::Duration;

use crate::args::{CommandLine, ParseExit, Subcommand};
use crate::delete::DeleteRequest;
use crate::error::CliError;
use crate::exit::ExitCategory;
use crate::export::ExportRequest;
use crate::get::GetRequest;
use crate::init::InitRequest;
use crate::list::ListRequest;
use crate::recover::RecoverRequest;
use crate::rotate_key::RotateKeyRequest;
use crate::set::SetRequest;
use crate::unlock::UnlockRequest;

/// 標準エラー出力のメッセージの先頭に付けるプログラム名。
pub const PROGRAM_NAME: &str = "fidelogic-cli";

/// CLI アプリケーションの実処理。
///
/// 最初にプロセス硬化を適用し、失敗した場合は引数を読まずに失敗終了する。
/// 硬化に成功した後に、プロセスの引数で [`run_with_args`] を実行する。
///
/// # Returns
///
/// [`ExitCategory`] に対応する終了コード。
pub fn run() -> ExitCode {
    if let Err(error) = sys::process::harden_process() {
        return report_error(&mut std::io::stderr().lock(), CliError::from(error)).into();
    }

    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let mut stderr = std::io::stderr().lock();
    // 標準ライブラリの標準出力のバッファは消去されないため、秘密の項目を書けるように、バッファを持たない出力先を使う。
    let Ok(mut stdout) = sys::tty::standard_output() else {
        return report_error(&mut stderr, CliError::OutputFailed).into();
    };
    run_with_args(&args, &mut stdout, &mut stderr).into()
}

/// 引数の列を解析し、サブコマンドを実行する。
///
/// プロセス硬化は行わない。硬化は呼び出し元 ([`run`]) の責務である。
///
/// # Args
///
/// - `args`: プログラム名を除いた引数の列。
/// - `stdout`: ヘルプ、バージョン、サブコマンドの出力の書き込み先。
/// - `stderr`: エラーメッセージの書き込み先。
///
/// # Returns
///
/// 終了コードの分類。`--help` / `--version` は [`ExitCategory::Success`]、
/// 引数の誤りは [`ExitCategory::Usage`]、サブコマンドの失敗は [`CliError::exit_category`] の値。
pub fn run_with_args(
    args: &[OsString],
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> ExitCategory {
    match args::parse(args) {
        Ok(command_line) => match execute(&command_line, stdout, stderr) {
            Ok(()) => ExitCategory::Success,
            Err(error) => report_error(stderr, error),
        },
        Err(ParseExit::Help(text)) => match write_block(stdout, &text) {
            Ok(()) => ExitCategory::Success,
            Err(_) => report_error(stderr, CliError::OutputFailed),
        },
        Err(ParseExit::Invalid(message)) => {
            // 標準エラー出力への書き込み失敗は報告先が無いため、結果を無視する。
            let _ = write_error_line(stderr, &message);
            ExitCategory::Usage
        }
    }
}

/// サブコマンドを実行する。
///
/// # Errors
///
/// サブコマンドの失敗を [`CliError`] で返す。
fn execute(
    command_line: &CommandLine,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let vault = command_line.vault.as_deref();
    let password_source = &command_line.password_source;
    match &command_line.subcommand {
        Subcommand::Init { kit_html } => init::run(
            InitRequest {
                vault,
                password_source,
                kit_html: kit_html.as_deref(),
            },
            stdout,
            stderr,
        ),
        Subcommand::Unlock {
            idle_timeout_seconds,
        } => unlock::run(
            UnlockRequest {
                vault,
                password_source,
                idle_timeout: Duration::from_secs(*idle_timeout_seconds),
            },
            stdout,
            stderr,
        ),
        Subcommand::List => list::run(
            ListRequest {
                vault,
                password_source,
            },
            stdout,
        ),
        Subcommand::Get { entry, action } => get::run(
            GetRequest {
                vault,
                password_source,
                entry,
                action: *action,
            },
            stdout,
        ),
        Subcommand::Set { entry, notes } => set::run(
            SetRequest {
                vault,
                password_source,
                entry,
                notes,
            },
            stdout,
            stderr,
        ),
        Subcommand::Delete { entry, assume_yes } => delete::run(
            DeleteRequest {
                vault,
                password_source,
                entry,
                assume_yes: *assume_yes,
            },
            stdout,
            stderr,
        ),
        Subcommand::Export { target, confirmed } => export::run(
            ExportRequest {
                vault,
                password_source,
                target,
                confirmed: *confirmed,
            },
            stdout,
            stderr,
        ),
        Subcommand::Recover { recovery_code } => recover::run(
            RecoverRequest {
                vault,
                password_source,
                recovery_code: recovery_code.as_deref(),
            },
            stdout,
            stderr,
        ),
        Subcommand::RotateKey { mode } => rotate_key::run(
            RotateKeyRequest {
                vault,
                password_source,
                mode,
            },
            stdout,
            stderr,
        ),
        // 応答は、起動した親とつながる標準出力に書く。
        Subcommand::ClipboardWorker { policy } => {
            sys::clipboard::run_worker(*policy, stdout).map_err(CliError::from)
        }
    }
}

/// エラーを標準エラー出力に書き、終了コードの分類を返す。
fn report_error(stderr: &mut impl Write, error: CliError) -> ExitCategory {
    // 標準エラー出力への書き込み失敗は報告先が無いため、結果を無視する。
    let _ = write_error_line(stderr, &error.to_string());
    error.exit_category()
}

/// `fidelogic-cli: <メッセージ>` の形で 1 行を書く。
///
/// メッセージが複数行の場合は、各行の前後の空白を除き、空行を捨てて空白 1 つでつなぐ。
/// `bpaf` が組み立てるメッセージの形に依存せず、出力を 1 行に保つためである。
fn write_error_line(stderr: &mut impl Write, message: &str) -> std::io::Result<()> {
    write!(stderr, "{PROGRAM_NAME}:")?;
    for line in message
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        write!(stderr, " {line}")?;
    }
    writeln!(stderr)?;
    stderr.flush()
}

/// 複数行の文章を、末尾の改行を 1 つにそろえて書く。
fn write_block(stdout: &mut impl Write, text: &str) -> std::io::Result<()> {
    writeln!(stdout, "{}", text.trim_end())?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::io::{self, Write};

    use super::{PROGRAM_NAME, run_with_args, write_error_line};
    use crate::exit::ExitCategory;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// 書き込みが常に失敗する出力先 (閉じたパイプの代わり)。
    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }

    fn run_strs(
        args: &[&str],
    ) -> Result<(ExitCategory, String, String), Box<dyn std::error::Error>> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let category = run_with_args(&args, &mut stdout, &mut stderr);
        Ok((
            category,
            String::from_utf8(stdout)?,
            String::from_utf8(stderr)?,
        ))
    }

    #[test]
    fn test_help_goes_to_stdout_with_success() -> TestResult {
        let (category, stdout, stderr) = run_strs(&["--help"])?;
        assert_eq!(category, ExitCategory::Success);
        assert!(stdout.contains("rotate-key"));
        assert!(stdout.ends_with('\n') && !stdout.ends_with("\n\n"));
        assert!(stderr.is_empty());
        Ok(())
    }

    #[test]
    fn test_invalid_arguments_go_to_stderr_with_usage() -> TestResult {
        let (category, stdout, stderr) = run_strs(&["open"])?;
        assert_eq!(category, ExitCategory::Usage);
        assert!(stdout.is_empty());
        assert!(stderr.starts_with(&format!("{PROGRAM_NAME}: ")));
        assert_eq!(
            stderr.lines().count(),
            1,
            "1 行の出力の確認に失敗: {stderr}"
        );
        Ok(())
    }

    /// `--vault` が必須のサブコマンドは、指定が無ければ、端末やファイルに触れる前に引数の誤りになること。
    #[test]
    fn test_missing_vault_is_a_usage_error() -> TestResult {
        let invocations: [&[&str]; 9] = [
            &["init"],
            &["recover"],
            &["rotate-key"],
            &["unlock"],
            &["list"],
            &["get", "github"],
            &["set", "github"],
            &["delete", "github"],
            &["export", "--stdout"],
        ];
        for args in invocations {
            let (category, stdout, stderr) = run_strs(args)?;
            assert_eq!(
                category,
                ExitCategory::Usage,
                "{args:?} の分類の確認に失敗。"
            );
            assert!(stdout.is_empty());
            assert_eq!(
                stderr,
                format!("{PROGRAM_NAME}: `--vault <PATH>` で Vault のパスを指定してください。\n")
            );
        }
        Ok(())
    }

    #[test]
    fn test_help_write_failure_is_reported_as_failure() -> TestResult {
        let args = [OsString::from("--help")];
        let mut stderr = Vec::new();
        let category = run_with_args(&args, &mut BrokenPipe, &mut stderr);
        assert_eq!(category, ExitCategory::Failure);
        assert_eq!(
            String::from_utf8(stderr)?,
            format!("{PROGRAM_NAME}: 標準出力への書き込みに失敗しました。\n")
        );
        Ok(())
    }

    #[test]
    fn test_multiline_error_message_is_written_as_one_line() -> TestResult {
        let mut stderr = Vec::new();
        write_error_line(&mut stderr, "first line\n\n  second line  \n")?;
        assert_eq!(
            String::from_utf8(stderr)?,
            format!("{PROGRAM_NAME}: first line second line\n")
        );
        Ok(())
    }

    #[test]
    fn test_stderr_write_failure_keeps_exit_category() {
        let args = [OsString::from("open")];
        let category = run_with_args(&args, &mut Vec::new(), &mut BrokenPipe);
        assert_eq!(category, ExitCategory::Usage);
    }
}
