//! # 平文の書き出し (`export`)
//!
//! `export` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//!
//! 全エントリを、暗号化していない JSON で書き出す。形式は次のとおりである。
//!
//! ```text
//! {"format": "fidelogic-vault-export", "version": 1, "entries": [{"id": "...", "title": "...", ...}]}
//! ```
//!
//! 各エントリは `id`、`title`、`username`、`password`、`url`、`totp`、`notes`、`created_at`、`updated_at`、
//! `unknown_fields` (`tag` と `value_hex`) を持ち、値の無いキーは省く。スロットと、未知のレコードは書き出さない。
//!
//! ## 出力先
//!
//! | 指定 | 出力先 |
//! | :-- | :-- |
//! | `--output <PATH>` | 権限 `0600` の新しいファイル。既存のファイルは上書きしない |
//! | `--stdout` | 標準出力。暗号化するコマンドへ直接渡すと、平文をディスクに残さない |
//!
//! ## 警告と同意
//!
//! 常に [`PLAINTEXT_WARNING`] を標準エラー出力に書き、制御端末で `y` の同意を求める。
//! `--confirm-plaintext` を指定すると同意を求めない。パスワードの入力元を指定した実行は非対話とみなし、
//! `--confirm-plaintext` を必須とする (引数の解析で拒否する)。
//!
//! 同意の前に解錠して全エントリを検査し、応答を待つ間は、復号した平文を保持しない。
//! 鍵は、書き出しを始める前に消去する。書き出しに失敗した場合と中断した場合は、作成したファイルを削除する。
//! `--stdout` の失敗では、書き出し済みの内容が出力先に残る。

use std::io::Write;
use std::path::{Path, PathBuf};

use fidelogic_core::Credential;

use crate::entry_session::{EntryKey, open_vault, require_vault};
use crate::error::CliError;
use crate::export_json::write_export;
use crate::interaction::{
    InterruptibleWriter, ask_consent, ensure_not_interrupted, warn_if_directory_not_synced,
    write_output, write_warning,
};
use crate::secret_input::PasswordSource;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{DirectorySync, StorageError, write_new_private_file};
use crate::sys::tty::Terminal;

/// 平文の書き出しの警告。
pub const PLAINTEXT_WARNING: &str = "警告: 書き出す内容は暗号化していない平文で、すべてのパスワードを含みます。不要になったら削除してください。";

/// 平文の書き出しの同意を求めるプロンプト。
const CONSENT_PROMPT: &str =
    "平文を書き出します。続ける場合は y を入力してください (y/N、入力は表示されません): ";

/// 書き出しの出力先。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportTarget {
    /// 新しいファイル。
    File(PathBuf),
    /// 標準出力。
    StandardOutput,
}

/// `export` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct ExportRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// 出力先。
    pub target: &'a ExportTarget,
    /// `--confirm-plaintext`: 同意を求めずに書き出す。
    pub confirmed: bool,
}

/// Vault を解錠して、全エントリを平文の JSON で書き出す。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: 標準出力。出力先が標準出力の場合は JSON を、ファイルの場合は結果を書く。バッファを持たない出力先を渡す。
/// - `stderr`: 警告の書き込み先。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - 同意を求める場合に制御端末を開けないと [`CliError::TerminalRequired`]。
/// - 出力先のファイルがすでに存在する場合は [`CliError::ExportDestinationExists`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワードと改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - 同意しなかった場合は [`CliError::ExportDeclined`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - 標準出力に書き込めない場合は [`CliError::OutputFailed`]。
/// - その他の読み込みとファイル操作の失敗は、対応する [`CliError`]。
///
/// いずれの場合も、Vault は変更しない。
pub fn run(
    request: ExportRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let vault = require_vault(request.vault)?;
    // 同意を求められない環境では、ファイルに触れる前に中止する。
    if !request.confirmed {
        Terminal::open().map_err(|_| CliError::TerminalRequired)?;
    }
    // 復号した内容を破棄し終えるまで、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    if let ExportTarget::File(path) = request.target
        && path.symlink_metadata().is_ok()
    {
        return Err(CliError::ExportDestinationExists);
    }
    let credentials = decrypt_after_consent(vault, &request, &watcher, stderr)?;
    match request.target {
        ExportTarget::File(path) => {
            let sync = write_file(path, &credentials, &watcher)?;
            drop(credentials);
            warn_if_directory_not_synced(stderr, sync);
            report(stdout, path).map_err(|_| CliError::OutputFailed)
        }
        ExportTarget::StandardOutput => write_output(stdout, &|| watcher.is_interrupted(), |out| {
            write_export(out, &credentials)
        }),
    }
}

/// 解錠して全エントリを検査し、警告を書いて同意を得てから、全エントリを復号する。鍵は戻る前に消去する。
fn decrypt_after_consent(
    vault: &Path,
    request: &ExportRequest<'_>,
    watcher: &InterruptWatcher,
    stderr: &mut impl Write,
) -> Result<Vec<Credential>, CliError> {
    let (lock, loaded) = open_vault(vault)?;
    drop(lock);
    let key = EntryKey::unlock_with_password(&loaded, request.password_source, watcher)?;
    // 復号した平文は、この文の終わりで消去する。
    key.credentials(&loaded)?;
    write_warning(stderr, PLAINTEXT_WARNING);
    if !request.confirmed && !ask_consent(CONSENT_PROMPT, watcher)? {
        return Err(CliError::ExportDeclined);
    }
    ensure_not_interrupted(watcher)?;
    key.credentials(&loaded)
}

/// 新しいファイルに書き出す。
fn write_file(
    path: &Path,
    credentials: &[Credential],
    watcher: &InterruptWatcher,
) -> Result<DirectorySync, CliError> {
    write_new_private_file(path, |file| {
        let mut out = InterruptibleWriter::new(file, || watcher.is_interrupted());
        write_export(&mut out, credentials)?;
        // 書き終えた直後の中断も失敗にして、ファイルを残さない。
        if watcher.is_interrupted() {
            return Err(std::io::Error::from(std::io::ErrorKind::Other));
        }
        Ok(())
    })
    .map_err(|error| match error {
        _ if watcher.is_interrupted() => CliError::Interrupted,
        StorageError::AlreadyExists => CliError::ExportDestinationExists,
        other => CliError::from(other),
    })
}

/// ファイルに書き出した結果を書く。
fn report(stdout: &mut impl Write, path: &Path) -> std::io::Result<()> {
    writeln!(stdout, "書き出しました: {}", path.display())?;
    stdout.flush()
}
