//! # エントリの削除 (`delete`)
//!
//! `delete` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//!
//! タイトルが一致するエントリを 1 件削除する。削除は元に戻せないため、制御端末で `y` の同意を求める。
//! `--yes` を指定すると同意を求めない。パスワードの入力元を指定した実行は非対話とみなし、
//! `--yes` を必須とする (引数の解析で拒否する)。
//!
//! 解錠と全エントリの検査の後に同意を求め、応答を待つ間は、復号した平文を保持しない。
//! ロックは応答を待つ間も保持する。

use std::io::Write;
use std::path::Path;

use crate::display::escaped;
use crate::entry_ops::find_by_title;
use crate::entry_session::{EntryKey, open_vault, require_vault};
use crate::error::CliError;
use crate::get::lookup_error;
use crate::interaction::{ask_consent, ensure_not_interrupted, warn_if_directory_not_synced};
use crate::secret_input::PasswordSource;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::VaultLock;
use crate::sys::tty::Terminal;
use crate::vault_file::{LoadedVault, SavedVault};

/// `delete` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct DeleteRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// 対象のエントリのタイトル。
    pub entry: &'a str,
    /// `--yes`: 同意を求めずに削除する。
    pub assume_yes: bool,
}

/// Vault を解錠して、指定されたエントリを削除する。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: 結果の書き込み先。
/// - `stderr`: 警告の書き込み先。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - 同意を求める場合に制御端末を開けないと [`CliError::TerminalRequired`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワードと改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - タイトルが一致するエントリが無い場合は [`CliError::EntryNotFound`]、複数ある場合は [`CliError::EntryAmbiguous`]。
/// - 同意しなかった場合は [`CliError::DeletionDeclined`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - その他の読み込み、乱数、暗号処理、ファイル操作の失敗は、対応する [`CliError`]。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。このとき Vault は更新済みである。
///
/// [`CliError::OutputFailed`] 以外の失敗では、Vault を変更しない。
pub fn run(
    request: DeleteRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let vault = require_vault(request.vault)?;
    // 同意を求められない環境では、ファイルに触れる前に中止する。
    if !request.assume_yes {
        Terminal::open().map_err(|_| CliError::TerminalRequired)?;
    }
    // 秘密を保持している間は、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    let (lock, loaded) = open_vault(vault)?;
    let key = EntryKey::unlock_with_password(&loaded, request.password_source, &watcher)?;
    let saved = remove_entry(
        &lock,
        &loaded,
        &key,
        request.entry,
        request.assume_yes,
        &watcher,
    )?;
    drop(key);
    // 保存した後は、中断のシグナルを受けていても、結果を報告する。
    warn_if_directory_not_synced(stderr, saved.directory_sync);
    report(stdout, request.entry).map_err(|_| CliError::OutputFailed)
}

/// 同意を得て、タイトルが一致するエントリを除いた内容を保存する。
///
/// # Errors
///
/// [`run`] の、検索、同意、保存の失敗。失敗した場合は Vault を変更しない。
pub(crate) fn remove_entry(
    lock: &VaultLock,
    loaded: &LoadedVault,
    key: &EntryKey,
    title: &str,
    assume_yes: bool,
    watcher: &InterruptWatcher,
) -> Result<SavedVault, CliError> {
    // 同意を求める前に、対象の有無と改ざんを確かめる。復号した平文は、この文の終わりで消去する。
    find_by_title(&key.credentials(loaded)?, title).map_err(lookup_error)?;
    if !assume_yes {
        // 対話モードでは、開始の時点で端末の有無を調べていない。
        Terminal::open().map_err(|_| CliError::TerminalRequired)?;
        let prompt = format!(
            "エントリ「{}」を削除します。元に戻せません。\n続ける場合は y を入力してください (y/N、入力は表示されません): ",
            escaped(title)
        );
        if !ask_consent(&prompt, watcher)? {
            return Err(CliError::DeletionDeclined);
        }
    }
    ensure_not_interrupted(watcher)?;
    let mut credentials = key.credentials(loaded)?;
    let index = find_by_title(&credentials, title).map_err(lookup_error)?;
    credentials.remove(index);
    key.save(lock, loaded, &credentials)
}

/// 削除の結果を書く。
pub(crate) fn report(stdout: &mut impl Write, title: &str) -> std::io::Result<()> {
    writeln!(stdout, "エントリを削除しました: {}", escaped(title))?;
    stdout.flush()
}
