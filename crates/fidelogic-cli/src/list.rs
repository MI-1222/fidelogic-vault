//! # エントリの一覧 (`list`)
//!
//! `list` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//!
//! 解錠して全エントリを復号し、タイトル、ユーザー名、URL をタブで区切って 1 件 1 行で書く。
//! タイトルの順に並べる。パスワード、TOTP、メモは書かない。エントリが無ければ何も書かない。
//! タブや改行などの、表示を乱しうる文字はエスケープする。
//! 鍵は、一覧を書き始める前に消去する。

use std::io::Write;
use std::path::Path;

use crate::display::write_list;
use crate::entry_session::{read_credentials, require_vault};
use crate::error::CliError;
use crate::interaction::{ensure_not_interrupted, write_output};
use crate::secret_input::PasswordSource;
use crate::sys::signal::InterruptWatcher;

/// `list` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct ListRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
}

/// Vault を解錠して、エントリの一覧を書く。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: 一覧の書き込み先。バッファを持たない出力先を渡す。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワードと改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - 一覧を書き込めない場合は [`CliError::OutputFailed`]。
/// - その他の読み込みとロックの失敗は、対応する [`CliError`]。
///
/// いずれの場合も、Vault は変更しない。
pub fn run(request: ListRequest<'_>, stdout: &mut impl Write) -> Result<(), CliError> {
    let vault = require_vault(request.vault)?;
    // 復号した内容を破棄し終えるまで、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    let credentials = read_credentials(vault, request.password_source, &watcher)?;
    ensure_not_interrupted(&watcher)?;
    write_output(stdout, &|| watcher.is_interrupted(), |out| {
        write_list(out, &credentials)
    })
}
