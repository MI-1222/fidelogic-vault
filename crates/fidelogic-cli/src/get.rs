//! # エントリの取り出し (`get`)
//!
//! `get` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//!
//! ## 出力
//!
//! | 指定 | 内容 |
//! | :-- | :-- |
//! | (指定なし) | 全項目を表示する。パスワード、TOTP、メモは伏せる |
//! | `--field <項目>` | 値だけを、保存されたバイト列のまま標準出力に書く。改行を加えず、エスケープもしない |
//! | `--clip <項目>` | 値をクリップボードへコピーする。標準出力には値を書かない |
//!
//! `--field` の値を端末に書くと、値に含まれる制御文字はそのまま端末に解釈される。
//!
//! `--clip` は、鍵と他の項目を消去してからコピーし、
//! 30 秒後に消去するワーカーを起動する ([`crate::sys::clipboard`])。パスワード、TOTP、メモは、クリップボードの履歴からの除外を指定する。
//! コピーできる値は [`crate::sys::clipboard::MAX_TEXT_LEN`] バイトまでである。

use std::io::Write;
use std::path::Path;

use fidelogic_core::{Credential, SecretVec};

use crate::display::write_summary;
use crate::entry_ops::{EntryField, GetAction, LookupError, find_by_title};
use crate::entry_session::{read_credentials, require_vault};
use crate::error::CliError;
use crate::interaction::{ensure_not_interrupted, write_output};
use crate::secret_input::PasswordSource;
use crate::sys::clipboard::{ClipboardError, HistoryPolicy, copy_with_auto_clear};
use crate::sys::signal::InterruptWatcher;

/// `get` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct GetRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// 対象のエントリのタイトル。
    pub entry: &'a str,
    /// 出力の方法。
    pub action: GetAction,
}

/// Vault を解錠して、指定されたエントリを出力する。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: 結果の書き込み先。バッファを持たない出力先を渡す。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワードと改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - タイトルが一致するエントリが無い場合は [`CliError::EntryNotFound`]、複数ある場合は [`CliError::EntryAmbiguous`]。
/// - 指定した項目に値が無い場合は [`CliError::FieldNotSet`]。
/// - コピーに失敗した場合は [`CliError::Clipboard`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。
/// - その他の読み込みとロックの失敗は、対応する [`CliError`]。
///
/// いずれの場合も、Vault は変更しない。
pub fn run(request: GetRequest<'_>, stdout: &mut impl Write) -> Result<(), CliError> {
    let vault = require_vault(request.vault)?;
    // 復号した内容を破棄し終えるまで、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    let credentials = read_credentials(vault, request.password_source, &watcher)?;
    // 対象でないエントリは、ここで消去する。
    let credential = select(credentials, request.entry)?;
    ensure_not_interrupted(&watcher)?;
    present(
        credential,
        request.action,
        false,
        stdout,
        &|| watcher.is_interrupted(),
        copy_with_auto_clear,
    )
}

/// タイトルが一致するエントリを取り出す。他のエントリは破棄する。
pub(crate) fn select(
    mut credentials: Vec<Credential>,
    title: &str,
) -> Result<Credential, CliError> {
    let index = find_by_title(&credentials, title).map_err(lookup_error)?;
    Ok(credentials.swap_remove(index))
}

/// 検索の失敗を変換する。
pub(crate) const fn lookup_error(error: LookupError) -> CliError {
    match error {
        LookupError::NotFound => CliError::EntryNotFound,
        LookupError::Ambiguous => CliError::EntryAmbiguous,
    }
}

/// 1 件のエントリを、指定の方法で出力する。
///
/// # Args
///
/// - `newline`: 値だけを書く場合に、末尾に改行を加えるか。対話モードで、次の入力の案内と分けるために使う。
/// - `is_interrupted`: 中断のシグナルを受けたかを返す処理。
/// - `copy`: クリップボードへコピーする処理。呼ぶ前に、エントリは消去する。
///
/// # Errors
///
/// [`run`] の、項目の値、コピー、出力の失敗。
pub(crate) fn present(
    credential: Credential,
    action: GetAction,
    newline: bool,
    stdout: &mut impl Write,
    is_interrupted: &dyn Fn() -> bool,
    copy: impl FnOnce(&str, HistoryPolicy) -> Result<(), ClipboardError>,
) -> Result<(), CliError> {
    match action {
        GetAction::Summary => write_output(stdout, is_interrupted, |out| {
            write_summary(out, &credential)
        }),
        GetAction::Print(field) => {
            let value = field.value(&credential).ok_or(CliError::FieldNotSet)?;
            write_output(stdout, is_interrupted, |out| {
                out.write_all(value)?;
                if newline {
                    out.write_all(b"\n")?;
                }
                Ok(())
            })
        }
        GetAction::Copy(field) => {
            let value = take_value(credential, field)?;
            let text =
                core::str::from_utf8(value.as_slice()).map_err(|_| CliError::MalformedEntry)?;
            copy(text, field.history_policy())?;
            drop(value);
            write_output(stdout, is_interrupted, |out| {
                writeln!(
                    out,
                    "{} をクリップボードにコピーしました。30 秒後に消去します。",
                    field.label()
                )
            })
        }
    }
}

/// 指定の項目の値を取り出し、エントリを破棄する。
fn take_value(credential: Credential, field: EntryField) -> Result<SecretVec, CliError> {
    field
        .value(&credential)
        .map(SecretVec::from_slice)
        .ok_or(CliError::FieldNotSet)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use fidelogic_core::{Credential, SecretVec};

    use super::{present, select};
    use crate::entry_ops::{EntryField, GetAction};
    use crate::error::CliError;
    use crate::sys::clipboard::{ClipboardError, HistoryPolicy};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn entry(title: &str) -> Credential {
        let mut credential = Credential::new([1; 16]);
        credential.title = Some(title.to_owned());
        credential.username = Some(SecretVec::from_slice(b"alice"));
        credential.password = Some(SecretVec::from_slice(b"PASSWORD-VALUE"));
        credential.notes = Some(SecretVec::from_slice(b"line 1\n\x1b[2J\nline 3\n"));
        credential
    }

    /// 出力の結果、書いた内容、コピーした内容。
    type Presented = (Result<(), CliError>, Vec<u8>, Vec<(String, HistoryPolicy)>);

    fn run(action: GetAction, newline: bool, copy_result: Result<(), ClipboardError>) -> Presented {
        let copied = RefCell::new(Vec::new());
        let mut stdout = Vec::new();
        let result = present(
            entry("site"),
            action,
            newline,
            &mut stdout,
            &|| false,
            |text, policy| {
                copied.borrow_mut().push((text.to_owned(), policy));
                copy_result
            },
        );
        (result, stdout, copied.into_inner())
    }

    #[test]
    fn test_summary_does_not_reveal_secrets_or_copy() -> TestResult {
        let (result, stdout, copied) = run(GetAction::Summary, false, Ok(()));
        assert_eq!(result, Ok(()));
        let stdout = String::from_utf8(stdout)?;
        assert!(stdout.contains("ユーザー名: alice\n"));
        assert!(!stdout.contains("PASSWORD-VALUE") && !stdout.contains("line 1"));
        assert!(copied.is_empty());
        Ok(())
    }

    #[test]
    fn test_print_writes_the_stored_bytes_only() {
        for (newline, expected) in [
            (false, &b"line 1\n\x1b[2J\nline 3\n"[..]),
            (true, b"line 1\n\x1b[2J\nline 3\n\n"),
        ] {
            let (result, stdout, copied) =
                run(GetAction::Print(EntryField::Notes), newline, Ok(()));
            assert_eq!(result, Ok(()));
            assert_eq!(stdout, expected, "改行 {newline} の出力の確認に失敗。");
            assert!(copied.is_empty());
        }
    }

    #[test]
    fn test_copy_passes_the_value_and_policy_without_printing_it() -> TestResult {
        for (field, value, policy) in [
            (
                EntryField::Password,
                "PASSWORD-VALUE",
                HistoryPolicy::Exclude,
            ),
            (EntryField::Username, "alice", HistoryPolicy::Allow),
        ] {
            let (result, stdout, copied) = run(GetAction::Copy(field), false, Ok(()));
            assert_eq!(result, Ok(()));
            assert_eq!(copied, [(value.to_owned(), policy)]);
            let stdout = String::from_utf8(stdout)?;
            assert!(
                stdout.starts_with(field.label()) && !stdout.contains(value),
                "{field:?} のコピーの報告の確認に失敗: {stdout}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_unset_field_is_reported_without_copying() {
        for action in [
            GetAction::Print(EntryField::Totp),
            GetAction::Copy(EntryField::Url),
        ] {
            let (result, stdout, copied) = run(action, true, Ok(()));
            assert_eq!(
                result,
                Err(CliError::FieldNotSet),
                "{action:?} の確認に失敗。"
            );
            assert!(stdout.is_empty() && copied.is_empty());
        }
    }

    #[test]
    fn test_copy_failure_is_reported_without_success_message() {
        let (result, stdout, _) = run(
            GetAction::Copy(EntryField::Password),
            false,
            Err(ClipboardError::Unavailable),
        );
        assert_eq!(
            result,
            Err(CliError::Clipboard(ClipboardError::Unavailable))
        );
        assert!(stdout.is_empty());
    }

    #[test]
    fn test_interrupted_output_writes_nothing() {
        let mut stdout = Vec::new();
        let result = present(
            entry("site"),
            GetAction::Print(EntryField::Password),
            false,
            &mut stdout,
            &|| true,
            |_, _| Ok(()),
        );
        assert_eq!(result, Err(CliError::Interrupted));
        assert!(stdout.is_empty());
    }

    #[test]
    fn test_select_requires_a_unique_title() -> TestResult {
        let selected =
            select(vec![entry("a"), entry("b")], "b").map_err(|error| error.to_string())?;
        assert_eq!(selected.title.as_deref(), Some("b"));
        for (titles, expected) in [
            (&["a"][..], CliError::EntryNotFound),
            (&["b", "b"], CliError::EntryAmbiguous),
        ] {
            let credentials = titles.iter().map(|title| entry(title)).collect();
            assert_eq!(
                select(credentials, "b").map(|credential| credential.entry_id),
                Err(expected),
                "{titles:?} の確認に失敗。"
            );
        }
        Ok(())
    }
}
