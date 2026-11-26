//! # エントリの追加と更新 (`set`)
//!
//! `set` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//!
//! ## 入力
//!
//! タイトルは引数で指定し、項目の値は制御端末で次の順に尋ねる。入力は表示しない。
//!
//! 1. ユーザー名 (PRECIS `UsernameCaseMapped` で正準化する)
//! 2. パスワード (2 回入力する。PRECIS `OpaqueString` で正準化する)
//! 3. URL
//! 4. TOTP のシード、または `otpauth://` URI
//! 5. メモ (1 行)
//!
//! 空の Enter は、新しいエントリではその項目の省略、既存のエントリでは現在の値の維持になる。
//! 値を消す操作は無い。端末の 1 行は [`crate::secret_input::MAX_PASSWORD_LEN`] バイトまでである。
//!
//! 長いメモや複数行のメモは、`--notes-file` のファイルか `--notes-stdin` の標準入力から読み込む。
//! この場合はメモを尋ねない。内容は [`MAX_NOTES_LEN`] バイトまでの UTF-8 で、末尾の改行を含めてそのまま保存する。
//! ファイルの権限は検査しない。
//!
//! ## 保存
//!
//! 解錠と全エントリの検査の後に値を尋ね、入力を待つ間は、復号した平文を保持しない。
//! ロックは入力の間も保持する。変更する項目が無い場合は保存しない。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fidelogic_core::{
    SecretVec, ct_eq_bytes_bool, opaque_string_secret, username_case_mapped_secret,
};

use crate::display::escaped;
use crate::entry_ops::{
    EntryField, FieldChanges, LookupError, apply_changes, find_by_title, is_valid_title,
    new_credential, new_entry_id,
};
use crate::entry_session::{EntryKey, open_vault, require_vault};
use crate::error::CliError;
use crate::get::lookup_error;
use crate::interaction::{ensure_not_interrupted, warn_if_directory_not_synced};
use crate::secret_input::{PasswordSource, SecretInput, SecretInputError, read_password};
use crate::sys::random::fill_random;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::VaultLock;
use crate::sys::tty::{InputStream, ReadOutcome, Terminal};
use crate::vault_file::{LoadedVault, SavedVault};

/// ファイルまたは標準入力から読み込むメモの上限 (バイト)。
pub const MAX_NOTES_LEN: usize = 65536;

/// パスワードを再入力させるときのプロンプト。
const REPEAT_PASSWORD_PROMPT: &str = "確認のため、もう一度入力してください: ";

/// メモの入力元。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum NotesSource {
    /// 他の項目と同じく、制御端末で尋ねる。
    #[default]
    Prompt,
    /// ファイルから読み込む。
    File(PathBuf),
    /// 標準入力から読み込む。
    StandardInput,
}

/// `set` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct SetRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// 対象のエントリのタイトル。
    pub entry: &'a str,
    /// メモの入力元。
    pub notes: &'a NotesSource,
}

/// エントリの追加または更新の結果。
#[derive(Debug)]
pub(crate) enum SetOutcome {
    /// 新しいエントリを追加して保存した。
    Added(SavedVault),
    /// 既存のエントリを更新して保存した。
    Updated(SavedVault),
    /// 変更する項目が無いため、保存しなかった。
    Unchanged,
}

/// Vault を解錠して、指定されたエントリを追加または更新する。
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
/// - タイトルが空であるか、制御文字を含む場合は [`CliError::InvalidEntryName`]。
/// - 制御端末を開けない場合は [`CliError::TerminalRequired`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワードと改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - タイトルが一致するエントリが複数ある場合は [`CliError::EntryAmbiguous`]。
/// - メモを読み込めない場合は [`CliError::Terminal`]、
///   内容を受け付けられない場合は [`CliError::NotesEmpty`]、[`CliError::NotesTooLong`]、[`CliError::InvalidField`]。
/// - 項目の入力を受け付けられない場合は [`CliError::InvalidField`]、[`CliError::FieldTooLong`]、
///   [`CliError::PasswordMismatch`]、[`CliError::EntryInputAborted`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - その他の読み込み、乱数、暗号処理、ファイル操作の失敗は、対応する [`CliError`]。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。このとき Vault は更新済みである。
///
/// [`CliError::OutputFailed`] 以外の失敗では、Vault を変更しない。
pub fn run(
    request: SetRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let vault = require_vault(request.vault)?;
    if !is_valid_title(request.entry) {
        return Err(CliError::InvalidEntryName);
    }
    // 項目を尋ねられない環境では、ファイルに触れる前に中止する。
    Terminal::open().map_err(|_| CliError::TerminalRequired)?;
    // 秘密を保持している間は、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    let (lock, loaded) = open_vault(vault)?;
    let key = EntryKey::unlock_with_password(&loaded, request.password_source, &watcher)?;
    let outcome = edit_entry(&lock, &loaded, &key, request.entry, request.notes, &watcher)?;
    drop(key);
    // 保存した後は、中断のシグナルを受けていても、結果を報告する。
    report(stdout, stderr, request.entry, &outcome).map_err(|_| CliError::OutputFailed)
}

/// 項目の値を尋ねて、エントリを追加または更新する。
///
/// # Errors
///
/// [`run`] の、タイトル、入力、保存の失敗。失敗した場合は Vault を変更しない。
pub(crate) fn edit_entry(
    lock: &VaultLock,
    loaded: &LoadedVault,
    key: &EntryKey,
    title: &str,
    notes: &NotesSource,
    watcher: &InterruptWatcher,
) -> Result<SetOutcome, CliError> {
    if !is_valid_title(title) {
        return Err(CliError::InvalidEntryName);
    }
    // 対象の有無と改ざんを、値を尋ねる前に確かめる。復号した平文は、この文の終わりで消去する。
    let is_new = match find_by_title(&key.credentials(loaded)?, title) {
        Ok(_) => false,
        Err(LookupError::NotFound) => true,
        Err(error @ LookupError::Ambiguous) => return Err(lookup_error(error)),
    };
    let notes = read_notes(notes, watcher)?;
    announce(title, is_new, watcher)?;
    let changes = collect_changes(is_new, notes, |field, prompt| {
        field_input(
            field,
            read_password(&PasswordSource::Terminal, prompt, watcher),
        )
    })?;
    if !is_new && changes.is_empty() {
        return Ok(SetOutcome::Unchanged);
    }
    ensure_not_interrupted(watcher)?;

    let mut credentials = key.credentials(loaded)?;
    let now = unix_time();
    let index = if is_new {
        let entry_id =
            new_entry_id(&credentials, fill_random).map_err(|_| CliError::EntropySourceFailed)?;
        credentials.push(new_credential(entry_id, title, now));
        credentials.len() - 1
    } else {
        find_by_title(&credentials, title).map_err(lookup_error)?
    };
    let credential = credentials.get_mut(index).ok_or(CliError::InvalidState)?;
    apply_changes(credential, changes, now);
    let saved = key.save(lock, loaded, &credentials)?;
    Ok(if is_new {
        SetOutcome::Added(saved)
    } else {
        SetOutcome::Updated(saved)
    })
}

/// 追加と更新のどちらになるかと、入力が表示されないことを端末に書く。
fn announce(title: &str, is_new: bool, watcher: &InterruptWatcher) -> Result<(), CliError> {
    let action = if is_new { "追加" } else { "更新" };
    let message = format!(
        "エントリ「{}」を{action}します。入力した内容は表示されません。\n",
        escaped(title)
    );
    let terminal = Terminal::open().map_err(|_| CliError::TerminalRequired)?;
    if terminal.write(&message, watcher)? {
        Ok(())
    } else {
        Err(CliError::Interrupted)
    }
}

/// 指定された入力元から、メモを読み込む。端末で尋ねる指定の場合は `None`。
fn read_notes(
    source: &NotesSource,
    watcher: &InterruptWatcher,
) -> Result<Option<SecretVec>, CliError> {
    let mut stream = match source {
        NotesSource::Prompt => return Ok(None),
        NotesSource::File(path) => InputStream::notes_file(path)?,
        NotesSource::StandardInput => InputStream::inherited(0)?,
    };
    // 上限を 1 バイト超えるまで読み、超過を検出する。再確保で複写が残らないように、先に確保する。
    let mut buffer = SecretVec::zeroed(MAX_NOTES_LEN + 1);
    let mut filled = 0usize;
    while let Some(rest) = buffer
        .as_mut_slice()
        .get_mut(filled..)
        .filter(|rest| !rest.is_empty())
    {
        match stream.read(rest, watcher)? {
            ReadOutcome::Data(count) => filled = filled.saturating_add(count),
            ReadOutcome::EndOfInput => break,
            ReadOutcome::Interrupted => return Err(CliError::Interrupted),
        }
    }
    let contents = buffer
        .as_slice()
        .get(..filled)
        .ok_or(CliError::InvalidState)?;
    check_notes(contents)?;
    Ok(Some(SecretVec::from_slice(contents)))
}

/// 現在の Unix 時刻 (秒)。1970 年より前を指す時計では 0 にする。
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// 追加または更新の結果を書く。
pub(crate) fn report(
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    title: &str,
    outcome: &SetOutcome,
) -> std::io::Result<()> {
    let (summary, saved) = match outcome {
        SetOutcome::Added(saved) => ("エントリを追加しました", Some(saved)),
        SetOutcome::Updated(saved) => ("エントリを更新しました", Some(saved)),
        SetOutcome::Unchanged => ("変更はありません", None),
    };
    if let Some(saved) = saved {
        warn_if_directory_not_synced(stderr, saved.directory_sync);
    }
    writeln!(stdout, "{summary}: {}", escaped(title))?;
    stdout.flush()
}

/// 端末から読んだ 1 行を、項目の値にする。
///
/// # Returns
///
/// 空の行は `None`。
///
/// # Errors
///
/// 上限を超える場合は [`CliError::FieldTooLong`]、入力が終わった場合は [`CliError::EntryInputAborted`]、
/// それ以外の失敗は [`CliError::SecretInput`]。
pub(crate) fn field_input(
    field: EntryField,
    input: Result<SecretInput, SecretInputError>,
) -> Result<Option<SecretVec>, CliError> {
    match input {
        // `mlock` したバッファから、エントリが保持する型に移す。入力のバッファは、ここで消去する。
        Ok(input) => Ok(Some(SecretVec::from_slice(input.as_bytes()))),
        Err(SecretInputError::Empty) => Ok(None),
        Err(SecretInputError::TooLong) => Err(CliError::FieldTooLong(field)),
        Err(SecretInputError::EndOfInput) => Err(CliError::EntryInputAborted),
        Err(error) => Err(error.into()),
    }
}

/// メモの内容を検査する。
///
/// # Errors
///
/// 空の場合は [`CliError::NotesEmpty`]、[`MAX_NOTES_LEN`] を超える場合は [`CliError::NotesTooLong`]、
/// UTF-8 でない場合は [`CliError::InvalidField`]。
pub(crate) fn check_notes(contents: &[u8]) -> Result<(), CliError> {
    if contents.is_empty() {
        Err(CliError::NotesEmpty)
    } else if contents.len() > MAX_NOTES_LEN {
        Err(CliError::NotesTooLong)
    } else {
        utf8(EntryField::Notes, contents).map(|_| ())
    }
}

/// 値を UTF-8 の文字列として借用する。複写は作らない。
fn utf8(field: EntryField, value: &[u8]) -> Result<&str, CliError> {
    core::str::from_utf8(value).map_err(|_| CliError::InvalidField(field))
}

/// 項目を順に尋ねて、変更する値を集める。
///
/// # Args
///
/// - `is_new`: 新しいエントリの追加か。プロンプトの案内が変わる。
/// - `notes`: ファイルまたは標準入力から読み込んだメモ。指定した場合は、メモを尋ねない。
/// - `ask`: 項目とプロンプトを受け取り、1 行を読み込む処理。空の行は `None` を返す。
///
/// # Errors
///
/// - 値を受け付けられない場合は [`CliError::InvalidField`]。
/// - 2 回入力したパスワードが異なる場合は [`CliError::PasswordMismatch`]。
/// - `ask` の失敗は、そのまま返す。
pub(crate) fn collect_changes(
    is_new: bool,
    notes: Option<SecretVec>,
    mut ask: impl FnMut(EntryField, &str) -> Result<Option<SecretVec>, CliError>,
) -> Result<FieldChanges, CliError> {
    let hint = if is_new {
        "(空の Enter で省略)"
    } else {
        "(空の Enter で変更しない)"
    };
    let mut ask_field =
        |field: EntryField| ask(field, &format!("{} {hint}: ", field.prompt_label()));
    let mut changes = FieldChanges::default();

    if let Some(input) = ask_field(EntryField::Username)? {
        let field = EntryField::Username;
        let canonical = username_case_mapped_secret(utf8(field, input.as_slice())?)
            .map_err(|_| CliError::InvalidField(field))?;
        changes.username = Some(canonical);
    }
    if let Some(input) = ask_field(EntryField::Password)? {
        let field = EntryField::Password;
        let canonical = opaque_string_secret(utf8(field, input.as_slice())?)
            .map_err(|_| CliError::InvalidField(field))?;
        drop(input);
        let repeated = ask(field, REPEAT_PASSWORD_PROMPT)?.ok_or(CliError::PasswordMismatch)?;
        let repeated = opaque_string_secret(utf8(field, repeated.as_slice())?)
            .map_err(|_| CliError::PasswordMismatch)?;
        if !ct_eq_bytes_bool(canonical.as_slice(), repeated.as_slice()) {
            return Err(CliError::PasswordMismatch);
        }
        changes.password = Some(canonical);
    }
    // パスワードの再入力では `ask` を直接呼ぶ。
    // 最初の `ask_field` をその後も使うと `ask` の可変借用が重なり、コンパイルできないため、定義し直す。
    let mut ask_field =
        |field: EntryField| ask(field, &format!("{} {hint}: ", field.prompt_label()));
    if let Some(input) = ask_field(EntryField::Url)? {
        changes.url = Some(utf8(EntryField::Url, input.as_slice())?.to_owned());
    }
    if let Some(input) = ask_field(EntryField::Totp)? {
        utf8(EntryField::Totp, input.as_slice())?;
        changes.totp = Some(input);
    }
    changes.notes = match notes {
        Some(notes) => Some(notes),
        None => match ask_field(EntryField::Notes)? {
            Some(input) => {
                utf8(EntryField::Notes, input.as_slice())?;
                Some(input)
            }
            None => None,
        },
    };
    Ok(changes)
}

#[cfg(test)]
mod tests {
    use fidelogic_core::SecretVec;

    use super::{MAX_NOTES_LEN, check_notes, collect_changes, field_input};
    use crate::entry_ops::{EntryField, FieldChanges};
    use crate::error::CliError;
    use crate::secret_input::SecretInputError;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn test_field_input_errors() {
        let cases = [
            (SecretInputError::Empty, Ok(false)),
            (
                SecretInputError::TooLong,
                Err(CliError::FieldTooLong(EntryField::Url)),
            ),
            (
                SecretInputError::EndOfInput,
                Err(CliError::EntryInputAborted),
            ),
            (
                SecretInputError::Interrupted,
                Err(CliError::SecretInput(SecretInputError::Interrupted)),
            ),
            (
                SecretInputError::MemoryLockFailed,
                Err(CliError::SecretInput(SecretInputError::MemoryLockFailed)),
            ),
        ];
        for (error, expected) in cases {
            let result = field_input(EntryField::Url, Err(error)).map(|value| value.is_some());
            assert_eq!(result, expected, "{error:?} の変換に失敗。");
        }
    }

    #[test]
    fn test_notes_boundaries() {
        let cases = [
            ("空", Vec::new(), Err(CliError::NotesEmpty)),
            ("1 バイト", b"x".to_vec(), Ok(())),
            ("改行のみ", b"\n".to_vec(), Ok(())),
            ("上限", vec![b'a'; MAX_NOTES_LEN], Ok(())),
            (
                "上限 + 1",
                vec![b'a'; MAX_NOTES_LEN + 1],
                Err(CliError::NotesTooLong),
            ),
            (
                "UTF-8 でない",
                vec![b'a', 0xff],
                Err(CliError::InvalidField(EntryField::Notes)),
            ),
        ];
        for (name, contents, expected) in cases {
            assert_eq!(check_notes(&contents), expected, "{name} の検査に失敗。");
        }
    }

    /// 項目と、その問いへの応答の組。
    type Answers<'a> = &'a [(EntryField, &'a [u8])];

    /// 値を集めた結果と、表示したプロンプト。
    type Collected = (Result<FieldChanges, CliError>, Vec<String>);

    /// 項目ごとの応答を順に返し、尋ねた項目とプロンプトを記録して、値を集める。
    fn collect(
        is_new: bool,
        notes: Option<&str>,
        answers: Answers<'_>,
    ) -> Result<Collected, Box<dyn std::error::Error>> {
        let mut answers = answers.iter();
        let mut prompts = Vec::new();
        let notes = notes.map(|text| SecretVec::from_slice(text.as_bytes()));
        let result = collect_changes(is_new, notes, |field, prompt| {
            prompts.push(prompt.to_owned());
            let &(expected, answer) = answers.next().ok_or(CliError::InvalidState)?;
            assert_eq!(field, expected, "尋ねる順の確認に失敗。");
            Ok((!answer.is_empty()).then(|| SecretVec::from_slice(answer)))
        });
        if result.is_ok() {
            assert!(answers.next().is_none(), "応答を残さないことの確認に失敗。");
        }
        Ok((result, prompts))
    }

    use EntryField::{Notes, Password, Totp, Url, Username};

    fn values(changes: &FieldChanges) -> [Option<Vec<u8>>; 5] {
        let secret = |value: &Option<SecretVec>| value.as_ref().map(|v| v.as_slice().to_vec());
        [
            secret(&changes.username),
            secret(&changes.password),
            changes.url.as_ref().map(|url| url.as_bytes().to_vec()),
            secret(&changes.totp),
            secret(&changes.notes),
        ]
    }

    #[test]
    fn test_every_field_is_asked_in_order_and_canonicalized() -> TestResult {
        let (result, prompts) = collect(
            true,
            None,
            &[
                (Username, "Alice".as_bytes()),
                (Password, "pass\u{3000}word".as_bytes()),
                (Password, "pass word".as_bytes()),
                (Url, b"https://example.com"),
                (Totp, b"SEED"),
                (Notes, b"memo"),
            ],
        )?;
        let changes = result.map_err(|error| error.to_string())?;
        assert_eq!(
            values(&changes),
            [
                &b"alice"[..],
                b"pass word",
                b"https://example.com",
                b"SEED",
                b"memo"
            ]
            .map(|value| Some(value.to_vec()))
        );
        assert_eq!(
            prompts,
            [
                "ユーザー名 (空の Enter で省略): ",
                "パスワード (空の Enter で省略): ",
                "確認のため、もう一度入力してください: ",
                "URL (空の Enter で省略): ",
                "TOTP のシードまたは otpauth URI (空の Enter で省略): ",
                "メモ (1 行) (空の Enter で省略): ",
            ],
            "新規の案内の確認に失敗。"
        );
        Ok(())
    }

    #[test]
    fn test_empty_answers_change_nothing_and_skip_confirmation() -> TestResult {
        let (result, prompts) = collect(
            false,
            None,
            &[
                (Username, b""),
                (Password, b""),
                (Url, b""),
                (Totp, b""),
                (Notes, b""),
            ],
        )?;
        assert!(result.map_err(|error| error.to_string())?.is_empty());
        assert!(
            prompts.iter().all(|prompt| prompt.contains("変更しない")),
            "更新の案内の確認に失敗: {prompts:?}"
        );
        Ok(())
    }

    #[test]
    fn test_notes_from_a_source_are_not_asked() -> TestResult {
        let (result, _) = collect(
            false,
            Some("line 1\nline 2\n"),
            &[(Username, b""), (Password, b""), (Url, b""), (Totp, b"")],
        )?;
        assert_eq!(
            values(&result.map_err(|error| error.to_string())?)[4],
            Some(b"line 1\nline 2\n".to_vec())
        );
        Ok(())
    }

    #[test]
    fn test_password_confirmation_must_match() -> TestResult {
        for repeated in [&b"other"[..], b"", b"Secret"] {
            let (result, _) = collect(
                true,
                None,
                &[(Username, b""), (Password, b"secret"), (Password, repeated)],
            )?;
            assert_eq!(
                result.map(|changes| changes.is_empty()),
                Err(CliError::PasswordMismatch),
                "{repeated:?} の不一致の確認に失敗。"
            );
        }
        Ok(())
    }

    #[test]
    fn test_invalid_values_name_the_field() -> TestResult {
        let invalid: &[(Answers<'_>, EntryField)] = &[
            (&[(Username, b"a\x07")], Username),
            (&[(Username, b"\xff")], Username),
            (&[(Username, b""), (Password, b"a\x07")], Password),
            (&[(Username, b""), (Password, b"\xff")], Password),
            (&[(Username, b""), (Password, b""), (Url, b"\xff")], Url),
            (
                &[
                    (Username, b""),
                    (Password, b""),
                    (Url, b""),
                    (Totp, b"\xff"),
                ],
                Totp,
            ),
            (
                &[
                    (Username, b""),
                    (Password, b""),
                    (Url, b""),
                    (Totp, b""),
                    (Notes, b"\xff"),
                ],
                Notes,
            ),
        ];
        for &(answers, field) in invalid {
            let (result, _) = collect(true, None, answers)?;
            assert_eq!(
                result.map(|changes| changes.is_empty()),
                Err(CliError::InvalidField(field)),
                "{field:?} の拒否に失敗。"
            );
        }
        Ok(())
    }
}
