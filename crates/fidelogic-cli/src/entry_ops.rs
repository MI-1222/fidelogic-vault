//! # エントリの操作 (`entry_ops`)
//!
//! 復号した [`Credential`] の列に対する、検索、項目の指定、追加と更新を置く。
//! 入出力を持たず、OS に依存しない。
//!
//! ## エントリの指定
//!
//! 利用者はエントリをタイトルで指定する。比較はバイト列の完全一致で、大文字と小文字、
//! Unicode の正規化の違いは区別する。同じタイトルのエントリが複数ある場合は、どれも選ばない。
//! CLI は同じタイトルのエントリを作らないが、他の手段で作られた Vault には存在しうる。

use core::fmt;
use core::str::FromStr;

use fidelogic_core::{
    Credential, ENTRY_ID_LEN, EntryId, MANIFEST_ENTRY_ID, SecretVec, SystemError,
};

use crate::sys::clipboard::HistoryPolicy;

/// 新しい識別子を選び直す回数の上限。
///
/// 正常な乱数源では、予約値や使用中の値は実用上現れない。上限に達する乱数源は故障とみなす。
const ENTRY_ID_ATTEMPTS: u32 = 4;

/// エントリの項目のうち、利用者が名前で指定して取り出せるもの。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryField {
    /// ユーザー名。
    Username,
    /// パスワード。
    Password,
    /// URL。
    Url,
    /// TOTP のシード、または `otpauth://` URI。
    Totp,
    /// メモ。
    Notes,
}

impl EntryField {
    /// すべての項目。
    pub const ALL: [Self; 5] = [
        Self::Username,
        Self::Password,
        Self::Url,
        Self::Totp,
        Self::Notes,
    ];

    /// コマンドラインで指定する名前を返す。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Password => "password",
            Self::Url => "url",
            Self::Totp => "totp",
            Self::Notes => "notes",
        }
    }

    /// 画面に表示する名称を返す。
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Username => "ユーザー名",
            Self::Password => "パスワード",
            Self::Url => "URL",
            Self::Totp => "TOTP",
            Self::Notes => "メモ",
        }
    }

    /// `set` が値を尋ねるプロンプトに使う名称を返す。
    ///
    /// TOTP とメモは、入力できる内容を示すため、[`EntryField::label`] と異なる。
    #[must_use]
    pub(crate) const fn prompt_label(self) -> &'static str {
        match self {
            Self::Totp => "TOTP のシードまたは otpauth URI",
            Self::Notes => "メモ (1 行)",
            Self::Username | Self::Password | Self::Url => self.label(),
        }
    }

    /// 画面で値を伏せる項目かを返す。
    #[must_use]
    pub const fn is_secret(self) -> bool {
        match self {
            Self::Password | Self::Totp | Self::Notes => true,
            Self::Username | Self::Url => false,
        }
    }

    /// クリップボードへコピーするときの、履歴からの除外の扱いを返す。秘密の項目は除外する。
    #[must_use]
    pub const fn history_policy(self) -> HistoryPolicy {
        if self.is_secret() {
            HistoryPolicy::Exclude
        } else {
            HistoryPolicy::Allow
        }
    }

    /// `credential` の、この項目の値を返す。未設定の場合は `None`。
    #[must_use]
    pub fn value(self, credential: &Credential) -> Option<&[u8]> {
        match self {
            Self::Username => credential.username.as_ref().map(SecretVec::as_slice),
            Self::Password => credential.password.as_ref().map(SecretVec::as_slice),
            Self::Url => credential.url.as_deref().map(str::as_bytes),
            Self::Totp => credential.totp.as_ref().map(SecretVec::as_slice),
            Self::Notes => credential.notes.as_ref().map(SecretVec::as_slice),
        }
    }
}

/// 項目の名前が、どの項目にも当たらないことを表すエラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownFieldName;

impl fmt::Display for UnknownFieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("項目は username, password, url, totp, notes のいずれかを指定してください。")
    }
}

impl std::error::Error for UnknownFieldName {}

impl FromStr for EntryField {
    type Err = UnknownFieldName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|field| field.name() == name)
            .ok_or(UnknownFieldName)
    }
}

/// `get` が、指定されたエントリをどう出力するか。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetAction {
    /// 秘密の項目を伏せて、全項目を表示する。
    Summary,
    /// 1 つの項目の値だけを標準出力に書く。
    Print(EntryField),
    /// 1 つの項目の値をクリップボードへコピーする。
    Copy(EntryField),
}

/// タイトルによる検索の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// 一致するエントリが無い。
    NotFound,
    /// 一致するエントリが複数ある。
    Ambiguous,
}

/// タイトルが一致する唯一のエントリの位置を返す。
///
/// # Errors
///
/// 一致するエントリが無い場合は [`LookupError::NotFound`]、複数ある場合は [`LookupError::Ambiguous`]。
pub fn find_by_title(credentials: &[Credential], title: &str) -> Result<usize, LookupError> {
    let mut matches = credentials
        .iter()
        .enumerate()
        .filter(|(_, credential)| credential.title.as_deref() == Some(title))
        .map(|(index, _)| index);
    let first = matches.next().ok_or(LookupError::NotFound)?;
    match matches.next() {
        Some(_) => Err(LookupError::Ambiguous),
        None => Ok(first),
    }
}

/// 画面の表示を乱しうる文字かを返す。制御文字と、表示の向きを変える書式文字が当たる。
#[must_use]
pub fn is_unsafe_for_display(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            // 左右の向きの標識と、埋め込み、上書き、分離の書式文字。
            '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}

/// 新しいエントリのタイトルとして使えるかを返す。
///
/// 空のタイトルと、画面の表示を乱しうる文字を含むタイトルは使えない。
#[must_use]
pub fn is_valid_title(title: &str) -> bool {
    !title.is_empty() && !title.chars().any(is_unsafe_for_display)
}

/// 1 回の追加または更新で、利用者が入力した値。`None` の項目は変更しない。
#[derive(Default)]
pub struct FieldChanges {
    /// 正準化済みのユーザー名。
    pub username: Option<SecretVec>,
    /// 正準化済みのパスワード。
    pub password: Option<SecretVec>,
    /// URL。
    pub url: Option<String>,
    /// TOTP のシード、または `otpauth://` URI (UTF-8)。
    pub totp: Option<SecretVec>,
    /// メモ (UTF-8)。
    pub notes: Option<SecretVec>,
}

impl FieldChanges {
    /// 変更する項目が無いかを返す。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.username.is_none()
            && self.password.is_none()
            && self.url.is_none()
            && self.totp.is_none()
            && self.notes.is_none()
    }
}

impl fmt::Debug for FieldChanges {
    /// 値をログへ出さないため、変更の有無だけを表示する。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FieldChanges")
            .field("username", &self.username.is_some())
            .field("password", &self.password.is_some())
            .field("url", &self.url.is_some())
            .field("totp", &self.totp.is_some())
            .field("notes", &self.notes.is_some())
            .finish()
    }
}

/// タイトルと作成日時だけを持つ、新しいエントリを作る。
#[must_use]
pub fn new_credential(entry_id: EntryId, title: &str, now: u64) -> Credential {
    let mut credential = Credential::new(entry_id);
    credential.title = Some(title.to_owned());
    credential.created_at = Some(now);
    credential.updated_at = Some(now);
    credential
}

/// 入力した値をエントリに反映し、更新日時を `now` にする。入力の無い項目と、未知のフィールドは変えない。
pub fn apply_changes(credential: &mut Credential, changes: FieldChanges, now: u64) {
    let FieldChanges {
        username,
        password,
        url,
        totp,
        notes,
    } = changes;
    // 置き換える前の秘密は、`SecretVec` の破棄で消去される。
    credential.username = username.or_else(|| credential.username.take());
    credential.password = password.or_else(|| credential.password.take());
    credential.url = url.or_else(|| credential.url.take());
    credential.totp = totp.or_else(|| credential.totp.take());
    credential.notes = notes.or_else(|| credential.notes.take());
    credential.updated_at = Some(now);
}

/// 予約値 (全ゼロ) でも、`credentials` で使用中でもない識別子を、乱数から選ぶ。
///
/// # Errors
///
/// 乱数源が失敗した場合と、使える値が続けて得られない場合は [`SystemError::EntropySourceFailed`]。
pub fn new_entry_id<R>(
    credentials: &[Credential],
    mut fill_random: R,
) -> Result<EntryId, SystemError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    for _ in 0..ENTRY_ID_ATTEMPTS {
        let mut candidate = [0u8; ENTRY_ID_LEN];
        fill_random(&mut candidate)?;
        let used = credentials
            .iter()
            .any(|credential| credential.entry_id == candidate);
        if candidate != MANIFEST_ENTRY_ID && !used {
            return Ok(candidate);
        }
    }
    Err(SystemError::EntropySourceFailed)
}

#[cfg(test)]
mod tests {
    use fidelogic_core::{Credential, SecretVec, SystemError, UnknownField};

    use super::{
        EntryField, FieldChanges, LookupError, UnknownFieldName, apply_changes, find_by_title,
        is_valid_title, new_credential, new_entry_id,
    };
    use crate::sys::clipboard::HistoryPolicy;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn secret(text: &str) -> SecretVec {
        SecretVec::from_slice(text.as_bytes())
    }

    fn titled(id: u8, title: Option<&str>) -> Credential {
        let mut credential = Credential::new([id; 16]);
        credential.title = title.map(str::to_owned);
        credential
    }

    /// すべての項目を持つエントリ。
    fn full() -> Credential {
        let mut credential = titled(1, Some("full"));
        credential.username = Some(secret("alice"));
        credential.password = Some(secret("pw"));
        credential.url = Some("https://example.com".to_owned());
        credential.totp = Some(secret("seed"));
        credential.notes = Some(secret("memo"));
        credential
    }

    #[test]
    fn test_field_names_round_trip() {
        for field in EntryField::ALL {
            assert_eq!(
                field.name().parse::<EntryField>(),
                Ok(field),
                "{field:?} の名前の解析に失敗。"
            );
        }
    }

    #[test]
    fn test_unknown_field_names_are_rejected() {
        for name in ["", "title", "Password", " password", "pass", "notes ", "id"] {
            assert_eq!(
                name.parse::<EntryField>(),
                Err(UnknownFieldName),
                "{name:?} の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_field_values_and_policies() {
        let credential = full();
        let cases: [(EntryField, &[u8], HistoryPolicy); 5] = [
            (EntryField::Username, b"alice", HistoryPolicy::Allow),
            (EntryField::Password, b"pw", HistoryPolicy::Exclude),
            (
                EntryField::Url,
                b"https://example.com",
                HistoryPolicy::Allow,
            ),
            (EntryField::Totp, b"seed", HistoryPolicy::Exclude),
            (EntryField::Notes, b"memo", HistoryPolicy::Exclude),
        ];
        for (field, value, policy) in cases {
            assert_eq!(
                field.value(&credential),
                Some(value),
                "{field:?} の値の取得に失敗。"
            );
            assert_eq!(
                field.history_policy(),
                policy,
                "{field:?} の除外の扱いの確認に失敗。"
            );
            assert_eq!(
                field.value(&titled(2, None)),
                None,
                "{field:?} の未設定の確認に失敗。"
            );
        }
    }

    #[test]
    fn test_find_by_title_requires_a_unique_exact_match() {
        let credentials = [
            titled(1, Some("github")),
            titled(2, Some("GitHub")),
            titled(3, None),
            titled(4, Some("twin")),
            titled(5, Some("twin")),
            titled(6, Some("caf\u{e9}")),
        ];
        let cases = [
            ("github", Ok(0)),
            ("GitHub", Ok(1)),
            ("caf\u{e9}", Ok(5)),
            ("cafe\u{301}", Err(LookupError::NotFound)),
            ("git", Err(LookupError::NotFound)),
            ("github ", Err(LookupError::NotFound)),
            ("", Err(LookupError::NotFound)),
            ("twin", Err(LookupError::Ambiguous)),
        ];
        for (title, expected) in cases {
            assert_eq!(
                find_by_title(&credentials, title),
                expected,
                "{title:?} の検索に失敗。"
            );
        }
        assert_eq!(find_by_title(&[], "github"), Err(LookupError::NotFound));
    }

    #[test]
    fn test_valid_titles() {
        for title in [
            "github",
            "my bank account",
            " padded ",
            "銀行",
            "🔑",
            "-dash",
        ] {
            assert!(is_valid_title(title), "{title:?} の受理に失敗。");
        }
        for title in [
            "",
            "a\nb",
            "a\tb",
            "a\u{1b}[31m",
            "a\u{7f}",
            "a\u{9b}",
            "a\u{202e}b",
            "a\u{2066}b",
            "a\u{200f}b",
        ] {
            assert!(!is_valid_title(title), "{title:?} の拒否に失敗。");
        }
    }

    #[test]
    fn test_new_credential_has_title_and_creation_time_only() {
        let credential = new_credential([9; 16], "new", 100);
        assert_eq!(credential.entry_id, [9; 16]);
        assert_eq!(credential.title.as_deref(), Some("new"));
        assert_eq!(credential.created_at, Some(100));
        assert_eq!(credential.updated_at, Some(100));
        assert!(
            EntryField::ALL
                .iter()
                .all(|field| field.value(&credential).is_none())
        );
        assert!(credential.unknown_fields.is_empty());
    }

    #[test]
    fn test_apply_changes_keeps_absent_fields_and_unknown_fields() {
        let mut credential = full();
        credential.created_at = Some(10);
        credential.updated_at = Some(20);
        credential.unknown_fields.push(UnknownField {
            tag: 9,
            value: secret("future"),
        });
        let changes = FieldChanges {
            password: Some(secret("next")),
            url: Some("https://example.org".to_owned()),
            ..FieldChanges::default()
        };
        apply_changes(&mut credential, changes, 30);
        let expected: [(EntryField, &[u8]); 5] = [
            (EntryField::Username, b"alice"),
            (EntryField::Password, b"next"),
            (EntryField::Url, b"https://example.org"),
            (EntryField::Totp, b"seed"),
            (EntryField::Notes, b"memo"),
        ];
        for (field, value) in expected {
            assert_eq!(
                field.value(&credential),
                Some(value),
                "{field:?} の反映に失敗。"
            );
        }
        assert_eq!(credential.title.as_deref(), Some("full"));
        assert_eq!(credential.created_at, Some(10));
        assert_eq!(credential.updated_at, Some(30));
        assert_eq!(credential.unknown_fields.len(), 1);
    }

    #[test]
    fn test_apply_changes_sets_every_field() {
        let mut credential = new_credential([9; 16], "new", 1);
        let changes = FieldChanges {
            username: Some(secret("u")),
            password: Some(secret("p")),
            url: Some("l".to_owned()),
            totp: Some(secret("t")),
            notes: Some(secret("n")),
        };
        apply_changes(&mut credential, changes, 2);
        let values: Vec<_> = EntryField::ALL
            .iter()
            .map(|field| field.value(&credential))
            .collect();
        assert_eq!(
            values,
            [b"u", b"p", b"l", b"t", b"n"].map(|value| Some(&value[..]))
        );
    }

    #[test]
    fn test_field_changes_emptiness() {
        assert!(FieldChanges::default().is_empty());
        let cases: [FieldChanges; 5] = [
            FieldChanges {
                username: Some(secret("u")),
                ..FieldChanges::default()
            },
            FieldChanges {
                password: Some(secret("p")),
                ..FieldChanges::default()
            },
            FieldChanges {
                url: Some("l".to_owned()),
                ..FieldChanges::default()
            },
            FieldChanges {
                totp: Some(secret("t")),
                ..FieldChanges::default()
            },
            FieldChanges {
                notes: Some(secret("n")),
                ..FieldChanges::default()
            },
        ];
        for changes in cases {
            assert!(!changes.is_empty(), "{changes:?} の判定に失敗。");
        }
    }

    /// 呼び出しごとに、`values` の値で全体を埋める乱数源。
    fn scripted(values: &[u8]) -> impl FnMut(&mut [u8]) -> Result<(), SystemError> + '_ {
        let mut values = values.iter().copied();
        move |destination: &mut [u8]| {
            let value = values.next().ok_or(SystemError::EntropySourceFailed)?;
            destination.fill(value);
            Ok(())
        }
    }

    #[test]
    fn test_new_entry_id_skips_reserved_and_used_values() -> TestResult {
        let used = [titled(1, None), titled(2, None)];
        // 予約値 (0)、使用中 (1, 2) を飛ばして、3 を選ぶ。
        let id = new_entry_id(&used, scripted(&[0, 1, 2, 3])).map_err(|error| error.to_string())?;
        assert_eq!(id, [3; 16]);
        Ok(())
    }

    #[test]
    fn test_new_entry_id_gives_up_on_a_stuck_source() {
        let used = [titled(1, None)];
        for values in [&[0u8; 16][..], &[1; 16], &[]] {
            assert_eq!(
                new_entry_id(&used, scripted(values)),
                Err(SystemError::EntropySourceFailed),
                "{values:?} の中止に失敗。"
            );
        }
    }
}
