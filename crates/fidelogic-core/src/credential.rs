//! # クレデンシャルのスキーマとエントリ内部の符号化
//!
//! [`crate::entry`] が暗号化するエントリ 1 件の平文 (バイト列) を、クレデンシャルの各フィールドへ対応付ける。エントリのチャンク分割や暗号化はここでは扱わない。
//!
//! ## 本体の構造
//!
//! 整数タグのコンパクトな TLV の列である。
//!
//! ```text
//! (tag u8 | len LEB128 | value) の繰り返し
//! ```
//!
//! `len` は符号なし LEB128 (最大 `u32`) で、最短の表現だけを受け付ける。
//! 同じ内容は常に同じバイト列になる (正準形)。
//!
//! | タグ | フィールド   | 値                                              | 保持する型   |
//! | ---: | :----------- | :---------------------------------------------- | :----------- |
//! |    1 | `title`      | UTF-8                                           | `String`     |
//! |    2 | `username`   | UTF-8 (PRECIS `UsernameCaseMapped` 済み)        | `SecretVec`  |
//! |    3 | `password`   | UTF-8 (PRECIS `OpaqueString` 済み)              | `SecretVec`  |
//! |    4 | `url`        | UTF-8                                           | `String`     |
//! |    5 | `totp`       | UTF-8 (シード、または `otpauth://` URI)         | `SecretVec`  |
//! |    6 | `notes`      | UTF-8                                           | `SecretVec`  |
//! |    7 | `created_at` | 8 バイトのビッグエンディアン (Unix 秒)          | `u64`        |
//! |    8 | `updated_at` | 8 バイトのビッグエンディアン (Unix 秒)          | `u64`        |
//!
//! `entry_id` は内側チャンクヘッダーが持つため、本体には含めない。
//! 本体の復号側は、`entry_id` を [`OpenedEntry`] から受け取る。
//!
//! ## 正準形と前方互換
//!
//! - フィールドはタグの昇順に並べる。既知のタグは各 1 回までである。
//! - タグ 0 は予約で、使えない。
//! - 9 以上のタグは未知のフィールドとして、値をそのまま [`UnknownField`] に保持する。再符号化しても同じバイト列に戻る
//! - 復号側は、昇順でない並び、既知タグの重複、最短でない `len`、型に合わない値を拒否する。
//!
//! ## 秘密情報の扱い
//!
//! 秘密のフィールドは [`SecretVec`] で保持し、符号化の結果も [`SecretVec`] で返す。
//! ユーザー名とパスワードは [`Credential::set_username`] / [`Credential::set_password`] が PRECIS で正準化してから格納する。復号側は UTF-8 の妥当性だけを確かめ、PRECIS は再適用しない。

use alloc::string::String;
use alloc::vec::Vec;

use crate::entry::{EntryId, MANIFEST_ENTRY_ID, OpenedEntry};
use crate::error::{PrecisError, TlvParseError, VaultError};
use crate::precis::{opaque_string_secret, username_case_mapped_secret};
use crate::zeroize::SecretVec;

/// `title` のタグ。
pub const TAG_TITLE: u8 = 1;
/// `username` のタグ。
pub const TAG_USERNAME: u8 = 2;
/// `password` のタグ。
pub const TAG_PASSWORD: u8 = 3;
/// `url` のタグ。
pub const TAG_URL: u8 = 4;
/// `totp` のタグ。
pub const TAG_TOTP: u8 = 5;
/// `notes` のタグ。
pub const TAG_NOTES: u8 = 6;
/// `created_at` のタグ。
pub const TAG_CREATED_AT: u8 = 7;
/// `updated_at` のタグ。
pub const TAG_UPDATED_AT: u8 = 8;

/// 未知のフィールドに使える最小のタグ。これより小さいタグは既知または予約である。
pub const FIRST_UNKNOWN_TAG: u8 = 9;

/// タイムスタンプの値のバイト長。
const TIMESTAMP_LEN: usize = 8;

/// 本バージョンが解釈しないフィールド。再符号化のために値をそのまま保持する。
#[derive(Debug, Clone)]
pub struct UnknownField {
    /// フィールドのタグ。[`FIRST_UNKNOWN_TAG`] 以上でなければ符号化できない。
    pub tag: u8,
    /// フィールドの値。秘密を含みうるため [`SecretVec`] で保持する。
    pub value: SecretVec,
}

/// クレデンシャル 1 件。すべてのフィールドは省略できる。
#[derive(Clone)]
pub struct Credential {
    /// エントリ識別子。全ゼロ (予約値) は使えない。
    pub entry_id: EntryId,
    /// タイトル。
    pub title: Option<String>,
    /// ユーザー名 (UTF-8)。[`Credential::set_username`] で設定する。
    pub username: Option<SecretVec>,
    /// パスワード (UTF-8)。[`Credential::set_password`] で設定する。
    pub password: Option<SecretVec>,
    /// URL。
    pub url: Option<String>,
    /// TOTP のシード、または `otpauth://` URI (UTF-8)。
    pub totp: Option<SecretVec>,
    /// メモ (UTF-8)。
    pub notes: Option<SecretVec>,
    /// 作成日時 (Unix 秒)。
    pub created_at: Option<u64>,
    /// 更新日時 (Unix 秒)。
    pub updated_at: Option<u64>,
    /// 未知のフィールド。タグの昇順に並べる。
    pub unknown_fields: Vec<UnknownField>,
}

impl core::fmt::Debug for Credential {
    /// 値をログへ出さないため、各フィールドは有無だけを表示する。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Credential")
            .field("entry_id", &self.entry_id)
            .field("has_title", &self.title.is_some())
            .field("has_username", &self.username.is_some())
            .field("has_password", &self.password.is_some())
            .field("has_url", &self.url.is_some())
            .field("has_totp", &self.totp.is_some())
            .field("has_notes", &self.notes.is_some())
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("unknown_field_count", &self.unknown_fields.len())
            .finish()
    }
}

impl Credential {
    /// フィールドをすべて省略した状態のクレデンシャルを生成する。
    #[must_use]
    pub const fn new(entry_id: EntryId) -> Self {
        Self {
            entry_id,
            title: None,
            username: None,
            password: None,
            url: None,
            totp: None,
            notes: None,
            created_at: None,
            updated_at: None,
            unknown_fields: Vec::new(),
        }
    }

    /// ユーザー名を PRECIS `UsernameCaseMapped` で正準化して設定する。
    ///
    /// # Errors
    /// 空文字列、または禁止コードポイントを含む場合は [`PrecisError`]。このとき既存の値は変更しない。
    pub fn set_username(&mut self, input: &str) -> Result<(), PrecisError> {
        self.username = Some(username_case_mapped_secret(input)?);
        Ok(())
    }

    /// パスワードを PRECIS `OpaqueString` で正準化して設定する。
    ///
    /// # Errors
    /// 空文字列、または禁止コードポイントを含む場合は [`PrecisError`]。このとき既存の値は変更しない。
    pub fn set_password(&mut self, input: &str) -> Result<(), PrecisError> {
        self.password = Some(opaque_string_secret(input)?);
        Ok(())
    }

    /// ユーザー名を `&str` として返す。未設定の場合は `None`。
    #[must_use]
    pub fn username_str(&self) -> Option<&str> {
        secret_as_str(self.username.as_ref())
    }

    /// パスワードを `&str` として返す。未設定の場合は `None`。
    #[must_use]
    pub fn password_str(&self) -> Option<&str> {
        secret_as_str(self.password.as_ref())
    }

    /// TOTP を `&str` として返す。未設定の場合は `None`。
    #[must_use]
    pub fn totp_str(&self) -> Option<&str> {
        secret_as_str(self.totp.as_ref())
    }

    /// メモを `&str` として返す。未設定の場合は `None`。
    #[must_use]
    pub fn notes_str(&self) -> Option<&str> {
        secret_as_str(self.notes.as_ref())
    }

    /// クレデンシャルを正準形のバイト列へ符号化する。
    ///
    /// 戻り値を [`crate::entry::EntrySource::data`] に渡して暗号化する。
    ///
    /// # Errors
    /// - `entry_id` が予約値 (全ゼロ) の場合は [`TlvParseError::InvalidFormat`]。
    /// - 未知のフィールドのタグが [`FIRST_UNKNOWN_TAG`] 未満、または昇順でない場合は [`TlvParseError::InvalidFormat`]。
    /// - `username`, `password`, `totp`, `notes` が UTF-8 でない場合は [`TlvParseError::InvalidFormat`] (復号側が拒否するため)。
    /// - 値の長さが `u32` を超える場合は [`TlvParseError::InvalidLength`]。
    ///
    /// 1 件のエントリが収まる大きさには、[`crate::entry::seal_entries`] のチャンク数の上限 (`u16`) による別の制約がある。この関数は `u32` までを受け付ける。
    pub fn encode(&self) -> Result<SecretVec, VaultError> {
        if self.entry_id == MANIFEST_ENTRY_ID {
            return Err(invalid_format());
        }
        for text in [&self.username, &self.password, &self.totp, &self.notes]
            .into_iter()
            .flatten()
        {
            utf8(text.as_slice())?;
        }
        let mut previous_tag = FIRST_UNKNOWN_TAG;
        for field in &self.unknown_fields {
            if field.tag < previous_tag {
                return Err(invalid_format());
            }
            previous_tag = field.tag;
        }

        let created_at = self.created_at.map(u64::to_be_bytes);
        let updated_at = self.updated_at.map(u64::to_be_bytes);
        let known: [(u8, Option<&[u8]>); 8] = [
            (TAG_TITLE, self.title.as_deref().map(str::as_bytes)),
            (
                TAG_USERNAME,
                self.username.as_ref().map(SecretVec::as_slice),
            ),
            (
                TAG_PASSWORD,
                self.password.as_ref().map(SecretVec::as_slice),
            ),
            (TAG_URL, self.url.as_deref().map(str::as_bytes)),
            (TAG_TOTP, self.totp.as_ref().map(SecretVec::as_slice)),
            (TAG_NOTES, self.notes.as_ref().map(SecretVec::as_slice)),
            (TAG_CREATED_AT, created_at.as_ref().map(<[u8; 8]>::as_slice)),
            (TAG_UPDATED_AT, updated_at.as_ref().map(<[u8; 8]>::as_slice)),
        ];
        let unknown = self
            .unknown_fields
            .iter()
            .map(|field| (field.tag, Some(field.value.as_slice())));

        // 再割り当てによる旧領域の残留を避けるため、全体の長さを先に求めて一度で確保する。
        let mut total = 0usize;
        for (_, value) in known.iter().copied().chain(unknown.clone()) {
            if let Some(value) = value {
                let len = u32::try_from(value.len()).map_err(|_| invalid_length())?;
                total = value
                    .len()
                    .checked_add(1 + varint_len(len))
                    .and_then(|field_len| total.checked_add(field_len))
                    .ok_or_else(invalid_length)?;
            }
        }
        let mut out = SecretVec::with_capacity(total);
        for (tag, value) in known.iter().copied().chain(unknown) {
            if let Some(value) = value {
                let len = u32::try_from(value.len()).map_err(|_| invalid_length())?;
                out.push(tag);
                put_varint(&mut out, len);
                out.extend_from_slice(value);
            }
        }
        Ok(out)
    }

    /// 符号化済みの本体と `entry_id` からクレデンシャルを復元する。
    ///
    /// # Errors
    /// 次の場合は [`TlvParseError`] を [`VaultError::Parse`] に包んで返す。
    /// - `entry_id` が予約値 (全ゼロ): `InvalidFormat`。
    /// - タグ 0、タグの降順、既知タグの重複: `InvalidFormat`。
    /// - テキストのフィールドが UTF-8 でない、タイムスタンプが 8 バイトでない: `InvalidFormat`。
    /// - `len` が最短表現でない、`u32` を超える: `InvalidFormat`。
    /// - 本体が `tag`、`len`、`value` の途中で終わる: `UnexpectedEof`。
    pub fn decode(entry_id: EntryId, body: &[u8]) -> Result<Self, VaultError> {
        if entry_id == MANIFEST_ENTRY_ID {
            return Err(invalid_format());
        }
        let mut cred = Self::new(entry_id);
        let mut position = 0usize;
        let mut previous_tag = 0u8;
        while position < body.len() {
            let tag = body[position];
            position += 1;
            // タグ 0 は予約。既知タグは昇順かつ 1 回まで、未知タグは同じタグの連続を許す。
            if tag == 0 || tag < previous_tag || (tag == previous_tag && tag < FIRST_UNKNOWN_TAG) {
                return Err(invalid_format());
            }
            previous_tag = tag;
            let len = read_varint(body, &mut position)? as usize;
            let end = position
                .checked_add(len)
                .filter(|&end| end <= body.len())
                .ok_or(VaultError::Parse(TlvParseError::UnexpectedEof))?;
            let value = &body[position..end];
            position = end;
            match tag {
                TAG_TITLE => cred.title = Some(String::from(utf8(value)?)),
                TAG_USERNAME => cred.username = Some(secret_text(value)?),
                TAG_PASSWORD => cred.password = Some(secret_text(value)?),
                TAG_URL => cred.url = Some(String::from(utf8(value)?)),
                TAG_TOTP => cred.totp = Some(secret_text(value)?),
                TAG_NOTES => cred.notes = Some(secret_text(value)?),
                TAG_CREATED_AT => cred.created_at = Some(timestamp(value)?),
                TAG_UPDATED_AT => cred.updated_at = Some(timestamp(value)?),
                _ => cred.unknown_fields.push(UnknownField {
                    tag,
                    value: SecretVec::from_slice(value),
                }),
            }
        }
        Ok(cred)
    }

    /// [`crate::entry::open_entries`] が返したエントリからクレデンシャルを復元する。
    ///
    /// # Errors
    /// [`Credential::decode`] と同じ。
    pub fn decode_opened(entry: &OpenedEntry) -> Result<Self, VaultError> {
        Self::decode(entry.entry_id, entry.data.as_slice())
    }
}

/// UTF-8 として妥当な秘密バイト列を `&str` として返す。妥当でない場合は `None`。
fn secret_as_str(value: Option<&SecretVec>) -> Option<&str> {
    value.and_then(|v| core::str::from_utf8(v.as_slice()).ok())
}

/// 形式不正のエラーを返す。
const fn invalid_format() -> VaultError {
    VaultError::Parse(TlvParseError::InvalidFormat)
}

/// 長さの超過のエラーを返す。
const fn invalid_length() -> VaultError {
    VaultError::Parse(TlvParseError::InvalidLength)
}

/// `len` を符号なし LEB128 で表したときのバイト数を返す。
const fn varint_len(value: u32) -> usize {
    match value {
        0..=0x7F => 1,
        0x80..=0x3FFF => 2,
        0x4000..=0x1F_FFFF => 3,
        0x20_0000..=0x0FFF_FFFF => 4,
        _ => 5,
    }
}

/// `len` を符号なし LEB128 で書き込む。
fn put_varint(out: &mut SecretVec, mut value: u32) {
    while value >= 0x80 {
        out.push((value & 0x7F) as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// 符号なし LEB128 を読み込み、`position` を進める。最短でない表現と `u32` を超える値は拒否する。
fn read_varint(body: &[u8], position: &mut usize) -> Result<u32, VaultError> {
    let mut value = 0u64;
    for index in 0..5u32 {
        let byte = *body
            .get(*position)
            .ok_or(VaultError::Parse(TlvParseError::UnexpectedEof))?;
        *position += 1;
        value |= u64::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            // 2 バイト目以降の最上位グループが 0 なら、より短く書ける。
            if index > 0 && byte == 0 {
                return Err(invalid_format());
            }
            return u32::try_from(value).map_err(|_| invalid_format());
        }
    }
    Err(invalid_format())
}

/// 値を UTF-8 として検証する。
fn utf8(value: &[u8]) -> Result<&str, VaultError> {
    core::str::from_utf8(value).map_err(|_| invalid_format())
}

/// 値を UTF-8 として検証したうえで、秘密のバッファへ複製する。
fn secret_text(value: &[u8]) -> Result<SecretVec, VaultError> {
    utf8(value)?;
    Ok(SecretVec::from_slice(value))
}

/// 8 バイトのビッグエンディアンのタイムスタンプを読み取る。
fn timestamp(value: &[u8]) -> Result<u64, VaultError> {
    let bytes: [u8; TIMESTAMP_LEN] = value.try_into().map_err(|_| invalid_format())?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{CipherSuiteId, VaultCipher};
    use crate::entry::{EntrySource, open_entries, seal_entries};
    use crate::error::SystemError;
    use crate::tlv::VaultHeader;
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    const ID_A: EntryId = [0xA1; 16];

    fn parse_err(err: VaultError) -> TlvParseError {
        match err {
            VaultError::Parse(inner) => inner,
            other => panic!("Parse 以外のエラーを検出: {other:?}"),
        }
    }

    fn full_credential() -> Credential {
        let mut cred = Credential::new(ID_A);
        cred.title = Some("GitHub".to_string());
        cred.set_username("Alice").unwrap();
        cred.set_password("p@ss word").unwrap();
        cred.url = Some("https://github.com/login".to_string());
        cred.totp = Some(SecretVec::from_slice(b"otpauth://totp/x?secret=ABC"));
        cred.notes = Some(SecretVec::from_slice("メモ 🔑".as_bytes()));
        cred.created_at = Some(1_700_000_000);
        cred.updated_at = Some(u64::MAX);
        cred.unknown_fields = vec![
            UnknownField {
                tag: 9,
                value: SecretVec::from_slice(&[1, 2, 3]),
            },
            UnknownField {
                tag: 9,
                value: SecretVec::new(),
            },
            UnknownField {
                tag: 255,
                value: SecretVec::from_slice(&[0xFF; 300]),
            },
        ];
        cred
    }

    fn assert_same(a: &Credential, b: &Credential, label: &str) {
        let secret = |v: &Option<SecretVec>| v.as_ref().map(|s| s.as_slice().to_vec());
        assert_eq!(a.entry_id, b.entry_id, "{label}: entry_id の不一致");
        assert_eq!(a.title, b.title, "{label}: title の不一致");
        assert_eq!(
            secret(&a.username),
            secret(&b.username),
            "{label}: username"
        );
        assert_eq!(
            secret(&a.password),
            secret(&b.password),
            "{label}: password"
        );
        assert_eq!(a.url, b.url, "{label}: url の不一致");
        assert_eq!(secret(&a.totp), secret(&b.totp), "{label}: totp");
        assert_eq!(secret(&a.notes), secret(&b.notes), "{label}: notes");
        assert_eq!(a.created_at, b.created_at, "{label}: created_at");
        assert_eq!(a.updated_at, b.updated_at, "{label}: updated_at");
        let unknown = |c: &Credential| {
            c.unknown_fields
                .iter()
                .map(|f| (f.tag, f.value.as_slice().to_vec()))
                .collect::<Vec<_>>()
        };
        assert_eq!(unknown(a), unknown(b), "{label}: unknown_fields");
    }

    // 正常系。

    #[test]
    fn test_roundtrip_full_credential() {
        let cred = full_credential();
        let body = cred.encode().unwrap();
        let decoded = Credential::decode(ID_A, body.as_slice()).unwrap();
        assert_same(&cred, &decoded, "全フィールド");
        let again = decoded.encode().unwrap();
        assert_eq!(body.as_slice(), again.as_slice(), "再符号化のバイト列一致");
    }

    #[test]
    fn test_roundtrip_empty_credential() {
        let cred = Credential::new(ID_A);
        let body = cred.encode().unwrap();
        assert!(body.is_empty(), "フィールドなしの本体は空");
        let decoded = Credential::decode(ID_A, body.as_slice()).unwrap();
        assert_same(&cred, &decoded, "空");
    }

    #[test]
    fn test_encode_golden_bytes() {
        let mut cred = Credential::new(ID_A);
        cred.title = Some("a".to_string());
        cred.set_username("Bob").unwrap();
        cred.created_at = Some(1);
        let body = cred.encode().unwrap();
        let expected: [u8; 18] = [
            0x01, 0x01, b'a', 0x02, 0x03, b'b', b'o', b'b', 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(body.as_slice(), &expected, "ゴールデンバイト列の一致");
    }

    #[test]
    fn test_roundtrip_empty_text_values() {
        let mut cred = Credential::new(ID_A);
        cred.title = Some(String::new());
        cred.notes = Some(SecretVec::new());
        let body = cred.encode().unwrap();
        assert_eq!(body.as_slice(), &[0x01, 0x00, 0x06, 0x00], "空値の符号化");
        let decoded = Credential::decode(ID_A, body.as_slice()).unwrap();
        assert_same(&cred, &decoded, "空文字列");
    }

    #[test]
    fn test_len_varint_boundaries() {
        for len in [0usize, 1, 127, 128, 255, 16_383, 16_384, 70_000] {
            let mut cred = Credential::new(ID_A);
            cred.notes = Some(SecretVec::from_vec(vec![b'x'; len]));
            let body = cred.encode().unwrap();
            let expected_len_bytes = match len {
                0..=127 => 1,
                128..=16_383 => 2,
                _ => 3,
            };
            assert_eq!(
                body.len(),
                1 + expected_len_bytes + len,
                "len={len} の符号化長"
            );
            let decoded = Credential::decode(ID_A, body.as_slice()).unwrap();
            assert_same(&cred, &decoded, &format!("len={len}"));
        }
    }

    #[test]
    fn test_unknown_fields_preserved_byte_exact() {
        let body: [u8; 12] = [
            0x01, 0x01, b't', 0x09, 0x02, 0xAA, 0xBB, 0x09, 0x00, 0xFE, 0x01, 0x07,
        ];
        let cred = Credential::decode(ID_A, &body).unwrap();
        assert_eq!(cred.unknown_fields.len(), 3, "未知フィールドの保持件数");
        assert_eq!(cred.unknown_fields[0].tag, 9);
        assert_eq!(cred.unknown_fields[1].value.len(), 0);
        assert_eq!(cred.unknown_fields[2].tag, 0xFE);
        let again = cred.encode().unwrap();
        assert_eq!(
            again.as_slice(),
            &body,
            "未知フィールドを含む再符号化のバイト列一致"
        );
    }

    #[test]
    fn test_set_username_and_password_normalize() {
        let mut cred = Credential::new(ID_A);
        cred.set_username("ALICE").unwrap();
        assert_eq!(cred.username_str(), Some("alice"), "ユーザー名の小文字化");
        cred.set_password("a\u{00A0}b").unwrap();
        assert_eq!(cred.password_str(), Some("a b"), "パスワードの空白の写像");
    }

    #[test]
    fn test_set_username_and_password_reject_invalid() {
        let mut cred = Credential::new(ID_A);
        cred.set_username("keep").unwrap();
        assert!(cred.set_username("").is_err(), "空のユーザー名の拒否");
        assert_eq!(cred.username_str(), Some("keep"), "失敗時は既存値を保持");
        assert!(cred.set_password("").is_err(), "空のパスワードの拒否");
        assert!(cred.set_password("a\u{0007}b").is_err(), "制御文字の拒否");
        assert!(cred.password.is_none(), "失敗時はパスワード未設定のまま");
    }

    #[test]
    fn test_debug_hides_values() {
        let text = format!("{:?}", full_credential());
        for needle in ["alice", "GitHub", "p@ss", "github.com", "otpauth", "メモ"] {
            assert!(!text.contains(needle), "Debug 出力に {needle} が含まれた");
        }
    }

    // 異常系 (復号)。

    #[test]
    fn test_decode_rejects_reserved_entry_id() {
        let err = Credential::decode(MANIFEST_ENTRY_ID, &[]).unwrap_err();
        assert_eq!(parse_err(err), TlvParseError::InvalidFormat);
    }

    #[test]
    fn test_decode_rejects_malformed_bodies() {
        let cases: [(&str, &[u8], TlvParseError); 19] = [
            ("タグ 0", &[0x00, 0x00], TlvParseError::InvalidFormat),
            (
                "既知タグの重複",
                &[0x01, 0x00, 0x01, 0x00],
                TlvParseError::InvalidFormat,
            ),
            (
                "既知タグの降順",
                &[0x02, 0x00, 0x01, 0x00],
                TlvParseError::InvalidFormat,
            ),
            (
                "未知タグの降順",
                &[0x0A, 0x00, 0x09, 0x00],
                TlvParseError::InvalidFormat,
            ),
            (
                "未知タグの後の既知タグ (降順)",
                &[0x09, 0x00, 0x08, 0x08, 0, 0, 0, 0, 0, 0, 0, 0],
                TlvParseError::InvalidFormat,
            ),
            ("len が途中で終わる", &[0x01], TlvParseError::UnexpectedEof),
            (
                "varint が途中で終わる",
                &[0x01, 0x80],
                TlvParseError::UnexpectedEof,
            ),
            (
                "value が不足",
                &[0x01, 0x03, b'a'],
                TlvParseError::UnexpectedEof,
            ),
            (
                "最短でない len",
                &[0x01, 0x80, 0x00],
                TlvParseError::InvalidFormat,
            ),
            (
                "len が u32 を超える",
                &[0x09, 0x80, 0x80, 0x80, 0x80, 0x10],
                TlvParseError::InvalidFormat,
            ),
            (
                "len が 6 バイト以上",
                &[0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
                TlvParseError::InvalidFormat,
            ),
            (
                "UTF-8 でない title",
                &[0x01, 0x01, 0xFF],
                TlvParseError::InvalidFormat,
            ),
            (
                "8 バイトでない updated_at",
                &[0x08, 0x07, 0, 0, 0, 0, 0, 0, 1],
                TlvParseError::InvalidFormat,
            ),
            (
                "空の created_at",
                &[0x07, 0x00],
                TlvParseError::InvalidFormat,
            ),
            (
                "9 バイトの created_at",
                &[0x07, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                TlvParseError::InvalidFormat,
            ),
            (
                "3 バイトの最短でない len",
                &[0x09, 0x81, 0x80, 0x00],
                TlvParseError::InvalidFormat,
            ),
            (
                "5 バイト目で継続して途切れる len",
                &[0x09, 0x80, 0x80, 0x80, 0x80, 0x80],
                TlvParseError::InvalidFormat,
            ),
            (
                "5 バイトの len の後に value が無い",
                &[0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F],
                TlvParseError::UnexpectedEof,
            ),
            (
                "8 バイトでないタイムスタンプ",
                &[0x07, 0x04, 0, 0, 0, 1],
                TlvParseError::InvalidFormat,
            ),
        ];
        for (label, body, expected) in cases {
            let err = Credential::decode(ID_A, body).expect_err(label);
            assert_eq!(parse_err(err), expected, "{label}");
        }
    }

    #[test]
    fn test_decode_rejects_invalid_utf8_in_every_text_field() {
        for tag in [
            TAG_TITLE,
            TAG_USERNAME,
            TAG_PASSWORD,
            TAG_URL,
            TAG_TOTP,
            TAG_NOTES,
        ] {
            let err = Credential::decode(ID_A, &[tag, 0x02, 0xC3, 0x28]).expect_err("不正 UTF-8");
            assert_eq!(parse_err(err), TlvParseError::InvalidFormat, "tag={tag}");
        }
    }

    // 異常系 (符号化)。

    #[test]
    fn test_encode_rejects_reserved_entry_id() {
        let err = Credential::new(MANIFEST_ENTRY_ID).encode().unwrap_err();
        assert_eq!(parse_err(err), TlvParseError::InvalidFormat);
    }

    #[test]
    fn test_encode_rejects_bad_unknown_fields() {
        let make = |tags: &[u8]| {
            let mut cred = Credential::new(ID_A);
            cred.unknown_fields = tags
                .iter()
                .map(|&tag| UnknownField {
                    tag,
                    value: SecretVec::new(),
                })
                .collect();
            cred
        };
        for (label, tags) in [
            ("予約タグ 0", &[0u8][..]),
            ("既知タグ 1", &[1]),
            ("既知タグ 8", &[8]),
            ("降順", &[10, 9]),
        ] {
            let err = make(tags).encode().expect_err(label);
            assert_eq!(parse_err(err), TlvParseError::InvalidFormat, "{label}");
        }
        assert!(
            make(&[9, 9, 10]).encode().is_ok(),
            "同じタグの連続と昇順の許容"
        );
    }

    // エントリの暗号化との結合。

    #[test]
    fn test_seal_open_roundtrip_with_large_credential() {
        let mut cred = full_credential();
        cred.notes = Some(SecretVec::from_vec(vec![b'k'; 4096]));
        let mut other = Credential::new([0xB2; 16]);
        other.title = Some("small".to_string());

        for suite in [
            CipherSuiteId::XChaCha20Poly1305,
            CipherSuiteId::Aes256GcmSiv,
        ] {
            let cipher = VaultCipher::new(suite, &[0x42u8; 32]);
            let header = VaultHeader::new(1, suite.as_u8(), 3);
            let bodies = [cred.encode().unwrap(), other.encode().unwrap()];
            let sources = [
                EntrySource {
                    entry_id: cred.entry_id,
                    data: bodies[0].as_slice(),
                },
                EntrySource {
                    entry_id: other.entry_id,
                    data: bodies[1].as_slice(),
                },
            ];
            let mut counter = 0u8;
            let records = seal_entries(&cipher, &header, &sources, |buf: &mut [u8]| {
                counter = counter.wrapping_add(1);
                buf.fill(counter);
                Ok::<(), SystemError>(())
            })
            .unwrap();
            let opened = open_entries(&cipher, &header, &records).unwrap();
            assert_eq!(opened.len(), 2, "復号したエントリ数");
            let first = Credential::decode_opened(&opened[0]).unwrap();
            let second = Credential::decode_opened(&opened[1]).unwrap();
            assert_same(&cred, &first, "4KiB のメモを含むエントリ");
            assert_same(&other, &second, "小さいエントリ");
        }
    }

    #[test]
    fn test_varint_helpers_roundtrip_at_every_width_boundary() {
        let cases: [(u32, usize); 11] = [
            (0, 1),
            (0x7F, 1),
            (0x80, 2),
            (0x3FFF, 2),
            (0x4000, 3),
            (0x1F_FFFF, 3),
            (0x20_0000, 4),
            (0x0FFF_FFFF, 4),
            (0x1000_0000, 5),
            (u32::MAX - 1, 5),
            (u32::MAX, 5),
        ];
        for (value, width) in cases {
            let mut out = SecretVec::new();
            put_varint(&mut out, value);
            assert_eq!(out.len(), width, "value={value:#x} の符号化幅");
            assert_eq!(varint_len(value), width, "value={value:#x} の varint_len");
            let mut position = 0usize;
            let decoded = read_varint(out.as_slice(), &mut position).unwrap();
            assert_eq!(decoded, value, "value={value:#x} の往復");
            assert_eq!(position, width, "value={value:#x} の消費長");
        }
    }

    #[test]
    fn test_decode_opened_rejects_reserved_entry_id_and_malformed_body() {
        let reserved = OpenedEntry {
            entry_id: MANIFEST_ENTRY_ID,
            data: SecretVec::new(),
        };
        let err = Credential::decode_opened(&reserved).unwrap_err();
        assert_eq!(parse_err(err), TlvParseError::InvalidFormat);
        let malformed = OpenedEntry {
            entry_id: ID_A,
            data: SecretVec::from_slice(&[0x01, 0x05, b'a']),
        };
        let err = Credential::decode_opened(&malformed).unwrap_err();
        assert_eq!(parse_err(err), TlvParseError::UnexpectedEof);
    }

    #[test]
    fn test_seal_open_roundtrip_with_empty_credential() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let cipher = VaultCipher::new(suite, &[0x42u8; 32]);
        let header = VaultHeader::new(1, suite.as_u8(), 1);
        let cred = Credential::new(ID_A);
        let body = cred.encode().unwrap();
        let sources = [EntrySource {
            entry_id: ID_A,
            data: body.as_slice(),
        }];
        let records = seal_entries(&cipher, &header, &sources, |buf: &mut [u8]| {
            buf.fill(7);
            Ok::<(), SystemError>(())
        })
        .unwrap();
        let opened = open_entries(&cipher, &header, &records).unwrap();
        assert_eq!(opened.len(), 1, "復号したエントリ数");
        let decoded = Credential::decode_opened(&opened[0]).unwrap();
        assert_same(&cred, &decoded, "0 バイトのエントリ");
    }

    #[test]
    fn test_encode_rejects_invalid_utf8_in_every_secret_text_field() {
        for tag in [TAG_USERNAME, TAG_PASSWORD, TAG_TOTP, TAG_NOTES] {
            let mut cred = Credential::new(ID_A);
            let invalid = Some(SecretVec::from_slice(&[0xC3, 0x28]));
            match tag {
                TAG_USERNAME => cred.username = invalid,
                TAG_PASSWORD => cred.password = invalid,
                TAG_TOTP => cred.totp = invalid,
                _ => cred.notes = invalid,
            }
            let err = cred.encode().expect_err("不正 UTF-8");
            assert_eq!(parse_err(err), TlvParseError::InvalidFormat, "tag={tag}");
        }
    }

    #[test]
    fn test_str_accessors_return_values_and_none() {
        let mut cred = Credential::new(ID_A);
        assert_eq!(cred.username_str(), None, "未設定のユーザー名");
        assert_eq!(cred.password_str(), None, "未設定のパスワード");
        assert_eq!(cred.totp_str(), None, "未設定の TOTP");
        assert_eq!(cred.notes_str(), None, "未設定のメモ");
        cred.totp = Some(SecretVec::from_slice(b"JBSWY3DP"));
        cred.notes = Some(SecretVec::from_slice("メモ".as_bytes()));
        assert_eq!(cred.totp_str(), Some("JBSWY3DP"), "TOTP の取得");
        assert_eq!(cred.notes_str(), Some("メモ"), "メモの取得");
        cred.totp = Some(SecretVec::from_slice(&[0xC3, 0x28]));
        cred.notes = Some(SecretVec::from_slice(&[0xFF]));
        assert_eq!(cred.totp_str(), None, "不正 UTF-8 の TOTP");
        assert_eq!(cred.notes_str(), None, "不正 UTF-8 のメモ");
    }

    #[test]
    fn test_unknown_field_debug_hides_value() {
        let field = UnknownField {
            tag: 9,
            value: SecretVec::from_slice(b"secret-unknown-value"),
        };
        let text = format!("{field:?}");
        assert!(!text.contains("secret-unknown-value"), "値の非露出");
        assert!(!text.contains("115"), "10 進表記のバイト列の非露出");
    }
}
