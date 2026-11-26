//! # 平文の JSON 書き出し (`export_json`)
//!
//! `export` が書き出す JSON の形式を定める。入出力先は呼び出し側が渡し、OS に依存しない。
//!
//! ## 形式
//!
//! ```text
//! {
//!   "format": "fidelogic-vault-export",
//!   "version": 1,
//!   "entries": [
//!     {
//!       "id": "<エントリ識別子の 16 進 32 文字>",
//!       "title": "...", "username": "...", "password": "...", "url": "...",
//!       "totp": "...", "notes": "...",
//!       "created_at": <Unix 秒>, "updated_at": <Unix 秒>,
//!       "unknown_fields": [{"tag": <タグ>, "value_hex": "<値の 16 進>"}]
//!     }
//!   ]
//! }
//! ```
//!
//! - エントリは Vault の記録順に並べる。
//! - 値の無い項目はキーごと省く。`unknown_fields` も、未知のフィールドが無ければ省く。
//! - 制御文字と、表示の向きを変える書式文字は `\uXXXX` にする。端末に書き出しても表示が書き換わらず、
//!   JSON として読めば元の文字になる。
//!
//! ## 秘密の扱い
//!
//! 文字列を組み立てず、値を借用したまま `out` へ順に書く。バッファを持つ書き込み先を渡すと、
//! 消去されない複写が残るため、`File` などを直接渡す。

use std::io::{self, Write};

use fidelogic_core::Credential;

use crate::entry_ops::{EntryField, is_unsafe_for_display};

/// 書き出しの形式の名前。
const FORMAT_NAME: &str = "fidelogic-vault-export";

/// 書き出しの形式の版。
const FORMAT_VERSION: u32 = 1;

/// 全エントリを、平文の JSON で書き出す。
///
/// # Errors
///
/// 書き込みに失敗した場合と、秘密の項目が UTF-8 でない場合 ([`io::ErrorKind::InvalidData`])。
pub(crate) fn write_export(
    out: &mut (impl Write + ?Sized),
    credentials: &[Credential],
) -> io::Result<()> {
    write!(
        out,
        "{{\n  \"format\": \"{FORMAT_NAME}\",\n  \"version\": {FORMAT_VERSION},\n  \"entries\": ["
    )?;
    let mut separator = "\n";
    for credential in credentials {
        out.write_all(separator.as_bytes())?;
        separator = ",\n";
        write_entry(out, credential)?;
    }
    if !credentials.is_empty() {
        out.write_all(b"\n  ")?;
    }
    out.write_all(b"]\n}\n")?;
    out.flush()
}

/// 1 件のエントリを、JSON のオブジェクトとして書く。
fn write_entry(out: &mut (impl Write + ?Sized), credential: &Credential) -> io::Result<()> {
    out.write_all(b"    {\n      \"id\": \"")?;
    write_hex(out, &credential.entry_id)?;
    out.write_all(b"\"")?;
    if let Some(title) = credential.title.as_deref() {
        write_member(out, "title", title.as_bytes())?;
    }
    for field in EntryField::ALL {
        if let Some(value) = field.value(credential) {
            write_member(out, field.name(), value)?;
        }
    }
    for (name, timestamp) in [
        ("created_at", credential.created_at),
        ("updated_at", credential.updated_at),
    ] {
        if let Some(seconds) = timestamp {
            write!(out, ",\n      \"{name}\": {seconds}")?;
        }
    }
    if !credential.unknown_fields.is_empty() {
        out.write_all(b",\n      \"unknown_fields\": [")?;
        let mut separator = "";
        for field in &credential.unknown_fields {
            write!(
                out,
                "{separator}{{\"tag\": {}, \"value_hex\": \"",
                field.tag
            )?;
            write_hex(out, field.value.as_slice())?;
            out.write_all(b"\"}")?;
            separator = ", ";
        }
        out.write_all(b"]")?;
    }
    out.write_all(b"\n    }")
}

/// 先行するメンバーに続けて、文字列の値を持つメンバーを書く。
fn write_member(out: &mut (impl Write + ?Sized), name: &str, value: &[u8]) -> io::Result<()> {
    // `str` は値を借用するだけで、秘密の複写を作らない。
    let text =
        core::str::from_utf8(value).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    write!(out, ",\n      \"{name}\": \"")?;
    write_string_body(out, text)?;
    out.write_all(b"\"")
}

/// JSON の文字列の中身を書く。エスケープが要らない範囲はそのまま書く。
fn write_string_body(out: &mut (impl Write + ?Sized), text: &str) -> io::Result<()> {
    let mut rest = text;
    while let Some((position, character)) = rest
        .char_indices()
        .find(|&(_, character)| needs_escape(character))
    {
        let (plain, tail) = rest.split_at(position);
        out.write_all(plain.as_bytes())?;
        match character {
            '"' => out.write_all(b"\\\"")?,
            '\\' => out.write_all(b"\\\\")?,
            '\n' => out.write_all(b"\\n")?,
            '\r' => out.write_all(b"\\r")?,
            '\t' => out.write_all(b"\\t")?,
            '\u{8}' => out.write_all(b"\\b")?,
            '\u{c}' => out.write_all(b"\\f")?,
            // 対象の文字はすべて基本多言語面にあるため、4 桁で表せる。
            other => write!(out, "\\u{:04x}", u32::from(other))?,
        }
        rest = tail.get(character.len_utf8()..).unwrap_or_default();
    }
    out.write_all(rest.as_bytes())
}

/// JSON の文字列の中で、エスケープして書く文字かを返す。
fn needs_escape(character: char) -> bool {
    matches!(character, '"' | '\\') || is_unsafe_for_display(character)
}

/// バイト列を、小文字の 16 進で書く。
fn write_hex(out: &mut (impl Write + ?Sized), bytes: &[u8]) -> io::Result<()> {
    for byte in bytes {
        write!(out, "{byte:02x}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io;

    use fidelogic_core::{Credential, SecretVec, UnknownField};

    use super::write_export;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn secret(text: &str) -> SecretVec {
        SecretVec::from_slice(text.as_bytes())
    }

    fn exported(credentials: &[Credential]) -> Result<String, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        write_export(&mut out, credentials)?;
        Ok(String::from_utf8(out)?)
    }

    #[test]
    fn test_empty_vault() -> TestResult {
        assert_eq!(
            exported(&[])?,
            "{\n  \"format\": \"fidelogic-vault-export\",\n  \"version\": 1,\n  \"entries\": []\n}\n"
        );
        Ok(())
    }

    #[test]
    fn test_entries_keep_order_and_omit_unset_fields() -> TestResult {
        let mut full = Credential::new([0xab; 16]);
        full.title = Some("z-title".to_owned());
        full.username = Some(secret("alice"));
        full.password = Some(secret("pw"));
        full.url = Some("https://a.example/?q=1".to_owned());
        full.totp = Some(secret("seed"));
        full.notes = Some(secret("memo"));
        full.created_at = Some(0);
        full.updated_at = Some(u64::MAX);
        full.unknown_fields = vec![
            UnknownField {
                tag: 9,
                value: SecretVec::from_slice(&[0x00, 0x0f, 0xff]),
            },
            UnknownField {
                tag: 255,
                value: SecretVec::from_slice(&[]),
            },
        ];
        let bare = Credential::new([0x01; 16]);
        let expected = concat!(
            "{\n",
            "  \"format\": \"fidelogic-vault-export\",\n",
            "  \"version\": 1,\n",
            "  \"entries\": [\n",
            "    {\n",
            "      \"id\": \"abababababababababababababababab\",\n",
            "      \"title\": \"z-title\",\n",
            "      \"username\": \"alice\",\n",
            "      \"password\": \"pw\",\n",
            "      \"url\": \"https://a.example/?q=1\",\n",
            "      \"totp\": \"seed\",\n",
            "      \"notes\": \"memo\",\n",
            "      \"created_at\": 0,\n",
            "      \"updated_at\": 18446744073709551615,\n",
            "      \"unknown_fields\": [{\"tag\": 9, \"value_hex\": \"000fff\"}, {\"tag\": 255, \"value_hex\": \"\"}]\n",
            "    },\n",
            "    {\n",
            "      \"id\": \"01010101010101010101010101010101\"\n",
            "    }\n",
            "  ]\n",
            "}\n",
        );
        assert_eq!(exported(&[full, bare])?, expected);
        Ok(())
    }

    #[test]
    fn test_strings_are_escaped() -> TestResult {
        let cases = [
            ("", ""),
            ("a\"b\\c/d", "a\\\"b\\\\c/d"),
            ("a\nb\rc\td", "a\\nb\\rc\\td"),
            ("\u{8}\u{c}", "\\b\\f"),
            ("\0\u{1}\u{1b}\u{1f}", "\\u0000\\u0001\\u001b\\u001f"),
            ("\u{7f}\u{80}\u{9f}", "\\u007f\\u0080\\u009f"),
            ("\u{202e}\u{2066}", "\\u202e\\u2066"),
            ("銀行 🔑 \u{2028}", "銀行 🔑 \u{2028}"),
        ];
        for (input, expected) in cases {
            let mut credential = Credential::new([2; 16]);
            credential.notes = Some(secret(input));
            let output = exported(&[credential])?;
            let line = format!("\"notes\": \"{expected}\"\n");
            assert!(
                output.contains(&line),
                "{input:?} のエスケープに失敗: {output:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_non_utf8_secret_is_rejected() {
        let mut credential = Credential::new([2; 16]);
        credential.password = Some(SecretVec::from_slice(&[0xff]));
        let result = write_export(&mut Vec::new(), &[credential]);
        assert_eq!(
            result.map_err(|error| error.kind()),
            Err(io::ErrorKind::InvalidData)
        );
    }

    /// 書き込みの失敗を、握りつぶさずに返すこと。
    #[test]
    fn test_write_failure_is_returned() {
        struct Failing(usize);
        impl io::Write for Failing {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Err(io::Error::from(io::ErrorKind::BrokenPipe));
                }
                self.0 -= 1;
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut credential = Credential::new([2; 16]);
        credential.notes = Some(secret("memo\nline"));
        // 書き込みが何回目で失敗しても、失敗を返す。
        for successes in 0..8 {
            let result = write_export(&mut Failing(successes), core::slice::from_ref(&credential));
            assert_eq!(
                result.map_err(|error| error.kind()),
                Err(io::ErrorKind::BrokenPipe),
                "{successes} 回目の後の失敗の確認に失敗。"
            );
        }
    }
}
