//! # エントリの画面表示 (`display`)
//!
//! `list` と `get` が書く、一覧と 1 件の要約の形式を定める。入出力先は呼び出し側が渡し、OS に依存しない。
//!
//! 保存されている文字列は、画面の表示を乱しうる文字 ([`is_unsafe_for_display`]) をエスケープして書く。
//! 端末の制御列を含むタイトルなどで、表示が書き換わることを防ぐためである。
//! エスケープは、改行、復帰、タブを `\n`, `\r`, `\t`、それ以外を `\u{1b}` の形にする。
//! 秘密の項目は、値の長さに依存しない固定の伏せ字にする。

use std::io::{self, Write};

use fidelogic_core::Credential;

use crate::entry_ops::{EntryField, is_unsafe_for_display};

/// 秘密の項目の値の代わりに書く文字列。
const MASK: &str = "********";

/// 値の無い項目に書く文字列。
const UNSET: &str = "(未設定)";

/// タイトルの無いエントリの、タイトルの代わりに書く文字列。
const UNTITLED: &str = "(タイトルなし)";

/// 画面の表示を乱しうる文字をエスケープして、`text` を書く。
///
/// 複写を作らず、エスケープが要らない範囲はそのまま書く。
///
/// # Errors
///
/// 書き込みに失敗した場合。
pub(crate) fn write_escaped(out: &mut impl Write, text: &str) -> io::Result<()> {
    let mut rest = text;
    while let Some((position, character)) = rest
        .char_indices()
        .find(|&(_, character)| is_unsafe_for_display(character))
    {
        let (plain, tail) = rest.split_at(position);
        out.write_all(plain.as_bytes())?;
        write!(out, "{}", character.escape_default())?;
        rest = tail.get(character.len_utf8()..).unwrap_or_default();
    }
    out.write_all(rest.as_bytes())
}

/// [`write_escaped`] の結果を文字列で返す。端末のプロンプトに埋め込む、秘密でない文字列に使う。
pub(crate) fn escaped(text: &str) -> String {
    text.chars().fold(
        String::with_capacity(text.len()),
        |mut result, character| {
            if is_unsafe_for_display(character) {
                result.extend(character.escape_default());
            } else {
                result.push(character);
            }
            result
        },
    )
}

/// 一覧を、タイトル、ユーザー名、URL をタブで区切った 1 件 1 行で書く。タイトルの順に並べる。
///
/// 値の無いユーザー名と URL は空にする。秘密の項目は書かない。
///
/// # Errors
///
/// 書き込みに失敗した場合。
pub(crate) fn write_list(out: &mut impl Write, credentials: &[Credential]) -> io::Result<()> {
    let mut sorted: Vec<&Credential> = credentials.iter().collect();
    // 同じタイトルは、Vault の記録順を保つ。
    sorted.sort_by(|left, right| left.title.cmp(&right.title));
    for credential in sorted {
        write_escaped(out, credential.title.as_deref().unwrap_or(UNTITLED))?;
        out.write_all(b"\t")?;
        write_escaped(out, credential.username_str().unwrap_or_default())?;
        out.write_all(b"\t")?;
        write_escaped(out, credential.url.as_deref().unwrap_or_default())?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

/// 1 件の全項目を、秘密を伏せて書く。
///
/// # Errors
///
/// 書き込みに失敗した場合。
pub(crate) fn write_summary(out: &mut impl Write, credential: &Credential) -> io::Result<()> {
    out.write_all("タイトル: ".as_bytes())?;
    write_escaped(out, credential.title.as_deref().unwrap_or(UNTITLED))?;
    out.write_all(b"\n")?;
    for field in EntryField::ALL {
        write!(out, "{}: ", field.label())?;
        match field.value(credential) {
            None => out.write_all(UNSET.as_bytes())?,
            Some(_) if field.is_secret() => out.write_all(MASK.as_bytes())?,
            // 秘密でない項目は、復号の時点で UTF-8 であることを確かめている。
            Some(value) => write_escaped(
                out,
                core::str::from_utf8(value)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
            )?,
        }
        out.write_all(b"\n")?;
    }
    for (label, timestamp) in [
        ("作成日時", credential.created_at),
        ("更新日時", credential.updated_at),
    ] {
        match timestamp {
            Some(seconds) => writeln!(out, "{label} (Unix 秒): {seconds}")?,
            None => writeln!(out, "{label} (Unix 秒): {UNSET}")?,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fidelogic_core::{Credential, SecretVec};

    use super::{escaped, write_list, write_summary};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn secret(text: &str) -> SecretVec {
        SecretVec::from_slice(text.as_bytes())
    }

    fn entry(title: Option<&str>, username: Option<&str>, url: Option<&str>) -> Credential {
        let mut credential = Credential::new([1; 16]);
        credential.title = title.map(str::to_owned);
        credential.username = username.map(secret);
        credential.url = url.map(str::to_owned);
        credential
    }

    #[test]
    fn test_escaping_replaces_only_unsafe_characters() {
        let cases = [
            ("", ""),
            ("plain text", "plain text"),
            ("銀行 🔑 \\n", "銀行 🔑 \\n"),
            ("a\nb\tc\rd", "a\\nb\\tc\\rd"),
            ("\u{1b}[2J", "\\u{1b}[2J"),
            ("x\u{7f}\u{9b}", "x\\u{7f}\\u{9b}"),
            ("a\u{202e}b", "a\\u{202e}b"),
            ("\0", "\\u{0}"),
        ];
        for (input, expected) in cases {
            assert_eq!(escaped(input), expected, "{input:?} のエスケープに失敗。");
        }
    }

    fn listed(credentials: &[Credential]) -> Result<String, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        write_list(&mut out, credentials)?;
        Ok(String::from_utf8(out)?)
    }

    #[test]
    fn test_list_is_sorted_and_tab_separated_without_secrets() -> TestResult {
        let mut second = entry(Some("b-site"), Some("bob"), Some("https://b.example"));
        second.password = Some(secret("PASSWORD-VALUE"));
        second.totp = Some(secret("TOTP-VALUE"));
        second.notes = Some(secret("NOTES-VALUE"));
        let credentials = [
            second,
            entry(Some("a\tsite"), None, None),
            entry(None, Some("c\nuser"), None),
        ];
        // タイトルの無いエントリは、タイトルのあるエントリより前に並ぶ。
        assert_eq!(
            listed(&credentials)?,
            "(タイトルなし)\tc\\nuser\t\n\
             a\\tsite\t\t\n\
             b-site\tbob\thttps://b.example\n"
        );
        Ok(())
    }

    #[test]
    fn test_empty_list_writes_nothing() -> TestResult {
        assert_eq!(listed(&[])?, "");
        Ok(())
    }

    fn summarized(credential: &Credential) -> Result<String, Box<dyn std::error::Error>> {
        let mut out = Vec::new();
        write_summary(&mut out, credential)?;
        Ok(String::from_utf8(out)?)
    }

    #[test]
    fn test_summary_masks_secrets() -> TestResult {
        let mut credential = entry(Some("site"), Some("alice"), Some("https://a.example\u{1b}"));
        credential.password = Some(secret("PASSWORD-VALUE"));
        credential.totp = Some(secret("T"));
        credential.notes = Some(secret("line 1\nline 2"));
        credential.created_at = Some(1);
        credential.updated_at = Some(2);
        assert_eq!(
            summarized(&credential)?,
            "タイトル: site\n\
             ユーザー名: alice\n\
             パスワード: ********\n\
             URL: https://a.example\\u{1b}\n\
             TOTP: ********\n\
             メモ: ********\n\
             作成日時 (Unix 秒): 1\n\
             更新日時 (Unix 秒): 2\n"
        );
        Ok(())
    }

    #[test]
    fn test_summary_marks_unset_fields() -> TestResult {
        assert_eq!(
            summarized(&entry(None, None, None))?,
            "タイトル: (タイトルなし)\n\
             ユーザー名: (未設定)\n\
             パスワード: (未設定)\n\
             URL: (未設定)\n\
             TOTP: (未設定)\n\
             メモ: (未設定)\n\
             作成日時 (Unix 秒): (未設定)\n\
             更新日時 (Unix 秒): (未設定)\n"
        );
        Ok(())
    }
}
