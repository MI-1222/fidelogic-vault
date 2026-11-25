//! # マスターパスワードの正準化 (`password`)
//!
//! [`crate::secret_input`] が読み込んだバイト列を、鍵導出に渡す形にする。
//! Vault を作成する処理と解錠する処理は、同じ入力から同じバイト列を得るために、必ずこのモジュールを通す。
//! コアのスロットの関数はパスワードを正準化せず、渡されたバイト列をそのまま鍵導出に使う。
//! このモジュールは OS に依存しない。
//!
//! ## 規則
//!
//! 1. UTF-8 として解釈する。
//! 2. PRECIS の `OpaqueString` プロファイル (RFC 8265 Section 4.2) を、コアの実装の範囲で適用する。
//!    非 ASCII の空白は ASCII の空白に置き換える。大文字と小文字は区別する。
//!    制御文字などの禁止された文字を含む入力は拒否する。
//!
//! コアの正準合成は、NFC の一部だけを行う。対象は、一部のラテン文字とダイアクリティカルマークの組と、
//! ハングル字母である (`fidelogic_core` の `compose_pair`)。それ以外の分解された文字 (かなと結合濁点など) は、
//! 合成せずに別のバイト列として扱う。合成済みの文字で入力した場合と、分解された文字で入力した場合は、
//! 異なるパスワードになる。
//!
//! 長さの下限と、文字種の条件は設けない。空の入力は拒否する。
//!
//! ## 秘密の扱い
//!
//! 正準化の結果は、破棄時に消去する [`SecretVec`] で返す。このバッファは `mlock` しない。

use core::fmt;

use fidelogic_core::{PrecisProfile, SecretVec};

/// マスターパスワードの正準化の失敗。入力の内容や、誤りの位置は含まない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// UTF-8 として解釈できない。
    NotUtf8,
    /// 空であるか、使用できない文字がある。
    Rejected,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => formatter.write_str("パスワードが UTF-8 ではありません。"),
            Self::Rejected => formatter.write_str("パスワードに使用できない文字が含まれています。"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// パスワードのバイト列を正準化する。
///
/// # Args
///
/// - `input`: 行の終端を含まない入力。
///
/// # Errors
///
/// - UTF-8 として解釈できない場合は [`PasswordError::NotUtf8`]。
/// - 空の場合と、使用できない文字がある場合は [`PasswordError::Rejected`]。
pub fn canonicalize_password(input: &[u8]) -> Result<SecretVec, PasswordError> {
    // `str` は入力を借用するだけで、秘密の複写を作らない。
    let text = core::str::from_utf8(input).map_err(|_| PasswordError::NotUtf8)?;
    PrecisProfile::OpaqueString
        .enforce_str_secret(text)
        .map_err(|_| PasswordError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::{PasswordError, canonicalize_password};

    /// 正準化の結果を、比較できる形にする。
    fn canonical(input: &[u8]) -> Result<Vec<u8>, PasswordError> {
        canonicalize_password(input).map(|password| password.as_slice().to_vec())
    }

    #[test]
    fn test_canonical_input_is_unchanged() {
        for input in [
            "correct horse battery staple",
            "Pass Word",
            " leading and trailing ",
            "パスワード",
            "ＡＢＣ",
            "🔑 key",
            "a",
        ] {
            assert_eq!(
                canonical(input.as_bytes()),
                Ok(input.as_bytes().to_vec()),
                "{input:?} を変えないことの確認に失敗。"
            );
        }
    }

    #[test]
    fn test_spaces_and_composition_are_normalized() {
        let cases = [
            ("全角の空白", "a\u{3000}b", "a b"),
            ("改行しない空白", "a\u{00a0}b", "a b"),
            ("ラテン文字の合成", "caf\u{0065}\u{0301}", "caf\u{00e9}"),
            ("ハングル字母の合成", "\u{1100}\u{1161}\u{11a8}", "\u{ac01}"),
        ];
        for (name, input, expected) in cases {
            assert_eq!(
                canonical(input.as_bytes()),
                Ok(expected.as_bytes().to_vec()),
                "{name}の正準化に失敗。"
            );
        }
    }

    /// コアの正準合成の対象外の組は、合成しない。
    /// この結果が変わると、作成済みの Vault を同じ入力で解錠できなくなる。
    #[test]
    fn test_composition_outside_core_scope_is_kept() {
        let decomposed = "\u{304b}\u{3099}";
        assert_eq!(
            canonical(decomposed.as_bytes()),
            Ok(decomposed.as_bytes().to_vec()),
            "かなと結合濁点を変えないことの確認に失敗。"
        );
    }

    #[test]
    fn test_disallowed_input_is_rejected() {
        let cases = [
            ("空", ""),
            ("タブ", "a\tb"),
            ("ヌル文字", "a\u{0}b"),
            ("エスケープ", "a\u{1b}b"),
            ("改行", "a\nb"),
            ("私用領域", "a\u{e000}"),
        ];
        for (name, input) in cases {
            assert_eq!(
                canonical(input.as_bytes()),
                Err(PasswordError::Rejected),
                "{name}を含む入力の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_invalid_utf8_is_rejected() {
        let cases: [(&str, &[u8]); 4] = [
            ("単独の 0xFF", &[0xff]),
            ("途中で切れた文字", &[b'a', 0xe3, 0x81]),
            ("冗長な表現", &[0xc0, 0xaf]),
            ("サロゲート", &[0xed, 0xa0, 0x80]),
        ];
        for (name, input) in cases {
            assert_eq!(
                canonical(input),
                Err(PasswordError::NotUtf8),
                "{name}の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_error_display_ends_with_japanese_period() {
        for error in [PasswordError::NotUtf8, PasswordError::Rejected] {
            assert!(
                error.to_string().ends_with('。'),
                "エラーメッセージの末尾が句点でないため失敗しました: {error}"
            );
        }
    }
}
