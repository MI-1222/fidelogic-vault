//! # リカバリーコード (`recovery_code`)
//!
//! Vault のリカバリー用スロット (Slot 2) の秘密になるコードを、生成、符号化、検証する。
//! このコードは、単独で Vault 全体を復号できる秘密である。
//! このモジュールは OS に依存しない。乱数源は呼び出し側が渡す ([`crate::sys::random::fill_random`])。
//!
//! ## 形式
//!
//! 区切りを除いた正準形は、ASCII の [`RECOVERY_CODE_LEN`] (30) 文字である。
//!
//! | 位置 | 内容 |
//! | :-- | :-- |
//! | 1〜2 文字目 | プレフィックス `FL` |
//! | 3〜30 文字目 | 乱数 128 bit に続けてチェックサム 12 bit を並べた 140 bit を、上位から 5 bit ずつ文字にしたもの |
//!
//! - 文字は Crockford Base32 の `0123456789ABCDEFGHJKMNPQRSTVWXYZ` である (`I`, `L`, `O`, `U` を使わない)。
//! - チェックサムは、ASCII の `FL` と乱数 16 バイトを続けた列から求める。
//!   CRC-16/CCITT-FALSE (多項式 `0x1021`、初期値 `0xFFFF`、反転なし、出力の XOR なし) の上位 12 bit である。
//! - 表示は 5 文字ずつ `-` で区切る (`FLXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`)。
//!
//! ## 入力の解釈
//!
//! - `-` と半角の空白は、位置と個数によらず区切りとして無視する。
//! - 英字の大文字と小文字を区別しない。
//! - 3 文字目以降の `O` は `0`、`I` と `L` は `1` と読み替える。プレフィックスは読み替えない。
//! - 文字数、プレフィックス、文字種、チェックサムのいずれかが合わない入力は拒否する。
//!   鍵導出より前に、入力の誤りを検出するためである。
//!
//! ## チェックサムの検出範囲
//!
//! 3 文字目以降の 1 文字の誤りと、隣り合う 2 文字の入れ替えは、すべて検出する。
//! 2 文字以上の誤りは、約 4096 分の 1 の割合で見逃す。見逃した場合は、Slot 2 の解錠に失敗する。
//! チェックサムは入力の誤りを見つけるためのもので、改ざんは防がない。
//!
//! ## 秘密の扱い
//!
//! 乱数、正準形、表示用の文字列のバッファには `mlock` した [`LockedBuffer`] を使い、破棄時に消去する。
//! `mlock` に失敗した場合は処理を中止する。
//! 符号化、文字から値への変換、チェックサムの照合は、秘密の値で分岐やメモリ参照の位置を変えないように書いている。
//! 一方、読み取りでの区切りの判定と、使えない文字やプレフィックスの不一致による中止は、入力の内容で分岐する。
//! 生成される機械語は検査していない。
//!
//! チェックサムの照合で使う未処理のビット、CRC の状態、2 つのチェックサムは、照合の結果によらず消去する。
//! それ以外の一時的な値と、レジスタやスタックに複写された値の消去は保証しない。
//!
//! ## コアとの接続
//!
//! [`RecoveryCode::as_bytes`] の正準形を、`fidelogic_core` の Slot 2 の関数に渡す。
//! 対象は `wrap_dek_slot2_code_for_header` と `unwrap_dek_slot2_code_for_header` である。
//! コアの `normalize_recovery_code` は正準形を変更しない。
//! コアは読み替えとチェックサムの検証を行わないため、利用者の入力は [`RecoveryCode::parse`] を通してから渡す。

use core::fmt;

use fidelogic_core::{
    LockedBuffer, SystemError, ct_eq_array, ct_select, volatile_zeroize, volatile_zeroize_words,
};

/// リカバリーコードの先頭に付ける識別子。
pub const RECOVERY_CODE_PREFIX: &[u8; 2] = b"FL";

/// リカバリーコードが持つ乱数のバイト数 (128 bit)。
pub const RECOVERY_SECRET_LEN: usize = 16;

/// 区切りを除いた正準形の文字数。
pub const RECOVERY_CODE_LEN: usize = 30;

/// 表示用の、区切りを含む文字数。
pub const GROUPED_RECOVERY_CODE_LEN: usize = 35;

/// Crockford Base32 の文字集合。添字が 5 bit の値である。
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 1 文字が表すビット数。
const SYMBOL_BITS: u32 = 5;

/// チェックサムのビット数。
const CHECKSUM_BITS: u32 = 12;

/// 表示用の形で、区切りの間に置く文字数。
const GROUP_LEN: usize = 5;

/// CRC-16/CCITT-FALSE の多項式。
const CRC_POLYNOMIAL: u16 = 0x1021;

/// CRC-16/CCITT-FALSE の初期値。
const CRC_INITIAL: u16 = 0xffff;

/// 検証を通ったリカバリーコード。正準形を `mlock` したページに保持し、破棄時に消去する。
pub struct RecoveryCode {
    code: LockedBuffer<RECOVERY_CODE_LEN>,
}

impl RecoveryCode {
    /// 乱数源から 128 bit を読み、新しいリカバリーコードを作る。
    ///
    /// # Args
    ///
    /// - `fill_random`: 渡されたバッファ全体を、暗号論的に安全な乱数で埋める関数。
    ///   長さ [`RECOVERY_SECRET_LEN`] のバッファで 1 回だけ呼ぶ。
    ///
    /// # Errors
    ///
    /// - バッファを `mlock` できない場合は [`RecoveryCodeError::MemoryLockFailed`]。
    /// - `fill_random` が失敗した場合は [`RecoveryCodeError::EntropySourceFailed`]。
    pub fn generate<F>(fill_random: F) -> Result<Self, RecoveryCodeError>
    where
        F: FnOnce(&mut [u8]) -> Result<(), SystemError>,
    {
        // 乱数を読む前にすべてのバッファを確保し、確保に失敗する場合は乱数を作らない。
        let mut secret = locked_buffer::<RECOVERY_SECRET_LEN>()?;
        let mut code = locked_buffer::<RECOVERY_CODE_LEN>()?;
        fill_random(secret.as_mut_slice()).map_err(|_| RecoveryCodeError::EntropySourceFailed)?;
        encode(secret.as_slice(), code.as_mut_slice());
        Ok(Self { code })
    }

    /// 利用者が入力したリカバリーコードを読み取り、チェックサムを検証する。
    ///
    /// 解釈の規則はモジュールの説明を参照する。入力は左から順に調べ、最初に見つかった誤りを返す。
    /// チェックサムは、他の誤りが無い場合に調べる。
    ///
    /// # Args
    ///
    /// - `input`: 行の終端を含まない入力。
    ///
    /// # Errors
    ///
    /// - バッファを `mlock` できない場合は [`RecoveryCodeError::MemoryLockFailed`]。
    /// - 区切りを除いた文字数が [`RECOVERY_CODE_LEN`] でない場合は [`RecoveryCodeError::InvalidLength`]。
    /// - 先頭の 2 文字が `FL` でない場合は [`RecoveryCodeError::InvalidPrefix`]。
    /// - 3 文字目以降に、読み替えても使えない文字がある場合は [`RecoveryCodeError::InvalidCharacter`]。
    /// - チェックサムが一致しない場合は [`RecoveryCodeError::ChecksumMismatch`]。
    pub fn parse(input: &[u8]) -> Result<Self, RecoveryCodeError> {
        let mut code = locked_buffer::<RECOVERY_CODE_LEN>()?;
        let mut len = 0usize;
        for &byte in input.iter().filter(|&&byte| byte != b'-' && byte != b' ') {
            let slot = code
                .as_mut_slice()
                .get_mut(len)
                .ok_or(RecoveryCodeError::InvalidLength)?;
            *slot = match RECOVERY_CODE_PREFIX.get(len) {
                Some(&expected) if byte.to_ascii_uppercase() == expected => expected,
                Some(_) => return Err(RecoveryCodeError::InvalidPrefix),
                None => {
                    let value = symbol_value(byte).ok_or(RecoveryCodeError::InvalidCharacter)?;
                    symbol_for(value)
                }
            };
            len += 1;
        }
        if len != RECOVERY_CODE_LEN {
            return Err(RecoveryCodeError::InvalidLength);
        }
        verify_checksum(code.as_slice())?;
        Ok(Self { code })
    }

    /// 区切りを含まない正準形 (ASCII の 30 文字) を返す。
    ///
    /// 戻り値は秘密である。消去されないバッファへ複写しない。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.code.as_slice()
    }

    /// 表示用の、5 文字ずつ `-` で区切った形を作る。
    ///
    /// # Errors
    ///
    /// バッファを `mlock` できない場合は [`RecoveryCodeError::MemoryLockFailed`]。
    pub fn grouped(&self) -> Result<LockedBuffer<GROUPED_RECOVERY_CODE_LEN>, RecoveryCodeError> {
        let mut grouped = locked_buffer::<GROUPED_RECOVERY_CODE_LEN>()?;
        let mut symbols = self.code.as_slice().iter();
        for (position, slot) in grouped.as_mut_slice().iter_mut().enumerate() {
            if position % (GROUP_LEN + 1) == GROUP_LEN {
                *slot = b'-';
            } else if let Some(&symbol) = symbols.next() {
                *slot = symbol;
            }
        }
        Ok(grouped)
    }
}

impl fmt::Debug for RecoveryCode {
    /// 内容を表示しない。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryCode(..)")
    }
}

/// リカバリーコードの生成と読み取りの失敗を表すエラー。秘密情報と、誤りの位置は含まない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryCodeError {
    /// 区切りを除いた文字数が一致しない。
    InvalidLength,
    /// プレフィックスが一致しない。
    InvalidPrefix,
    /// 使えない文字がある。
    InvalidCharacter,
    /// チェックサムが一致しない。
    ChecksumMismatch,
    /// バッファのメモリロックに失敗した。
    MemoryLockFailed,
    /// 乱数の取得に失敗した。
    EntropySourceFailed,
}

impl fmt::Display for RecoveryCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(
                formatter,
                "リカバリーコードは、区切りを除いて {RECOVERY_CODE_LEN} 文字で指定してください。"
            ),
            Self::InvalidPrefix => {
                formatter.write_str("リカバリーコードが `FL` で始まっていません。")
            }
            Self::InvalidCharacter => {
                formatter.write_str("リカバリーコードに使えない文字が含まれています。")
            }
            Self::ChecksumMismatch => formatter.write_str(
                "リカバリーコードのチェックサムが一致しません。入力した文字を確認してください。",
            ),
            Self::MemoryLockFailed => {
                formatter.write_str("リカバリーコード用バッファのメモリロックに失敗しました。")
            }
            Self::EntropySourceFailed => formatter.write_str("乱数の取得に失敗しました。"),
        }
    }
}

impl std::error::Error for RecoveryCodeError {}

/// ゼロ埋めした、`mlock` 済みのバッファを確保する。
fn locked_buffer<const N: usize>() -> Result<LockedBuffer<N>, RecoveryCodeError> {
    LockedBuffer::zero_strict().map_err(|_| RecoveryCodeError::MemoryLockFailed)
}

/// 乱数とチェックサムを、正準形に符号化する。
///
/// `secret` は [`RECOVERY_SECRET_LEN`] バイト、`code` は [`RECOVERY_CODE_LEN`] バイトである。
fn encode(secret: &[u8], code: &mut [u8]) {
    let (prefix, payload) = code.split_at_mut(RECOVERY_CODE_PREFIX.len());
    prefix.copy_from_slice(RECOVERY_CODE_PREFIX);
    let mut payload = payload.iter_mut();

    // 乱数 128 bit とチェックサム 12 bit を、上位ビットから 5 bit ずつ文字にする。
    let fields = secret
        .iter()
        .map(|&byte| (u32::from(byte), u8::BITS))
        .chain(core::iter::once((
            u32::from(checksum(secret)),
            CHECKSUM_BITS,
        )));
    let mut pending = 0u32;
    let mut pending_bits = 0u32;
    for (value, width) in fields {
        pending = (pending << width) | value;
        pending_bits += width;
        while pending_bits >= SYMBOL_BITS {
            pending_bits -= SYMBOL_BITS;
            if let Some(slot) = payload.next() {
                *slot = symbol_for(((pending >> pending_bits) & 0x1f) as u8);
            }
        }
        pending &= (1 << pending_bits) - 1;
    }
    volatile_zeroize_words(core::slice::from_mut(&mut pending));
}

/// チェックサムの照合で使う作業値。どの経路で戻る場合も、破棄時に消去する。
#[derive(Default)]
struct ChecksumWork {
    /// 復号したビットのうち、まだバイトに満たない分。最後はチェックサムの 12 bit が残る。
    pending: u32,
    /// CRC の状態 (ビッグエンディアン)。
    crc: [u8; 2],
    /// 復号した乱数から求めたチェックサム。
    expected: [u8; 2],
    /// 入力されたチェックサム。
    provided: [u8; 2],
}

impl ChecksumWork {
    /// すべての作業値をゼロにする。
    fn erase(&mut self) {
        volatile_zeroize_words(core::slice::from_mut(&mut self.pending));
        volatile_zeroize(&mut self.crc);
        volatile_zeroize(&mut self.expected);
        volatile_zeroize(&mut self.provided);
    }
}

impl Drop for ChecksumWork {
    fn drop(&mut self) {
        self.erase();
    }
}

/// 正準形のチェックサムを照合する。
///
/// `code` は、プレフィックスと使える文字だけからなる [`RECOVERY_CODE_LEN`] バイトである。
fn verify_checksum(code: &[u8]) -> Result<(), RecoveryCodeError> {
    // 復号した乱数はバッファに置かず、1 バイトそろうごとに CRC へ反映する。
    let mut work = ChecksumWork {
        crc: prefix_crc().to_be_bytes(),
        ..ChecksumWork::default()
    };
    let mut secret_bytes = 0usize;
    let mut pending_bits = 0u32;
    for &symbol in code.iter().skip(RECOVERY_CODE_PREFIX.len()) {
        let value = symbol_value(symbol).ok_or(RecoveryCodeError::InvalidCharacter)?;
        work.pending = (work.pending << SYMBOL_BITS) | u32::from(value);
        pending_bits += SYMBOL_BITS;
        if secret_bytes < RECOVERY_SECRET_LEN && pending_bits >= u8::BITS {
            pending_bits -= u8::BITS;
            work.crc = crc16_update(
                u16::from_be_bytes(work.crc),
                (work.pending >> pending_bits) as u8,
            )
            .to_be_bytes();
            secret_bytes += 1;
            work.pending &= (1 << pending_bits) - 1;
        }
    }
    // 乱数の後に残る 12 bit が、入力されたチェックサムである。
    work.provided = (work.pending as u16).to_be_bytes();
    work.expected = truncate_crc(u16::from_be_bytes(work.crc)).to_be_bytes();
    if bool::from(ct_eq_array(&work.expected, &work.provided)) {
        Ok(())
    } else {
        Err(RecoveryCodeError::ChecksumMismatch)
    }
}

/// 乱数に対する 12 bit のチェックサムを求める。
fn checksum(secret: &[u8]) -> u16 {
    truncate_crc(
        secret
            .iter()
            .fold(prefix_crc(), |crc, &byte| crc16_update(crc, byte)),
    )
}

/// プレフィックスを反映した CRC の状態を返す。
fn prefix_crc() -> u16 {
    RECOVERY_CODE_PREFIX
        .iter()
        .fold(CRC_INITIAL, |crc, &byte| crc16_update(crc, byte))
}

/// CRC の上位 12 bit を取り出す。
const fn truncate_crc(crc: u16) -> u16 {
    crc >> (u16::BITS - CHECKSUM_BITS)
}

/// 5 bit の値を、Crockford Base32 の文字にする。
///
/// 値によらず全部の文字を走査し、値を添字に使わない。`value` は 32 未満である。
fn symbol_for(value: u8) -> u8 {
    (0u8..)
        .zip(ALPHABET.iter())
        .fold(0, |symbol, (index, &candidate)| {
            ct_select(ct_eq_array(&[index], &[value]), candidate, symbol)
        })
}

/// 入力の 1 文字を、読み替えたうえで 5 bit の値にする。使えない文字は `None`。
fn symbol_value(symbol: u8) -> Option<u8> {
    let upper = symbol.to_ascii_uppercase();
    let is_letter_o = ct_eq_array(&[upper], b"O");
    let is_one_alias = ct_eq_array(&[upper], b"I") | ct_eq_array(&[upper], b"L");
    let canonical = ct_select(is_letter_o, b'0', ct_select(is_one_alias, b'1', upper));

    let mut value = 0u8;
    let mut found = ct_eq_array(&[0u8], &[1u8]);
    for (index, &candidate) in (0u8..).zip(ALPHABET.iter()) {
        let matches = ct_eq_array(&[candidate], &[canonical]);
        value = ct_select(matches, index, value);
        found |= matches;
    }
    bool::from(found).then_some(value)
}

/// CRC-16/CCITT-FALSE の状態に 1 バイトを反映する。
///
/// 内容によって分岐しないように、多項式の適用はマスクで選ぶ。
fn crc16_update(crc: u16, byte: u8) -> u16 {
    (0..u8::BITS).fold(crc ^ (u16::from(byte) << u8::BITS), |state, _| {
        let mask = 0u16.wrapping_sub(state >> (u16::BITS - 1));
        (state << 1) ^ (CRC_POLYNOMIAL & mask)
    })
}

#[cfg(test)]
mod tests {
    use fidelogic_core::SystemError;

    use super::{
        CRC_INITIAL, ChecksumWork, GROUPED_RECOVERY_CODE_LEN, RECOVERY_CODE_LEN,
        RECOVERY_SECRET_LEN, RecoveryCode, RecoveryCodeError, crc16_update, symbol_for,
        symbol_value,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// 仕様の文字集合。添字が 5 bit の値である。
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// 乱数、正準形、表示形の組。実装とは別の参照実装で、仕様から計算した値。
    const VECTORS: [(&str, [u8; RECOVERY_SECRET_LEN], &str, &str); 4] = [
        (
            "全ビット 0",
            [0x00; RECOVERY_SECRET_LEN],
            "FL0000000000000000000000000014",
            "FL000-00000-00000-00000-00000-00014",
        ),
        (
            "全ビット 1",
            [0xff; RECOVERY_SECRET_LEN],
            "FLZZZZZZZZZZZZZZZZZZZZZZZZZW10",
            "FLZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZW10",
        ),
        (
            "連番",
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f,
            ],
            "FL000G40R40M30E209185GR38E1X9Q",
            "FL000-G40R4-0M30E-20918-5GR38-E1X9Q",
        ),
        (
            "文字の並び",
            [
                0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6, 0x35, 0xcf, 0x84, 0x65, 0x3a, 0x56,
                0xd7, 0xc6,
            ],
            "FL0123456789ABCDEFGHJKMNPQRS5X",
            "FL012-34567-89ABC-DEFGH-JKMNP-QRS5X",
        ),
    ];

    /// 指定した乱数を返す乱数源で、コードを作る。
    fn generate_from(secret: [u8; RECOVERY_SECRET_LEN]) -> Result<RecoveryCode, RecoveryCodeError> {
        RecoveryCode::generate(|destination| {
            assert_eq!(destination.len(), RECOVERY_SECRET_LEN);
            destination.copy_from_slice(&secret);
            Ok(())
        })
    }

    /// 読み取りの結果を、正準形かエラーにする。
    fn parsed(input: &[u8]) -> Result<Vec<u8>, RecoveryCodeError> {
        RecoveryCode::parse(input).map(|code| code.as_bytes().to_vec())
    }

    #[test]
    fn test_crc16_matches_published_check_value() {
        let crc = b"123456789"
            .iter()
            .fold(CRC_INITIAL, |crc, &byte| crc16_update(crc, byte));
        assert_eq!(crc, 0x29b1);
    }

    #[test]
    fn test_symbol_for_covers_the_alphabet() {
        for (value, &expected) in (0u8..).zip(ALPHABET.iter()) {
            assert_eq!(symbol_for(value), expected, "値 {value} の符号化に失敗。");
        }
    }

    #[test]
    fn test_symbol_value_accepts_only_alphabet_and_aliases() {
        for symbol in 0..=u8::MAX {
            let canonical = match symbol.to_ascii_uppercase() {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                other => other,
            };
            let expected = (0u8..)
                .zip(ALPHABET.iter())
                .find(|&(_, &candidate)| candidate == canonical)
                .map(|(value, _)| value);
            assert_eq!(
                symbol_value(symbol),
                expected,
                "バイト {symbol:#04x} の復号に失敗。"
            );
        }
    }

    #[test]
    fn test_generate_encodes_reference_vectors() -> TestResult {
        for (name, secret, canonical, _) in VECTORS {
            let code = generate_from(secret)?;
            assert_eq!(
                code.as_bytes(),
                canonical.as_bytes(),
                "{name} の生成に失敗。"
            );
        }
        Ok(())
    }

    #[test]
    fn test_generate_reads_the_source_once() -> TestResult {
        let mut calls = 0;
        RecoveryCode::generate(|destination| {
            calls += 1;
            destination.fill(0x5a);
            Ok(())
        })?;
        assert_eq!(calls, 1);
        Ok(())
    }

    #[test]
    fn test_generate_fails_when_the_source_fails() {
        let result = RecoveryCode::generate(|destination| {
            destination.fill(0xa5);
            Err(SystemError::EntropySourceFailed)
        });
        assert_eq!(
            result.map(|_| ()),
            Err(RecoveryCodeError::EntropySourceFailed)
        );
    }

    #[test]
    fn test_grouped_splits_into_five_characters() -> TestResult {
        for (name, secret, _, grouped) in VECTORS {
            let result = generate_from(secret)?.grouped()?;
            assert_eq!(
                result.as_slice(),
                grouped.as_bytes(),
                "{name} の整形に失敗。"
            );
            assert_eq!(result.len(), GROUPED_RECOVERY_CODE_LEN);
        }
        Ok(())
    }

    #[test]
    fn test_parse_accepts_canonical_and_grouped_forms() {
        for (name, _, canonical, grouped) in VECTORS {
            for input in [canonical, grouped] {
                assert_eq!(
                    parsed(input.as_bytes()),
                    Ok(canonical.as_bytes().to_vec()),
                    "{name} の読み取りに失敗: {input}"
                );
            }
        }
    }

    #[test]
    fn test_parse_normalizes_separators_case_and_aliases() {
        let canonical = "FL0123456789ABCDEFGHJKMNPQRS5X";
        let cases = [
            ("小文字", "fl012-34567-89abc-defgh-jkmnp-qrs5x"),
            ("空白区切り", "FL012 34567 89ABC DEFGH JKMNP QRS5X"),
            (
                "前後と連続の区切り",
                " --FL012--34567  89ABCDEFGHJKMNPQRS5X- ",
            ),
            (
                "プレフィックス内の区切り",
                "F-L 0123456789ABCDEFGHJKMNPQRS5X",
            ),
            (
                "1 文字ごとの区切り",
                "F-L-0-1-2-3-4-5-6-7-8-9-A-B-C-D-E-F-G-H-J-K-M-N-P-Q-R-S-5-X",
            ),
            ("大文字の O と I", "FLOI23456789ABCDEFGHJKMNPQRS5X"),
            ("小文字の o と i", "FLoi23456789ABCDEFGHJKMNPQRS5X"),
            ("大文字の L", "FL0L23456789ABCDEFGHJKMNPQRS5X"),
            ("小文字の l", "fl0l23456789abcdefghjkmnpqrs5x"),
        ];
        for (name, input) in cases {
            assert_eq!(
                parsed(input.as_bytes()),
                Ok(canonical.as_bytes().to_vec()),
                "{name} の読み取りに失敗: {input}"
            );
        }

        // 末尾のチェックサムの文字の読み替えと、大文字と小文字が混ざるプレフィックス。
        let ones = "FLZZZZZZZZZZZZZZZZZZZZZZZZZW10";
        let zeros = "FL0000000000000000000000000014";
        let cases = [
            (
                "チェックサムの I と O",
                "FlZZZZZZZZZZZZZZZZZZZZZZZZZWIO",
                ones,
            ),
            (
                "チェックサムの l と o",
                "fLZZZZZZZZZZZZZZZZZZZZZZZZZWlo",
                ones,
            ),
            ("全体の O と L", "FLOOOOOOOOOOOOOOOOOOOOOOOOOOL4", zeros),
        ];
        for (name, input, expected) in cases {
            assert_eq!(
                parsed(input.as_bytes()),
                Ok(expected.as_bytes().to_vec()),
                "{name} の読み取りに失敗: {input}"
            );
        }
    }

    #[test]
    fn test_parse_rejects_wrong_length() {
        let canonical = "FL0123456789ABCDEFGHJKMNPQRS5X";
        let cases: [(&str, String); 7] = [
            ("空", String::new()),
            ("区切りのみ", "- - -".to_string()),
            ("プレフィックスのみ", "FL".to_string()),
            ("1 文字", "F".to_string()),
            ("29 文字", canonical.chars().take(29).collect()),
            ("31 文字", format!("{canonical}0")),
            ("長大な入力", format!("{canonical}{}", "0".repeat(4096))),
        ];
        for (name, input) in cases {
            assert_eq!(
                parsed(input.as_bytes()),
                Err(RecoveryCodeError::InvalidLength),
                "{name} の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_parse_rejects_wrong_prefix() {
        let cases = [
            ("プレフィックスなし", "0123456789ABCDEFGHJKMNPQRS5X"),
            ("1 文字目が違う", "EL0123456789ABCDEFGHJKMNPQRS5X"),
            ("2 文字目が違う", "FM0123456789ABCDEFGHJKMNPQRS5X"),
            ("L を 1 に読み替えない", "F10123456789ABCDEFGHJKMNPQRS5X"),
            ("L を I に読み替えない", "FI0123456789ABCDEFGHJKMNPQRS5X"),
            ("1 文字目が英数字でない", "!L0123456789ABCDEFGHJKMNPQRS5X"),
            ("2 文字目が英数字でない", "F!0123456789ABCDEFGHJKMNPQRS5X"),
        ];
        for (name, input) in cases {
            assert_eq!(
                parsed(input.as_bytes()),
                Err(RecoveryCodeError::InvalidPrefix),
                "{name} の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_parse_rejects_invalid_characters() {
        // 7 文字目を置き換える。
        let cases = [
            ("U", "U"),
            ("小文字の u", "u"),
            ("下線", "_"),
            ("アスタリスク", "*"),
            ("タブ", "\t"),
            ("改行", "\n"),
            ("NUL", "\0"),
            ("全角の数字", "４"),
            ("全角のハイフン", "－"),
            ("絵文字", "🔑"),
        ];
        for (name, replacement) in cases {
            let input = format!("FL0123{replacement}56789ABCDEFGHJKMNPQRS5X");
            assert_eq!(
                parsed(input.as_bytes()),
                Err(RecoveryCodeError::InvalidCharacter),
                "{name} の拒否に失敗。"
            );
        }
        assert_eq!(
            parsed(&[b'F', b'L', 0xff]),
            Err(RecoveryCodeError::InvalidCharacter),
            "UTF-8 でないバイトの拒否に失敗。"
        );
    }

    #[test]
    fn test_parse_reports_the_leftmost_error() {
        let canonical = "FL0123456789ABCDEFGHJKMNPQRS5X";
        assert_eq!(
            parsed(b"XXU"),
            Err(RecoveryCodeError::InvalidPrefix),
            "プレフィックスの誤りの優先に失敗。"
        );
        assert_eq!(
            parsed(b"FLU"),
            Err(RecoveryCodeError::InvalidCharacter),
            "短い入力の文字の誤りの優先に失敗。"
        );
        assert_eq!(
            parsed(format!("{canonical}U").as_bytes()),
            Err(RecoveryCodeError::InvalidLength),
            "31 文字目の長さの判定に失敗。"
        );
    }

    #[test]
    fn test_parse_rejects_every_single_character_substitution() {
        for (name, _, canonical, _) in VECTORS {
            for position in 2..RECOVERY_CODE_LEN {
                for &replacement in ALPHABET {
                    let mut input = canonical.as_bytes().to_vec();
                    let Some(slot) = input.get_mut(position) else {
                        continue;
                    };
                    if *slot == replacement {
                        continue;
                    }
                    *slot = replacement;
                    assert_eq!(
                        parsed(&input),
                        Err(RecoveryCodeError::ChecksumMismatch),
                        "{name} の {position} 文字目の置換の検出に失敗。"
                    );
                }
            }
        }
    }

    #[test]
    fn test_parse_rejects_every_adjacent_transposition() {
        for (name, _, canonical, _) in VECTORS {
            for position in 2..RECOVERY_CODE_LEN - 1 {
                let mut input = canonical.as_bytes().to_vec();
                input.swap(position, position + 1);
                if input == canonical.as_bytes() {
                    continue;
                }
                assert_eq!(
                    parsed(&input),
                    Err(RecoveryCodeError::ChecksumMismatch),
                    "{name} の {position} 文字目の入れ替えの検出に失敗。"
                );
            }
        }
    }

    #[test]
    fn test_checksum_work_erases_every_field() {
        // フィールドを省略しないことで、追加したときにこのテストの更新を必要にする。
        let mut work = ChecksumWork {
            pending: u32::MAX,
            crc: [0xff; 2],
            expected: [0xff; 2],
            provided: [0xff; 2],
        };
        work.erase();
        let ChecksumWork {
            pending,
            crc,
            expected,
            provided,
        } = work;
        assert_eq!(pending, 0, "未処理のビットの消去に失敗。");
        assert_eq!(crc, [0; 2], "CRC の状態の消去に失敗。");
        assert_eq!(expected, [0; 2], "求めたチェックサムの消去に失敗。");
        assert_eq!(provided, [0; 2], "入力されたチェックサムの消去に失敗。");
    }

    #[test]
    fn test_debug_output_hides_the_code() -> TestResult {
        let code = generate_from([0xff; RECOVERY_SECRET_LEN])?;
        assert_eq!(format!("{code:?}"), "RecoveryCode(..)");
        Ok(())
    }

    #[test]
    fn test_error_messages_end_with_japanese_period() {
        let errors = [
            RecoveryCodeError::InvalidLength,
            RecoveryCodeError::InvalidPrefix,
            RecoveryCodeError::InvalidCharacter,
            RecoveryCodeError::ChecksumMismatch,
            RecoveryCodeError::MemoryLockFailed,
            RecoveryCodeError::EntropySourceFailed,
        ];
        for error in errors {
            assert!(
                error.to_string().ends_with('。'),
                "{error:?} の文末の確認に失敗。"
            );
        }
    }
}
