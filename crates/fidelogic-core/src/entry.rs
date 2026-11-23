//! # エントリの暗号化・チャンク分割・マニフェスト
//!
//! Vault に格納するエントリ (資格情報など) を、固定長の `TAG_ENTRY` レコード列へ変換し、
//! 検証しながら復元する。保存のたびに全レコードを再暗号化する前提である。
//!
//! ## レコードの構造 (ペイロード 255 バイト、ディスク上は 257 バイト)
//!
//! ```text
//! ノンス | AEAD(内側チャンクヘッダー 22B | データ | ゼロパディング) | タグ 16B
//! ```
//!
//! 内側チャンクヘッダーは `entry_id 16B | chunk_index u16 | total_chunks u16 | data_len u16`
//! (ビッグエンディアン) である。ノンスは暗号スイートごとに 24 バイト (XChaCha20-Poly1305) または
//! 12 バイト (AES-256-GCM-SIV) で、1 チャンクのデータ容量は 193 バイトまたは 205 バイトとなる。
//! 全レコードを同じ長さにするため、レコードの長さからエントリの大きさは分からない。
//!
//! ## レコード列の並び
//!
//! 「マニフェストのチャンク、各エントリのチャンク (マニフェストの記載順)」に固定する。
//! マニフェストは予約 `entry_id` (全ゼロ) のエントリで、有効な全エントリの
//! `entry_id 16B | total_chunks u16` を順に並べたものである。
//! 復号側は、入れ替え・欠損・重複・余分なレコードをすべて拒否する。
//! エントリを構成するチャンクを丸ごと削除しても、マニフェストの記載と食い違うため検知できる。
//!
//! ## 関連データと巻き戻し検知
//!
//! AEAD の関連データには [`VaultHeader::associated_data`] (`epoch_id` を含む 14 バイト) をそのまま結合する。
//! 別の世代のレコードを混ぜた場合や、古い世代のレコード列を新しいヘッダーで開いた場合は
//! 認証に失敗する。古い世代のファイルそのものを読み込ませる巻き戻しは、
//! 呼び出し側が [`VaultHeader::verify_epoch_progression`] で検知する。
//!
//! ## ノンスの生成方式
//!
//! ノンスは呼び出し元が与える乱数源でレコードごとに生成する。コアに乱数クレートは無い。
//! 決定論的な生成 (`epoch_id` とレコード番号) は採らない。クラッシュからの復旧や
//! 同じ世代の再書き込みで、同じノンスが別の内容に再利用される恐れがあるためである。
//! XChaCha20-Poly1305 の 192 ビットのノンスは、ランダム生成でも衝突を実用上無視できる。
//! AES-256-GCM-SIV の 96 ビットのノンスは、同じ鍵で 2^32 レコードを暗号化した時点でも衝突確率が約 2^-33 である。
//! 衝突しても、同一の関連データと平文のときに限り等しさが分かるだけで、鍵や平文は漏れない (RFC 8452)。
//!
//! ## エラー
//!
//! 復号側の失敗はすべて [`VaultError::AuthenticationFailed`] に一様化する。
//! 失敗の原因 (順序、欠損、改ざん、世代) を呼び出し元に区別させない。

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::cipher::{CipherSuiteId, TAG_LEN, VaultCipher};
use crate::error::{CryptoError, SystemError, VaultError};
use crate::tlv::{EntryPayload, TlvRecord, VaultHeader};
use crate::zeroize::{SecretBytes, SecretVec};

/// エントリ識別子のバイト長。
pub const ENTRY_ID_LEN: usize = 16;

/// エントリ識別子。
pub type EntryId = [u8; ENTRY_ID_LEN];

/// マニフェスト専用の予約 `entry_id` (全ゼロ)。利用者のエントリには使えない。
pub const MANIFEST_ENTRY_ID: EntryId = [0u8; ENTRY_ID_LEN];

/// `TAG_ENTRY` レコードの固定ペイロード長 (ノンス + 暗号文 + 認証タグ)。
pub const ENTRY_RECORD_PAYLOAD_LEN: usize = 255;

/// 内側チャンクヘッダーのバイト長。
pub const CHUNK_HEADER_LEN: usize = 22;

/// マニフェストの 1 項目 (`entry_id` と `total_chunks`) のバイト長。
pub const MANIFEST_ITEM_LEN: usize = ENTRY_ID_LEN + 2;

/// 内側チャンク (ヘッダー + データ + パディング) の最大長。スタック上の作業領域の大きさに使う。
const MAX_INNER_LEN: usize = 227;

/// ノンスの最大長 (XChaCha20-Poly1305 の 24 バイト)。
const MAX_NONCE_LEN: usize = 24;

/// 暗号化前のエントリ 1 件。
#[derive(Clone, Copy)]
pub struct EntrySource<'a> {
    /// エントリ識別子。全ゼロ (予約値) と、同一 Vault 内の重複は許されない。
    pub entry_id: EntryId,
    /// エントリの平文。内容の消去は呼び出し元の責務である。
    pub data: &'a [u8],
}

impl core::fmt::Debug for EntrySource<'_> {
    /// 平文をログへ出さないため、`data` は長さだけを表示する。
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EntrySource")
            .field("entry_id", &self.entry_id)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// 復号したエントリ 1 件。
#[derive(Debug)]
pub struct OpenedEntry {
    /// エントリ識別子。
    pub entry_id: EntryId,
    /// エントリの平文。破棄時にゼロ消去される。
    pub data: SecretVec,
}

/// 暗号スイートごとの、1 チャンクに収まるデータの最大バイト数を返す。
///
/// XChaCha20-Poly1305 は 193 バイト、AES-256-GCM-SIV は 205 バイトである。
#[must_use]
pub const fn chunk_data_capacity(suite_id: CipherSuiteId) -> usize {
    ENTRY_RECORD_PAYLOAD_LEN - suite_id.nonce_len() - TAG_LEN - CHUNK_HEADER_LEN
}

/// エントリ列とマニフェストを暗号化し、固定長の `TAG_ENTRY` レコード列を返す。
///
/// 並びは「マニフェストのチャンク、各エントリのチャンク (`entries` の順)」である。
/// ノンスは `fill_random` でレコードごとに生成する。
///
/// # Errors
/// - `header.suite_id` が `cipher` の暗号スイートと一致しない場合、
///   予約 `entry_id` の使用、`entry_id` の重複、チャンク数が `u16` を超える大きさのエントリの場合は
///   [`CryptoError::InvalidParameter`] を [`VaultError::Crypto`] に包んで返す。
/// - 乱数源が失敗した場合は [`VaultError::System`]。
/// - 暗号化に失敗した場合は [`VaultError::Crypto`]。
pub fn seal_entries<R>(
    cipher: &VaultCipher,
    header: &VaultHeader,
    entries: &[EntrySource<'_>],
    fill_random: R,
) -> Result<Vec<TlvRecord>, VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    let mut fill_random = fill_random;
    if header.suite_id != cipher.suite_id().as_u8() {
        return Err(invalid_parameter());
    }
    let capacity = chunk_data_capacity(cipher.suite_id());
    let aad = header.associated_data();

    let mut seen = BTreeSet::new();
    let mut manifest = Vec::with_capacity(entries.len().saturating_mul(MANIFEST_ITEM_LEN));
    for entry in entries {
        if entry.entry_id == MANIFEST_ENTRY_ID || !seen.insert(entry.entry_id) {
            return Err(invalid_parameter());
        }
        let total = chunk_total(entry.data.len(), capacity)?;
        manifest.extend_from_slice(&entry.entry_id);
        manifest.extend_from_slice(&total.to_be_bytes());
    }

    let mut records = Vec::new();
    seal_stream(
        cipher,
        &aad,
        &MANIFEST_ENTRY_ID,
        &manifest,
        &mut records,
        &mut fill_random,
    )?;
    for entry in entries {
        seal_stream(
            cipher,
            &aad,
            &entry.entry_id,
            entry.data,
            &mut records,
            &mut fill_random,
        )?;
    }
    Ok(records)
}

/// 不正な引数を表すエラーを返す。
const fn invalid_parameter() -> VaultError {
    VaultError::Crypto(CryptoError::InvalidParameter)
}

/// データ長に対するチャンク数を返す。空データも 1 チャンクとして扱う。
///
/// # Errors
/// チャンク数が `u16` に収まらない場合は [`CryptoError::InvalidParameter`]。
fn chunk_total(data_len: usize, capacity: usize) -> Result<u16, VaultError> {
    let count = data_len.div_ceil(capacity).max(1);
    u16::try_from(count).map_err(|_| invalid_parameter())
}

/// 1 つのエントリ (またはマニフェスト) をチャンクへ分割して暗号化し、`out` に追加する。
fn seal_stream<R>(
    cipher: &VaultCipher,
    aad: &[u8],
    entry_id: &EntryId,
    data: &[u8],
    out: &mut Vec<TlvRecord>,
    fill_random: &mut R,
) -> Result<(), VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    let capacity = chunk_data_capacity(cipher.suite_id());
    let total = chunk_total(data.len(), capacity)?;
    for index in 0..total {
        let start = usize::from(index) * capacity;
        let end = data.len().min(start + capacity);
        let chunk = data.get(start..end).unwrap_or(&[]);
        out.push(seal_chunk(
            cipher,
            aad,
            entry_id,
            index,
            total,
            chunk,
            fill_random,
        )?);
    }
    Ok(())
}

/// 1 チャンクを暗号化して固定長の `TAG_ENTRY` レコードにする。
fn seal_chunk<R>(
    cipher: &VaultCipher,
    aad: &[u8],
    entry_id: &EntryId,
    index: u16,
    total: u16,
    chunk: &[u8],
    fill_random: &mut R,
) -> Result<TlvRecord, VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    let nonce_len = cipher.nonce_len();
    let inner_len = ENTRY_RECORD_PAYLOAD_LEN - nonce_len - TAG_LEN;
    let data_len = u16::try_from(chunk.len()).map_err(|_| invalid_parameter())?;

    let mut nonce = [0u8; MAX_NONCE_LEN];
    let nonce = nonce.get_mut(..nonce_len).ok_or_else(invalid_parameter)?;
    fill_random(nonce)?;

    let mut work = SecretBytes::<MAX_INNER_LEN>::zero();
    let inner = work
        .as_mut_slice()
        .get_mut(..inner_len)
        .ok_or_else(invalid_parameter)?;
    write_at(inner, 0, entry_id)?;
    write_at(inner, 16, &index.to_be_bytes())?;
    write_at(inner, 18, &total.to_be_bytes())?;
    write_at(inner, 20, &data_len.to_be_bytes())?;
    write_at(inner, CHUNK_HEADER_LEN, chunk)?;

    let auth_tag = cipher.encrypt_in_place_detached(nonce, aad, inner)?;

    let mut ciphertext = Vec::with_capacity(nonce_len + inner_len);
    ciphertext.extend_from_slice(nonce);
    ciphertext.extend_from_slice(inner);
    Ok(TlvRecord::Entry(EntryPayload::new(ciphertext, auth_tag)))
}

/// `dst` の `offset` 以降へ `src` を書き込む。範囲外の場合は [`CryptoError::InvalidSliceLength`]。
fn write_at(dst: &mut [u8], offset: usize, src: &[u8]) -> Result<(), VaultError> {
    let end = offset
        .checked_add(src.len())
        .ok_or(VaultError::Crypto(CryptoError::InvalidSliceLength))?;
    dst.get_mut(offset..end)
        .ok_or(VaultError::Crypto(CryptoError::InvalidSliceLength))?
        .copy_from_slice(src);
    Ok(())
}

/// [`seal_entries`] が作ったレコード列を検証しながら復号する。
///
/// `TlvRecord::Unknown` は無視する。それ以外のレコードは、マニフェストの記載と過不足なく一致しなければならない。
///
/// # Errors
/// 認証失敗、順序の入れ替え、欠損、重複、余分なレコード、世代の不一致、形式の不正はすべて
/// [`VaultError::AuthenticationFailed`] を返す。
pub fn open_entries(
    cipher: &VaultCipher,
    header: &VaultHeader,
    records: &[TlvRecord],
) -> Result<Vec<OpenedEntry>, VaultError> {
    open_entries_inner(cipher, header, records).map_err(|_| VaultError::AuthenticationFailed)
}

/// 復号したチャンクの内側ヘッダー。データ本体は作業領域の `CHUNK_HEADER_LEN` 以降にある。
struct ChunkMeta {
    entry_id: EntryId,
    index: u16,
    total: u16,
    data_len: usize,
}

/// [`open_entries`] の本体。失敗の種類は呼び出し側で一様化する。
fn open_entries_inner(
    cipher: &VaultCipher,
    header: &VaultHeader,
    records: &[TlvRecord],
) -> Result<Vec<OpenedEntry>, VaultError> {
    if header.suite_id != cipher.suite_id().as_u8() {
        return Err(invalid_parameter());
    }
    let aad = header.associated_data();
    let mut payloads = records.iter().filter_map(|record| match record {
        TlvRecord::Entry(payload) => Some(payload),
        TlvRecord::Unknown { .. } => None,
    });
    let mut work = SecretBytes::<MAX_INNER_LEN>::zero();

    let manifest = read_stream(
        cipher,
        &aad,
        &MANIFEST_ENTRY_ID,
        None,
        &mut payloads,
        &mut work,
    )?;
    if manifest.len() % MANIFEST_ITEM_LEN != 0 {
        return Err(invalid_parameter());
    }

    let mut seen = BTreeSet::new();
    let mut opened = Vec::with_capacity(manifest.len() / MANIFEST_ITEM_LEN);
    for item in manifest.as_slice().chunks_exact(MANIFEST_ITEM_LEN) {
        let (id_bytes, total_bytes) = item.split_at(ENTRY_ID_LEN);
        let entry_id: EntryId = id_bytes.try_into().map_err(|_| invalid_parameter())?;
        let total = u16::from_be_bytes(total_bytes.try_into().map_err(|_| invalid_parameter())?);
        if entry_id == MANIFEST_ENTRY_ID || total == 0 || !seen.insert(entry_id) {
            return Err(invalid_parameter());
        }
        let data = read_stream(
            cipher,
            &aad,
            &entry_id,
            Some(total),
            &mut payloads,
            &mut work,
        )?;
        opened.push(OpenedEntry { entry_id, data });
    }
    if payloads.next().is_some() {
        return Err(invalid_parameter());
    }
    Ok(opened)
}

/// 同じ `entry_id` のチャンク列を先頭から読み、検証しながらデータを連結する。
///
/// `expected_total` が `None` のとき (マニフェスト) は、先頭チャンクの `total_chunks` に従う。
/// 全チャンクが満杯で、最後のチャンクだけが端数であることを要求し、正準でない分割を拒否する。
fn read_stream<'a, I>(
    cipher: &VaultCipher,
    aad: &[u8],
    entry_id: &EntryId,
    expected_total: Option<u16>,
    payloads: &mut I,
    work: &mut SecretBytes<MAX_INNER_LEN>,
) -> Result<SecretVec, VaultError>
where
    I: Iterator<Item = &'a EntryPayload>,
{
    let capacity = chunk_data_capacity(cipher.suite_id());
    let mut data = SecretVec::new();
    let mut total = expected_total;
    let mut index: u16 = 0;
    loop {
        let payload = payloads.next().ok_or_else(invalid_parameter)?;
        let meta = open_chunk(cipher, aad, payload, work)?;
        let stream_total = *total.get_or_insert(meta.total);
        if meta.entry_id != *entry_id
            || meta.index != index
            || meta.total != stream_total
            || stream_total == 0
        {
            return Err(invalid_parameter());
        }
        let is_last = index + 1 == stream_total;
        let canonical = if is_last {
            stream_total == 1 || meta.data_len >= 1
        } else {
            meta.data_len == capacity
        };
        if !canonical {
            return Err(invalid_parameter());
        }
        let end = CHUNK_HEADER_LEN + meta.data_len;
        data.extend_from_slice(
            work.as_slice()
                .get(CHUNK_HEADER_LEN..end)
                .ok_or_else(invalid_parameter)?,
        );
        if is_last {
            return Ok(data);
        }
        index += 1;
    }
}

/// 1 レコードを復号して内側ヘッダーを検証する。データは `work` の `CHUNK_HEADER_LEN` 以降に残る。
fn open_chunk(
    cipher: &VaultCipher,
    aad: &[u8],
    payload: &EntryPayload,
    work: &mut SecretBytes<MAX_INNER_LEN>,
) -> Result<ChunkMeta, VaultError> {
    let nonce_len = cipher.nonce_len();
    let inner_len = ENTRY_RECORD_PAYLOAD_LEN - nonce_len - TAG_LEN;
    if payload.ciphertext.len() != nonce_len + inner_len {
        return Err(invalid_parameter());
    }
    let (nonce, encrypted) = payload.ciphertext.split_at(nonce_len);
    let inner = work
        .as_mut_slice()
        .get_mut(..inner_len)
        .ok_or_else(invalid_parameter)?;
    inner.copy_from_slice(encrypted);
    cipher.decrypt_in_place_detached_tag(nonce, aad, inner, &payload.auth_tag)?;

    let entry_id: EntryId = inner
        .get(..ENTRY_ID_LEN)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(invalid_parameter)?;
    let index = read_u16(inner, 16)?;
    let total = read_u16(inner, 18)?;
    let data_len = usize::from(read_u16(inner, 20)?);
    let capacity = inner_len - CHUNK_HEADER_LEN;
    if data_len > capacity || index >= total {
        return Err(invalid_parameter());
    }
    // パディングはすべてゼロでなければならない。
    let padding = inner
        .get(CHUNK_HEADER_LEN + data_len..)
        .ok_or_else(invalid_parameter)?;
    if padding.iter().fold(0u8, |acc, byte| acc | byte) != 0 {
        return Err(invalid_parameter());
    }
    Ok(ChunkMeta {
        entry_id,
        index,
        total,
        data_len,
    })
}

/// `src` の `offset` からビッグエンディアンの `u16` を読む。
fn read_u16(src: &[u8], offset: usize) -> Result<u16, VaultError> {
    let bytes: [u8; 2] = src
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(VaultError::Crypto(CryptoError::InvalidSliceLength))?;
    Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tlv::{AUTH_TAG_LEN, record_serialized_len, serialize_record};
    use alloc::format;
    use alloc::vec;

    const SUITES: [CipherSuiteId; 2] = [
        CipherSuiteId::XChaCha20Poly1305,
        CipherSuiteId::Aes256GcmSiv,
    ];

    fn make_cipher(suite: CipherSuiteId) -> VaultCipher {
        VaultCipher::new(suite, &[0x42u8; 32])
    }

    fn make_header(suite: CipherSuiteId, epoch: u64) -> VaultHeader {
        VaultHeader::new(1, suite.as_u8(), epoch)
    }

    /// 呼び出しごとに異なるノンスを埋める決定論的な乱数源 (テスト専用)。
    fn counter_rng() -> impl FnMut(&mut [u8]) -> Result<(), SystemError> {
        let mut counter: u64 = 0;
        move |buf: &mut [u8]| {
            counter += 1;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = counter.to_le_bytes()[i % 8] ^ (i as u8).wrapping_mul(31);
            }
            Ok(())
        }
    }

    fn id(n: u8) -> EntryId {
        [n; ENTRY_ID_LEN]
    }

    fn data_of(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_add(seed)).collect()
    }

    fn seal(suite: CipherSuiteId, epoch: u64, lens: &[usize]) -> (Vec<TlvRecord>, Vec<Vec<u8>>) {
        let datas: Vec<Vec<u8>> = lens
            .iter()
            .enumerate()
            .map(|(i, &len)| data_of(len, i as u8))
            .collect();
        let sources: Vec<EntrySource<'_>> = datas
            .iter()
            .enumerate()
            .map(|(i, d)| EntrySource {
                entry_id: id(i as u8 + 1),
                data: d,
            })
            .collect();
        let records = seal_entries(
            &make_cipher(suite),
            &make_header(suite, epoch),
            &sources,
            counter_rng(),
        )
        .expect("テスト用エントリの暗号化に失敗しました。");
        (records, datas)
    }

    fn open(
        suite: CipherSuiteId,
        epoch: u64,
        records: &[TlvRecord],
    ) -> Result<Vec<OpenedEntry>, VaultError> {
        open_entries(&make_cipher(suite), &make_header(suite, epoch), records)
    }

    // ---- 正常系 ----

    #[test]
    fn test_chunk_capacity_per_suite() {
        assert_eq!(chunk_data_capacity(CipherSuiteId::XChaCha20Poly1305), 193);
        assert_eq!(chunk_data_capacity(CipherSuiteId::Aes256GcmSiv), 205);
    }

    #[test]
    fn test_roundtrip_boundary_lengths() {
        for suite in SUITES {
            let cap = chunk_data_capacity(suite);
            let lens = [
                0,
                1,
                cap - 1,
                cap,
                cap + 1,
                2 * cap,
                2 * cap + 1,
                1000,
                4096,
            ];
            let (records, datas) = seal(suite, 7, &lens);
            let opened = open(suite, 7, &records).expect("復号に失敗しました。");
            assert_eq!(
                opened.len(),
                lens.len(),
                "エントリ数の復元に成功 ({suite:?})。"
            );
            for (i, entry) in opened.iter().enumerate() {
                assert_eq!(
                    entry.entry_id,
                    id(i as u8 + 1),
                    "entry_id の復元に成功 ({suite:?}, {i})。"
                );
                assert_eq!(
                    entry.data.as_slice(),
                    datas[i].as_slice(),
                    "平文の復元に成功 ({suite:?}, 長さ {})。",
                    lens[i]
                );
            }
        }
    }

    #[test]
    fn test_every_record_is_fixed_length_entry() {
        for suite in SUITES {
            let (records, _) = seal(suite, 1, &[0, 5, 500]);
            for (i, record) in records.iter().enumerate() {
                let TlvRecord::Entry(payload) = record else {
                    panic!("レコード {i} が Entry であること。");
                };
                assert_eq!(
                    payload.ciphertext.len() + AUTH_TAG_LEN,
                    ENTRY_RECORD_PAYLOAD_LEN,
                    "ペイロード長が 255 バイトに固定 ({suite:?}, {i})。"
                );
                assert_eq!(
                    record_serialized_len(record),
                    Ok(257),
                    "ディスク上の長さが 257 バイト ({suite:?}, {i})。"
                );
            }
        }
    }

    #[test]
    fn test_record_count_matches_manifest_and_chunks() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        // マニフェスト 1 チャンク + 空 1 + 193 バイト 1 + 194 バイト 2
        let (records, _) = seal(suite, 1, &[0, 193, 194]);
        assert_eq!(records.len(), 1 + 1 + 1 + 2, "レコード数の一致に成功。");
    }

    #[test]
    fn test_manifest_spans_multiple_chunks() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        // 193 / 18 = 10 項目で 1 チャンクに収まるため、11 件で 2 チャンクになる。
        let lens = [0usize; 11];
        let (records, datas) = seal(suite, 1, &lens);
        assert_eq!(
            records.len(),
            2 + 11,
            "マニフェスト 2 チャンクの生成に成功。"
        );
        let opened = open(suite, 1, &records).expect("復号に失敗しました。");
        assert_eq!(
            opened.len(),
            datas.len(),
            "多チャンクのマニフェストの復元に成功。"
        );
    }

    #[test]
    fn test_empty_entry_list_has_single_manifest_record() {
        for suite in SUITES {
            let (records, _) = seal(suite, 1, &[]);
            assert_eq!(
                records.len(),
                1,
                "空 Vault のマニフェストが 1 レコード ({suite:?})。"
            );
            let opened = open(suite, 1, &records).expect("復号に失敗しました。");
            assert!(opened.is_empty(), "空 Vault の復元に成功 ({suite:?})。");
        }
    }

    #[test]
    fn test_nonces_differ_between_records() {
        let (records, _) = seal(CipherSuiteId::Aes256GcmSiv, 1, &[600]);
        let nonces: Vec<&[u8]> = records
            .iter()
            .map(|r| match r {
                TlvRecord::Entry(p) => &p.ciphertext[..12],
                TlvRecord::Unknown { .. } => &[][..],
            })
            .collect();
        for (i, a) in nonces.iter().enumerate() {
            for b in &nonces[i + 1..] {
                assert_ne!(a, b, "レコードごとに異なるノンスの使用に成功。");
            }
        }
    }

    #[test]
    fn test_unknown_records_are_ignored_on_open() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (mut records, datas) = seal(suite, 1, &[10, 300]);
        records.insert(
            2,
            TlvRecord::new_unknown(0x7f, vec![1, 2, 3]).expect("未知タグの生成に失敗しました。"),
        );
        records.push(
            TlvRecord::new_unknown(0x80, Vec::new()).expect("未知タグの生成に失敗しました。"),
        );
        let opened = open(suite, 1, &records).expect("未知レコードを無視して復号できること。");
        assert_eq!(opened.len(), datas.len(), "未知レコードの無視に成功。");
    }

    #[test]
    fn test_serialized_records_roundtrip_through_tlv() {
        let suite = CipherSuiteId::Aes256GcmSiv;
        let (records, datas) = seal(suite, 3, &[0, 400]);
        let mut restored = Vec::new();
        for record in &records {
            let bytes = serialize_record(record).expect("シリアライズに失敗しました。");
            let (parsed, rest) =
                crate::tlv::deserialize_record(&bytes).expect("デシリアライズに失敗しました。");
            assert!(rest.is_empty());
            restored.push(parsed);
        }
        let opened = open(suite, 3, &restored).expect("復号に失敗しました。");
        assert_eq!(
            opened[1].data.as_slice(),
            datas[1].as_slice(),
            "TLV 往復後の復号に成功。"
        );
    }

    // ---- 異常系: 復号 ----

    fn assert_rejected(result: Result<Vec<OpenedEntry>, VaultError>, what: &str) {
        assert!(
            matches!(result, Err(VaultError::AuthenticationFailed)),
            "{what}の拒否に失敗。"
        );
    }

    #[test]
    fn test_open_rejects_reordered_records() {
        for suite in SUITES {
            let (mut records, _) = seal(suite, 1, &[300, 300]);
            let last = records.len() - 1;
            records.swap(1, last);
            assert_rejected(open(suite, 1, &records), "エントリ間の順序入れ替え");
        }
    }

    #[test]
    fn test_open_rejects_chunk_swap_within_entry() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (mut records, _) = seal(suite, 1, &[500]);
        records.swap(1, 2);
        assert_rejected(open(suite, 1, &records), "チャンクの入れ替え");
    }

    #[test]
    fn test_open_rejects_missing_records() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (records, _) = seal(suite, 1, &[500, 10]);
        for index in 0..records.len() {
            let mut cut = records.clone();
            cut.remove(index);
            assert_rejected(open(suite, 1, &cut), &format!("レコード {index} の欠損"));
        }
    }

    #[test]
    fn test_open_rejects_whole_entry_deletion() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        // マニフェスト 1 + エントリ 1 (2 チャンク) + エントリ 2 (1 チャンク)。エントリ 1 を丸ごと消す。
        let (mut records, _) = seal(suite, 1, &[300, 10]);
        records.drain(1..3);
        assert_rejected(open(suite, 1, &records), "エントリ単位の削除");
    }

    #[test]
    fn test_open_rejects_truncated_tail_entry() {
        let suite = CipherSuiteId::Aes256GcmSiv;
        let (mut records, _) = seal(suite, 1, &[10, 10]);
        records.pop();
        assert_rejected(open(suite, 1, &records), "末尾エントリの削除");
    }

    #[test]
    fn test_open_rejects_duplicated_record() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (mut records, _) = seal(suite, 1, &[500]);
        let dup = records[1].clone();
        records.insert(2, dup);
        assert_rejected(open(suite, 1, &records), "チャンクの重複");
    }

    #[test]
    fn test_open_rejects_extra_trailing_record() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (mut records, _) = seal(suite, 1, &[10]);
        let extra = records[1].clone();
        records.push(extra);
        assert_rejected(open(suite, 1, &records), "余分なレコード");
    }

    #[test]
    fn test_open_rejects_epoch_mismatch() {
        for suite in SUITES {
            let (records, _) = seal(suite, 5, &[10, 400]);
            assert_rejected(open(suite, 6, &records), "別世代のヘッダーでの復号");
            assert_rejected(open(suite, 4, &records), "古い世代のヘッダーでの復号");
        }
    }

    #[test]
    fn test_open_rejects_records_mixed_from_other_epoch() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (mut current, _) = seal(suite, 2, &[10, 10]);
        let (old, _) = seal(suite, 1, &[10, 10]);
        current[2] = old[2].clone();
        assert_rejected(open(suite, 2, &current), "世代の混入");
    }

    #[test]
    fn test_open_rejects_wrong_key() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (records, _) = seal(suite, 1, &[10]);
        let other = VaultCipher::new(suite, &[0x43u8; 32]);
        assert_rejected(
            open_entries(&other, &make_header(suite, 1), &records),
            "別の鍵での復号",
        );
    }

    #[test]
    fn test_open_rejects_tampered_bytes() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (records, _) = seal(suite, 1, &[10]);
        for index in 0..records.len() {
            let mut body = records.clone();
            if let TlvRecord::Entry(p) = &mut body[index] {
                p.ciphertext[30] ^= 1;
            }
            assert_rejected(open(suite, 1, &body), "暗号文の改ざん");
            let mut tag = records.clone();
            if let TlvRecord::Entry(p) = &mut tag[index] {
                p.auth_tag[0] ^= 1;
            }
            assert_rejected(open(suite, 1, &tag), "認証タグの改ざん");
        }
    }

    #[test]
    fn test_open_rejects_wrong_ciphertext_length() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let (mut records, _) = seal(suite, 1, &[10]);
        if let TlvRecord::Entry(p) = &mut records[0] {
            p.ciphertext.pop();
        }
        assert_rejected(open(suite, 1, &records), "短いレコード");
    }

    #[test]
    fn test_open_rejects_empty_record_list() {
        assert_rejected(
            open(CipherSuiteId::XChaCha20Poly1305, 1, &[]),
            "マニフェストの無いレコード列",
        );
    }

    // ---- 異常系: 非正準なレコードの拒否 ----

    /// 指定した内側ヘッダーとデータで、正規の手順を経ずにレコードを組み立てる (テスト専用)。
    fn forge_record(
        suite: CipherSuiteId,
        epoch: u64,
        entry_id: EntryId,
        index: u16,
        total: u16,
        data: &[u8],
        padding_byte: u8,
    ) -> TlvRecord {
        forge_record_with_len(
            suite,
            epoch,
            entry_id,
            index,
            total,
            data,
            data.len() as u16,
            padding_byte,
        )
    }

    /// 内側ヘッダーの `data_len` を実際のデータ長と独立に指定できる偽造ヘルパー。
    #[allow(clippy::too_many_arguments)]
    fn forge_record_with_len(
        suite: CipherSuiteId,
        epoch: u64,
        entry_id: EntryId,
        index: u16,
        total: u16,
        data: &[u8],
        declared_len: u16,
        padding_byte: u8,
    ) -> TlvRecord {
        let cipher = make_cipher(suite);
        let nonce_len = cipher.nonce_len();
        let inner_len = ENTRY_RECORD_PAYLOAD_LEN - nonce_len - TAG_LEN;
        let mut inner = vec![padding_byte; inner_len];
        inner[..CHUNK_HEADER_LEN].fill(0);
        inner[..16].copy_from_slice(&entry_id);
        inner[16..18].copy_from_slice(&index.to_be_bytes());
        inner[18..20].copy_from_slice(&total.to_be_bytes());
        inner[20..22].copy_from_slice(&declared_len.to_be_bytes());
        inner[22..22 + data.len()].copy_from_slice(data);
        let nonce = vec![9u8; nonce_len];
        let tag = cipher
            .encrypt_in_place_detached(
                &nonce,
                &make_header(suite, epoch).associated_data(),
                &mut inner,
            )
            .expect("偽造レコードの暗号化に失敗しました。");
        let mut ciphertext = nonce;
        ciphertext.extend_from_slice(&inner);
        TlvRecord::Entry(EntryPayload::new(ciphertext, tag))
    }

    /// 空のマニフェストの正規レコード。
    fn empty_manifest(suite: CipherSuiteId) -> TlvRecord {
        forge_record(suite, 1, MANIFEST_ENTRY_ID, 0, 1, &[], 0)
    }

    #[test]
    fn test_forge_helper_produces_valid_empty_vault() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let opened = open(suite, 1, &[empty_manifest(suite)])
            .expect("偽造ヘルパーの正規レコードの復号に失敗しました。");
        assert!(
            opened.is_empty(),
            "偽造ヘルパーの正規レコードの復号に成功。"
        );
    }

    #[test]
    fn test_open_rejects_nonzero_padding() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let bad = forge_record(suite, 1, MANIFEST_ENTRY_ID, 0, 1, &[], 0x55);
        assert_rejected(open(suite, 1, &[bad]), "非ゼロのパディング");
    }

    #[test]
    fn test_open_rejects_non_canonical_chunking() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let cap = chunk_data_capacity(suite);
        // マニフェストが 2 チャンクで、先頭チャンクが満杯でない。
        let short_first = [
            forge_record(suite, 1, MANIFEST_ENTRY_ID, 0, 2, &[0u8; 18], 0),
            forge_record(suite, 1, MANIFEST_ENTRY_ID, 1, 2, &[0u8; 18], 0),
        ];
        assert_rejected(open(suite, 1, &short_first), "満杯でない先頭チャンク");
        // マニフェストが 2 チャンクで、最後のチャンクが空。
        let empty_last = [
            forge_record(suite, 1, MANIFEST_ENTRY_ID, 0, 2, &vec![0u8; cap], 0),
            forge_record(suite, 1, MANIFEST_ENTRY_ID, 1, 2, &[], 0),
        ];
        assert_rejected(open(suite, 1, &empty_last), "空の最終チャンク");
    }

    #[test]
    fn test_open_rejects_header_inconsistencies() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let bad_index = forge_record(suite, 1, MANIFEST_ENTRY_ID, 1, 1, &[], 0);
        assert_rejected(open(suite, 1, &[bad_index]), "total 以上の chunk_index");
        let wrong_id = forge_record(suite, 1, id(1), 0, 1, &[], 0);
        assert_rejected(
            open(suite, 1, &[wrong_id]),
            "マニフェストでない先頭レコード",
        );
        let mut tampered = forge_record(suite, 1, MANIFEST_ENTRY_ID, 0, 1, &[0u8; 10], 0);
        if let TlvRecord::Entry(p) = &mut tampered {
            p.auth_tag[0] ^= 1;
        }
        assert_rejected(open(suite, 1, &[tampered]), "タグ不一致のレコード");
    }

    #[test]
    fn test_open_rejects_declared_length_over_capacity() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let cap = chunk_data_capacity(suite) as u16;
        let bad = forge_record_with_len(suite, 1, MANIFEST_ENTRY_ID, 0, 1, &[], cap + 1, 0);
        assert_rejected(open(suite, 1, &[bad]), "容量を超える data_len");
    }

    /// 偽造したマニフェスト 1 チャンクと、その後ろのレコード列を開く。
    fn open_forged_manifest(
        manifest: &[u8],
        tail: &[TlvRecord],
    ) -> Result<Vec<OpenedEntry>, VaultError> {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let mut records = vec![forge_record(suite, 1, MANIFEST_ENTRY_ID, 0, 1, manifest, 0)];
        records.extend_from_slice(tail);
        open(suite, 1, &records)
    }

    fn manifest_item(entry_id: EntryId, total: u16) -> Vec<u8> {
        let mut item = entry_id.to_vec();
        item.extend_from_slice(&total.to_be_bytes());
        item
    }

    #[test]
    fn test_open_rejects_malformed_manifest() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let entry = forge_record(suite, 1, id(1), 0, 1, b"x", 0);

        // 正規のマニフェストなら復号できる (偽造手順の確認)。
        let ok = open_forged_manifest(&manifest_item(id(1), 1), core::slice::from_ref(&entry));
        assert_eq!(
            ok.map(|v| v.len()).ok(),
            Some(1),
            "偽造した正規マニフェストの復号に成功。"
        );

        let mut truncated = manifest_item(id(1), 1);
        truncated.pop();
        assert_rejected(
            open_forged_manifest(&truncated, core::slice::from_ref(&entry)),
            "項目長の倍数でないマニフェスト",
        );
        assert_rejected(
            open_forged_manifest(
                &manifest_item(MANIFEST_ENTRY_ID, 1),
                core::slice::from_ref(&entry),
            ),
            "予約 entry_id を含むマニフェスト",
        );
        assert_rejected(
            open_forged_manifest(&manifest_item(id(1), 0), &[]),
            "total が 0 のマニフェスト項目",
        );
        let mut duplicated = manifest_item(id(1), 1);
        duplicated.extend(manifest_item(id(1), 1));
        assert_rejected(
            open_forged_manifest(&duplicated, &[entry.clone(), entry.clone()]),
            "重複する entry_id のマニフェスト",
        );
        // マニフェストは 2 チャンクと記載しているが、実際のエントリのチャンクは total = 1。
        assert_rejected(
            open_forged_manifest(&manifest_item(id(1), 2), core::slice::from_ref(&entry)),
            "total の食い違い",
        );
        // マニフェストの記載と別の entry_id のチャンクが続く。
        let other = forge_record(suite, 1, id(2), 0, 1, b"x", 0);
        assert_rejected(
            open_forged_manifest(&manifest_item(id(1), 1), &[other]),
            "entry_id の食い違い",
        );
    }

    #[test]
    fn test_entry_source_debug_redacts_plaintext() {
        let source = EntrySource {
            entry_id: id(1),
            data: &[0xDE, 0xAD, 0xBE, 0xEF],
        };
        let text = format!("{source:?}");
        assert!(text.contains("data_len: 4"), "データ長の表示に失敗。");
        assert!(
            !text.contains("222") && !text.contains("0xDE"),
            "平文バイトの非表示に失敗。"
        );
    }

    // ---- 異常系: 暗号化 ----

    fn seal_with(
        entries: &[EntrySource<'_>],
        suite: CipherSuiteId,
        header_suite: CipherSuiteId,
    ) -> Result<Vec<TlvRecord>, VaultError> {
        seal_entries(
            &make_cipher(suite),
            &make_header(header_suite, 1),
            entries,
            counter_rng(),
        )
    }

    #[test]
    fn test_seal_rejects_reserved_entry_id() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let entries = [EntrySource {
            entry_id: MANIFEST_ENTRY_ID,
            data: b"x",
        }];
        assert_eq!(
            seal_with(&entries, suite, suite).err(),
            Some(VaultError::Crypto(CryptoError::InvalidParameter)),
            "予約 entry_id の拒否に失敗。"
        );
    }

    #[test]
    fn test_seal_rejects_duplicate_entry_id() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let entries = [
            EntrySource {
                entry_id: id(1),
                data: b"a",
            },
            EntrySource {
                entry_id: id(1),
                data: b"b",
            },
        ];
        assert_eq!(
            seal_with(&entries, suite, suite).err(),
            Some(VaultError::Crypto(CryptoError::InvalidParameter)),
            "entry_id の重複の拒否に失敗。"
        );
    }

    #[test]
    fn test_seal_rejects_suite_mismatch() {
        let entries = [EntrySource {
            entry_id: id(1),
            data: b"a",
        }];
        let result = seal_with(
            &entries,
            CipherSuiteId::XChaCha20Poly1305,
            CipherSuiteId::Aes256GcmSiv,
        );
        assert_eq!(
            result.err(),
            Some(VaultError::Crypto(CryptoError::InvalidParameter)),
            "暗号スイートの不一致の拒否に失敗。"
        );
    }

    #[test]
    fn test_seal_rejects_too_many_chunks() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let big = vec![0u8; chunk_data_capacity(suite) * 65_536];
        let entries = [EntrySource {
            entry_id: id(1),
            data: &big,
        }];
        assert_eq!(
            seal_with(&entries, suite, suite).err(),
            Some(VaultError::Crypto(CryptoError::InvalidParameter)),
            "チャンク数の上限超過の拒否に失敗。"
        );
    }

    #[test]
    fn test_seal_propagates_rng_failure() {
        let suite = CipherSuiteId::XChaCha20Poly1305;
        let entries = [EntrySource {
            entry_id: id(1),
            data: b"a",
        }];
        let result = seal_entries(
            &make_cipher(suite),
            &make_header(suite, 1),
            &entries,
            |_: &mut [u8]| Err(SystemError::EntropySourceFailed),
        );
        assert_eq!(
            result.err(),
            Some(VaultError::System(SystemError::EntropySourceFailed)),
            "乱数源の失敗の伝播に失敗。"
        );
    }
}
