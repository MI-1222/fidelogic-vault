//! # エントリのチャンク分割・マニフェストのプロパティテストスイート。
//!
//! ランダム生成したエントリ列を `seal_entries` / `open_entries` で往復させ、
//! 往復の可逆性と、順序入れ替え・欠損・重複・世代の混入・エントリ単位の削除の拒否を検証する。

use fidelogic_core::cipher::{CipherSuiteId, VaultCipher};
use fidelogic_core::entry::{
    ENTRY_ID_LEN, EntryId, EntrySource, chunk_data_capacity, open_entries, seal_entries,
};
use fidelogic_core::error::{SystemError, VaultError};
use fidelogic_core::tlv::{TlvRecord, VaultHeader};
use proptest::prelude::*;

/// 本スイートで使う `ProptestConfig` を構築する。
fn entry_proptest_config() -> ProptestConfig {
    ProptestConfig {
        cases: 512,
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// 暗号スイートを選ぶストラテジ。
fn arb_suite() -> impl Strategy<Value = CipherSuiteId> {
    prop_oneof![
        Just(CipherSuiteId::XChaCha20Poly1305),
        Just(CipherSuiteId::Aes256GcmSiv),
    ]
}

/// チャンク境界付近を含む長さのエントリ列 (最大 14 件。11 件以上でマニフェストが複数チャンクになる) を生成するストラテジ。
fn arb_entries() -> impl Strategy<Value = Vec<Vec<u8>>> {
    let len = prop_oneof![
        1 => Just(0usize),
        2 => 1usize..=16,
        2 => 190usize..=210,
        2 => 380usize..=420,
        1 => 0usize..=1200,
    ];
    prop::collection::vec(
        len.prop_flat_map(|n| prop::collection::vec(any::<u8>(), n)),
        0..=14,
    )
}

/// 呼び出しごとに異なるノンスを埋める決定論的な乱数源 (テスト専用)。
fn counter_rng() -> impl FnMut(&mut [u8]) -> Result<(), SystemError> {
    let mut counter: u64 = 0;
    move |buf: &mut [u8]| {
        counter += 1;
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = counter.to_le_bytes()[i % 8] ^ (i as u8).wrapping_mul(29);
        }
        Ok(())
    }
}

fn entry_id(index: usize) -> EntryId {
    [u8::try_from(index + 1).unwrap_or(0xff); ENTRY_ID_LEN]
}

fn seal(
    suite: CipherSuiteId,
    epoch: u64,
    datas: &[Vec<u8>],
) -> Result<Vec<TlvRecord>, TestCaseError> {
    let sources: Vec<EntrySource<'_>> = datas
        .iter()
        .enumerate()
        .map(|(i, data)| EntrySource {
            entry_id: entry_id(i),
            data,
        })
        .collect();
    seal_entries(
        &VaultCipher::new(suite, &[0x11u8; 32]),
        &VaultHeader::new(1, suite.as_u8(), epoch),
        &sources,
        counter_rng(),
    )
    .map_err(|e| TestCaseError::fail(format!("暗号化に失敗: {e:?}")))
}

fn open(
    suite: CipherSuiteId,
    epoch: u64,
    records: &[TlvRecord],
) -> Result<Vec<fidelogic_core::entry::OpenedEntry>, VaultError> {
    open_entries(
        &VaultCipher::new(suite, &[0x11u8; 32]),
        &VaultHeader::new(1, suite.as_u8(), epoch),
        records,
    )
}

proptest! {
    #![proptest_config(entry_proptest_config())]

    /// 任意のエントリ列が、暗号化と復号で内容も順序も変わらずに往復する。
    #[test]
    fn prop_roundtrip_preserves_entries(
        suite in arb_suite(),
        epoch in any::<u64>(),
        datas in arb_entries(),
    ) {
        let records = seal(suite, epoch, &datas)?;
        let opened = open(suite, epoch, &records)
            .map_err(|e| TestCaseError::fail(format!("復号に失敗: {e:?}")))?;
        prop_assert_eq!(opened.len(), datas.len());
        for (i, (entry, data)) in opened.iter().zip(&datas).enumerate() {
            prop_assert_eq!(entry.entry_id, entry_id(i));
            prop_assert_eq!(entry.data.as_slice(), data.as_slice());
        }
    }

    /// すべてのレコードが固定長で、レコード数はマニフェストと各エントリのチャンク数の和に一致する。
    #[test]
    fn prop_record_count_and_fixed_length(
        suite in arb_suite(),
        datas in arb_entries(),
    ) {
        let records = seal(suite, 1, &datas)?;
        let capacity = chunk_data_capacity(suite);
        let chunks = |len: usize| len.div_ceil(capacity).max(1);
        let manifest_len = datas.len() * (ENTRY_ID_LEN + 2);
        let expected = chunks(manifest_len) + datas.iter().map(|d| chunks(d.len())).sum::<usize>();
        prop_assert_eq!(records.len(), expected);
        for record in &records {
            match record {
                TlvRecord::Entry(payload) => prop_assert_eq!(payload.ciphertext.len() + 16, 255),
                TlvRecord::Unknown { .. } => prop_assert!(false, "未知レコードが混入した。"),
            }
        }
    }

    /// 2 つ以上のレコードを入れ替えると、内容が同一でない限り復号は拒否される。
    #[test]
    fn prop_reordering_is_rejected(
        suite in arb_suite(),
        datas in arb_entries(),
        a in any::<prop::sample::Index>(),
        b in any::<prop::sample::Index>(),
    ) {
        let mut records = seal(suite, 1, &datas)?;
        let (i, j) = (a.index(records.len()), b.index(records.len()));
        prop_assume!(i != j);
        records.swap(i, j);
        prop_assert_eq!(open(suite, 1, &records).err(), Some(VaultError::AuthenticationFailed));
    }

    /// 任意の 1 レコードの欠損、重複、末尾への余分なレコードの追加はすべて拒否される。
    #[test]
    fn prop_missing_duplicated_and_extra_records_are_rejected(
        suite in arb_suite(),
        datas in arb_entries(),
        at in any::<prop::sample::Index>(),
    ) {
        let records = seal(suite, 1, &datas)?;
        let index = at.index(records.len());

        let mut missing = records.clone();
        missing.remove(index);
        prop_assert_eq!(open(suite, 1, &missing).err(), Some(VaultError::AuthenticationFailed));

        let mut duplicated = records.clone();
        duplicated.insert(index, records[index].clone());
        prop_assert_eq!(open(suite, 1, &duplicated).err(), Some(VaultError::AuthenticationFailed));

        let mut extra = records.clone();
        extra.push(records[index].clone());
        prop_assert_eq!(open(suite, 1, &extra).err(), Some(VaultError::AuthenticationFailed));
    }

    /// 別の世代のヘッダーでの復号、別の世代のレコードの混入、エントリ単位の削除は拒否される。
    #[test]
    fn prop_epoch_mixing_and_entry_deletion_are_rejected(
        suite in arb_suite(),
        datas in arb_entries(),
        epoch in 1u64..u64::MAX,
        victim in any::<prop::sample::Index>(),
    ) {
        let records = seal(suite, epoch, &datas)?;
        prop_assert_eq!(open(suite, epoch + 1, &records).err(), Some(VaultError::AuthenticationFailed));
        prop_assert_eq!(open(suite, epoch - 1, &records).err(), Some(VaultError::AuthenticationFailed));

        // 別の世代で作ったレコードを 1 つだけ混ぜる。
        let old = seal(suite, epoch - 1, &datas)?;
        let mixed_index = victim.index(records.len());
        let mut mixed = records.clone();
        mixed[mixed_index] = old[mixed_index].clone();
        prop_assert_eq!(open(suite, epoch, &mixed).err(), Some(VaultError::AuthenticationFailed));

        // エントリ 1 件を構成するチャンクを丸ごと削除する。
        if !datas.is_empty() {
            let capacity = chunk_data_capacity(suite);
            let chunks = |len: usize| len.div_ceil(capacity).max(1);
            let target = victim.index(datas.len());
            let manifest_chunks = chunks(datas.len() * (ENTRY_ID_LEN + 2));
            let start = manifest_chunks + datas[..target].iter().map(|d| chunks(d.len())).sum::<usize>();
            let mut deleted = records.clone();
            deleted.drain(start..start + chunks(datas[target].len()));
            prop_assert_eq!(open(suite, epoch, &deleted).err(), Some(VaultError::AuthenticationFailed));
        }
    }
}
