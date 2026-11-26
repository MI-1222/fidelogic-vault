//! # スロットの作成と鍵の更新 (`rekey`)
//!
//! Vault の KEK スロットを作り、鍵の更新後のスロットの一覧と暗号器を組み立てる。
//! `init`、`recover`、`rotate-key` が使う。このモジュールは OS に依存せず、ファイルと端末を扱わない。
//! 乱数源と鍵導出パラメータは呼び出し側が渡す。
//!
//! ## 更新の種類
//!
//! | 種類 | DEK | Slot 0 (パスワード) | Slot 1 (WebAuthn PRF) | Slot 2 (リカバリーコード) | 未知のスロット |
//! | :-- | :-- | :-- | :-- | :-- | :-- |
//! | [`KeyChange::Rewrap`] (コードなし) | 維持 | 作り直す | 維持 | 維持 | 維持 |
//! | [`KeyChange::Rewrap`] (コードあり) | 維持 | 作り直す | 維持 | 作り直す | 維持 |
//! | [`KeyChange::ReplaceDek`] | 新規 | 作り直す | 取り除く | 作り直す | 維持 |
//!
//! 作り直すスロットは、同じ識別子の最初のスロットの位置に置き、同じ識別子の残りのスロットは取り除く。
//! 該当するスロットが無い場合は、末尾に加える。維持するスロットは、内容と順序を変えない。
//!
//! ## 更新で失効するもの
//!
//! [`KeyChange::Rewrap`] は DEK を変えない。更新前の Vault の複製と、
//! 更新前のパスワードやリカバリーコードを持つ者は、DEK を取り出して、更新後の内容も復号できる。漏洩が疑われる場合は DEK を作り直す。
//!
//! [`KeyChange::ReplaceDek`] の後も、未知のスロットは古い DEK を包んだまま残る。
//! 前方互換のために内容を解釈せずに保持するためで、そのスロットでは更新後の内容を復号できない。

use fidelogic_core::{
    Argon2Params, CipherSuiteId, DEK_LEN, KekSlotEntry, SLOT_ID_PRF, SLOT0_NONCE_LEN,
    SLOT0_SALT_LEN, SLOT2_NONCE_LEN, SLOT2_SALT_LEN, SecretBytes, SystemError, VaultCipher,
    VaultError, VaultHeader, wrap_dek_slot0_for_header, wrap_dek_slot2_for_header,
};

use crate::recovery_code::RecoveryCode;

/// 鍵の更新の種類。
#[derive(Debug, Clone, Copy)]
pub enum KeyChange<'a> {
    /// DEK を変えずに、スロットを包み直す。
    Rewrap {
        /// 新しいリカバリーコード。`None` の場合は Slot 2 を変えない。
        recovery_code: Option<&'a RecoveryCode>,
    },
    /// 新しい DEK を作る。
    ReplaceDek {
        /// 新しいリカバリーコード。
        recovery_code: &'a RecoveryCode,
    },
}

/// 更新後の鍵の構成。
pub struct UpdatedKeys {
    /// エントリを暗号化する暗号器。更新後の DEK を持つ。
    pub cipher: VaultCipher,
    /// 更新後の KEK スロットの一覧。
    pub slots: Vec<KekSlotEntry>,
}

/// WebAuthn PRF のスロット (Slot 1) があるかを返す。内容が有効かは問わない。
#[must_use]
pub fn has_prf_slot(slots: &[KekSlotEntry]) -> bool {
    slots.iter().any(|slot| slot.slot_id() == SLOT_ID_PRF)
}

/// DEK をマスターパスワードで包んだ、新しい Slot 0 を作る。
///
/// # Args
///
/// - `password`: 正準化済みのパスワード ([`crate::password::canonicalize_password`])。
/// - `fill_random`: ソルト、ノンスの順に乱数を読む。
///
/// # Errors
///
/// - 乱数源が失敗した場合は [`VaultError::System`]。
/// - 鍵導出または暗号化に失敗した場合は、対応する [`VaultError`]。
pub fn new_password_slot<R>(
    dek: &SecretBytes<DEK_LEN>,
    header: &VaultHeader,
    password: &[u8],
    params: &Argon2Params,
    fill_random: &mut R,
) -> Result<KekSlotEntry, VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    // ソルトとノンスは秘密ではない。
    let mut salt = [0u8; SLOT0_SALT_LEN];
    let mut nonce = [0u8; SLOT0_NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    wrap_dek_slot0_for_header(dek, password, &salt, &nonce, params, header)
}

/// DEK をリカバリーコードで包んだ、新しい Slot 2 を作る。
///
/// # Args
///
/// - `fill_random`: ソルト、ノンスの順に乱数を読む。
///
/// # Errors
///
/// [`new_password_slot`] と同じ。
pub fn new_recovery_slot<R>(
    dek: &SecretBytes<DEK_LEN>,
    header: &VaultHeader,
    recovery_code: &RecoveryCode,
    fill_random: &mut R,
) -> Result<KekSlotEntry, VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    // ソルトとノンスは秘密ではない。
    let mut salt = [0u8; SLOT2_SALT_LEN];
    let mut nonce = [0u8; SLOT2_NONCE_LEN];
    fill_random(&mut salt)?;
    fill_random(&mut nonce)?;
    // 正準化を伴う `wrap_dek_slot2_code_for_header` は、コードを `mlock` しないヒープに複写するため使わない。
    // 正準形はコアの正準化で変化しないため、正準化を伴わない関数に渡しても同じ結果になる。
    wrap_dek_slot2_for_header(dek, recovery_code.as_bytes(), &salt, &nonce, header)
}

/// 鍵の更新後のスロットの一覧と暗号器を作る。扱いはモジュール doc の表のとおりである。
///
/// エントリの再暗号化と保存は行わない ([`crate::vault_file::save_vault`] が行う)。
///
/// # Args
///
/// - `header`: 更新する Vault のヘッダー。暗号スイートと、スロットの関連データを決める。
/// - `slots`: 更新前の KEK スロットの一覧。
/// - `current_dek`: 解錠で得た、更新前の DEK。
/// - `password`: 新しい Slot 0 に使う、正準化済みのパスワード。
/// - `change`: 更新の種類。
/// - `params`: 新しい Slot 0 の鍵導出パラメータ。
/// - `fill_random`: DEK (作り直す場合)、Slot 0 のソルトとノンス、Slot 2 のソルトとノンス (作り直す場合) の順に乱数を読む。
///
/// # Errors
///
/// - ヘッダーの暗号スイートが未対応の場合は [`VaultError::Crypto`]。
/// - 乱数源が失敗した場合は [`VaultError::System`]。
/// - 鍵導出または暗号化に失敗した場合は、対応する [`VaultError`]。
pub fn update_keys<R>(
    header: &VaultHeader,
    slots: &[KekSlotEntry],
    current_dek: &SecretBytes<DEK_LEN>,
    password: &[u8],
    change: KeyChange<'_>,
    params: &Argon2Params,
    mut fill_random: R,
) -> Result<UpdatedKeys, VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    let suite = CipherSuiteId::from_u8(header.suite_id)?;
    // コアのスロットの関数は `SecretBytes` を受け取るため、新しい DEK は `mlock` しない領域に置く。破棄時に消去する。
    let mut replaced_dek = SecretBytes::<DEK_LEN>::zero();
    let mut updated = slots.to_vec();
    let (dek, recovery_code) = match change {
        KeyChange::Rewrap { recovery_code } => (current_dek, recovery_code),
        KeyChange::ReplaceDek { recovery_code } => {
            fill_random(replaced_dek.as_mut_slice())?;
            // Slot 1 は古い DEK を包んでおり、PRF の出力が無いと作り直せない。
            updated.retain(|slot| slot.slot_id() != SLOT_ID_PRF);
            (&replaced_dek, Some(recovery_code))
        }
    };

    let password_slot = new_password_slot(dek, header, password, params, &mut fill_random)?;
    replace_slot(&mut updated, password_slot);
    if let Some(recovery_code) = recovery_code {
        let recovery_slot = new_recovery_slot(dek, header, recovery_code, &mut fill_random)?;
        replace_slot(&mut updated, recovery_slot);
    }
    Ok(UpdatedKeys {
        cipher: VaultCipher::new(suite, dek.as_bytes()),
        slots: updated,
    })
}

/// 同じ識別子の最初のスロットの位置に `slot` を置き、同じ識別子の残りを取り除く。無ければ末尾に加える。
fn replace_slot(slots: &mut Vec<KekSlotEntry>, slot: KekSlotEntry) {
    let slot_id = slot.slot_id();
    let position = slots
        .iter()
        .position(|existing| existing.slot_id() == slot_id)
        .unwrap_or(slots.len());
    // `position` より前には同じ識別子が無いため、取り除いた後も挿入の位置は変わらない。
    slots.retain(|existing| existing.slot_id() != slot_id);
    slots.insert(position, slot);
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use fidelogic_core::{
        Argon2Params, Argon2idSlotPayload, CipherSuiteId, DEK_LEN, EntrySource, KekSlotEntry,
        SecretBytes, SystemError, VaultCipher, VaultError, VaultHeader, open_entries, seal_entries,
        unwrap_dek_slot0_for_header, unwrap_dek_slot2_for_header,
    };

    use super::{KeyChange, UpdatedKeys, has_prf_slot, update_keys};
    use crate::recovery_code::RecoveryCode;

    type TestResult = Result<(), Box<dyn Error>>;

    const PASSWORD: &[u8] = b"new password";

    /// 更新前の DEK の値。
    const OLD_DEK: [u8; DEK_LEN] = [0xA5; DEK_LEN];

    fn header() -> VaultHeader {
        VaultHeader::new(1, CipherSuiteId::XChaCha20Poly1305.as_u8(), 9)
    }

    /// テストで使うリカバリーコード (乱数が全ビット 0)。
    fn recovery_code() -> Result<RecoveryCode, Box<dyn Error>> {
        Ok(RecoveryCode::parse(b"FL000-00000-00000-00000-00000-00014")?)
    }

    /// 内容を識別できる値を持つスロット。中身は解釈しない。
    fn slot(slot_id: u8, marker: u8) -> Result<KekSlotEntry, Box<dyn Error>> {
        Ok(KekSlotEntry::new(slot_id, 9, vec![marker; 8]).map_err(|error| format!("{error}"))?)
    }

    /// スロットの識別子と、先頭の内容の組。
    fn layout(slots: &[KekSlotEntry]) -> Vec<(u8, usize)> {
        slots
            .iter()
            .map(|slot| (slot.slot_id(), slot.wrapped_dek().len()))
            .collect()
    }

    /// 呼び出しの順に、全バイトが 1, 2, 3, ... となる値で埋める乱数源。要求された長さを記録する。
    fn counting_source(
        lengths: &mut Vec<usize>,
    ) -> impl FnMut(&mut [u8]) -> Result<(), SystemError> {
        move |destination| {
            lengths.push(destination.len());
            let value =
                u8::try_from(lengths.len()).map_err(|_| SystemError::EntropySourceFailed)?;
            destination.fill(value);
            Ok(())
        }
    }

    fn update(
        slots: &[KekSlotEntry],
        change: KeyChange<'_>,
        lengths: &mut Vec<usize>,
    ) -> Result<UpdatedKeys, Box<dyn Error>> {
        Ok(update_keys(
            &header(),
            slots,
            &SecretBytes::new(OLD_DEK),
            PASSWORD,
            change,
            &Argon2Params::fast_test(),
            counting_source(lengths),
        )
        .map_err(|error| format!("鍵の更新に失敗: {error}"))?)
    }

    fn find(slots: &[KekSlotEntry], slot_id: u8) -> Result<&KekSlotEntry, Box<dyn Error>> {
        let mut matched = slots.iter().filter(|slot| slot.slot_id() == slot_id);
        let found = matched.next().ok_or("スロットがありません。")?;
        assert!(matched.next().is_none(), "スロットが重複しています。");
        Ok(found)
    }

    /// 暗号器が `dek` を持つことを、暗号化と復号で確かめる。
    fn assert_cipher_uses(cipher: &VaultCipher, dek: &[u8; DEK_LEN]) -> TestResult {
        let entry = EntrySource {
            entry_id: [1; 16],
            data: b"data",
        };
        let records = seal_entries(cipher, &header(), &[entry], |nonce: &mut [u8]| {
            nonce.fill(0x42);
            Ok(())
        })
        .map_err(|error| format!("{error}"))?;
        let expected = VaultCipher::new(CipherSuiteId::XChaCha20Poly1305, dek);
        let opened = open_entries(&expected, &header(), &records)
            .map_err(|error| format!("暗号器の鍵の確認に失敗: {error}"))?;
        assert_eq!(opened.len(), 1);
        Ok(())
    }

    fn assert_password_slot_wraps(slots: &[KekSlotEntry], dek: &[u8; DEK_LEN]) -> TestResult {
        let unwrapped = unwrap_dek_slot0_for_header(find(slots, 0)?, PASSWORD, &header())
            .map_err(|error| format!("Slot 0 の解錠に失敗: {error}"))?;
        assert_eq!(unwrapped.as_bytes(), dek, "Slot 0 の DEK の確認に失敗。");
        Ok(())
    }

    fn assert_recovery_slot_wraps(slots: &[KekSlotEntry], dek: &[u8; DEK_LEN]) -> TestResult {
        let code = recovery_code()?;
        let unwrapped = unwrap_dek_slot2_for_header(find(slots, 2)?, code.as_bytes(), &header())
            .map_err(|error| format!("Slot 2 の解錠に失敗: {error}"))?;
        assert_eq!(unwrapped.as_bytes(), dek, "Slot 2 の DEK の確認に失敗。");
        Ok(())
    }

    #[test]
    fn test_prf_slot_is_detected_by_identifier() -> TestResult {
        assert!(!has_prf_slot(&[]));
        assert!(!has_prf_slot(&[slot(0, 1)?, slot(2, 2)?, slot(7, 3)?]));
        // 内容が無効でも、識別子が 1 のスロットは Slot 1 とする。
        assert!(has_prf_slot(&[slot(0, 1)?, slot(1, 2)?]));
        Ok(())
    }

    #[test]
    fn test_rewrap_without_code_replaces_only_password_slot() -> TestResult {
        let before = [slot(0, 10)?, slot(1, 11)?, slot(2, 12)?, slot(7, 13)?];
        let mut lengths = Vec::new();
        let change = KeyChange::Rewrap {
            recovery_code: None,
        };
        let updated = update(&before, change, &mut lengths)?;

        assert_eq!(lengths, [16, 24], "乱数の読み方の確認に失敗。");
        let ids: Vec<u8> = updated.slots.iter().map(KekSlotEntry::slot_id).collect();
        assert_eq!(ids, [0, 1, 2, 7], "スロットの順序の確認に失敗。");
        assert!(
            updated.slots.get(1..) == before.get(1..),
            "Slot 0 以外を変えないことの確認に失敗。"
        );
        assert_password_slot_wraps(&updated.slots, &OLD_DEK)?;
        let payload = Argon2idSlotPayload::from_slot_entry(find(&updated.slots, 0)?)
            .map_err(|error| format!("{error}"))?;
        assert_eq!(payload.salt, [1; 16], "Slot 0 のソルトの確認に失敗。");
        assert_eq!(payload.nonce, [2; 24], "Slot 0 のノンスの確認に失敗。");
        assert_eq!(
            payload.params.m_cost(),
            Argon2Params::fast_test().m_cost(),
            "鍵導出パラメータの確認に失敗。"
        );
        assert_cipher_uses(&updated.cipher, &OLD_DEK)
    }

    #[test]
    fn test_rewrap_with_code_replaces_password_and_recovery_slots() -> TestResult {
        let before = [slot(0, 10)?, slot(1, 11)?, slot(2, 12)?, slot(7, 13)?];
        let code = recovery_code()?;
        let mut lengths = Vec::new();
        let change = KeyChange::Rewrap {
            recovery_code: Some(&code),
        };
        let updated = update(&before, change, &mut lengths)?;

        assert_eq!(lengths, [16, 24, 32, 24], "乱数の読み方の確認に失敗。");
        let ids: Vec<u8> = updated.slots.iter().map(KekSlotEntry::slot_id).collect();
        assert_eq!(ids, [0, 1, 2, 7], "スロットの順序の確認に失敗。");
        for index in [1, 3] {
            assert!(
                updated.slots.get(index) == before.get(index),
                "Slot 1 と未知のスロットを変えないことの確認に失敗。"
            );
        }
        assert_password_slot_wraps(&updated.slots, &OLD_DEK)?;
        assert_recovery_slot_wraps(&updated.slots, &OLD_DEK)?;
        assert_cipher_uses(&updated.cipher, &OLD_DEK)
    }

    #[test]
    fn test_replace_dek_drops_prf_slot_and_keeps_unknown_slots() -> TestResult {
        let before = [
            slot(7, 13)?,
            slot(0, 10)?,
            slot(1, 11)?,
            slot(2, 12)?,
            slot(1, 14)?,
            slot(3, 15)?,
        ];
        let code = recovery_code()?;
        let mut lengths = Vec::new();
        let change = KeyChange::ReplaceDek {
            recovery_code: &code,
        };
        let updated = update(&before, change, &mut lengths)?;

        assert_eq!(lengths, [32, 16, 24, 32, 24], "乱数の読み方の確認に失敗。");
        let ids: Vec<u8> = updated.slots.iter().map(KekSlotEntry::slot_id).collect();
        assert_eq!(ids, [7, 0, 2, 3], "スロットの構成の確認に失敗。");
        assert!(
            updated.slots.first() == before.first() && updated.slots.last() == before.last(),
            "未知のスロットを変えないことの確認に失敗。"
        );
        // 1 回目の乱数が新しい DEK になる。
        let new_dek = [1; DEK_LEN];
        assert_password_slot_wraps(&updated.slots, &new_dek)?;
        assert_recovery_slot_wraps(&updated.slots, &new_dek)?;
        assert_cipher_uses(&updated.cipher, &new_dek)
    }

    #[test]
    fn test_missing_slots_are_appended() -> TestResult {
        let before = [slot(7, 13)?];
        let code = recovery_code()?;
        for change in [
            KeyChange::Rewrap {
                recovery_code: Some(&code),
            },
            KeyChange::ReplaceDek {
                recovery_code: &code,
            },
        ] {
            let updated = update(&before, change, &mut Vec::new())?;
            let ids: Vec<u8> = updated.slots.iter().map(KekSlotEntry::slot_id).collect();
            assert_eq!(ids, [7, 0, 2], "{change:?} の追加の確認に失敗。");
        }
        Ok(())
    }

    #[test]
    fn test_duplicated_replaced_slots_collapse_into_first_position() -> TestResult {
        let before = [slot(2, 12)?, slot(0, 10)?, slot(2, 16)?, slot(0, 17)?];
        let code = recovery_code()?;
        let change = KeyChange::Rewrap {
            recovery_code: Some(&code),
        };
        let updated = update(&before, change, &mut Vec::new())?;
        let ids: Vec<u8> = updated.slots.iter().map(KekSlotEntry::slot_id).collect();
        assert_eq!(ids, [2, 0], "重複の置き換えの確認に失敗。");

        // 作り直さないスロットは、重複していても変えない。
        let change = KeyChange::Rewrap {
            recovery_code: None,
        };
        let updated = update(&before, change, &mut Vec::new())?;
        assert_eq!(
            layout(&updated.slots)
                .iter()
                .map(|&(id, _)| id)
                .collect::<Vec<_>>(),
            [2, 0, 2]
        );
        Ok(())
    }

    #[test]
    fn test_entropy_failure_at_any_request_is_reported() -> TestResult {
        let code = recovery_code()?;
        let change = KeyChange::ReplaceDek {
            recovery_code: &code,
        };
        for failing in 0..5 {
            let mut calls = 0;
            let result = update_keys(
                &header(),
                &[],
                &SecretBytes::new(OLD_DEK),
                PASSWORD,
                change,
                &Argon2Params::fast_test(),
                |buffer: &mut [u8]| {
                    calls += 1;
                    if calls > failing {
                        return Err(SystemError::EntropySourceFailed);
                    }
                    buffer.fill(7);
                    Ok(())
                },
            );
            assert!(
                matches!(
                    result,
                    Err(VaultError::System(SystemError::EntropySourceFailed))
                ),
                "{} 回目の乱数の失敗の報告に失敗。",
                failing + 1
            );
        }
        Ok(())
    }

    #[test]
    fn test_cipher_follows_header_suite() -> TestResult {
        for suite in [
            CipherSuiteId::XChaCha20Poly1305,
            CipherSuiteId::Aes256GcmSiv,
        ] {
            let mut header = header();
            header.suite_id = suite.as_u8();
            let updated = update_keys(
                &header,
                &[],
                &SecretBytes::new(OLD_DEK),
                PASSWORD,
                KeyChange::Rewrap {
                    recovery_code: None,
                },
                &Argon2Params::fast_test(),
                counting_source(&mut Vec::new()),
            )
            .map_err(|error| format!("{error}"))?;
            assert_eq!(
                updated.cipher.suite_id(),
                suite,
                "暗号スイートの確認に失敗。"
            );
        }
        Ok(())
    }

    #[test]
    fn test_unsupported_cipher_suite_is_rejected() -> TestResult {
        let mut unsupported = header();
        unsupported.suite_id = 0x7f;
        let result = update_keys(
            &unsupported,
            &[],
            &SecretBytes::new(OLD_DEK),
            PASSWORD,
            KeyChange::Rewrap {
                recovery_code: None,
            },
            &Argon2Params::fast_test(),
            counting_source(&mut Vec::new()),
        );
        assert!(
            matches!(result, Err(VaultError::Crypto(_))),
            "未対応の暗号スイートの拒否に失敗。"
        );
        Ok(())
    }
}
