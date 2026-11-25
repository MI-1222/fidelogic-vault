//! 鍵を更新するサブコマンドのテストで使う Vault と、更新後の Vault の検査。
//!
//! Vault は、全スロット、未知のスロット、複数のチャンクに分かれるエントリ、未知のレコードを持つ。
//! 作成には高速な鍵導出パラメータを使う。

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use fidelogic_cli::init::build_new_vault;
use fidelogic_cli::recovery_code::RecoveryCode;
use fidelogic_cli::rekey::{new_password_slot, new_recovery_slot};
use fidelogic_cli::sys::random::fill_random;
use fidelogic_core::{
    Argon2Params, CipherSuiteId, DEK_LEN, EntrySource, KekSlotEntry, SecretBytes, TlvRecord, Vault,
    VaultCipher, VaultEngine, open_entries, seal_entries, serialize, unwrap_dek_slot0_for_header,
    wrap_dek_slot1_for_header,
};

use super::{PASSWORD, TestResult, read_vault};

/// 読み込んだ Vault を改ざんする操作。
pub type Tamper = fn(&mut Vault);

/// 作成する Vault のリカバリーコード (乱数が全ビット 0)。
pub const OLD_CODE: &str = "FL000-00000-00000-00000-00000-00014";

/// 更新後のマスターパスワード。
pub const NEW_PASSWORD: &str = "a different passphrase";

/// Slot 1 を包む WebAuthn PRF の出力の代わり。
pub const PRF_SECRET: [u8; 32] = [0x5a; 32];

/// 解釈できないスロットの識別子。
pub const UNKNOWN_SLOT_ID: u8 = 7;

/// 解釈できないレコードのタグ。
pub const UNKNOWN_TAG: u8 = 0x7e;

/// 作成する Vault の世代。
pub const FIXTURE_EPOCH: u64 = 1;

/// エントリの識別子と内容。2 件目は複数のチャンクに分かれる長さである。
pub fn entries() -> [([u8; 16], Vec<u8>); 2] {
    let long = (0..4096u32).map(|index| (index % 251) as u8).collect();
    [([1; 16], b"short entry".to_vec()), ([2; 16], long)]
}

/// テスト用の Vault を権限 `0600` で書き出し、内容を返す。`prf_slot` が真の場合は Slot 1 を持つ。
pub fn write_fixture(path: &Path, prf_slot: bool) -> Result<Vault, Box<dyn Error>> {
    write_fixture_with_suite(path, prf_slot, CipherSuiteId::XChaCha20Poly1305)
}

/// [`write_fixture`] と同じ Vault を、指定した暗号スイートで作る。
pub fn write_fixture_with_suite(
    path: &Path,
    prf_slot: bool,
    suite: CipherSuiteId,
) -> Result<Vault, Box<dyn Error>> {
    let code = RecoveryCode::parse(OLD_CODE.as_bytes())?;
    let contents = build_new_vault(
        PASSWORD.as_bytes(),
        &code,
        &Argon2Params::fast_test(),
        fill_random,
    )
    .map_err(|error| format!("{error}"))?;
    let (mut vault, _) =
        fidelogic_core::deserialize(&contents).map_err(|error| format!("{error}"))?;
    let password_slot = vault.slots.first().ok_or("Slot 0 がありません。")?;
    let dek = unwrap_dek_slot0_for_header(password_slot, PASSWORD.as_bytes(), &vault.header)
        .map_err(|error| format!("{error}"))?;
    // スロットの関連データは暗号スイートを含むため、ヘッダーを変えて作り直す。
    vault.header.suite_id = suite.as_u8();
    let params = Argon2Params::fast_test();
    let mut source = fill_random;
    vault.slots = vec![
        new_password_slot(
            &dek,
            &vault.header,
            PASSWORD.as_bytes(),
            &params,
            &mut source,
        )
        .map_err(|error| format!("{error}"))?,
        new_recovery_slot(&dek, &vault.header, &code, &mut source)
            .map_err(|error| format!("{error}"))?,
    ];

    if prf_slot {
        let slot = wrap_dek_slot1_for_header(&dek, &PRF_SECRET, &[3; 32], &[4; 24], &vault.header)
            .map_err(|error| format!("{error}"))?;
        vault.slots.insert(1, slot);
    }
    vault.slots.push(
        KekSlotEntry::new(UNKNOWN_SLOT_ID, 9, vec![0xC3; 40])
            .map_err(|error| format!("{error}"))?,
    );

    let entries = entries();
    let sources: Vec<EntrySource<'_>> = entries
        .iter()
        .map(|(entry_id, data)| EntrySource {
            entry_id: *entry_id,
            data,
        })
        .collect();
    let cipher = VaultCipher::new(suite, dek.as_bytes());
    vault.records = seal_entries(&cipher, &vault.header, &sources, fill_random)
        .map_err(|error| format!("{error}"))?;
    vault.records.push(
        TlvRecord::new_unknown(UNKNOWN_TAG, b"future record".to_vec())
            .map_err(|error| format!("{error}"))?,
    );
    write_vault(path, &vault)?;
    Ok(vault)
}

/// Vault を直列化して、権限 `0600` で書き出す。
pub fn write_vault(path: &Path, vault: &Vault) -> TestResult {
    fs::write(path, serialize(vault).map_err(|error| format!("{error}"))?)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn dek_of(engine: &VaultEngine) -> Result<[u8; DEK_LEN], Box<dyn Error>> {
    let dek: &SecretBytes<DEK_LEN> = engine.dek().map_err(|error| format!("{error}"))?;
    Ok(*dek.as_bytes())
}

/// パスワードで解錠できる場合は DEK を返す。
pub fn dek_by_password(vault: &Vault, password: &str) -> Option<[u8; DEK_LEN]> {
    let mut engine = VaultEngine::from_slot_entries(&vault.slots);
    engine
        .unlock_vault_with_password(vault, password.as_bytes())
        .ok()?;
    dek_of(&engine).ok()
}

/// リカバリーコードで解錠できる場合は DEK を返す。
pub fn dek_by_code(vault: &Vault, code: &str) -> Option<[u8; DEK_LEN]> {
    let mut engine = VaultEngine::from_slot_entries(&vault.slots);
    engine
        .unlock_vault_with_recovery_code(vault, code.as_bytes())
        .ok()?;
    dek_of(&engine).ok()
}

/// PRF の出力で解錠できる場合は DEK を返す。
pub fn dek_by_prf(vault: &Vault) -> Option<[u8; DEK_LEN]> {
    let mut engine = VaultEngine::from_slot_entries(&vault.slots);
    engine.unlock_vault_with_prf(vault, &PRF_SECRET).ok()?;
    dek_of(&engine).ok()
}

/// 指定した識別子のスロットを返す。
pub fn slot(vault: &Vault, slot_id: u8) -> Option<&KekSlotEntry> {
    vault.slots.iter().find(|slot| slot.slot_id() == slot_id)
}

pub fn slot_ids(vault: &Vault) -> Vec<u8> {
    vault.slots.iter().map(KekSlotEntry::slot_id).collect()
}

/// 更新後の Vault が、世代を 1 つ進め、`dek` で全エントリを復号でき、未知のレコードを保持していること。
pub fn assert_updated(path: &Path, dek: &[u8; DEK_LEN]) -> Result<Vault, Box<dyn Error>> {
    let vault = read_vault(path)?;
    assert_eq!(
        vault.header.epoch_id,
        FIXTURE_EPOCH + 1,
        "世代の確認に失敗。"
    );
    let suite =
        CipherSuiteId::from_u8(vault.header.suite_id).map_err(|error| format!("{error}"))?;
    let cipher = VaultCipher::new(suite, dek);
    let opened = open_entries(&cipher, &vault.header, &vault.records)
        .map_err(|error| format!("更新後のエントリの復号に失敗: {error}"))?;
    let opened: Vec<([u8; 16], Vec<u8>)> = opened
        .iter()
        .map(|entry| (entry.entry_id, entry.data.as_slice().to_vec()))
        .collect();
    assert!(opened == entries(), "更新後のエントリの内容の確認に失敗。");
    assert!(
        matches!(
            vault.records.last(),
            Some(TlvRecord::Unknown { tag: UNKNOWN_TAG, raw_bytes })
                if raw_bytes.as_slice() == b"future record"
        ),
        "未知のレコードの保持の確認に失敗。"
    );
    assert_eq!(
        fs::symlink_metadata(path)?.permissions().mode() & 0o7777,
        0o600
    );
    Ok(vault)
}
