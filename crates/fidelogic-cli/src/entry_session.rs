//! # エントリを扱うための解錠と保存 (`entry_session`)
//!
//! `list`, `get`, `set`, `delete`, `export`, `unlock` が共通で使う、Vault の読み込み、
//! マスターパスワード (Slot 0) での解錠、全エントリの復号と復号したエントリの保存を置く。
//! このモジュールは OS に依存しない。
//!
//! 復号は常に全エントリに対して行う。マニフェストの検査は全レコードを必要とし、
//! タイトルは各エントリの中にあるためである。

use std::path::Path;

use fidelogic_core::{
    CipherSuiteId, Credential, EntrySource, SecretVec, SlotCredential, VaultCipher, VaultEngine,
    VaultError, open_entries,
};

use crate::error::CliError;
use crate::interaction::{ensure_not_interrupted, read_canonical_password};
use crate::secret_input::PasswordSource;
use crate::sys::random::fill_random;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{VaultLock, VaultPath};
use crate::vault_file::{LoadedVault, SavedVault, save_vault};

/// 端末からマスターパスワードを読み込むときのプロンプト。
const PASSWORD_PROMPT: &str = "マスターパスワード: ";

/// サイドカーロックを待たずに取得して、Vault を読み込む。
///
/// # Errors
///
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 解析できない場合は [`CliError::AuthenticationFailed`]。
/// - ロックの取得と読み込みの失敗は、対応する [`CliError`]。
pub(crate) fn load_locked(path: VaultPath) -> Result<(VaultLock, LoadedVault), CliError> {
    let lock = VaultLock::try_acquire(path)?;
    let loaded = LoadedVault::read(&lock)
        .map_err(CliError::from_load_error)?
        .ok_or(CliError::VaultNotFound)?;
    Ok((lock, loaded))
}

/// `--vault` の指定を返す。端末やファイルに触れる前に呼び、指定の漏れを引数の誤りにする。
///
/// # Errors
///
/// `vault` が `None` の場合は [`CliError::VaultPathRequired`]。
pub(crate) fn require_vault(vault: Option<&Path>) -> Result<&Path, CliError> {
    vault.ok_or(CliError::VaultPathRequired)
}

/// `vault` のパスを解決して、[`load_locked`] で読み込む。
///
/// # Errors
///
/// パスの解決の失敗は [`CliError::Storage`]。それ以外は [`load_locked`] と同じ。
pub(crate) fn open_vault(vault: &Path) -> Result<(VaultLock, LoadedVault), CliError> {
    load_locked(VaultPath::resolve(vault)?)
}

/// 解錠した状態の鍵。破棄するときに [`VaultEngine::zeroize_key`] で DEK を消去する。
pub(crate) struct EntryKey {
    engine: VaultEngine,
}

impl EntryKey {
    /// 指定の入力元からマスターパスワードを読み込んで、解錠する。
    ///
    /// エントリは復号しない。改ざんの検査は、呼び出し側が [`EntryKey::credentials`] で行う。
    ///
    /// # Errors
    ///
    /// - 読み込みと正準化の失敗は、対応する [`CliError`]。
    /// - 解錠の失敗は、理由によらず [`CliError::AuthenticationFailed`]。
    /// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
    pub(crate) fn unlock_with_password(
        loaded: &LoadedVault,
        source: &PasswordSource,
        watcher: &InterruptWatcher,
    ) -> Result<Self, CliError> {
        let password: SecretVec = read_canonical_password(source, PASSWORD_PROMPT, watcher)?;
        let mut engine = VaultEngine::from_slot_entries(loaded.slots());
        engine
            .unlock_vault_with_credential(
                loaded.vault(),
                SlotCredential::password(password.as_slice()),
            )
            .map_err(CliError::from_unlock_error)?;
        drop(password);
        ensure_not_interrupted(watcher)?;
        Ok(Self { engine })
    }

    /// `loaded` の全エントリを復号して、Vault の記録順に返す。
    ///
    /// # Errors
    ///
    /// - 保持する DEK で復号できない場合と、改ざんされている場合は [`CliError::AuthenticationFailed`]。
    /// - 復号したエントリをクレデンシャルとして解釈できない場合は [`CliError::MalformedEntry`]。
    pub(crate) fn credentials(&self, loaded: &LoadedVault) -> Result<Vec<Credential>, CliError> {
        let cipher = self.cipher(loaded)?;
        open_entries(&cipher, loaded.header(), loaded.records())
            .map_err(CliError::from_unlock_error)?
            .iter()
            .map(|entry| Credential::decode_opened(entry).map_err(|_| CliError::MalformedEntry))
            .collect()
    }

    /// `credentials` を保存後の全エントリとして、世代を 1 つ進めて保存する。スロットは変えない。
    ///
    /// # Errors
    ///
    /// 保存の失敗は [`CliError::from_save_error`] の値。いずれの失敗でも、Vault は変更しない。
    pub(crate) fn save(
        &self,
        lock: &VaultLock,
        loaded: &LoadedVault,
        credentials: &[Credential],
    ) -> Result<SavedVault, CliError> {
        let bodies = credentials
            .iter()
            .map(|credential| Ok((credential.entry_id, credential.encode()?)))
            .collect::<Result<Vec<_>, VaultError>>()
            .map_err(|_| CliError::VaultSaveFailed)?;
        let sources: Vec<EntrySource<'_>> = bodies
            .iter()
            .map(|(entry_id, body)| EntrySource {
                entry_id: *entry_id,
                data: body.as_slice(),
            })
            .collect();
        save_vault(
            lock,
            loaded,
            &self.cipher(loaded)?,
            loaded.slots().to_vec(),
            &sources,
            fill_random,
        )
        .map_err(CliError::from_save_error)
    }

    /// `loaded` の暗号スイートと、保持する DEK から暗号器を作る。
    fn cipher(&self, loaded: &LoadedVault) -> Result<VaultCipher, CliError> {
        let suite = CipherSuiteId::from_u8(loaded.header().suite_id)
            .map_err(|error| CliError::from_unlock_error(error.into()))?;
        let dek = self.engine.dek().map_err(CliError::from_unlock_error)?;
        Ok(VaultCipher::new(suite, dek.as_bytes()))
    }
}

impl Drop for EntryKey {
    fn drop(&mut self) {
        if self.engine.zeroize_key().is_err() {
            // 解錠していない状態からは遷移できないため、状態によらず消去する。
            self.engine.emergency_zeroize();
        }
    }
}

/// 読み取りだけを行うサブコマンドの手順。Vault を読み込んでロックを解放し、解錠して全エントリを返す。
///
/// 鍵は、戻る前に消去する。返したエントリを破棄し終えるまで、`watcher` を保持する。
///
/// # Errors
///
/// [`open_vault`]、[`EntryKey::unlock_with_password`]、[`EntryKey::credentials`] の失敗。
pub(crate) fn read_credentials(
    vault: &Path,
    source: &PasswordSource,
    watcher: &InterruptWatcher,
) -> Result<Vec<Credential>, CliError> {
    let (lock, loaded) = open_vault(vault)?;
    // 読み込んだ内容だけを使うため、利用者の入力を待つ間はロックを保持しない。
    drop(lock);
    let key = EntryKey::unlock_with_password(&loaded, source, watcher)?;
    key.credentials(&loaded)
}
