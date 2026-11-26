//! # 鍵を更新して保存する手順 (`key_update`)
//!
//! 既存の Vault を解錠してスロットを作り直す、`recover` と `rotate-key` の共通の手順を置く。
//! スロットの作り方は [`crate::rekey`] が定める。このモジュールは OS に依存しない。
//!
//! ## 手順
//!
//! 1. 準備 ([`UpdateTarget::open`]): 制御端末を開き、中断の捕捉を始める。
//!    サイドカーロックを待たずに取得して Vault を読み込み、HTML の出力先が空いていることを確かめる。
//! 2. 解錠 ([`UnlockedVault::unlock`]): 資格情報で解錠し、全エントリを復号できることを確かめる。
//! 3. 更新と保存 ([`update_and_save`]): 新しいリカバリーコードを発行する場合は、
//!    HTML を書き出し、代替画面に表示して末尾の再入力を確認する。その後、世代を 1 つ進めて、アトミックに保存する。
//!
//! 全エントリの検査を、新しいパスワードを入力させるより前に行う。改ざんされた Vault を、
//! 利用者がパスワードやコードを控える前に検出するためである。
//! 検査で復号した平文はすぐに消去し、保存の直前に復号し直す。入力と確認を待つ間は、平文を保持しない。
//! DEK は、解錠から保存まで保持する。
//!
//! 利用者がコードを控えたことを確認するまで、Vault は書き換えない。
//! 保存せずに終わる場合 (失敗と中断) は、書き出した HTML を削除する。
//! `SIGKILL` などでプロセスが終了した場合は、HTML が残ることがある。
//! 残った HTML のコードに対応するスロットは、保存されていない可能性がある。
//!
//! ロックは、利用者の入力と確認の間も保持する。ロックに従わない処理がその間に Vault を書き換えた場合は、
//! 保存の直前の検証 ([`crate::vault_file`]) で中止する。

use std::io::Write;
use std::path::Path;

use fidelogic_core::{
    Argon2Params, CipherSuiteId, EntrySource, OpenedEntry, SecretVec, SlotCredential, VaultCipher,
    VaultEngine, VaultError, open_entries,
};

use crate::args::RecoveryCodePlan;
use crate::error::CliError;
use crate::interaction::{
    PendingKit, confirm_recovery_kit, ensure_kit_destination_is_free, ensure_not_interrupted,
    report_kit, warn_if_directory_not_synced, write_warning,
};
use crate::recovery_code::RecoveryCode;
use crate::rekey::{KeyChange, UpdatedKeys, update_keys};
use crate::sys::random::fill_random;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{VaultLock, VaultPath};
use crate::sys::tty::Terminal;
use crate::vault_file::{LoadedVault, SavedVault, VaultFileError, save_vault};

/// 控えを確認した後に保存できなかった場合の警告。
const UNUSABLE_CODE_WARNING: &str = "警告: Vault を保存できなかったため、表示したリカバリーコードは使えません。以前のコードは破棄しないでください。";

/// 更新する Vault と、更新の間だけ保持する端末とロック。
///
/// 秘密を保持する値より先に宣言し、後で破棄する。破棄するまで、中断のシグナルでプロセスは終了しない。
pub(crate) struct UpdateTarget {
    /// 更新する Vault のロック。
    pub(crate) lock: VaultLock,
    /// 入力と表示に使う制御端末。
    terminal: Terminal,
    /// 中断の捕捉。
    pub(crate) watcher: InterruptWatcher,
}

impl UpdateTarget {
    /// 端末とロックを取得し、Vault を読み込む。
    ///
    /// # Errors
    ///
    /// - `vault` が `None` の場合は [`CliError::VaultPathRequired`]。
    /// - 制御端末を開けない場合は [`CliError::TerminalRequired`]。
    /// - Vault が無い場合は [`CliError::VaultNotFound`]。
    /// - 解析できない場合は [`CliError::AuthenticationFailed`]。
    /// - HTML の出力先にファイルがある場合は [`CliError::KitAlreadyExists`]。
    /// - ロックの取得と読み込みの失敗は、対応する [`CliError`]。
    pub(crate) fn open(
        vault: Option<&Path>,
        kit_html: Option<&Path>,
    ) -> Result<(Self, LoadedVault), CliError> {
        let vault = vault.ok_or(CliError::VaultPathRequired)?;
        // 入力と表示ができない環境では、ファイルに触れる前に中止する。
        let terminal = Terminal::open().map_err(|_| CliError::TerminalRequired)?;
        // 秘密を保持している間は、中断のシグナルでプロセスを終了させない。
        let watcher = InterruptWatcher::install()?;
        let lock = VaultLock::try_acquire(VaultPath::resolve(vault)?)?;
        let loaded = LoadedVault::read(&lock)
            .map_err(CliError::from_load_error)?
            .ok_or(CliError::VaultNotFound)?;
        ensure_kit_destination_is_free(kit_html)?;
        Ok((
            Self {
                lock,
                terminal,
                watcher,
            },
            loaded,
        ))
    }
}

/// 解錠した Vault。DEK を持つ状態機械を保持し、破棄時に消去する。エントリの平文は保持しない。
pub(crate) struct UnlockedVault {
    loaded: LoadedVault,
    engine: VaultEngine,
}

impl UnlockedVault {
    /// 資格情報で解錠し、全エントリを復号できることを確かめる。
    ///
    /// # Errors
    ///
    /// 解錠と復号の失敗は、理由によらず [`CliError::AuthenticationFailed`]。
    pub(crate) fn unlock(
        loaded: LoadedVault,
        credential: SlotCredential<'_>,
    ) -> Result<Self, CliError> {
        let mut engine = VaultEngine::from_slot_entries(loaded.slots());
        engine
            .unlock_vault_with_credential(loaded.vault(), credential)
            .map_err(CliError::from_unlock_error)?;
        // 復号した平文は、この文の終わりで破棄して消去する。
        decrypt_entries(&loaded, &engine).map_err(CliError::from_unlock_error)?;
        Ok(Self { loaded, engine })
    }

    /// 読み込んだ Vault を返す。
    pub(crate) fn loaded(&self) -> &LoadedVault {
        &self.loaded
    }
}

/// 解錠した状態機械の DEK で、全エントリを復号する。
fn decrypt_entries(
    loaded: &LoadedVault,
    engine: &VaultEngine,
) -> Result<Vec<OpenedEntry>, VaultError> {
    let header = loaded.header();
    let suite = CipherSuiteId::from_u8(header.suite_id)?;
    let cipher = VaultCipher::new(suite, engine.dek()?.as_bytes());
    open_entries(&cipher, header, loaded.records())
}

/// 鍵の更新の種類。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateKind<'a> {
    /// DEK を変えずに、スロットを包み直す。
    Rewrap(RecoveryCodePlan<&'a Path>),
    /// DEK を作り直す。リカバリーコードは常に再発行する。
    ReplaceDek {
        /// 再発行するリカバリーキットの HTML の出力先。
        kit_html: Option<&'a Path>,
    },
}

impl<'a> UpdateKind<'a> {
    /// この更新でのリカバリーコードの扱いを返す。
    pub(crate) const fn recovery_code(self) -> RecoveryCodePlan<&'a Path> {
        match self {
            Self::Rewrap(plan) => plan,
            Self::ReplaceDek { kit_html } => RecoveryCodePlan::Reissue { kit_html },
        }
    }
}

/// 解錠した Vault のスロットを作り直し、世代を 1 つ進めて保存する。
///
/// # Args
///
/// - `password`: 新しい Slot 0 に使う、正準化済みのパスワード。スロットを作った後に消去する。
/// - `kind`: 更新の種類。リカバリーコードを再発行するかと、HTML の出力先を含む。
/// - `stderr`: 警告の書き込み先。
///
/// # Errors
///
/// - コードの再入力の前に端末の入力が終わった場合は [`CliError::RecoveryKitNotConfirmed`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - 読み込み後に Vault が書き換えられた場合は [`CliError::VaultFile`] または [`CliError::RollbackDetected`]。
/// - 乱数、暗号処理、ファイル操作の失敗は、対応する [`CliError`]。
///
/// いずれの失敗でも、Vault は変更しない。控えを確認した後に失敗した場合は、
/// 表示したコードが使えないことを警告する。
pub(crate) fn update_and_save(
    target: &UpdateTarget,
    unlocked: UnlockedVault,
    password: SecretVec,
    kind: UpdateKind<'_>,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let plan = kind.recovery_code();
    let code = match plan {
        RecoveryCodePlan::Keep => None,
        RecoveryCodePlan::Reissue { .. } => Some(RecoveryCode::generate(fill_random)?),
    };
    let change = match (kind, code.as_ref()) {
        (UpdateKind::Rewrap(_), recovery_code) => KeyChange::Rewrap { recovery_code },
        (UpdateKind::ReplaceDek { .. }, Some(recovery_code)) => {
            KeyChange::ReplaceDek { recovery_code }
        }
        (UpdateKind::ReplaceDek { .. }, None) => return Err(CliError::InvalidState),
    };
    let updated = update_keys(
        unlocked.loaded.header(),
        unlocked.loaded.slots(),
        unlocked.engine.dek().map_err(CliError::from_unlock_error)?,
        password.as_slice(),
        change,
        &Argon2Params::for_native(),
        fill_random,
    )
    .map_err(|error| CliError::from_save_error(VaultFileError::Vault(error)))?;
    drop(password);
    ensure_not_interrupted(&target.watcher)?;

    let kit = match code.as_ref() {
        Some(code) => present_recovery_code(target, code, plan.kit_html())?,
        None => None,
    };
    let issued = code.is_some();
    drop(code);

    let saved = ensure_not_interrupted(&target.watcher)
        .and_then(|()| reseal_and_save(&target.lock, &unlocked, updated));
    let saved = match saved {
        Ok(saved) => saved,
        Err(error) => {
            if issued {
                write_warning(stderr, UNUSABLE_CODE_WARNING);
            }
            return Err(error);
        }
    };
    // 保存した後は、中断のシグナルを受けていても、更新の結果を報告する。
    let kit_sync = kit.map(PendingKit::keep);
    for sync in [Some(saved.directory_sync), kit_sync].into_iter().flatten() {
        warn_if_directory_not_synced(stderr, sync);
    }
    Ok(())
}

/// 全エントリを復号し、更新後の鍵で暗号化し直して保存する。
fn reseal_and_save(
    lock: &VaultLock,
    unlocked: &UnlockedVault,
    updated: UpdatedKeys,
) -> Result<SavedVault, CliError> {
    let entries =
        decrypt_entries(&unlocked.loaded, &unlocked.engine).map_err(CliError::from_unlock_error)?;
    let sources: Vec<EntrySource<'_>> = entries
        .iter()
        .map(|entry| EntrySource {
            entry_id: entry.entry_id,
            data: entry.data.as_slice(),
        })
        .collect();
    save_vault(
        lock,
        &unlocked.loaded,
        &updated.cipher,
        updated.slots,
        &sources,
        fill_random,
    )
    .map_err(CliError::from_save_error)
}

/// HTML の指定がある場合は書き出し、コードを表示して控えを確認する。
fn present_recovery_code<'a>(
    target: &UpdateTarget,
    code: &RecoveryCode,
    kit_html: Option<&'a Path>,
) -> Result<Option<PendingKit<'a>>, CliError> {
    let grouped = code.grouped()?;
    let grouped = core::str::from_utf8(grouped.as_slice()).map_err(|_| CliError::InvalidState)?;
    let kit = match kit_html {
        Some(path) => Some(PendingKit::write(path, grouped)?),
        None => None,
    };
    confirm_recovery_kit(&target.terminal, grouped, code, &target.watcher)?;
    Ok(kit)
}

/// リカバリーコードを再発行した場合に、新しいコードを有効にしたことと、書き出した HTML の扱いを書く。
/// 再発行しない場合は、何も書かない。
pub(crate) fn report_recovery_code(
    stdout: &mut impl Write,
    plan: RecoveryCodePlan<&Path>,
) -> std::io::Result<()> {
    let RecoveryCodePlan::Reissue { kit_html } = plan else {
        return Ok(());
    };
    writeln!(
        stdout,
        "新しいリカバリーコードを有効にしました。以前のコードは、更新後の Vault では使えません。"
    )?;
    report_kit(stdout, kit_html)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::UpdateKind;
    use crate::args::RecoveryCodePlan;

    #[test]
    fn test_recovery_code_plan_follows_update_kind() {
        let kit_html = Some(Path::new("kit"));
        let reissue = RecoveryCodePlan::Reissue { kit_html };
        let cases = [
            (
                UpdateKind::Rewrap(RecoveryCodePlan::Keep),
                RecoveryCodePlan::Keep,
            ),
            (UpdateKind::Rewrap(reissue), reissue),
            (UpdateKind::ReplaceDek { kit_html }, reissue),
            (
                UpdateKind::ReplaceDek { kit_html: None },
                RecoveryCodePlan::Reissue { kit_html: None },
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.recovery_code(), expected, "{kind:?} の判定に失敗。");
        }
    }
}
