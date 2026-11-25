//! # Vault の作成 (`init`)
//!
//! `init` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//! 端末、ファイル、乱数の操作は [`crate::sys`] が行う。
//!
//! ## 作成する Vault
//!
//! - 暗号スイートは XChaCha20-Poly1305、フォーマットバージョンは [`VAULT_FORMAT_VERSION`]、
//!   世代は [`INITIAL_EPOCH_ID`] である。
//! - スロットは Slot 0 (マスターパスワード、[`Argon2Params::for_native`]) と Slot 2 (リカバリーコード) の 2 つである。
//! - エントリは持たず、空のマニフェストだけを持つ。
//!
//! ## 手順
//!
//! 1. 制御端末を開き、中断の捕捉を始める。
//! 2. サイドカーロックを待たずに取得し、Vault と HTML の出力先が空いていることを確かめる。
//! 3. マスターパスワードを読み込んで正準化する。端末から読み込む場合は 2 回入力させる。
//! 4. リカバリーコードを生成し、Vault の内容をメモリ上に組み立てる。
//! 5. `--kit-html` の指定がある場合は、HTML を権限 `0600` で新規に書き出す。
//! 6. 端末の代替画面にリカバリーキットを表示し、コードの末尾の再入力を確認する。
//! 7. Vault ファイルを新規に作成する。既存のファイルは置き換えない。
//!
//! 利用者がコードを控えたことを確認するまで、Vault ファイルは作成しない。
//! Vault ファイルを作成せずに終わる場合 (7 の失敗を含む失敗と、中断) は、書き出した HTML を削除する。
//! `SIGKILL` などでプロセスが終了した場合は、HTML が残ることがある。
//! 残った HTML のコードに対応する Vault は存在しない。
//!
//! HTML を確認より前に書き出すのは、書き込めない出力先を、利用者がコードを控える前に検出するためである。
//!
//! 画面の表示、控えの確認、HTML の後始末は、他のサブコマンドと共有する非公開のモジュール `interaction` が行う。
//! 次の「端末の表示の限界」は、コードを再発行するサブコマンドにも当てはまる。
//!
//! ## 端末の表示の限界
//!
//! リカバリーキットは代替画面 (`ESC[?1049h`) に表示し、消去してから元の画面に戻る。
//! 次の場合は、コードが画面やスクロールバックに残ることがある。
//!
//! - 代替画面に対応しない端末、代替画面の内容を履歴に保存する端末や端末多重化ソフト
//! - 端末の出力が停止していて、元の画面に戻す書き込みができない場合
//! - 表示中にプロセスが停止 (`Ctrl+Z`) または強制終了した場合
//!
//! 画面の記録、録画、撮影には対処しない。

use std::io::Write;
use std::path::Path;

use fidelogic_core::{
    Argon2Params, CipherSuiteId, DEK_LEN, SecretBytes, SystemError, Vault, VaultCipher, VaultError,
    VaultHeader, seal_entries, serialize,
};

use crate::error::CliError;
use crate::interaction::{
    PendingKit, confirm_recovery_kit, ensure_kit_destination_is_free, ensure_not_interrupted,
    read_new_password, report_kit, warn_if_directory_not_synced,
};
use crate::recovery_code::RecoveryCode;
use crate::rekey::{new_password_slot, new_recovery_slot};
use crate::secret_input::PasswordSource;
use crate::sys::random::fill_random;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{
    StorageError, VaultLock, VaultPath, create_vault_file_atomically, vault_file_exists,
};
use crate::sys::tty::Terminal;

/// 作成する Vault のフォーマットバージョン。
pub const VAULT_FORMAT_VERSION: u8 = 1;

/// 作成する Vault の最初の世代 (`epoch_id`)。
pub const INITIAL_EPOCH_ID: u64 = 1;

/// 作成する Vault の暗号スイート。
const CIPHER_SUITE: CipherSuiteId = CipherSuiteId::XChaCha20Poly1305;

/// `init` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct InitRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// `--kit-html` で指定された、HTML の出力先。
    pub kit_html: Option<&'a Path>,
}

/// Vault を作成する。手順はモジュール doc のとおりである。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: 作成の結果の書き込み先。
/// - `stderr`: 警告の書き込み先。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - 制御端末を開けない場合は [`CliError::TerminalRequired`]。入力元の指定があっても、端末は必要である。
/// - Vault のパスにファイルがある場合は [`CliError::VaultAlreadyExists`]。
/// - HTML の出力先にファイルがある場合は [`CliError::KitAlreadyExists`]。
///   出力先が Vault のパスと重なる場合は [`CliError::KitPathConflictsWithVault`]。
/// - 端末から入力した 2 回のパスワードが異なる場合は [`CliError::PasswordMismatch`]。
/// - コードの再入力の前に端末の入力が終わった場合は [`CliError::RecoveryKitNotConfirmed`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - その他の読み込み、乱数、暗号処理、ファイル操作の失敗は、対応する [`CliError`]。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。このとき Vault は作成済みである。
///
/// [`CliError::OutputFailed`] 以外の失敗では、Vault ファイルを作成も変更もしない。
pub fn run(
    request: InitRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let vault = request.vault.ok_or(CliError::VaultPathRequired)?;
    // リカバリーキットを表示できない環境では、パスワードを読み込む前に中止する。
    let terminal = Terminal::open().map_err(|_| CliError::TerminalRequired)?;
    // 秘密を保持している間は、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    let lock = VaultLock::try_acquire(VaultPath::resolve(vault)?)?;
    if vault_file_exists(&lock)? {
        return Err(CliError::VaultAlreadyExists);
    }
    ensure_kit_destination_is_free(request.kit_html)?;

    let password = read_new_password(request.password_source, &watcher)?;
    let code = RecoveryCode::generate(fill_random)?;
    let contents = build_new_vault(
        password.as_slice(),
        &code,
        &Argon2Params::for_native(),
        fill_random,
    )
    .map_err(CliError::from_creation_error)?;
    drop(password);
    ensure_not_interrupted(&watcher)?;
    // 鍵導出の間に、ロックに従わない処理が作ったファイルを、出力と表示の前に検出する。
    if vault_file_exists(&lock)? {
        return Err(CliError::VaultAlreadyExists);
    }

    let grouped = code.grouped()?;
    let grouped = core::str::from_utf8(grouped.as_slice()).map_err(|_| CliError::InvalidState)?;
    let kit = match request.kit_html {
        Some(path) => Some(PendingKit::write(path, grouped)?),
        None => None,
    };
    // 出力先が Vault と同じファイルを指す場合は、利用者がコードを控える前に中止する。
    if kit.is_some() && vault_file_exists(&lock)? {
        return Err(CliError::KitPathConflictsWithVault);
    }

    confirm_recovery_kit(&terminal, grouped, &code, &watcher)?;
    ensure_not_interrupted(&watcher)?;

    let vault_sync =
        create_vault_file_atomically(&lock, &contents).map_err(|error| match error {
            StorageError::AlreadyExists => CliError::VaultAlreadyExists,
            other => CliError::from(other),
        })?;
    // Vault を作成した後は、中断のシグナルを受けていても、作成の結果を報告する。
    let kit_sync = kit.map(PendingKit::keep);

    for sync in [Some(vault_sync), kit_sync].into_iter().flatten() {
        warn_if_directory_not_synced(stderr, sync);
    }
    report_created(stdout, lock.vault_path().file(), request.kit_html)
        .map_err(|_| CliError::OutputFailed)
}

/// エントリを持たない新しい Vault を作り、直列化したバイト列を返す。
///
/// # Errors
///
/// - 乱数源が失敗した場合は [`VaultError::System`]。
/// - 鍵導出、暗号化、直列化に失敗した場合は、対応する [`VaultError`]。
pub fn build_new_vault<R>(
    password: &[u8],
    recovery_code: &RecoveryCode,
    params: &Argon2Params,
    mut fill_random: R,
) -> Result<Vec<u8>, VaultError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    let header = VaultHeader::new(VAULT_FORMAT_VERSION, CIPHER_SUITE.as_u8(), INITIAL_EPOCH_ID);
    // コアのスロットの関数は `SecretBytes` を受け取るため、DEK は `mlock` しない領域に置く。破棄時に消去する。
    let mut dek = SecretBytes::<DEK_LEN>::zero();
    fill_random(dek.as_mut_slice())?;

    let password_slot = new_password_slot(&dek, &header, password, params, &mut fill_random)?;
    let recovery_slot = new_recovery_slot(&dek, &header, recovery_code, &mut fill_random)?;

    let cipher = VaultCipher::new(CIPHER_SUITE, dek.as_bytes());
    let records = seal_entries(&cipher, &header, &[], fill_random)?;
    let vault = Vault::new(header, vec![password_slot, recovery_slot], records);
    serialize(&vault).map_err(VaultError::Parse)
}

/// 作成の結果を書く。
fn report_created(
    stdout: &mut impl Write,
    vault: &Path,
    kit_html: Option<&Path>,
) -> std::io::Result<()> {
    writeln!(stdout, "Vault を作成しました: {}", vault.display())?;
    report_kit(stdout, kit_html)?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use fidelogic_core::{
        Argon2Params, Argon2idSlotPayload, CipherSuiteId, DEK_LEN, KekSlots, SlotStatus,
        SystemError, Vault, VaultCipher, VaultEngine, VaultError, deserialize, open_entries,
        unwrap_dek_slot0_for_header, unwrap_dek_slot2_for_header,
    };

    use super::{INITIAL_EPOCH_ID, VAULT_FORMAT_VERSION, build_new_vault};
    use crate::recovery_code::RecoveryCode;

    type TestResult = Result<(), Box<dyn Error>>;

    const PASSWORD: &[u8] = b"correct horse battery staple";

    /// テストで使うリカバリーコード (乱数が全ビット 0)。
    fn recovery_code() -> Result<RecoveryCode, Box<dyn Error>> {
        Ok(RecoveryCode::parse(b"FL000-00000-00000-00000-00000-00014")?)
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

    /// 高速な鍵導出パラメータで Vault を作り、解析する。
    fn build_and_parse(lengths: &mut Vec<usize>) -> Result<Vault, Box<dyn Error>> {
        let contents = build_new_vault(
            PASSWORD,
            &recovery_code()?,
            &Argon2Params::fast_test(),
            counting_source(lengths),
        )
        .map_err(|error| format!("Vault の作成に失敗: {error}"))?;
        let (vault, rest) = deserialize(&contents).map_err(|error| format!("{error}"))?;
        assert!(
            rest.is_empty(),
            "末尾の余分なバイトが無いことの確認に失敗。"
        );
        Ok(vault)
    }

    #[test]
    fn test_new_vault_has_initial_header_and_two_slots() -> TestResult {
        let vault = build_and_parse(&mut Vec::new())?;
        assert_eq!(vault.header.version, VAULT_FORMAT_VERSION);
        assert_eq!(
            vault.header.suite_id,
            CipherSuiteId::XChaCha20Poly1305.as_u8()
        );
        assert_eq!(vault.header.epoch_id, INITIAL_EPOCH_ID);
        assert_eq!((VAULT_FORMAT_VERSION, INITIAL_EPOCH_ID), (1, 1));
        let slot_ids: Vec<u8> = vault.slots.iter().map(|slot| slot.slot_id()).collect();
        assert_eq!(slot_ids, [0, 2], "スロットの構成の確認に失敗。");
        Ok(())
    }

    /// DEK、ソルト、ノンスを、すべて乱数源から取ること。
    #[test]
    fn test_new_vault_takes_every_random_value_from_source() -> TestResult {
        let mut lengths = Vec::new();
        let vault = build_and_parse(&mut lengths)?;
        // DEK、Slot 0 のソルトとノンス、Slot 2 のソルトとノンス、マニフェストのノンス。
        assert_eq!(lengths, [32, 16, 24, 32, 24, 24]);

        let [password_slot, recovery_slot] = vault.slots.as_slice() else {
            return Err("スロットの数の確認に失敗。".into());
        };
        let payload = Argon2idSlotPayload::from_slot_entry(password_slot)
            .map_err(|error| format!("{error}"))?;
        assert_eq!(payload.salt, [2; 16], "Slot 0 のソルトの確認に失敗。");
        assert_eq!(payload.nonce, [3; 24], "Slot 0 のノンスの確認に失敗。");
        let params = Argon2Params::fast_test();
        assert_eq!(
            (
                payload.params.m_cost(),
                payload.params.t_cost(),
                payload.params.p_cost()
            ),
            (params.m_cost(), params.t_cost(), params.p_cost()),
            "鍵導出パラメータの記録に失敗。"
        );
        let recovery_payload = recovery_slot.wrapped_dek();
        assert!(
            recovery_payload.windows(32).any(|window| window == [4; 32])
                && recovery_payload.windows(24).any(|window| window == [5; 24]),
            "Slot 2 のソルトとノンスの確認に失敗。"
        );

        let dek = unwrap_dek_slot0_for_header(password_slot, PASSWORD, &vault.header)
            .map_err(|error| format!("{error}"))?;
        assert_eq!(dek.as_bytes(), &[1; DEK_LEN], "DEK の確認に失敗。");
        Ok(())
    }

    #[test]
    fn test_both_slots_wrap_the_same_key_and_manifest_opens() -> TestResult {
        let vault = build_and_parse(&mut Vec::new())?;
        let [password_slot, recovery_slot] = vault.slots.as_slice() else {
            return Err("スロットの数の確認に失敗。".into());
        };
        let code = recovery_code()?;
        let from_password = unwrap_dek_slot0_for_header(password_slot, PASSWORD, &vault.header)
            .map_err(|error| format!("{error}"))?;
        let from_recovery =
            unwrap_dek_slot2_for_header(recovery_slot, code.as_bytes(), &vault.header)
                .map_err(|error| format!("{error}"))?;
        assert_eq!(from_password.as_bytes(), from_recovery.as_bytes());

        let cipher = VaultCipher::new(CipherSuiteId::XChaCha20Poly1305, from_password.as_bytes());
        let entries = open_entries(&cipher, &vault.header, &vault.records)
            .map_err(|error| format!("{error}"))?;
        assert!(entries.is_empty(), "空の Vault の確認に失敗。");
        Ok(())
    }

    /// 解錠の経路 (状態機械とコアの正準化を通る API) で解錠できることと、誤った資格情報を拒否すること。
    #[test]
    fn test_new_vault_unlocks_through_engine() -> TestResult {
        let vault = build_and_parse(&mut Vec::new())?;
        let engine = || {
            VaultEngine::new(KekSlots::new(
                SlotStatus::Valid,
                SlotStatus::Unset,
                SlotStatus::Valid,
            ))
        };
        engine()
            .unlock_vault_with_password(&vault, PASSWORD)
            .map_err(|error| format!("パスワードでの解錠に失敗: {error}"))?;
        engine()
            .unlock_vault_with_recovery_code(&vault, b"fl000 00000 00000 00000 00000 00014")
            .map_err(|error| format!("リカバリーコードでの解錠に失敗: {error}"))?;
        assert_eq!(
            engine().unlock_vault_with_password(&vault, b"wrong password"),
            Err(VaultError::AuthenticationFailed)
        );
        assert_eq!(
            engine().unlock_vault_with_recovery_code(&vault, recovery_code()?.as_bytes()),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn test_entropy_failure_at_any_request_is_reported() -> TestResult {
        let code = recovery_code()?;
        for failing in 0..6 {
            let mut calls = 0;
            let result = build_new_vault(PASSWORD, &code, &Argon2Params::fast_test(), |buffer| {
                calls += 1;
                if calls > failing {
                    return Err(SystemError::EntropySourceFailed);
                }
                buffer.fill(7);
                Ok(())
            });
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
}
