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
    Argon2Params, CipherSuiteId, DEK_LEN, SLOT0_NONCE_LEN, SLOT0_SALT_LEN, SLOT2_NONCE_LEN,
    SLOT2_SALT_LEN, SecretBytes, SecretVec, SystemError, Vault, VaultCipher, VaultError,
    VaultHeader, ct_eq_bytes_bool, seal_entries, serialize, wrap_dek_slot0_for_header,
    wrap_dek_slot2_for_header,
};

use crate::error::CliError;
use crate::password::canonicalize_password;
use crate::recovery_code::RecoveryCode;
use crate::recovery_kit::{screen_parts, write_html};
use crate::secret_input::{PasswordSource, SecretInputError, read_password};
use crate::sys::random::fill_random;
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{
    DirectorySync, StorageError, VaultLock, VaultPath, create_vault_file_atomically,
    vault_file_exists, write_new_private_file,
};
use crate::sys::tty::Terminal;

/// 作成する Vault のフォーマットバージョン。
pub const VAULT_FORMAT_VERSION: u8 = 1;

/// 作成する Vault の最初の世代 (`epoch_id`)。
pub const INITIAL_EPOCH_ID: u64 = 1;

/// 作成する Vault の暗号スイート。
const CIPHER_SUITE: CipherSuiteId = CipherSuiteId::XChaCha20Poly1305;

/// 端末からマスターパスワードを読み込むときのプロンプト。
const NEW_PASSWORD_PROMPT: &str = "新しいマスターパスワード: ";

/// 端末からマスターパスワードを再入力させるときのプロンプト。
const REPEAT_PASSWORD_PROMPT: &str = "確認のため、もう一度入力してください: ";

/// リカバリーコードの末尾を再入力させるときのプロンプト。
const CONFIRMATION_PROMPT: &str = "末尾 5 文字 (入力は表示されません): ";

/// 再入力が一致しなかったときに、画面の末尾に表示する案内。
const MISMATCH_NOTICE: &str = "一致しません。もう一度入力してください。\n";

/// 代替画面に切り替える制御列。
const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h";

/// カーソルを左上に移して画面を消去する制御列。
const CLEAR_SCREEN: &str = "\x1b[H\x1b[2J";

/// 画面を消去してから、元の画面に戻る制御列。
const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[H\x1b[2J\x1b[?1049l";

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
    if request
        .kit_html
        .is_some_and(|path| path.symlink_metadata().is_ok())
    {
        return Err(CliError::KitAlreadyExists);
    }

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

    // ソルトとノンスは秘密ではない。
    let mut password_salt = [0u8; SLOT0_SALT_LEN];
    let mut password_nonce = [0u8; SLOT0_NONCE_LEN];
    fill_random(&mut password_salt)?;
    fill_random(&mut password_nonce)?;
    let mut recovery_salt = [0u8; SLOT2_SALT_LEN];
    let mut recovery_nonce = [0u8; SLOT2_NONCE_LEN];
    fill_random(&mut recovery_salt)?;
    fill_random(&mut recovery_nonce)?;

    let password_slot = wrap_dek_slot0_for_header(
        &dek,
        password,
        &password_salt,
        &password_nonce,
        params,
        &header,
    )?;
    // 正準化を伴う `wrap_dek_slot2_code_for_header` は、コードを `mlock` しないヒープに複写するため使わない。
    // 正準形はコアの正準化で変化しないため、正準化を伴わない関数に渡しても同じ結果になる。
    let recovery_slot = wrap_dek_slot2_for_header(
        &dek,
        recovery_code.as_bytes(),
        &recovery_salt,
        &recovery_nonce,
        &header,
    )?;

    let cipher = VaultCipher::new(CIPHER_SUITE, dek.as_bytes());
    let records = seal_entries(&cipher, &header, &[], fill_random)?;
    let vault = Vault::new(header, vec![password_slot, recovery_slot], records);
    serialize(&vault).map_err(VaultError::Parse)
}

/// マスターパスワードを読み込んで正準化する。端末の場合は 2 回入力させ、一致を確かめる。
fn read_new_password(
    source: &PasswordSource,
    watcher: &InterruptWatcher,
) -> Result<SecretVec, CliError> {
    let password = read_canonical_password(source, NEW_PASSWORD_PROMPT, watcher)?;
    if *source == PasswordSource::Terminal {
        let repeated = read_canonical_password(source, REPEAT_PASSWORD_PROMPT, watcher)?;
        if !ct_eq_bytes_bool(password.as_slice(), repeated.as_slice()) {
            return Err(CliError::PasswordMismatch);
        }
    }
    Ok(password)
}

/// パスワードを 1 回読み込んで正準化する。読み込んだ内容は、戻る前に消去する。
fn read_canonical_password(
    source: &PasswordSource,
    prompt: &str,
    watcher: &InterruptWatcher,
) -> Result<SecretVec, CliError> {
    let input = read_password(source, prompt, watcher)?;
    Ok(canonicalize_password(input.as_bytes())?)
}

/// 中断のシグナルを受けていた場合は失敗する。
fn ensure_not_interrupted(watcher: &InterruptWatcher) -> Result<(), CliError> {
    if watcher.is_interrupted() {
        Err(CliError::Interrupted)
    } else {
        Ok(())
    }
}

/// 代替画面にリカバリーキットを表示し、コードの末尾が正しく再入力されるまで繰り返す。
///
/// 成否によらず、戻る前に画面を消去して元の画面に戻す。
///
/// # Args
///
/// - `grouped`: 表示用の、区切りを含むコード。
///
/// # Errors
///
/// - 再入力の前に端末の入力が終わった場合 (`Ctrl+D`、切断) は [`CliError::RecoveryKitNotConfirmed`]。
/// - 中断のシグナルを受けた場合は、中断を示すエラー。
/// - 端末の読み書きに失敗した場合は、対応するエラー。
fn confirm_recovery_kit(
    terminal: &Terminal,
    grouped: &str,
    code: &RecoveryCode,
    watcher: &InterruptWatcher,
) -> Result<(), CliError> {
    let screen = AlternateScreen::enter(terminal, watcher)?;
    let mut notice = "";
    loop {
        // 失敗の案内でコードが画面の外に流れないように、毎回描き直す。
        screen.draw(screen_parts(grouped), notice)?;
        // 読み込みの手順は、端末からのパスワードの入力と同じである。
        match read_password(&PasswordSource::Terminal, CONFIRMATION_PROMPT, watcher) {
            Ok(input) if code.confirms_suffix(input.as_bytes()) => return Ok(()),
            Ok(_) | Err(SecretInputError::Empty | SecretInputError::TooLong) => {
                notice = MISMATCH_NOTICE;
            }
            Err(SecretInputError::EndOfInput) => return Err(CliError::RecoveryKitNotConfirmed),
            Err(error) => return Err(error.into()),
        }
    }
}

/// 端末の代替画面を使っている間だけ存在する値。破棄すると、画面を消去して元の画面に戻る。
struct AlternateScreen<'a> {
    terminal: &'a Terminal,
    watcher: &'a InterruptWatcher,
}

impl<'a> AlternateScreen<'a> {
    /// 代替画面に切り替える。
    fn enter(terminal: &'a Terminal, watcher: &'a InterruptWatcher) -> Result<Self, CliError> {
        // 切り替えの書き込みが途中で失敗しても、破棄の処理で元の画面に戻す。
        let screen = Self { terminal, watcher };
        screen.write(ENTER_ALTERNATE_SCREEN)?;
        Ok(screen)
    }

    /// 画面を消去し、`parts` と `notice` を順に書く。
    fn draw(&self, parts: [&str; 3], notice: &str) -> Result<(), CliError> {
        self.write(CLEAR_SCREEN)?;
        for part in parts {
            self.write(part)?;
        }
        self.write(notice)
    }

    fn write(&self, text: &str) -> Result<(), CliError> {
        if self.terminal.write(text, self.watcher)? {
            Ok(())
        } else {
            Err(CliError::Interrupted)
        }
    }
}

impl Drop for AlternateScreen<'_> {
    fn drop(&mut self) {
        // 中断した後にも書き込めるように、中断の確認を伴わない書き込みを使う。
        self.terminal.write_without_waiting(LEAVE_ALTERNATE_SCREEN);
    }
}

/// 書き出した HTML のリカバリーキット。[`PendingKit::keep`] を呼ばずに破棄すると、ファイルを削除する。
struct PendingKit<'a> {
    path: &'a Path,
    directory_sync: DirectorySync,
    keep: bool,
}

impl<'a> PendingKit<'a> {
    /// HTML を新規に書き出す。
    fn write(path: &'a Path, grouped: &str) -> Result<Self, CliError> {
        let directory_sync = write_new_private_file(path, |file| write_html(file, grouped))
            .map_err(|error| match error {
                StorageError::AlreadyExists => CliError::KitAlreadyExists,
                other => CliError::from(other),
            })?;
        Ok(Self {
            path,
            directory_sync,
            keep: false,
        })
    }

    /// ファイルを残し、親ディレクトリの同期の結果を返す。
    fn keep(mut self) -> DirectorySync {
        self.keep = true;
        self.directory_sync
    }
}

impl Drop for PendingKit<'_> {
    fn drop(&mut self) {
        if !self.keep {
            // 削除に失敗した場合も、元の失敗を報告する。残るコードに対応する Vault は存在しない。
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// 親ディレクトリの同期に失敗した場合に、警告を書く。
fn warn_if_directory_not_synced(stderr: &mut impl Write, sync: DirectorySync) {
    if let DirectorySync::Failed { errno } = sync {
        let message = format!(
            "警告: 親ディレクトリの同期に失敗しました (errno: {errno})。直後に電源が切れると、作成したファイルが失われる可能性があります。"
        );
        // 警告の書き込みに失敗しても、作成の結果は変わらないため、結果を無視する。
        let _ = crate::write_error_line(stderr, &message);
    }
}

/// 作成の結果を書く。
fn report_created(
    stdout: &mut impl Write,
    vault: &Path,
    kit_html: Option<&Path>,
) -> std::io::Result<()> {
    writeln!(stdout, "Vault を作成しました: {}", vault.display())?;
    if let Some(path) = kit_html {
        writeln!(
            stdout,
            "リカバリーキットを書き出しました: {}",
            path.display()
        )?;
        writeln!(stdout, "印刷した後は、このファイルを削除してください。")?;
    }
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

    use super::{
        INITIAL_EPOCH_ID, VAULT_FORMAT_VERSION, build_new_vault, warn_if_directory_not_synced,
    };
    use crate::recovery_code::RecoveryCode;
    use crate::sys::storage::DirectorySync;

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
    fn test_directory_sync_failure_is_warned_in_one_line() -> TestResult {
        let mut stderr = Vec::new();
        warn_if_directory_not_synced(&mut stderr, DirectorySync::Synced);
        assert!(
            stderr.is_empty(),
            "同期の成功で警告しないことの確認に失敗。"
        );

        warn_if_directory_not_synced(&mut stderr, DirectorySync::Failed { errno: 5 });
        let warning = String::from_utf8(stderr)?;
        assert!(
            warning.starts_with("fidelogic-cli: 警告: ")
                && warning.contains("errno: 5")
                && warning.lines().count() == 1,
            "警告の出力の確認に失敗: {warning}"
        );
        Ok(())
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
