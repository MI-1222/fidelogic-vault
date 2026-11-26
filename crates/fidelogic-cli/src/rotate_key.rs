//! # 鍵の更新 (`rotate-key`)
//!
//! `rotate-key` サブコマンドの処理を置く。現在のマスターパスワード (Slot 0) で解錠し、鍵を更新する。
//! このモジュールは OS に依存しない。
//!
//! ## 方式
//!
//! | 指定 | DEK | Slot 0 | Slot 1 (WebAuthn PRF) | Slot 2 (リカバリーコード) |
//! | :-- | :-- | :-- | :-- | :-- |
//! | `--kek-only` (既定) | 維持 | 作り直す | 維持 | 維持 |
//! | `--kek-only --new-recovery-code` | 維持 | 作り直す | 維持 | 作り直す |
//! | `--full-dek` | 新規 | 作り直す | 取り除く | 作り直す |
//!
//! どの方式も、未知のスロットと未知のレコードは変えず、全エントリを次の世代で暗号化し直す。
//! スロットの扱いの詳細は [`crate::rekey`]、解錠から保存までの手順は [`crate::recover`] を参照する。
//! `--full-dek` の同意の確認は、解錠の後、新しいパスワードの入力の前に行う。
//!
//! `--kek-only` は DEK を変えない。更新前の Vault の複製と、更新前のパスワードやリカバリーコードがあれば、
//! 更新後の内容も復号できる。漏洩が疑われる場合は `--full-dek` を使う。
//!
//! ## 入力
//!
//! - 現在のマスターパスワードは、`--password-stdin` などで指定した入力元から読み込む。指定が無ければ制御端末から読み込む。
//! - 新しいマスターパスワードは、常に制御端末で 2 回入力させる。現在と同じ値を入力した場合も、
//!   Slot 0 を新しいソルトとノンス、現在の既定の鍵導出パラメータで作り直し、全エントリを暗号化し直す。
//!
//! ## WebAuthn PRF のスロット
//!
//! `--full-dek` は、PRF の出力が無いと Slot 1 を作り直せないため、取り除く。Slot 1 がある場合は、
//! 現在のパスワードを制御端末から読み込むときは同意を求め、入力元を指定したときは `--drop-prf-slot` を必須とする。
//! `--drop-prf-slot` を指定した場合は、同意を求めない。

use std::io::Write;
use std::path::Path;

use fidelogic_core::SlotCredential;

use crate::args::RotateMode;
use crate::error::CliError;
use crate::interaction::{ask_consent, read_canonical_password, read_new_password};
use crate::key_update::{
    UnlockedVault, UpdateKind, UpdateTarget, report_recovery_code, update_and_save,
};
use crate::rekey::has_prf_slot;
use crate::secret_input::PasswordSource;
use crate::sys::signal::InterruptWatcher;

/// 端末から現在のマスターパスワードを読み込むときのプロンプト。
const CURRENT_PASSWORD_PROMPT: &str = "現在のマスターパスワード: ";

/// Slot 1 を取り除くことの同意を求めるプロンプト。
const PRF_REMOVAL_PROMPT: &str = concat!(
    "この Vault の WebAuthn PRF のスロットは --full-dek で破棄され、登録し直すまで PRF では解錠できません。\n",
    "続ける場合は y を入力してください (y/N、入力は表示されません): ",
);

/// `rotate-key` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct RotateKeyRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// 現在のマスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// 更新の方式。リカバリーコードを再発行する場合は、HTML の出力先を含む。
    pub mode: &'a RotateMode,
}

/// 現在のマスターパスワードで解錠し、鍵を更新する。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: 結果の書き込み先。
/// - `stderr`: 警告の書き込み先。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - 制御端末を開けない場合は [`CliError::TerminalRequired`]。入力元の指定があっても、端末は必要である。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワード、Slot 0 が無い場合、改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - Slot 1 がある Vault の `--full-dek` で、入力元を指定して `--drop-prf-slot` が無い場合は [`CliError::PrfSlotRequiresDrop`]、同意しなかった場合は [`CliError::PrfSlotDropDeclined`]。
/// - 端末から入力した 2 回の新しいパスワードが異なる場合は [`CliError::PasswordMismatch`]。
/// - HTML の出力先にファイルがある場合は [`CliError::KitAlreadyExists`]。
/// - コードの再入力の前に端末の入力が終わった場合は [`CliError::RecoveryKitNotConfirmed`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - その他の読み込み、乱数、暗号処理、ファイル操作の失敗は、対応する [`CliError`]。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。このとき Vault は更新済みである。
///
/// [`CliError::OutputFailed`] 以外の失敗では、Vault を変更しない。
pub fn run(
    request: RotateKeyRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let kind = match request.mode {
        RotateMode::KekOnly { recovery_code } => UpdateKind::Rewrap(recovery_code.as_deref()),
        RotateMode::FullDek { kit_html, .. } => UpdateKind::ReplaceDek {
            kit_html: kit_html.as_deref(),
        },
    };
    let (target, loaded) = UpdateTarget::open(request.vault, kind.recovery_code().kit_html())?;

    let current = read_canonical_password(
        request.password_source,
        CURRENT_PASSWORD_PROMPT,
        &target.watcher,
    )?;
    let unlocked = UnlockedVault::unlock(loaded, SlotCredential::password(current.as_slice()))?;
    drop(current);

    let drops_prf_slot =
        matches!(kind, UpdateKind::ReplaceDek { .. }) && has_prf_slot(unlocked.loaded().slots());
    if drops_prf_slot
        && let RotateMode::FullDek {
            drop_prf_slot: false,
            ..
        } = request.mode
    {
        confirm_prf_removal(request.password_source, &target.watcher)?;
    }

    let password = read_new_password(&PasswordSource::Terminal, &target.watcher)?;
    update_and_save(&target, unlocked, password, kind, stderr)?;

    report(
        stdout,
        target.lock.vault_path().file(),
        kind,
        drops_prf_slot,
    )
    .map_err(|_| CliError::OutputFailed)
}

/// Slot 1 を取り除くことの同意を得る。パスワードの入力元を指定した場合は、非対話の実行とみなして中止する。
fn confirm_prf_removal(
    password_source: &PasswordSource,
    watcher: &InterruptWatcher,
) -> Result<(), CliError> {
    if *password_source != PasswordSource::Terminal {
        return Err(CliError::PrfSlotRequiresDrop);
    }
    if ask_consent(PRF_REMOVAL_PROMPT, watcher)? {
        Ok(())
    } else {
        Err(CliError::PrfSlotDropDeclined)
    }
}

/// 更新の結果を書く。
fn report(
    stdout: &mut impl Write,
    vault: &Path,
    kind: UpdateKind<'_>,
    dropped_prf_slot: bool,
) -> std::io::Result<()> {
    let summary = match kind {
        UpdateKind::Rewrap(_) => "鍵を更新しました",
        UpdateKind::ReplaceDek { .. } => "DEK を更新し、全エントリを暗号化し直しました",
    };
    writeln!(stdout, "{summary}: {}", vault.display())?;
    if dropped_prf_slot {
        writeln!(stdout, "WebAuthn PRF のスロットを破棄しました。")?;
    }
    report_recovery_code(stdout, kind.recovery_code())?;
    stdout.flush()
}
