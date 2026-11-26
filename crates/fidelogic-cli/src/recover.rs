//! # リカバリーコードによる復旧 (`recover`)
//!
//! `recover` サブコマンドの処理を置く。
//! リカバリーコード (Slot 2) で解錠し、マスターパスワード (Slot 0) を再設定する。このモジュールは OS に依存しない。
//!
//! ## 入力
//!
//! - リカバリーコードは、常に制御端末からエコーせずに読み込む。解釈の規則は [`crate::recovery_code`] を参照する。
//!   チェックサムは鍵導出より前に検証し、誤りは入力の誤りとして表示する。
//! - 新しいマスターパスワードは、`--password-stdin` などで指定した入力元から読み込む。
//!   指定が無ければ、制御端末で 2 回入力させる。
//!
//! ## 更新する内容
//!
//! DEK は変えない。Slot 0 を作り直し、`--keep-recovery-code` の指定が無ければ Slot 2 も作り直す。
//! 他のスロットと未知のレコードは変えず、全エントリを次の世代で暗号化し直す。
//!
//! 手順は `rotate-key` と共通で、次の順に進む。
//!
//! 1. 制御端末を開き、サイドカーロックを待たずに取得して Vault を読み込む。HTML の出力先が空いていることを確かめる。
//! 2. 解錠して、全エントリを復号する。改ざんされた Vault は、利用者が新しいパスワードを入力する前に検出する。
//! 3. 新しいパスワードを読み込み、スロットを作る。
//! 4. コードを再発行する場合は、HTML を書き出し、代替画面に表示して末尾の再入力を確認する。
//! 5. 世代を 1 つ進めて、アトミックに保存する。
//!
//! 利用者がコードを控えたことを確認するまで、Vault は書き換えない。保存せずに終わる場合は、書き出した HTML を削除する。
//! `SIGKILL` などでプロセスが終了した場合は、HTML が残ることがある。ロックは、入力と確認の間も保持する。
//!
//! DEK を変えないため、更新前の Vault の複製と以前のコードがあれば、更新後の内容も復号できる。
//! コードの漏洩が疑われる場合は、続けて `rotate-key --full-dek` を実行する。

use std::io::Write;
use std::path::Path;

use fidelogic_core::SlotCredential;

use crate::args::RecoveryCodePlan;
use crate::error::CliError;
use crate::interaction::read_new_password;
use crate::key_update::{
    UnlockedVault, UpdateKind, UpdateTarget, report_recovery_code, update_and_save,
};
use crate::recovery_code::{RecoveryCode, RecoveryCodeError};
use crate::secret_input::{PasswordSource, SecretInputError, read_password};
use crate::sys::signal::InterruptWatcher;

/// 端末からリカバリーコードを読み込むときのプロンプト。
const RECOVERY_CODE_PROMPT: &str = "リカバリーコード (入力は表示されません): ";

/// `recover` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct RecoverRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// 新しいマスターパスワードの入力元。
    pub password_source: &'a PasswordSource,
    /// リカバリーコードの扱いと、再発行する場合の HTML の出力先。
    pub recovery_code: RecoveryCodePlan<&'a Path>,
}

/// リカバリーコードで解錠し、マスターパスワードを再設定する。
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
/// - 制御端末を開けない場合は [`CliError::TerminalRequired`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - リカバリーコードの形式やチェックサムの誤りは [`CliError::RecoveryCode`]。
/// - コードの入力の前に端末の入力が終わった場合は [`CliError::RecoveryCodeNotEntered`]。
/// - 誤ったコード、Slot 2 が無い場合、改ざんされた Vault は [`CliError::AuthenticationFailed`]。
/// - 端末から入力した 2 回のパスワードが異なる場合は [`CliError::PasswordMismatch`]。
/// - HTML の出力先にファイルがある場合は [`CliError::KitAlreadyExists`]。
/// - コードの再入力の前に端末の入力が終わった場合は [`CliError::RecoveryKitNotConfirmed`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - その他の読み込み、乱数、暗号処理、ファイル操作の失敗は、対応する [`CliError`]。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。このとき Vault は更新済みである。
///
/// [`CliError::OutputFailed`] 以外の失敗では、Vault を変更しない。
pub fn run(
    request: RecoverRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let (target, loaded) = UpdateTarget::open(request.vault, request.recovery_code.kit_html())?;

    let code = read_recovery_code(&target.watcher)?;
    // 正準化を伴う資格情報は、コードを `mlock` しないヒープに複写するため使わない。
    let unlocked = UnlockedVault::unlock(loaded, SlotCredential::recovery(code.as_bytes()))?;
    drop(code);

    let password = read_new_password(request.password_source, &target.watcher)?;
    let kind = UpdateKind::Rewrap(request.recovery_code);
    update_and_save(&target, unlocked, password, kind, stderr)?;

    report(
        stdout,
        target.lock.vault_path().file(),
        request.recovery_code,
    )
    .map_err(|_| CliError::OutputFailed)
}

/// 端末からリカバリーコードを読み込み、チェックサムを検証する。読み込んだ内容は、戻る前に消去する。
fn read_recovery_code(watcher: &InterruptWatcher) -> Result<RecoveryCode, CliError> {
    match read_password(&PasswordSource::Terminal, RECOVERY_CODE_PROMPT, watcher) {
        Ok(input) => Ok(RecoveryCode::parse(input.as_bytes())?),
        // 空の入力と長すぎる入力は、パスワードではなく、コードの文字数の誤りとして表示する。
        Err(SecretInputError::Empty | SecretInputError::TooLong) => {
            Err(RecoveryCodeError::InvalidLength.into())
        }
        Err(SecretInputError::EndOfInput) => Err(CliError::RecoveryCodeNotEntered),
        Err(error) => Err(error.into()),
    }
}

/// 復旧の結果を書く。
fn report(
    stdout: &mut impl Write,
    vault: &Path,
    recovery_code: RecoveryCodePlan<&Path>,
) -> std::io::Result<()> {
    writeln!(
        stdout,
        "マスターパスワードを再設定しました: {}",
        vault.display()
    )?;
    report_recovery_code(stdout, recovery_code)?;
    stdout.flush()
}
