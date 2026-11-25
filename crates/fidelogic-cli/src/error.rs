//! # CLI のエラー (`error`)
//!
//! サブコマンドの実行で起きる失敗を [`CliError`] にまとめ、表示するメッセージと終了コードの分類を対応付ける。
//! 引数の誤りは `bpaf` が組み立てたメッセージをそのまま表示するため、この型には含めない
//! ([`crate::args::ParseExit`] を参照)。
//!
//! ## 認証の失敗を 1 つにまとめる
//!
//! Vault の解錠と読み込みで起きた [`VaultError`] は、[`CliError::from_unlock_error`] で変換する。
//! 誤ったパスワード、未設定のスロット、改ざん (ヘッダーの解析失敗、認証タグの不一致、チャンクの欠損など) は、
//! すべて [`CliError::AuthenticationFailed`] になり、同じメッセージと同じ終了コードを返す。
//! 出力の違いから、どのスロットが設定されているかを推測させないためである。
//! ファイルのどこを改ざんすれば検知されるかも、同じ理由で推測させない。コアの [`VaultError::mask_auth_error`] と同じ規則に従う。

use core::fmt;

use fidelogic_core::VaultError;

use crate::exit::ExitCategory;
use crate::secret_input::SecretInputError;
use crate::sys::process::HardeningError;

/// 認証の失敗を表すメッセージ。失敗の理由によらず、この文言だけを表示する。
pub const AUTHENTICATION_FAILED_MESSAGE: &str = "Vault の解錠に失敗しました。";

/// サブコマンドの実行で起きる失敗。
///
/// 値はフィールドを持たないか、固定の文字列だけを持つ。
/// 秘密や、失敗の理由を細かく区別できる値 (オフセット、長さ、スロット番号など) を持たせない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliError {
    /// 起動時のプロセス硬化に失敗した。
    Hardening(HardeningError),
    /// サブコマンドがまだ実装されていない。値はサブコマンド名である。
    NotImplemented(&'static str),
    /// Vault の解錠または読み込みに失敗した。理由を区別しない。
    AuthenticationFailed,
    /// Vault の世代 (`epoch_id`) が、以前に読み込んだものより古い。
    RollbackDetected,
    /// エンジンの状態遷移が不正である (内部の誤り)。
    InvalidState,
    /// パスワードの入力に失敗した。中断を含む。
    SecretInput(SecretInputError),
    /// 標準出力への書き込みに失敗した。
    OutputFailed,
}

impl CliError {
    /// Vault の解錠と読み込みで起きた [`VaultError`] を、認証の失敗を 1 つにまとめて変換する。
    ///
    /// [`VaultError::mask_auth_error`] を適用したうえで、次のように対応付ける。
    ///
    /// | 変換前 | 変換後 |
    /// | :-- | :-- |
    /// | `InvalidState` | [`CliError::InvalidState`] |
    /// | `RollbackDetected` | [`CliError::RollbackDetected`] |
    /// | それ以外のすべて (`Parse`, `Crypto`, `System`, `Precis`, `SlotNotFound`, `AuthenticationFailed`) | [`CliError::AuthenticationFailed`] |
    ///
    /// # Notes
    ///
    /// 解錠と読み込み以外の処理 (入力した値の PRECIS 正準化など) で起きたエラーには使わない。
    /// 利用者の入力の誤りまで「解錠に失敗」と表示してしまうためである。
    #[must_use]
    pub const fn from_unlock_error(error: VaultError) -> Self {
        match error.mask_auth_error() {
            VaultError::InvalidState => Self::InvalidState,
            VaultError::RollbackDetected => Self::RollbackDetected,
            VaultError::Parse(_)
            | VaultError::Crypto(_)
            | VaultError::System(_)
            | VaultError::Precis(_)
            | VaultError::SlotNotFound
            | VaultError::AuthenticationFailed => Self::AuthenticationFailed,
        }
    }

    /// 終了コードの分類を返す。
    ///
    /// # Returns
    ///
    /// `AuthenticationFailed` は [`ExitCategory::AuthenticationFailed`]、
    /// 入力の中断は [`ExitCategory::Interrupted`]、それ以外は [`ExitCategory::Failure`]。
    #[must_use]
    pub const fn exit_category(self) -> ExitCategory {
        match self {
            Self::AuthenticationFailed => ExitCategory::AuthenticationFailed,
            Self::SecretInput(SecretInputError::Interrupted) => ExitCategory::Interrupted,
            Self::SecretInput(_)
            | Self::Hardening(_)
            | Self::NotImplemented(_)
            | Self::RollbackDetected
            | Self::InvalidState
            | Self::OutputFailed => ExitCategory::Failure,
        }
    }
}

impl From<HardeningError> for CliError {
    fn from(error: HardeningError) -> Self {
        Self::Hardening(error)
    }
}

impl From<SecretInputError> for CliError {
    fn from(error: SecretInputError) -> Self {
        Self::SecretInput(error)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hardening(error) => write!(formatter, "{error}"),
            Self::NotImplemented(name) => {
                write!(
                    formatter,
                    "サブコマンド `{name}` はまだ実装されていません。"
                )
            }
            Self::AuthenticationFailed => formatter.write_str(AUTHENTICATION_FAILED_MESSAGE),
            Self::RollbackDetected => formatter
                .write_str("Vault の世代が以前に読み込んだものより古いため、処理を中止しました。"),
            Self::InvalidState => formatter.write_str("内部状態が不正なため、処理を中止しました。"),
            Self::SecretInput(error) => write!(formatter, "{error}"),
            Self::OutputFailed => formatter.write_str("標準出力への書き込みに失敗しました。"),
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelogic_core::{CryptoError, PrecisError, SystemError, TlvParseError, VaultError};

    use super::{AUTHENTICATION_FAILED_MESSAGE, CliError};
    use crate::exit::ExitCategory;
    use crate::secret_input::SecretInputError;
    use crate::sys::process::{HardeningError, HardeningStep};

    /// 認証の失敗にまとめるべき `VaultError` の全バリアント。
    ///
    /// 下位のエラー型のバリアントもすべて列挙する。コアにバリアントが増えた場合は、ここにも追加する。
    fn errors_masked_as_authentication_failure() -> Vec<VaultError> {
        vec![
            VaultError::Parse(TlvParseError::UnexpectedEof),
            VaultError::Parse(TlvParseError::InvalidMagic),
            VaultError::Parse(TlvParseError::UnsupportedVersion),
            VaultError::Parse(TlvParseError::UnsupportedSuite),
            VaultError::Parse(TlvParseError::InvalidLength),
            VaultError::Parse(TlvParseError::InvalidFormat),
            VaultError::Crypto(CryptoError::AeadDecryptionFailed),
            VaultError::Crypto(CryptoError::AeadEncryptionFailed),
            VaultError::Crypto(CryptoError::KeyDerivationFailed),
            VaultError::Crypto(CryptoError::InvalidKeySize),
            VaultError::Crypto(CryptoError::InvalidNonceSize),
            VaultError::Crypto(CryptoError::InvalidTagSize),
            VaultError::Crypto(CryptoError::InvalidSliceLength),
            VaultError::Crypto(CryptoError::InvalidParameter),
            VaultError::System(SystemError::MemoryLockFailed),
            VaultError::System(SystemError::EntropySourceFailed),
            VaultError::Precis(PrecisError::EmptyInput),
            VaultError::Precis(PrecisError::DisallowedCodePoint(0x0007)),
            VaultError::SlotNotFound,
            VaultError::AuthenticationFailed,
        ]
    }

    #[test]
    fn test_unlock_errors_share_message_and_exit_code() {
        for error in errors_masked_as_authentication_failure() {
            let cli_error = CliError::from_unlock_error(error);
            assert_eq!(
                cli_error,
                CliError::AuthenticationFailed,
                "{error:?} の変換に失敗。"
            );
            assert_eq!(cli_error.to_string(), AUTHENTICATION_FAILED_MESSAGE);
            assert_eq!(
                cli_error.exit_category(),
                ExitCategory::AuthenticationFailed
            );
        }
    }

    #[test]
    fn test_unlock_error_keeps_state_and_rollback_distinct() {
        assert_eq!(
            CliError::from_unlock_error(VaultError::InvalidState),
            CliError::InvalidState
        );
        assert_eq!(
            CliError::from_unlock_error(VaultError::RollbackDetected),
            CliError::RollbackDetected
        );
        assert_eq!(
            CliError::RollbackDetected.exit_category(),
            ExitCategory::Failure
        );
        assert_eq!(
            CliError::InvalidState.exit_category(),
            ExitCategory::Failure
        );
    }

    #[test]
    fn test_hardening_error_is_general_failure_with_its_message() {
        let hardening = HardeningError::NotApplied {
            step: HardeningStep::CoreLimit,
        };
        let error = CliError::from(hardening);
        assert_eq!(error, CliError::Hardening(hardening));
        assert_eq!(error.to_string(), hardening.to_string());
        assert_eq!(error.exit_category(), ExitCategory::Failure);
    }

    #[test]
    fn test_only_interrupted_input_uses_interrupted_exit_code() {
        let interrupted = CliError::from(SecretInputError::Interrupted);
        assert_eq!(interrupted.exit_category(), ExitCategory::Interrupted);
        assert_eq!(
            interrupted.to_string(),
            SecretInputError::Interrupted.to_string()
        );
        for error in [
            SecretInputError::Empty,
            SecretInputError::TooLong,
            SecretInputError::MultipleLines,
            SecretInputError::EndOfInput,
            SecretInputError::MemoryLockFailed,
        ] {
            assert_eq!(
                CliError::from(error).exit_category(),
                ExitCategory::Failure,
                "{error:?} の終了コードの分類に失敗。"
            );
        }
    }

    #[test]
    fn test_messages_end_with_japanese_period() {
        let errors = [
            CliError::Hardening(HardeningError::Os {
                step: HardeningStep::Umask,
                errno: 1,
            }),
            CliError::NotImplemented("init"),
            CliError::AuthenticationFailed,
            CliError::RollbackDetected,
            CliError::InvalidState,
            CliError::SecretInput(SecretInputError::Interrupted),
            CliError::OutputFailed,
        ];
        for error in errors {
            let message = error.to_string();
            assert!(
                message.ends_with('。'),
                "{error:?} の文末の確認に失敗: {message}"
            );
        }
    }

    #[test]
    fn test_not_implemented_message_names_subcommand() {
        assert_eq!(
            CliError::NotImplemented("rotate-key").to_string(),
            "サブコマンド `rotate-key` はまだ実装されていません。"
        );
        assert_eq!(
            CliError::NotImplemented("rotate-key").exit_category(),
            ExitCategory::Failure
        );
    }
}
