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

use fidelogic_core::{SystemError, VaultError};

use crate::entry_ops::EntryField;
use crate::exit::ExitCategory;
use crate::password::PasswordError;
use crate::recovery_code::RecoveryCodeError;
use crate::secret_input::{MAX_PASSWORD_LEN, SecretInputError};
use crate::set::MAX_NOTES_LEN;
use crate::sys::clipboard::ClipboardError;
use crate::sys::process::HardeningError;
use crate::sys::signal::SignalError;
use crate::sys::storage::StorageError;
use crate::sys::tty::TtyError;
use crate::vault_file::VaultFileError;

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
    /// Vault の解錠または読み込みに失敗した。理由を区別しない。
    AuthenticationFailed,
    /// Vault の世代 (`epoch_id`) が、以前に読み込んだものより古い。
    RollbackDetected,
    /// エンジンの状態遷移が不正である (内部の誤り)。
    InvalidState,
    /// パスワードなどの秘密や、確認の応答の入力に失敗した。中断を含む。
    SecretInput(SecretInputError),
    /// 標準出力への書き込みに失敗した。
    OutputFailed,
    /// クリップボードへのコピーに失敗した。
    Clipboard(ClipboardError),
    /// 処理の途中で、中断のシグナルを受けた。
    Interrupted,
    /// 中断の捕捉を開始できない。
    Signal(SignalError),
    /// 端末の操作に失敗した。
    Terminal(TtyError),
    /// 制御端末を必要とする処理で、端末を開けない。
    TerminalRequired,
    /// Vault ファイルの操作に失敗した。
    Storage(StorageError),
    /// Vault のパスの指定が無い。
    VaultPathRequired,
    /// 作成する Vault のパスに、ファイルがすでに存在する。
    VaultAlreadyExists,
    /// リカバリーキットの出力先に、ファイルがすでに存在する。
    KitAlreadyExists,
    /// リカバリーキットの出力先が、Vault のパスと重なる。
    KitPathConflictsWithVault,
    /// 利用者がリカバリーコードを控えたことを確認できなかった。
    RecoveryKitNotConfirmed,
    /// 入力されたマスターパスワードを正準化できない。
    Password(PasswordError),
    /// 2 回入力した新しいパスワードが一致しない。
    PasswordMismatch,
    /// リカバリーコードの生成または読み取りに失敗した。
    RecoveryCode(RecoveryCodeError),
    /// 乱数の取得に失敗した。
    EntropySourceFailed,
    /// Vault の作成に必要な暗号処理に失敗した。
    VaultCreationFailed,
    /// 読み込む Vault のパスに、ファイルが無い。
    VaultNotFound,
    /// Vault の保存を中止した (外部の変更、世代の上限など)。
    VaultFile(VaultFileError),
    /// Vault の保存に必要な暗号処理に失敗した。
    VaultSaveFailed,
    /// リカバリーコードの入力の前に、端末の入力が終わった。
    RecoveryCodeNotEntered,
    /// WebAuthn PRF のスロットがある Vault で、非対話の実行に `--drop-prf-slot` の指定が無い。
    PrfSlotRequiresDrop,
    /// WebAuthn PRF のスロットの破棄に、利用者が同意しなかった。
    PrfSlotDropDeclined,
    /// 指定されたタイトルのエントリが無い。
    EntryNotFound,
    /// 指定されたタイトルのエントリが複数ある。
    EntryAmbiguous,
    /// 新しいエントリのタイトルとして使えない。
    InvalidEntryName,
    /// 認証に成功したエントリを、クレデンシャルとして解釈できない。
    MalformedEntry,
    /// 指定された項目に値が無い。
    FieldNotSet,
    /// 入力された項目の値を受け付けられない (使用できない文字、UTF-8 でない)。
    InvalidField(EntryField),
    /// 端末から入力した項目の値が、上限を超える。
    FieldTooLong(EntryField),
    /// 項目の入力の途中で、端末の入力が終わった。
    EntryInputAborted,
    /// ファイルまたは標準入力のメモが、上限を超える。
    NotesTooLong,
    /// ファイルまたは標準入力のメモが空である。
    NotesEmpty,
    /// エントリの削除に、利用者が同意しなかった。
    DeletionDeclined,
    /// 平文の書き出しに、利用者が同意しなかった。
    ExportDeclined,
    /// 書き出し先に、ファイルがすでに存在する。
    ExportDestinationExists,
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

    /// 新しい Vault の組み立てで起きた [`VaultError`] を変換する。
    ///
    /// # Returns
    ///
    /// 乱数の取得の失敗は [`CliError::EntropySourceFailed`]、それ以外は [`CliError::VaultCreationFailed`]。
    #[must_use]
    pub const fn from_creation_error(error: VaultError) -> Self {
        match error {
            VaultError::System(SystemError::EntropySourceFailed) => Self::EntropySourceFailed,
            VaultError::Parse(_)
            | VaultError::Crypto(_)
            | VaultError::System(_)
            | VaultError::Precis(_)
            | VaultError::SlotNotFound
            | VaultError::AuthenticationFailed
            | VaultError::InvalidState
            | VaultError::RollbackDetected => Self::VaultCreationFailed,
        }
    }

    /// 既存の Vault の読み込みで起きた [`VaultFileError`] を変換する。
    ///
    /// # Returns
    ///
    /// ファイルの操作の失敗は [`CliError::Storage`]、解析の失敗は [`CliError::from_unlock_error`] の値、
    /// それ以外は [`CliError::VaultFile`]。
    #[must_use]
    pub const fn from_load_error(error: VaultFileError) -> Self {
        match error {
            VaultFileError::Storage(error) => Self::Storage(error),
            VaultFileError::Vault(error) => Self::from_unlock_error(error),
            VaultFileError::ModifiedExternally
            | VaultFileError::PathMismatch
            | VaultFileError::EpochExhausted => Self::VaultFile(error),
        }
    }

    /// Vault の保存で起きた [`VaultFileError`] を変換する。
    ///
    /// # Returns
    ///
    /// ファイルの操作の失敗は [`CliError::Storage`]、世代の巻き戻しは [`CliError::RollbackDetected`]、
    /// 乱数の取得の失敗は [`CliError::EntropySourceFailed`]、
    /// その他の暗号処理と直列化の失敗は [`CliError::VaultSaveFailed`]、それ以外は [`CliError::VaultFile`]。
    #[must_use]
    pub const fn from_save_error(error: VaultFileError) -> Self {
        match error {
            VaultFileError::Storage(error) => Self::Storage(error),
            VaultFileError::Vault(VaultError::RollbackDetected) => Self::RollbackDetected,
            VaultFileError::Vault(VaultError::System(SystemError::EntropySourceFailed)) => {
                Self::EntropySourceFailed
            }
            VaultFileError::Vault(_) => Self::VaultSaveFailed,
            VaultFileError::ModifiedExternally
            | VaultFileError::PathMismatch
            | VaultFileError::EpochExhausted => Self::VaultFile(error),
        }
    }

    /// 終了コードの分類を返す。
    ///
    /// # Returns
    ///
    /// `AuthenticationFailed` は [`ExitCategory::AuthenticationFailed`]、
    /// 中断 (入力中と処理の途中) は [`ExitCategory::Interrupted`]、
    /// 必須の引数が無い [`CliError::VaultPathRequired`] は [`ExitCategory::Usage`]、
    /// それ以外は [`ExitCategory::Failure`]。
    #[must_use]
    pub const fn exit_category(self) -> ExitCategory {
        match self {
            Self::AuthenticationFailed => ExitCategory::AuthenticationFailed,
            Self::SecretInput(SecretInputError::Interrupted) | Self::Interrupted => {
                ExitCategory::Interrupted
            }
            Self::VaultPathRequired => ExitCategory::Usage,
            Self::SecretInput(_)
            | Self::Hardening(_)
            | Self::RollbackDetected
            | Self::InvalidState
            | Self::OutputFailed
            | Self::Clipboard(_)
            | Self::Signal(_)
            | Self::Terminal(_)
            | Self::TerminalRequired
            | Self::Storage(_)
            | Self::VaultAlreadyExists
            | Self::KitAlreadyExists
            | Self::KitPathConflictsWithVault
            | Self::RecoveryKitNotConfirmed
            | Self::Password(_)
            | Self::PasswordMismatch
            | Self::RecoveryCode(_)
            | Self::EntropySourceFailed
            | Self::VaultCreationFailed
            | Self::VaultNotFound
            | Self::VaultFile(_)
            | Self::VaultSaveFailed
            | Self::RecoveryCodeNotEntered
            | Self::PrfSlotRequiresDrop
            | Self::PrfSlotDropDeclined
            | Self::EntryNotFound
            | Self::EntryAmbiguous
            | Self::InvalidEntryName
            | Self::MalformedEntry
            | Self::FieldNotSet
            | Self::InvalidField(_)
            | Self::FieldTooLong(_)
            | Self::EntryInputAborted
            | Self::NotesTooLong
            | Self::NotesEmpty
            | Self::DeletionDeclined
            | Self::ExportDeclined
            | Self::ExportDestinationExists => ExitCategory::Failure,
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

impl From<ClipboardError> for CliError {
    fn from(error: ClipboardError) -> Self {
        Self::Clipboard(error)
    }
}

impl From<SignalError> for CliError {
    fn from(error: SignalError) -> Self {
        Self::Signal(error)
    }
}

impl From<TtyError> for CliError {
    fn from(error: TtyError) -> Self {
        Self::Terminal(error)
    }
}

impl From<StorageError> for CliError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<PasswordError> for CliError {
    fn from(error: PasswordError) -> Self {
        Self::Password(error)
    }
}

impl From<RecoveryCodeError> for CliError {
    fn from(error: RecoveryCodeError) -> Self {
        Self::RecoveryCode(error)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hardening(error) => write!(formatter, "{error}"),
            Self::AuthenticationFailed => formatter.write_str(AUTHENTICATION_FAILED_MESSAGE),
            Self::RollbackDetected => formatter
                .write_str("Vault の世代が以前に読み込んだものより古いため、処理を中止しました。"),
            Self::InvalidState => formatter.write_str("内部状態が不正なため、処理を中止しました。"),
            Self::SecretInput(error) => write!(formatter, "{error}"),
            Self::OutputFailed => formatter.write_str("標準出力への書き込みに失敗しました。"),
            Self::Clipboard(error) => write!(formatter, "{error}"),
            Self::Interrupted => formatter.write_str("処理を中断しました。"),
            Self::Signal(error) => write!(formatter, "{error}"),
            Self::Terminal(error) => write!(formatter, "{error}"),
            Self::TerminalRequired => {
                formatter.write_str("この操作には端末が必要です。端末から実行してください。")
            }
            Self::Storage(error) => write!(formatter, "{error}"),
            Self::VaultPathRequired => {
                formatter.write_str("`--vault <PATH>` で Vault のパスを指定してください。")
            }
            Self::VaultAlreadyExists => formatter
                .write_str("Vault のパスにファイルがすでに存在するため、作成を中止しました。"),
            Self::KitAlreadyExists => formatter.write_str(
                "リカバリーキットの出力先にファイルがすでに存在するため、処理を中止しました。",
            ),
            Self::KitPathConflictsWithVault => formatter.write_str(
                "リカバリーキットの出力先が Vault のパスと重なっています。別のパスを指定してください。",
            ),
            Self::RecoveryKitNotConfirmed => formatter.write_str(
                "リカバリーコードの控えを確認できないため、処理を中止しました。表示したコードは使えません。",
            ),
            Self::Password(error) => write!(formatter, "{error}"),
            Self::PasswordMismatch => formatter.write_str("入力した 2 つのパスワードが一致しません。"),
            Self::RecoveryCode(error) => write!(formatter, "{error}"),
            Self::EntropySourceFailed => formatter.write_str("乱数の取得に失敗しました。"),
            Self::VaultCreationFailed => formatter.write_str("Vault の作成に失敗しました。"),
            Self::VaultNotFound => formatter.write_str("指定されたパスに Vault がありません。"),
            Self::VaultFile(error) => write!(formatter, "{error}"),
            Self::VaultSaveFailed => {
                formatter.write_str("Vault の保存に必要な暗号処理に失敗しました。")
            }
            Self::RecoveryCodeNotEntered => {
                formatter.write_str("リカバリーコードの入力が途中で終了しました。")
            }
            Self::PrfSlotRequiresDrop => formatter.write_str(
                "Vault に WebAuthn PRF のスロットがあるため中止しました。破棄して続ける場合は `--drop-prf-slot` を指定してください。",
            ),
            Self::PrfSlotDropDeclined => formatter.write_str(
                "WebAuthn PRF のスロットを破棄しないため、鍵の更新を中止しました。",
            ),
            Self::EntryNotFound => formatter.write_str("指定されたエントリがありません。"),
            Self::EntryAmbiguous => formatter
                .write_str("同じタイトルのエントリが複数あるため、処理を中止しました。"),
            Self::InvalidEntryName => formatter
                .write_str("エントリのタイトルに、空の文字列と制御文字は使えません。"),
            Self::MalformedEntry => formatter
                .write_str("Vault に解釈できないエントリがあるため、処理を中止しました。"),
            Self::FieldNotSet => formatter.write_str("指定された項目は設定されていません。"),
            Self::InvalidField(field) => write!(
                formatter,
                "{} に使用できない文字が含まれているか、UTF-8 ではありません。",
                field.label()
            ),
            Self::FieldTooLong(field) => write!(
                formatter,
                "{} が、端末から入力できる上限の {MAX_PASSWORD_LEN} バイトを超えています。",
                field.label()
            ),
            Self::EntryInputAborted => formatter
                .write_str("入力が途中で終了したため、エントリを保存しませんでした。"),
            Self::NotesTooLong => write!(
                formatter,
                "メモが上限の {MAX_NOTES_LEN} バイトを超えています。"
            ),
            Self::NotesEmpty => formatter.write_str("メモの入力が空です。"),
            Self::DeletionDeclined => formatter
                .write_str("削除に同意しなかったため、エントリを削除しませんでした。"),
            Self::ExportDeclined => formatter
                .write_str("平文の書き出しに同意しなかったため、中止しました。"),
            Self::ExportDestinationExists => formatter
                .write_str("書き出し先にファイルがすでに存在するため、中止しました。"),
        }
    }
}

#[cfg(test)]
mod tests {
    use fidelogic_core::{CryptoError, PrecisError, SystemError, TlvParseError, VaultError};

    use super::{AUTHENTICATION_FAILED_MESSAGE, CliError};
    use crate::entry_ops::EntryField;
    use crate::exit::ExitCategory;
    use crate::password::PasswordError;
    use crate::recovery_code::RecoveryCodeError;
    use crate::secret_input::SecretInputError;
    use crate::sys::clipboard::ClipboardError;
    use crate::sys::process::{HardeningError, HardeningStep};
    use crate::sys::signal::SignalError;
    use crate::sys::storage::StorageError;
    use crate::sys::tty::TtyError;
    use crate::vault_file::VaultFileError;

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
            CliError::EntryNotFound,
            CliError::EntryAmbiguous,
            CliError::InvalidEntryName,
            CliError::MalformedEntry,
            CliError::FieldNotSet,
            CliError::InvalidField(EntryField::Username),
            CliError::FieldTooLong(EntryField::Notes),
            CliError::EntryInputAborted,
            CliError::NotesTooLong,
            CliError::NotesEmpty,
            CliError::DeletionDeclined,
            CliError::ExportDeclined,
            CliError::ExportDestinationExists,
            CliError::AuthenticationFailed,
            CliError::RollbackDetected,
            CliError::InvalidState,
            CliError::SecretInput(SecretInputError::Interrupted),
            CliError::OutputFailed,
            CliError::Clipboard(ClipboardError::Unavailable),
            CliError::Interrupted,
            CliError::Signal(SignalError::AlreadyActive),
            CliError::Terminal(TtyError::EchoNotDisabled),
            CliError::TerminalRequired,
            CliError::Storage(StorageError::Locked),
            CliError::VaultPathRequired,
            CliError::VaultAlreadyExists,
            CliError::KitAlreadyExists,
            CliError::KitPathConflictsWithVault,
            CliError::RecoveryKitNotConfirmed,
            CliError::Password(PasswordError::Rejected),
            CliError::PasswordMismatch,
            CliError::RecoveryCode(RecoveryCodeError::MemoryLockFailed),
            CliError::EntropySourceFailed,
            CliError::VaultCreationFailed,
            CliError::VaultNotFound,
            CliError::VaultFile(VaultFileError::ModifiedExternally),
            CliError::VaultSaveFailed,
            CliError::RecoveryCodeNotEntered,
            CliError::PrfSlotRequiresDrop,
            CliError::PrfSlotDropDeclined,
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
    fn test_exit_categories_of_interruption_and_missing_argument() {
        assert_eq!(
            CliError::Interrupted.exit_category(),
            ExitCategory::Interrupted
        );
        assert_eq!(
            CliError::VaultPathRequired.exit_category(),
            ExitCategory::Usage
        );
        for error in [
            CliError::TerminalRequired,
            CliError::VaultAlreadyExists,
            CliError::KitAlreadyExists,
            CliError::KitPathConflictsWithVault,
            CliError::RecoveryKitNotConfirmed,
            CliError::PasswordMismatch,
            CliError::from(PasswordError::NotUtf8),
            CliError::from(StorageError::Locked),
            CliError::EntropySourceFailed,
            CliError::VaultCreationFailed,
            CliError::VaultNotFound,
            CliError::VaultFile(VaultFileError::EpochExhausted),
            CliError::VaultSaveFailed,
            CliError::RecoveryCodeNotEntered,
            CliError::PrfSlotRequiresDrop,
            CliError::PrfSlotDropDeclined,
        ] {
            assert_eq!(
                error.exit_category(),
                ExitCategory::Failure,
                "{error:?} の終了コードの分類に失敗。"
            );
        }
    }

    /// 作成の失敗は、解錠の失敗のメッセージにまとめないこと。
    #[test]
    fn test_creation_errors_are_not_reported_as_authentication_failure() {
        assert_eq!(
            CliError::from_creation_error(VaultError::System(SystemError::EntropySourceFailed)),
            CliError::EntropySourceFailed
        );
        for error in errors_masked_as_authentication_failure() {
            let expected = if error == VaultError::System(SystemError::EntropySourceFailed) {
                CliError::EntropySourceFailed
            } else {
                CliError::VaultCreationFailed
            };
            assert_eq!(
                CliError::from_creation_error(error),
                expected,
                "{error:?} の変換に失敗。"
            );
        }
    }

    /// 保存を中止する理由のうち、`CliError` に固有の分類を持たないもの。
    const VAULT_FILE_ERRORS: [VaultFileError; 3] = [
        VaultFileError::ModifiedExternally,
        VaultFileError::PathMismatch,
        VaultFileError::EpochExhausted,
    ];

    /// 読み込みの解析の失敗は、解錠の失敗と同じ出力にすること。
    #[test]
    fn test_load_errors_are_masked_like_unlock_errors() {
        for error in errors_masked_as_authentication_failure() {
            assert_eq!(
                CliError::from_load_error(VaultFileError::Vault(error)),
                CliError::AuthenticationFailed,
                "{error:?} の変換に失敗。"
            );
        }
        assert_eq!(
            CliError::from_load_error(VaultFileError::Storage(StorageError::Locked)),
            CliError::Storage(StorageError::Locked)
        );
        for error in VAULT_FILE_ERRORS {
            assert_eq!(
                CliError::from_load_error(error),
                CliError::VaultFile(error),
                "{error:?} の変換に失敗。"
            );
        }
    }

    /// 保存の失敗は、解錠の失敗のメッセージにまとめないこと。
    #[test]
    fn test_save_errors_are_not_reported_as_authentication_failure() {
        for error in errors_masked_as_authentication_failure() {
            let expected = if error == VaultError::System(SystemError::EntropySourceFailed) {
                CliError::EntropySourceFailed
            } else {
                CliError::VaultSaveFailed
            };
            assert_eq!(
                CliError::from_save_error(VaultFileError::Vault(error)),
                expected,
                "{error:?} の変換に失敗。"
            );
        }
        assert_eq!(
            CliError::from_save_error(VaultFileError::Vault(VaultError::RollbackDetected)),
            CliError::RollbackDetected
        );
        assert_eq!(
            CliError::from_save_error(VaultFileError::Vault(VaultError::InvalidState)),
            CliError::VaultSaveFailed
        );
        assert_eq!(
            CliError::from_save_error(VaultFileError::Storage(StorageError::Locked)),
            CliError::Storage(StorageError::Locked)
        );
        for error in VAULT_FILE_ERRORS {
            let converted = CliError::from_save_error(error);
            assert_eq!(
                converted,
                CliError::VaultFile(error),
                "{error:?} の変換に失敗。"
            );
            assert_eq!(converted.to_string(), error.to_string());
        }
    }

    #[test]
    fn test_clipboard_error_is_general_failure_with_its_message() {
        let error = CliError::from(ClipboardError::Unavailable);
        assert_eq!(error, CliError::Clipboard(ClipboardError::Unavailable));
        assert_eq!(error.to_string(), ClipboardError::Unavailable.to_string());
        assert_eq!(error.exit_category(), ExitCategory::Failure);
    }

    /// 項目の値の誤りは、項目の名称を示すこと。
    #[test]
    fn test_field_errors_name_the_field() {
        for field in EntryField::ALL {
            for error in [CliError::InvalidField(field), CliError::FieldTooLong(field)] {
                assert!(
                    error.to_string().starts_with(field.label()),
                    "{error:?} の項目の表示の確認に失敗。"
                );
                assert_eq!(error.exit_category(), ExitCategory::Failure);
            }
        }
    }
}
