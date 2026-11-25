//! # Vault ファイルの読み込みと保存 (`vault_file`)
//!
//! [`crate::sys::storage`] の読み書きの上に、世代 (`epoch_id`) の検証と、全エントリの再暗号化を置く。
//! OS に依存する処理は含まない。
//!
//! ## 使い方
//!
//! 1. [`VaultLock`] でロックを取得し、[`LoadedVault::read`] で Vault を読み込む。
//! 2. 解錠してエントリを変更する。
//! 3. ロックを保持した状態で [`save_vault`] を呼ぶ。読み込みと保存の間にロックを解放していてもよい。
//!    その場合も、保存の直前に取得したロックを渡す。
//!
//! ## 保存の手順
//!
//! 1. ディスク上の Vault を読み直し、ヘッダーが読み込み時と一致することを確かめる (1 回目の検証)。
//! 2. 読み込み時のヘッダーから [`VaultHeader::checked_increment_epoch`] で次の世代のヘッダーを作る。
//! 3. 次の世代が、ディスク上の世代より進んでいることを [`VaultHeader::verify_epoch_progression`] で確かめる (2 回目の検証)。
//! 4. 全エントリを、次の世代のヘッダーを関連データとして、新しいノンスで暗号化し直す ([`seal_entries`])。
//!    未知のタグのレコード ([`TlvRecord::Unknown`]) は、読み込み時の順で後ろに付けて保持する。
//! 5. 直列化し、[`write_vault_file_atomically`] でアトミックに置き換える。
//!
//! ## 検証で検知するもの
//!
//! | 読み込み後のディスク上の Vault | 結果 |
//! | :-- | :-- |
//! | 読み込み時と同じヘッダー | 保存する |
//! | 世代が読み込み時より古い (古いスナップショットでの上書き) | [`VaultError::RollbackDetected`] |
//! | 世代が進んでいる、世代以外のヘッダーが異なる、ヘッダーが壊れている、ファイルが無い | [`VaultFileError::ModifiedExternally`] |
//!
//! ロックに従う処理どうしは、ロックによって直列化されるため、この検証に掛からない。
//! 検証が防ぐのは、ロックを取得しない外部のツールによる更新との競合である。
//!
//! ## 限界
//!
//! - 検証から `rename` までの間に外部のツールが書き込んだ場合は、検知できず上書きする。
//! - 外部のツールが世代とヘッダーを変えずに中身だけを書き換えた場合は、検知できず上書きする。
//! - 読み込んだ Vault そのものが古いスナップショットに置き換えられていても、読み込みの時点では検知できない。
//!   比較の基準となる世代を、Vault ファイルの外に保持していないためである。

use core::fmt;

use fidelogic_core::{
    EntrySource, KEK_SLOT_HEADER_LEN, KekSlotEntry, SystemError, TLV_HEADER_LEN, TlvParseError,
    TlvRecord, VAULT_HEADER_LEN, Vault, VaultCipher, VaultError, VaultHeader, deserialize,
    deserialize_header, seal_entries, serialize,
};

use crate::sys::storage::{
    DirectorySync, StorageError, VaultLock, VaultPath, read_vault_file, write_vault_file_atomically,
};

/// Vault ファイルとして解析できる最大のバイト数。
///
/// ヘッダー、255 個のスロット (ラップ済み DEK が各 65,535 バイト)、65,535 個のレコード (ペイロードが各 255 バイト) の合計である。
/// これを超えるファイルは解析できないため、解析する前に拒否する。
pub const MAX_VAULT_FILE_LEN: u64 = VAULT_HEADER_LEN as u64
    + 1
    + (u8::MAX as u64) * (KEK_SLOT_HEADER_LEN as u64 + u16::MAX as u64)
    + 2
    + (u16::MAX as u64) * (TLV_HEADER_LEN as u64 + u8::MAX as u64);

/// Vault ファイルの読み込みと保存の失敗。
///
/// 終了コードと利用者へのメッセージへの対応付けは、[`crate::error::CliError::from_load_error`] と [`crate::error::CliError::from_save_error`] が行う。
/// 読み込みで起きた [`VaultFileError::Vault`] は、解錠の失敗と同じく、理由を区別せずに表示する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultFileError {
    /// ファイルの読み書きに失敗した。
    Storage(StorageError),
    /// Vault の解析、再暗号化、直列化に失敗した。世代の巻き戻し ([`VaultError::RollbackDetected`]) もここに含む。
    Vault(VaultError),
    /// 読み込んだ後に、ディスク上の Vault がロックを取得しない処理によって変更された。
    ModifiedExternally,
    /// 保存に渡したロックの対象が、読み込んだ Vault のパスと異なる。
    PathMismatch,
    /// 世代 (`epoch_id`) が上限に達しており、これ以上進められない。
    EpochExhausted,
}

impl From<StorageError> for VaultFileError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<VaultError> for VaultFileError {
    fn from(error: VaultError) -> Self {
        Self::Vault(error)
    }
}

impl fmt::Display for VaultFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "{error}"),
            Self::Vault(error) => write!(f, "{error}"),
            Self::ModifiedExternally => f.write_str(
                "読み込んだ後に Vault ファイルが別の処理で変更されたため、保存を中止しました。",
            ),
            Self::PathMismatch => {
                f.write_str("ロックの対象が読み込んだ Vault と異なるため、保存を中止しました。")
            }
            Self::EpochExhausted => {
                f.write_str("Vault の世代が上限に達したため、保存を中止しました。")
            }
        }
    }
}

impl std::error::Error for VaultFileError {}

/// ディスクから読み込んだ Vault。保存の基準 (読み込み時の世代) を保持する。
#[derive(Clone)]
pub struct LoadedVault {
    /// 読み込んだ Vault ファイルのパス。
    path: VaultPath,
    /// 解析した Vault。
    vault: Vault,
}

impl LoadedVault {
    /// ロックの対象である Vault ファイルを読み込んで解析する。
    ///
    /// エントリの復号は行わない。復号は解錠した後に [`fidelogic_core::open_entries`] で行う。
    ///
    /// # Returns
    ///
    /// Vault ファイルが存在しない場合は `None`。
    ///
    /// # Errors
    ///
    /// - 読み込みに失敗した場合と、[`MAX_VAULT_FILE_LEN`] を超える場合は [`VaultFileError::Storage`]。
    /// - 解析に失敗した場合 (末尾に余分なバイトがある場合を含む) は [`VaultFileError::Vault`] (`VaultError::Parse`)。
    pub fn read(lock: &VaultLock) -> Result<Option<Self>, VaultFileError> {
        let Some(contents) = read_vault_file(lock, MAX_VAULT_FILE_LEN)? else {
            return Ok(None);
        };
        Ok(Some(Self {
            path: lock.vault_path().clone(),
            vault: parse_vault(&contents)?,
        }))
    }

    /// 読み込んだ Vault ファイルのパスを返す。
    #[must_use]
    pub fn path(&self) -> &VaultPath {
        &self.path
    }

    /// 読み込んだ Vault の全体を返す。解錠に使う。
    #[must_use]
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// 読み込み時のヘッダーを返す。
    #[must_use]
    pub fn header(&self) -> &VaultHeader {
        &self.vault.header
    }

    /// KEK スロットの一覧を返す。
    #[must_use]
    pub fn slots(&self) -> &[KekSlotEntry] {
        &self.vault.slots
    }

    /// TLV レコードの一覧 (エントリのレコードと未知のタグのレコード) を返す。
    #[must_use]
    pub fn records(&self) -> &[TlvRecord] {
        &self.vault.records
    }
}

impl fmt::Debug for LoadedVault {
    /// コアの型は `Debug` を実装していないため、ヘッダーの値と件数だけを表示する。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header = self.header();
        f.debug_struct("LoadedVault")
            .field("path", &self.path)
            .field("version", &header.version)
            .field("suite_id", &header.suite_id)
            .field("epoch_id", &header.epoch_id)
            .field("slot_count", &self.slots().len())
            .field("record_count", &self.records().len())
            .finish()
    }
}

/// 保存の結果。
#[derive(Debug)]
pub struct SavedVault {
    /// 書き込んだ Vault。次の保存の基準として使える。
    pub vault: LoadedVault,
    /// 親ディレクトリの同期の結果。
    pub directory_sync: DirectorySync,
}

/// Vault を、世代を 1 つ進めて保存する。手順はモジュール doc の「保存の手順」のとおりである。
///
/// # Args
///
/// - `lock`: 保存する Vault のロック。`base` を読み込んだパスと同じ対象でなければならない。
/// - `base`: 読み込み時の Vault。ヘッダーの世代を検証の基準とし、未知のタグのレコードを引き継ぐ。
///   エントリのレコードは引き継がず、`entries` から作り直す。
/// - `cipher`: DEK から作った暗号器。暗号スイートは `base` のヘッダーと一致しなければならない。
/// - `slots`: 保存する KEK スロットの一覧。変更しない場合は `base.slots()` の複製を渡す。
/// - `entries`: 保存後の全エントリ。ここに無いエントリは削除される。
/// - `fill_random`: ノンスを生成する乱数源。暗号論的に安全なものを渡す。
///
/// # Errors
///
/// - `lock` の対象が `base` のパスと異なる場合は [`VaultFileError::PathMismatch`]。
/// - ディスク上の Vault の世代が読み込み時より古い場合は [`VaultFileError::Vault`] (`VaultError::RollbackDetected`)。
/// - ディスク上の Vault が読み込み時から変更されている、または存在しない場合は [`VaultFileError::ModifiedExternally`]。
/// - 世代が `u64::MAX` に達している場合は [`VaultFileError::EpochExhausted`]。
/// - 再暗号化に失敗した場合 (暗号スイートの不一致、`entry_id` の重複、乱数源の失敗など) と、
///   直列化に失敗した場合 (レコード数の超過など) は [`VaultFileError::Vault`]。
/// - 読み書きに失敗した場合は [`VaultFileError::Storage`]。
///
/// いずれの失敗でも、ディスク上の Vault は変更しない。
pub fn save_vault<R>(
    lock: &VaultLock,
    base: &LoadedVault,
    cipher: &VaultCipher,
    slots: Vec<KekSlotEntry>,
    entries: &[EntrySource<'_>],
    fill_random: R,
) -> Result<SavedVault, VaultFileError>
where
    R: FnMut(&mut [u8]) -> Result<(), SystemError>,
{
    if lock.vault_path() != base.path() {
        return Err(VaultFileError::PathMismatch);
    }
    let on_disk = read_vault_file(lock, MAX_VAULT_FILE_LEN)?;
    let next_header = next_header_after_check(base.header(), on_disk.as_deref())?;

    let mut records = seal_entries(cipher, &next_header, entries, fill_random)?;
    records.extend(
        base.records()
            .iter()
            .filter(|record| matches!(record, TlvRecord::Unknown { .. }))
            .cloned(),
    );
    let vault = Vault::new(next_header, slots, records);
    let contents = serialize(&vault).map_err(VaultError::Parse)?;

    let directory_sync = write_vault_file_atomically(lock, &contents)?;
    Ok(SavedVault {
        vault: LoadedVault {
            path: base.path().clone(),
            vault,
        },
        directory_sync,
    })
}

/// Vault ファイルの全体を解析する。末尾に余分なバイトがあれば拒否する。
fn parse_vault(contents: &[u8]) -> Result<Vault, VaultError> {
    let (vault, rest) = deserialize(contents)?;
    if rest.is_empty() {
        Ok(vault)
    } else {
        Err(VaultError::Parse(TlvParseError::InvalidFormat))
    }
}

/// ディスク上の Vault が読み込み時から変わっていないことを確かめ、次の世代のヘッダーを返す。
///
/// # Args
///
/// - `loaded`: 読み込み時のヘッダー。
/// - `on_disk`: 保存の直前に読み直した Vault ファイルの内容。存在しない場合は `None`。
///
/// # Errors
///
/// モジュール doc の「検証で検知するもの」の表のとおり。世代が上限の場合は [`VaultFileError::EpochExhausted`]。
fn next_header_after_check(
    loaded: &VaultHeader,
    on_disk: Option<&[u8]>,
) -> Result<VaultHeader, VaultFileError> {
    let disk_header = on_disk
        .and_then(|contents| deserialize_header(contents).ok())
        .map(|(header, _)| header)
        .ok_or(VaultFileError::ModifiedExternally)?;
    if loaded.is_newer_than(&disk_header) {
        return Err(VaultFileError::Vault(VaultError::RollbackDetected));
    }
    if disk_header != *loaded {
        return Err(VaultFileError::ModifiedExternally);
    }

    let next = loaded
        .checked_increment_epoch()
        .ok_or(VaultFileError::EpochExhausted)?;
    // 上の一致の確認により成り立つが、書き込む世代がディスク上の世代より進んでいることを独立に確かめる。
    next.verify_epoch_progression(disk_header.epoch_id)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use fidelogic_core::{
        KEK_SLOT_HEADER_LEN, TLV_HEADER_LEN, TlvParseError, VAULT_HEADER_LEN, VaultError,
        VaultHeader, serialize_header,
    };

    use super::{MAX_VAULT_FILE_LEN, VaultFileError, next_header_after_check, parse_vault};
    use crate::sys::storage::{StorageError, StorageStep};

    /// テストで使う、世代 `epoch_id` のヘッダー。
    const fn header(epoch_id: u64) -> VaultHeader {
        VaultHeader::new(1, 1, epoch_id)
    }

    /// ヘッダーを比較できる組 (`magic`, `version`, `suite_id`, `epoch_id`) にする。
    /// コアの `VaultHeader` はテスト以外で `Debug` を実装しないため、`assert_eq!` に直接渡せない。
    fn fields(header: &VaultHeader) -> ([u8; 4], u8, u8, u64) {
        (
            header.magic,
            header.version,
            header.suite_id,
            header.epoch_id,
        )
    }

    /// [`next_header_after_check`] の結果を、比較できる形にする。
    fn check(
        loaded: &VaultHeader,
        on_disk: Option<&[u8]>,
    ) -> Result<([u8; 4], u8, u8, u64), VaultFileError> {
        next_header_after_check(loaded, on_disk).map(|next| fields(&next))
    }

    #[test]
    fn test_next_header_advances_epoch_when_disk_matches() -> Result<(), VaultFileError> {
        let loaded = header(7);
        let disk = serialize_header(&loaded);
        assert_eq!(
            check(&loaded, Some(&disk))?,
            fields(&header(8)),
            "世代を 1 つ進めることに失敗。"
        );
        Ok(())
    }

    #[test]
    fn test_next_header_reports_rollback_for_older_disk_epoch() {
        let disk = serialize_header(&header(6));
        assert_eq!(
            check(&header(7), Some(&disk)),
            Err(VaultFileError::Vault(VaultError::RollbackDetected)),
        );
    }

    #[test]
    fn test_next_header_reports_external_modification() {
        let loaded = header(7);
        let mut other_suite = loaded;
        other_suite.suite_id = 2;
        let mut other_version = loaded;
        other_version.version = 2;
        let newer = serialize_header(&header(8));
        let suite_changed = serialize_header(&other_suite);
        let version_changed = serialize_header(&other_version);
        let mut bad_magic = serialize_header(&loaded);
        bad_magic[0] ^= 0xFF;
        let truncated = serialize_header(&loaded);
        let truncated = &truncated[..VAULT_HEADER_LEN - 1];

        let cases: [(&str, Option<&[u8]>); 6] = [
            ("世代が進んでいる", Some(&newer)),
            ("暗号スイートが異なる", Some(&suite_changed)),
            ("バージョンが異なる", Some(&version_changed)),
            ("マジックバイトが壊れている", Some(&bad_magic)),
            ("ヘッダーが途中で切れている", Some(truncated)),
            ("ファイルが無い", None),
        ];
        for (label, disk) in cases {
            assert_eq!(
                check(&loaded, disk),
                Err(VaultFileError::ModifiedExternally),
                "{label}場合の検知に失敗。"
            );
        }
    }

    #[test]
    fn test_next_header_rejects_exhausted_epoch() {
        let loaded = header(u64::MAX);
        let disk = serialize_header(&loaded);
        assert_eq!(
            check(&loaded, Some(&disk)),
            Err(VaultFileError::EpochExhausted),
        );
    }

    #[test]
    fn test_parse_vault_rejects_trailing_bytes() -> Result<(), VaultError> {
        let mut contents = serialize_header(&header(1)).to_vec();
        // スロット 0 個、レコード 0 個。
        contents.extend_from_slice(&[0, 0, 0]);
        let vault = parse_vault(&contents)?;
        assert_eq!(fields(&vault.header), fields(&header(1)));

        contents.push(0);
        assert!(
            matches!(
                parse_vault(&contents),
                Err(VaultError::Parse(TlvParseError::InvalidFormat))
            ),
            "末尾の余分なバイトの拒否に失敗。"
        );
        Ok(())
    }

    #[test]
    fn test_max_vault_file_len_matches_format_limits() {
        let expected = VAULT_HEADER_LEN
            + 1
            + 255 * (KEK_SLOT_HEADER_LEN + 65_535)
            + 2
            + 65_535 * (TLV_HEADER_LEN + 255);
        assert_eq!(MAX_VAULT_FILE_LEN, expected as u64);
        assert_eq!(MAX_VAULT_FILE_LEN, 33_554_957);
    }

    #[test]
    fn test_error_display_ends_with_japanese_period() {
        let errors = [
            VaultFileError::Storage(StorageError::Os {
                step: StorageStep::Rename,
                errno: 18,
            }),
            VaultFileError::Vault(VaultError::RollbackDetected),
            VaultFileError::ModifiedExternally,
            VaultFileError::PathMismatch,
            VaultFileError::EpochExhausted,
        ];
        for error in errors {
            assert!(
                error.to_string().ends_with('。'),
                "エラーメッセージの末尾が句点でないため失敗しました: {error}"
            );
        }
    }
}
