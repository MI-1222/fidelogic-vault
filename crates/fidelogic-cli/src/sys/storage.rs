//! # 排他ロックとアトミックな保存 (`sys::storage`)
//!
//! Vault ファイルの読み書きのうち、OS によって手順が異なる処理を置く。
//! ファイルの中身 (ヘッダー、世代) は解釈しない。世代の検証は [`crate::vault_file`] が行う。
//!
//! ## 担う処理
//!
//! - Vault のパスの正規化 ([`VaultPath`])。
//! - サイドカー `<vault>.lock` による排他制御 ([`VaultLock`])。Vault 本体は保存のたびに `rename` で inode が入れ替わるため、
//!   名前を変えないサイドカーにロックを掛ける。
//! - Vault ファイルの読み込み ([`read_vault_file`])。
//! - アトミックな保存 ([`write_vault_file_atomically`])。同じディレクトリの一時ファイルへの書き込み、永続化、
//!   `rename` による置換、親ディレクトリの同期を順に行う。
//!
//! ## 使い方
//!
//! [`VaultPath::resolve`] で正規化したパスを [`VaultLock`] に渡してロックを取得し、
//! 以後の読み書きには [`VaultLock::vault_path`] が返すパスを使う。
//! ロックしたパスと読み書きするパスがずれないようにするためである。
//! 読み込みと保存の関数は [`VaultLock`] を引数に取り、ロックを保持していない状態では呼べない。
//!
//! ## アトミックな保存の手順
//!
//! 1. Vault と同じディレクトリに、権限 `0600` の一時ファイル `.<Vault のファイル名>.<乱数>.tmp` を、
//!    `O_CREAT | O_EXCL` で作成する。`rename` がファイルシステムをまたがない (`EXDEV` にならない) ようにするためである。
//! 2. 全量を書き込み、[`File::sync_all`] で記憶装置まで永続化する。
//!    Apple のプラットフォームでは `F_FULLFSYNC` となる。仮想ファイルシステムなどが `ENOTTY` / `ENOTSUP` を返したときだけ、`fsync` で同期し直す。
//! 3. `rename` で Vault を置き換える。置換の前後のどの時点でも、パスには旧または新の完全なファイルだけがある。
//! 4. 親ディレクトリを同期し、置換後のディレクトリエントリを永続化する。
//!
//! 1〜3 のいずれかが失敗した場合は、一時ファイルを削除して中断し、既存の Vault を変更しない。
//! 永続化 (2) の失敗では、書き込んだ内容がカーネルに破棄されている恐れがあるため、再試行もしない。
//! 親ディレクトリの同期 (4) の失敗は、置換が済んだ後のためエラーにせず、[`DirectorySync::Failed`] で知らせる。
//!
//! プロセスが手順の途中で強制終了した場合 (`SIGKILL`、`panic = "abort"` など) は、一時ファイルが残ることがある。
//! 残った一時ファイルは、後の保存の妨げにならない。名前が衝突した場合は別の名前で作り直すためである。
//!
//! ## サイドカーロックの規約と限界
//!
//! - ロックファイルは削除も改名もしない。削除すると、削除前のファイルを開いているプロセスと、
//!   作り直されたファイルを開いたプロセスが、同時にロックを取得できてしまう。
//! - ロックファイルは権限 `0600` で作成する。既存のロックファイルの内容と権限は変更しない。
//! - ロックファイルのパスがシンボリックリンクの場合は、参照先を開かずに失敗する。
//! - ロックは協調ロックであり、ロックを取得しないプログラムによる読み書きは防げない。
//! - 1 つのファイルを指す複数のハードリンクは、それぞれ別のロックファイルになるため、相互に排他できない。
//! - ネットワークファイルシステム上での排他は保証しない。
//!
//! ## OS ごとの差
//!
//! | 処理 | POSIX | Windows (未対応) |
//! | :-- | :-- | :-- |
//! | 排他ロック | `File::lock` (`flock`) | `File::lock` (`LockFileEx`) |
//! | 永続化 | `File::sync_all`。Apple では `F_FULLFSYNC` となり、仮想ファイルシステムが `ENOTTY` / `ENOTSUP` を返したときだけ `fsync` へ戻す | `FlushFileBuffers` |
//! | 置換 | `rename` の後に親ディレクトリを同期する | `ReplaceFileW` または `MoveFileExW` |
//! | 作成時の権限 | `0600` | - |

#![allow(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use tempfile::{Builder, NamedTempFile};

/// サイドカーロックファイルの名前として、Vault のファイル名の後ろに付ける接尾辞。
const LOCK_SUFFIX: &str = ".lock";

/// ロックファイルを作成するときの権限。オーナーの読み書きだけを許す。
const LOCK_FILE_MODE: u32 = 0o600;

/// 一時ファイルを作成するときの権限。オーナーの読み書きだけを許す。
const TEMP_FILE_MODE: u32 = 0o600;

/// 一時ファイルの名前の末尾に付ける接尾辞。
const TEMP_SUFFIX: &str = ".tmp";

/// `File::sync_all` が `F_FULLFSYNC` を使い、対応しないファイルシステムで `fsync` へ戻す必要がある環境か。
const FULL_FSYNC_FALLBACK: bool = cfg!(target_vendor = "apple");

/// OS の API の呼び出しが失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageStep {
    /// Vault のパスの解決。
    ResolvePath,
    /// ロックファイルを開く処理。
    OpenLockFile,
    /// 排他ロックの取得。
    Lock,
    /// Vault ファイルの読み込み。
    ReadVault,
    /// 一時ファイルの作成。
    CreateTempFile,
    /// 一時ファイルへの書き込み。
    WriteTempFile,
    /// 一時ファイルの永続化 (`fsync`)。
    SyncTempFile,
    /// `rename` による Vault ファイルの置換。
    Rename,
}

impl StorageStep {
    /// 手順の名称を日本語で返す。
    const fn label(self) -> &'static str {
        match self {
            Self::ResolvePath => "Vault のパスの解決",
            Self::OpenLockFile => "ロックファイルを開く処理",
            Self::Lock => "排他ロックの取得",
            Self::ReadVault => "Vault ファイルの読み込み",
            Self::CreateTempFile => "一時ファイルの作成",
            Self::WriteTempFile => "一時ファイルへの書き込み",
            Self::SyncTempFile => "一時ファイルの永続化",
            Self::Rename => "Vault ファイルの置換",
        }
    }
}

/// Vault ファイルの操作の失敗を表すエラー。
///
/// パスや秘密情報は含まない。`errno` は OS が返したエラー番号であり、診断のためだけに保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// パスがファイル名で終わっていない (空、末尾が `/`、末尾の要素が `.` または `..`)。
    InvalidPath,
    /// Vault のファイル名が、ロックファイル用の接尾辞 `.lock` で終わっている。
    ReservedName,
    /// Vault のパスが、通常のファイル以外 (ディレクトリ、FIFO など) を指している。
    VaultNotRegularFile,
    /// ロックファイルのパスにあるものが、通常のファイルではない。
    LockFileNotRegularFile,
    /// 他の保持者がロックを持っているため、待たずに取得できなかった。
    Locked,
    /// Vault ファイルが、読み込みの上限を超える大きさである。
    VaultTooLarge,
    /// OS の API の呼び出しが失敗した。
    Os {
        /// 失敗した手順。
        step: StorageStep,
        /// OS が返したエラー番号。取得できなかった場合は 0。
        errno: i32,
    },
}

impl StorageError {
    /// `std::io::Error` から、失敗した手順とエラー番号を取り出す。
    fn os(step: StorageStep, error: &io::Error) -> Self {
        Self::Os {
            step,
            errno: error.raw_os_error().unwrap_or(0),
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath => f.write_str("Vault のパスがファイル名で終わっていません。"),
            Self::ReservedName => {
                f.write_str("Vault のファイル名の末尾に `.lock` は使用できません。")
            }
            Self::VaultNotRegularFile => {
                f.write_str("Vault のパスが通常のファイルを指していません。")
            }
            Self::LockFileNotRegularFile => {
                f.write_str("ロックファイルのパスにあるものが通常のファイルではありません。")
            }
            Self::Locked => f.write_str("他の処理が Vault を使用中です。"),
            Self::VaultTooLarge => f.write_str("Vault ファイルが読み込める大きさを超えています。"),
            Self::Os { step, errno } => {
                write!(f, "{}に失敗しました (errno: {errno})。", step.label())
            }
        }
    }
}

impl std::error::Error for StorageError {}

/// 正規化した Vault ファイルのパス。
///
/// 保持するパスはすべて絶対パスで、シンボリックリンクを解決してある。
/// このため、同じファイルを相対パスやシンボリックリンクで指定しても、同じロックファイルになる。
///
/// 正規化は [`VaultPath::resolve`] を呼んだ時点の状態に基づく。
/// その後のファイルシステムの変更は反映しない。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPath {
    /// Vault ファイルがあるディレクトリ。
    directory: PathBuf,
    /// Vault ファイル。
    file: PathBuf,
    /// サイドカーロックファイル。
    lock_file: PathBuf,
}

impl VaultPath {
    /// 利用者が指定した Vault のパスを正規化する。ファイルは作成しない。
    ///
    /// - Vault が存在する場合は、シンボリックリンクをすべてたどり、実体のパスにする。
    /// - Vault が存在しない場合は、親ディレクトリを正規化してファイル名を結合する。
    ///   親ディレクトリを持たない相対パス (`vault.fvl` など) の親は、カレントディレクトリとする。
    ///
    /// # Errors
    ///
    /// - パスがファイル名で終わっていない場合は [`StorageError::InvalidPath`]。
    /// - 解決後のファイル名が `.lock` で終わる (大文字小文字を区別しない) 場合は [`StorageError::ReservedName`]。
    ///   別の Vault のロックファイルと同じ名前になるためである。
    /// - 通常のファイル以外が存在する場合は [`StorageError::VaultNotRegularFile`]。
    /// - 親ディレクトリが存在しない、シンボリックリンクの参照先が存在しないか循環している、
    ///   権限が無いなどの理由で解決できない場合は [`StorageError::Os`]。参照先の無いシンボリックリンクを受け付けないのは、
    ///   保存時の `rename` がリンクそのものを置き換えてしまうためである。
    pub fn resolve(path: &Path) -> Result<Self, StorageError> {
        let name = final_file_name(path).ok_or(StorageError::InvalidPath)?;
        let resolve_error = |error: io::Error| StorageError::os(StorageStep::ResolvePath, &error);

        let file = match fs::symlink_metadata(path) {
            Ok(_) => {
                let file = fs::canonicalize(path).map_err(resolve_error)?;
                if !fs::metadata(&file).map_err(resolve_error)?.is_file() {
                    return Err(StorageError::VaultNotRegularFile);
                }
                file
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."));
                fs::canonicalize(parent).map_err(resolve_error)?.join(name)
            }
            Err(error) => return Err(resolve_error(error)),
        };

        // 利用者の指定ではなく、解決後の名前で判定する。シンボリックリンクの参照先も対象にするためである。
        let resolved_name = file.file_name().ok_or(StorageError::InvalidPath)?;
        if has_lock_suffix(resolved_name) {
            return Err(StorageError::ReservedName);
        }
        let directory = file
            .parent()
            .ok_or(StorageError::InvalidPath)?
            .to_path_buf();
        let mut lock_file = file.clone().into_os_string();
        lock_file.push(LOCK_SUFFIX);

        Ok(Self {
            directory,
            file,
            lock_file: PathBuf::from(lock_file),
        })
    }

    /// Vault ファイルがあるディレクトリを返す。
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Vault ファイルのパスを返す。
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// サイドカーロックファイルのパスを返す。
    #[must_use]
    pub fn lock_file(&self) -> &Path {
        &self.lock_file
    }
}

/// パスの末尾の要素がファイル名である場合に、その名前を返す。
///
/// `Path::file_name` は末尾の `/` や `/.` を取り除いて解釈するため、
/// ディレクトリを意図した指定をファイル名と取り違えないように、末尾の要素を直接調べる。
fn final_file_name(path: &Path) -> Option<&OsStr> {
    let last = path
        .as_os_str()
        .as_encoded_bytes()
        .rsplit(|&byte| byte == b'/')
        .next()?;
    if matches!(last, b"" | b"." | b"..") {
        None
    } else {
        path.file_name()
    }
}

/// ファイル名がロックファイル用の接尾辞で終わるかを判定する。
///
/// 大文字小文字を区別しないファイルシステム (macOS の既定など) でも名前が衝突しないように、
/// ASCII の大文字小文字を無視する。
fn has_lock_suffix(name: &OsStr) -> bool {
    let bytes = name.as_encoded_bytes();
    bytes
        .len()
        .checked_sub(LOCK_SUFFIX.len())
        .and_then(|start| bytes.get(start..))
        .is_some_and(|tail| tail.eq_ignore_ascii_case(LOCK_SUFFIX.as_bytes()))
}

/// ロックファイルを開く。存在しなければ権限 `0600` で作成する。内容は切り詰めない。
///
/// ファイル記述子には `std` が `O_CLOEXEC` を付けるため、`exec` した子プロセスへは引き継がれない。
fn open_lock_file(path: &Path) -> Result<File, StorageError> {
    let open_error = |error: io::Error| StorageError::os(StorageStep::OpenLockFile, &error);

    let handle = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(LOCK_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(open_error)?;
    if handle.metadata().map_err(open_error)?.is_file() {
        Ok(handle)
    } else {
        Err(StorageError::LockFileNotRegularFile)
    }
}

/// サイドカーロックファイルの排他ロック。値が生存する間、ロックを保持する。
///
/// 値を破棄するとロックを解放する。プロセスが異常終了した場合 (`SIGKILL`、`panic = "abort"` など) は、
/// カーネルがファイル記述子を閉じる時点で解放する。ロックファイルは残す。
#[derive(Debug)]
#[must_use = "値を破棄すると、直ちにロックを解放する。"]
pub struct VaultLock {
    /// ロックを掛けたロックファイル。
    handle: File,
    /// ロックの対象である Vault のパス。
    path: VaultPath,
}

impl VaultLock {
    /// 排他ロックを取得する。他の保持者がいる場合は、解放されるまで待つ。
    ///
    /// 待ち時間に上限は無い。同じ Vault のロックを保持している処理が再び呼ぶと、
    /// 同じプロセス内であっても戻らない。
    ///
    /// # Errors
    ///
    /// - ロックファイルのパスに通常のファイル以外がある場合は [`StorageError::LockFileNotRegularFile`]。
    /// - ロックファイルを開けない (シンボリックリンクである場合を含む)、
    ///   またはロックを取得できない場合は [`StorageError::Os`]。シグナルハンドラーによって待機が中断された場合 (`EINTR`) も、
    ///   再試行せずにこのエラーを返す。
    pub fn acquire(path: VaultPath) -> Result<Self, StorageError> {
        let handle = open_lock_file(path.lock_file())?;
        handle
            .lock()
            .map_err(|error| StorageError::os(StorageStep::Lock, &error))?;
        Ok(Self { handle, path })
    }

    /// 排他ロックを、待たずに取得する。
    ///
    /// # Errors
    ///
    /// - 他の保持者がいる場合は [`StorageError::Locked`]。
    /// - ロックファイルのパスに通常のファイル以外がある場合は [`StorageError::LockFileNotRegularFile`]。
    /// - ロックファイルを開けない (シンボリックリンクである場合を含む)、
    ///   またはロックの取得が別の理由で失敗した場合は [`StorageError::Os`]。
    pub fn try_acquire(path: VaultPath) -> Result<Self, StorageError> {
        let handle = open_lock_file(path.lock_file())?;
        match handle.try_lock() {
            Ok(()) => Ok(Self { handle, path }),
            Err(TryLockError::WouldBlock) => Err(StorageError::Locked),
            Err(TryLockError::Error(error)) => Err(StorageError::os(StorageStep::Lock, &error)),
        }
    }

    /// ロックの対象である Vault のパスを返す。
    #[must_use]
    pub fn vault_path(&self) -> &VaultPath {
        &self.path
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // `flock` のロックはファイル記述子ではなく、開いたファイル記述 (open file description) に結び付く。
        // 別スレッドが起動した子プロセスは `exec` するまで記述子の複製を持つため、
        // 記述子を閉じるだけでは解放が遅れることがある。そのため、明示的に解放する。
        // 解放に失敗した場合は報告先が無く、記述子がすべて閉じられた時点でカーネルが解放する。
        let _ = self.handle.unlock();
    }
}

/// Vault ファイルの内容を読み込む。
///
/// ロックの対象である Vault のパス ([`VaultLock::vault_path`]) から読む。
/// 内容はヘッダーと暗号文であり、秘密を含まないため、通常の `Vec<u8>` に読み込む。
///
/// # Args
///
/// - `max_len`: 受け付ける最大のバイト数。巨大なファイルによるメモリの枯渇を防ぐ。
///
/// # Returns
///
/// Vault ファイルが存在しない場合は `None`。
///
/// # Errors
///
/// - 通常のファイル以外 (ディレクトリ、FIFO など) がある場合は [`StorageError::VaultNotRegularFile`]。
///   FIFO は `O_NONBLOCK` で開くため、書き込み側を待たずに失敗する。
/// - `max_len` バイトを超える場合は [`StorageError::VaultTooLarge`]。
/// - パスがシンボリックリンクに置き換えられている (`O_NOFOLLOW`)、権限が無いなどの理由で開けない場合と、
///   読み込みに失敗した場合は [`StorageError::Os`]。
pub fn read_vault_file(lock: &VaultLock, max_len: u64) -> Result<Option<Vec<u8>>, StorageError> {
    let read_error = |error: io::Error| StorageError::os(StorageStep::ReadVault, &error);

    let handle = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(lock.vault_path().file())
    {
        Ok(handle) => handle,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(read_error(error)),
    };
    if !handle.metadata().map_err(read_error)?.is_file() {
        return Err(StorageError::VaultNotRegularFile);
    }

    let mut contents = Vec::new();
    // 上限を 1 バイト超えて読めた場合に、上限を超えたと判定する。
    handle
        .take(max_len.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(read_error)?;
    if u64::try_from(contents.len()).map_or(true, |len| len > max_len) {
        return Err(StorageError::VaultTooLarge);
    }
    Ok(Some(contents))
}

/// 親ディレクトリの同期の結果。
///
/// 同期は Vault ファイルの置換が済んだ後に行うため、失敗しても保存そのものは取り消せない。
/// 失敗した場合、直後に電源が断たれると、置換が記憶装置に反映されず、旧い Vault に戻ることがある。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "親ディレクトリの同期に失敗したことを、利用者へ知らせるかを判断する。"]
pub enum DirectorySync {
    /// 親ディレクトリを同期した。
    Synced,
    /// 親ディレクトリを開けなかった、または同期に失敗した。
    Failed {
        /// OS が返したエラー番号。取得できなかった場合は 0。
        errno: i32,
    },
}

/// Vault ファイルを、内容 `contents` でアトミックに置き換える。Vault が存在しない場合は作成する。
///
/// 手順はモジュール doc の「アトミックな保存の手順」のとおりである。
/// 書き込む前の世代の検証は行わない。呼び出し側 ([`crate::vault_file`]) の責務である。
///
/// # Returns
///
/// 親ディレクトリの同期の結果。置換までは成功している。
///
/// # Errors
///
/// 一時ファイルの作成、書き込み、永続化、置換のいずれかに失敗した場合は、失敗した手順を示す [`StorageError::Os`]。
/// このとき一時ファイルは削除し、既存の Vault ファイルは変更しない。
pub fn write_vault_file_atomically(
    lock: &VaultLock,
    contents: &[u8],
) -> Result<DirectorySync, StorageError> {
    write_atomically_with(lock.vault_path(), contents, sync_file_durably)
}

/// [`write_vault_file_atomically`] の本体。永続化の処理 `sync` を差し替えられるようにしてある。
///
/// `sync` は、一時ファイルと親ディレクトリの両方の同期に使う。
fn write_atomically_with<S>(
    path: &VaultPath,
    contents: &[u8],
    sync: S,
) -> Result<DirectorySync, StorageError>
where
    S: Fn(&File) -> io::Result<()>,
{
    let mut temp = create_temp_file(path)?;
    if let Err(error) = temp.as_file_mut().write_all(contents) {
        return Err(discard_temp_file(
            temp,
            StorageError::os(StorageStep::WriteTempFile, &error),
        ));
    }
    if let Err(error) = sync(temp.as_file()) {
        return Err(discard_temp_file(
            temp,
            StorageError::os(StorageStep::SyncTempFile, &error),
        ));
    }
    // `persist` は `rename` で置き換える。失敗した場合は、一時ファイルが戻り値で返る。
    temp.persist(path.file()).map_err(|failure| {
        discard_temp_file(
            failure.file,
            StorageError::os(StorageStep::Rename, &failure.error),
        )
    })?;
    Ok(sync_directory(path.directory(), &sync))
}

/// Vault と同じディレクトリに、権限 `0600` の一時ファイルを作成する。
///
/// 名前は `.<Vault のファイル名>.<乱数>.tmp` である。`O_CREAT | O_EXCL` で作成するため、
/// 既存のファイルやシンボリックリンクを開くことはなく、名前が衝突した場合は別の名前で作り直す。
fn create_temp_file(path: &VaultPath) -> Result<NamedTempFile, StorageError> {
    let name = path.file().file_name().ok_or(StorageError::InvalidPath)?;
    let mut prefix = OsString::from(".");
    prefix.push(name);
    prefix.push(".");

    // `tempfile` は作成の失敗をパス付きの独自のエラーに包み、`raw_os_error` が失われる。
    // OS が返したエラー番号は、ファイルを開いた直後に控える。
    let errno = Cell::new(0);
    Builder::new()
        .prefix(&prefix)
        .suffix(TEMP_SUFFIX)
        .make_in(path.directory(), |candidate| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(TEMP_FILE_MODE)
                .open(candidate)
                .inspect_err(|error| errno.set(error.raw_os_error().unwrap_or(0)))
        })
        .map_err(|_| StorageError::Os {
            step: StorageStep::CreateTempFile,
            errno: errno.get(),
        })
}

/// 一時ファイルを削除し、渡された失敗をそのまま返す。
///
/// 削除の失敗は報告しない。元の失敗のほうが、利用者が対処すべき原因を示すためである。
fn discard_temp_file(temp: NamedTempFile, error: StorageError) -> StorageError {
    let _ = temp.close();
    error
}

/// 親ディレクトリを開いて同期する。失敗はエラーにせず、結果として返す。
fn sync_directory<S>(directory: &Path, sync: &S) -> DirectorySync
where
    S: Fn(&File) -> io::Result<()>,
{
    let result = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(directory)
        .and_then(|handle| sync(&handle));
    match result {
        Ok(()) => DirectorySync::Synced,
        Err(error) => DirectorySync::Failed {
            errno: error.raw_os_error().unwrap_or(0),
        },
    }
}

/// ファイルの内容とメタデータを記憶装置まで永続化する。
///
/// Apple のプラットフォームでは [`File::sync_all`] が `F_FULLFSYNC` となる。
/// `F_FULLFSYNC` に対応しないファイルシステム (仮想マシンの共有フォルダなど) が `ENOTTY` / `ENOTSUP` を返した場合に限り、
/// `fsync` で同期し直す。`fsync` は記憶装置の書き込みキャッシュの消去を要求しないため、電源断への耐性は下がる。
fn sync_file_durably(file: &File) -> io::Result<()> {
    sync_with_fallback(file, File::sync_all, FULL_FSYNC_FALLBACK)
}

/// `full_sync` で同期し、`fallback_enabled` かつ未対応のエラーのときだけ [`plain_fsync`] で同期し直す。
fn sync_with_fallback<F>(file: &File, full_sync: F, fallback_enabled: bool) -> io::Result<()>
where
    F: FnOnce(&File) -> io::Result<()>,
{
    match full_sync(file) {
        Err(error) if fallback_enabled && is_full_fsync_unsupported(error.raw_os_error()) => {
            plain_fsync(file)
        }
        result => result,
    }
}

/// `F_FULLFSYNC` に対応しないことを示すエラー番号 (`ENOTTY`, `ENOTSUP`) かを判定する。
///
/// 入出力の失敗 (`EIO` など) は対象にしない。書き込んだ内容が失われている恐れがあり、同期し直しても回復しないためである。
const fn is_full_fsync_unsupported(errno: Option<i32>) -> bool {
    matches!(errno, Some(libc::ENOTTY | libc::ENOTSUP))
}

/// `fsync` を呼ぶ。シグナルで中断された場合 (`EINTR`) は再試行する。
fn plain_fsync(file: &File) -> io::Result<()> {
    loop {
        // SAFETY: `file` は呼び出しの間借用されており、記述子は有効で、この間に閉じられない。
        // `fsync` は記述子だけを引数に取り、プロセスのメモリを読み書きしない。
        let result = unsafe { libc::fsync(file.as_raw_fd()) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        DirectorySync, StorageError, StorageStep, VaultLock, VaultPath, final_file_name,
        has_lock_suffix, is_full_fsync_unsupported, plain_fsync, sync_directory,
        sync_with_fallback, write_atomically_with,
    };

    type TestResult = Result<(), Box<dyn Error>>;

    /// `errno` の I/O エラーを返す同期処理の代わり。
    fn failing_sync(errno: i32) -> impl Fn(&File) -> io::Result<()> {
        move |_| Err(io::Error::from_raw_os_error(errno))
    }

    #[test]
    fn test_full_fsync_unsupported_only_for_enotty_and_enotsup() {
        assert!(is_full_fsync_unsupported(Some(libc::ENOTTY)));
        assert!(is_full_fsync_unsupported(Some(libc::ENOTSUP)));
        // macOS の `/dev/null` は `ENODEV` を返す。入出力の失敗とともに、`fsync` へ戻す対象ではない。
        for errno in [
            Some(libc::EIO),
            Some(libc::ENOSPC),
            Some(libc::ENODEV),
            Some(libc::EINVAL),
            Some(libc::EBADF),
            None,
        ] {
            assert!(
                !is_full_fsync_unsupported(errno),
                "{errno:?} を未対応のエラーと判定したため失敗しました。"
            );
        }
    }

    #[test]
    fn test_sync_with_fallback_retries_with_fsync_only_when_enabled() -> TestResult {
        let dir = TempDir::new()?;
        let file = File::create(dir.0.join("data"))?;

        for errno in [libc::ENOTTY, libc::ENOTSUP] {
            sync_with_fallback(&file, failing_sync(errno), true)?;
            let error = sync_with_fallback(&file, failing_sync(errno), false)
                .err()
                .ok_or("フォールバックが無効なのに成功したため失敗しました。")?;
            assert_eq!(error.raw_os_error(), Some(errno));
        }
        let error = sync_with_fallback(&file, failing_sync(libc::EIO), true)
            .err()
            .ok_or("入出力の失敗を成功として扱ったため失敗しました。")?;
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        sync_with_fallback(&file, |_| Ok(()), true)?;
        Ok(())
    }

    #[test]
    fn test_plain_fsync_succeeds_on_regular_file() -> TestResult {
        let dir = TempDir::new()?;
        plain_fsync(&File::create(dir.0.join("data"))?)?;
        Ok(())
    }

    #[test]
    fn test_fallback_fsync_reports_failure() -> TestResult {
        // パイプは同期できないため、`fsync` が失敗する。
        let (reader, _writer) = io::pipe()?;
        let pipe = File::from(OwnedFd::from(reader));
        assert!(
            plain_fsync(&pipe).is_err(),
            "`fsync` の失敗を成功として扱ったため失敗しました。"
        );
        assert!(
            sync_with_fallback(&pipe, failing_sync(libc::ENOTTY), true).is_err(),
            "フォールバック先の失敗を成功として扱ったため失敗しました。"
        );
        Ok(())
    }

    #[test]
    fn test_directory_sync_succeeds_through_fallback() -> TestResult {
        let dir = TempDir::new()?;
        let outcome = sync_directory(&dir.0, &|directory: &File| {
            sync_with_fallback(directory, failing_sync(libc::ENOTTY), true)
        });
        assert_eq!(outcome, DirectorySync::Synced);
        Ok(())
    }

    /// ディレクトリの中身の名前を並べて返す。
    fn entry_names(dir: &Path) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = fs::read_dir(dir)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, io::Error>>()?;
        names.sort();
        Ok(names)
    }

    #[test]
    fn test_failed_sync_removes_temp_file_and_keeps_vault() -> TestResult {
        let dir = TempDir::new()?;
        fs::write(dir.0.join("vault.fvl"), b"old")?;
        let path = VaultPath::resolve(&dir.0.join("vault.fvl"))?;

        for errno in [libc::EIO, libc::ENOSPC] {
            let error = write_atomically_with(&path, b"new", failing_sync(errno))
                .err()
                .ok_or("同期の失敗を成功として扱ったため失敗しました。")?;
            assert_eq!(
                error,
                StorageError::Os {
                    step: StorageStep::SyncTempFile,
                    errno,
                }
            );
            assert_eq!(fs::read(path.file())?, b"old");
            assert_eq!(entry_names(&dir.0)?, ["vault.fvl"]);
        }
        Ok(())
    }

    #[test]
    fn test_directory_sync_failure_is_reported_after_replacement() -> TestResult {
        let dir = TempDir::new()?;
        let path = VaultPath::resolve(&dir.0.join("vault.fvl"))?;
        let synced_files = Cell::new(0u32);
        let sync = |file: &File| {
            if file.metadata()?.is_dir() {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                synced_files.set(synced_files.get() + 1);
                file.sync_all()
            }
        };

        let outcome = write_atomically_with(&path, b"new", sync)?;
        assert_eq!(outcome, DirectorySync::Failed { errno: libc::EIO });
        assert_eq!(synced_files.get(), 1, "一時ファイルの同期の確認に失敗。");
        assert_eq!(fs::read(path.file())?, b"new");
        assert_eq!(entry_names(&dir.0)?, ["vault.fvl"]);
        Ok(())
    }

    #[test]
    fn test_final_file_name_accepts_plain_names() {
        let cases = [
            ("vault.fvl", "vault.fvl"),
            ("dir/vault.fvl", "vault.fvl"),
            ("/abs/dir/vault", "vault"),
            ("..hidden", "..hidden"),
            (".vault", ".vault"),
        ];
        for (path, expected) in cases {
            assert_eq!(
                final_file_name(Path::new(path)),
                Some(OsStr::new(expected)),
                "`{path}` のファイル名の取得に失敗。"
            );
        }
    }

    #[test]
    fn test_final_file_name_rejects_directory_forms() {
        for path in ["", "/", ".", "..", "dir/", "dir/.", "dir/..", "./"] {
            assert_eq!(
                final_file_name(Path::new(path)),
                None,
                "`{path}` の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_has_lock_suffix_ignores_ascii_case() {
        for name in [".lock", "a.lock", "a.LOCK", "a.Lock", "保管庫.lock"] {
            assert!(
                has_lock_suffix(OsStr::new(name)),
                "`{name}` の接尾辞の検出に失敗。"
            );
        }
        for name in ["", "lock", "a.locks", "a.lock.fvl", "alock", "保管庫"] {
            assert!(
                !has_lock_suffix(OsStr::new(name)),
                "`{name}` を接尾辞ありと判定したため失敗しました。"
            );
        }
    }

    #[test]
    fn test_error_display_ends_with_japanese_period() {
        let errors = [
            StorageError::InvalidPath,
            StorageError::ReservedName,
            StorageError::VaultNotRegularFile,
            StorageError::LockFileNotRegularFile,
            StorageError::Locked,
            StorageError::VaultTooLarge,
        ]
        .into_iter()
        .chain(
            [
                StorageStep::ResolvePath,
                StorageStep::OpenLockFile,
                StorageStep::Lock,
                StorageStep::ReadVault,
                StorageStep::CreateTempFile,
                StorageStep::WriteTempFile,
                StorageStep::SyncTempFile,
                StorageStep::Rename,
            ]
            .map(|step| StorageError::Os { step, errno: 5 }),
        );
        for error in errors {
            assert!(
                error.to_string().ends_with('。'),
                "エラーメッセージの末尾が句点でないため失敗しました: {error}"
            );
        }
    }

    #[test]
    fn test_error_display_includes_step_and_errno() {
        let message = StorageError::Os {
            step: StorageStep::OpenLockFile,
            errno: 13,
        }
        .to_string();
        assert!(
            message.contains("ロックファイル") && message.contains("13"),
            "手順名と errno をメッセージに含めることに失敗しました: {message}"
        );
    }

    /// テスト用の一時ディレクトリ。破棄するときに中身ごと削除する。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Result<Self, Box<dyn Error>> {
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fidelogic-cli-storage-{}-{nanos}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// 記述子の複製が残っていても、値の破棄でロックが解放されること。
    /// 複製は、子プロセスが `fork` から `exec` までの間に持つ記述子の代わりである。
    #[test]
    fn test_drop_releases_lock_while_descriptor_is_duplicated() -> TestResult {
        let dir = TempDir::new()?;
        let path = VaultPath::resolve(&dir.0.join("vault.fvl"))?;

        let lock = VaultLock::try_acquire(path.clone())?;
        let duplicate = lock.handle.try_clone()?;
        drop(lock);

        let reacquired = VaultLock::try_acquire(path)?;
        drop(reacquired);
        drop(duplicate);
        Ok(())
    }
}
