//! # 排他ロックとアトミックな保存 (`sys::storage`)
//!
//! Vault ファイルの読み書きのうち、OS によって手順が異なる処理を置く。
//! 実装済みなのは、パスの正規化と排他ロックである。アトミックな保存は未実装である。
//!
//! ## 担う処理
//!
//! - Vault のパスの正規化 ([`VaultPath`])。
//! - サイドカー `<vault>.lock` による排他制御 ([`VaultLock`])。Vault 本体は保存のたびに `rename` で inode が入れ替わるため、
//!   名前を変えないサイドカーにロックを掛ける。
//! - 同じディレクトリの一時ファイルへの書き込み、永続化、`rename` による置換、親ディレクトリの同期 (未実装)。
//!
//! ## 使い方
//!
//! [`VaultPath::resolve`] で正規化したパスを [`VaultLock`] に渡してロックを取得し、
//! 以後の読み書きには [`VaultLock::vault_path`] が返すパスを使う。
//! ロックしたパスと読み書きするパスがずれないようにするためである。
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

use core::fmt;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// サイドカーロックファイルの名前として、Vault のファイル名の後ろに付ける接尾辞。
const LOCK_SUFFIX: &str = ".lock";

/// ロックファイルを作成するときの権限。オーナーの読み書きだけを許す。
const LOCK_FILE_MODE: u32 = 0o600;

/// OS の API の呼び出しが失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageStep {
    /// Vault のパスの解決。
    ResolvePath,
    /// ロックファイルを開く処理。
    OpenLockFile,
    /// 排他ロックの取得。
    Lock,
}

impl StorageStep {
    /// 手順の名称を日本語で返す。
    const fn label(self) -> &'static str {
        match self {
            Self::ResolvePath => "Vault のパスの解決",
            Self::OpenLockFile => "ロックファイルを開く処理",
            Self::Lock => "排他ロックの取得",
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

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        StorageError, StorageStep, VaultLock, VaultPath, final_file_name, has_lock_suffix,
    };

    type TestResult = Result<(), Box<dyn Error>>;

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
            StorageError::Os {
                step: StorageStep::ResolvePath,
                errno: 2,
            },
            StorageError::Os {
                step: StorageStep::OpenLockFile,
                errno: 13,
            },
            StorageError::Os {
                step: StorageStep::Lock,
                errno: 4,
            },
        ];
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
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fidelogic-cli-storage-{}-{nanos}",
                std::process::id()
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
