//! # 排他ロックとアトミックな保存 (`sys::storage`)
//!
//! Vault ファイルの読み書きのうち、OS によって手順が異なる処理を置く。現時点では未実装である。
//!
//! ## 担う処理
//!
//! - サイドカー `<vault>.lock` による排他制御。Vault 本体は保存のたびに `rename` で inode が入れ替わるため、
//!   名前を変えないサイドカーにロックを掛ける
//! - 同じディレクトリの一時ファイルへの書き込み、永続化、`rename` による置換、親ディレクトリの同期
//!
//! ## OS ごとの差
//!
//! | 処理 | POSIX | Windows (未対応) |
//! | :-- | :-- | :-- |
//! | 排他ロック | `File::lock` (`flock`) | `File::lock` (`LockFileEx`) |
//! | 永続化 | `File::sync_all`。Apple では `F_FULLFSYNC` となり、仮想ファイルシステムが `ENOTTY` / `ENOTSUP` を返したときだけ `fsync` へ戻す | `FlushFileBuffers` |
//! | 置換 | `rename` の後に親ディレクトリを同期する | `ReplaceFileW` または `MoveFileExW` |
//! | 作成時の権限 | `0600` | - |
