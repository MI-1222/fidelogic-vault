//! # OS の乱数源 (`random`)
//!
//! 鍵素材、ソルト、ノンスに使う乱数を、OS の暗号論的に安全な乱数源から取得する。
//! 取得は `getrandom` クレートに任せ、このモジュールは `unsafe` を持たない。
//!
//! | OS | 取得元 (`getrandom` の既定) |
//! | :-- | :-- |
//! | macOS | `getentropy` |
//! | Linux | `getrandom` システムコール。使えない場合は `/dev/urandom` |
//!
//! Linux の `getrandom` システムコールは、起動直後で乱数源の初期化が済んでいない場合、完了まで戻らない。

use fidelogic_core::SystemError;

/// `destination` の全体を、OS の乱数で埋める。
///
/// 失敗した場合の `destination` の内容は定まらない。呼び出し側は使わずに破棄する。
///
/// # Errors
///
/// 乱数を取得できない場合は [`SystemError::EntropySourceFailed`]。
pub fn fill_random(destination: &mut [u8]) -> Result<(), SystemError> {
    getrandom::fill(destination).map_err(|_| SystemError::EntropySourceFailed)
}
