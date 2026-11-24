//! # 終了コードの規約 (`exit`)
//!
//! プロセスの終了コードを [`ExitCategory`] の 5 種類に限る。
//! 失敗の詳細は標準エラー出力のメッセージで伝え、終了コードは呼び出し元のスクリプトが分岐に使う粗い分類とする。
//!
//! | 分類 | 終了コード | 用途 |
//! | :-- | --: | :-- |
//! | [`ExitCategory::Success`] | 0 | 成功。`--help` と `--version` の表示を含む |
//! | [`ExitCategory::Failure`] | 1 | 一般の失敗 (プロセス硬化、入出力、未実装のサブコマンド、世代の巻き戻しなど) |
//! | [`ExitCategory::Usage`] | 2 | 引数の誤り |
//! | [`ExitCategory::AuthenticationFailed`] | 3 | 認証の失敗 (理由によらず 1 つにまとめる) |
//! | [`ExitCategory::Interrupted`] | 130 | `SIGINT` などによる中断 (`128 + SIGINT`) |
//!
//! 誤ったパスワード、未設定のスロット、改ざんされたファイルは、
//! いずれも [`ExitCategory::AuthenticationFailed`] になる。
//! 終了コードから失敗の理由を区別できないようにするためである。

use std::process::ExitCode;

/// プロセスの終了コードの分類。
///
/// 終了コードの数値は [`ExitCategory::code`] だけが定める。
/// 呼び出し側は数値を直接書かず、この型を [`ExitCode`] へ変換して返す。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCategory {
    /// 成功。
    Success,
    /// 一般の失敗。
    Failure,
    /// 引数の誤り。
    Usage,
    /// 認証の失敗。誤ったパスワード、未設定のスロット、改ざんを区別しない。
    AuthenticationFailed,
    /// 端末入力などの中断。
    Interrupted,
}

impl ExitCategory {
    /// 終了コードの数値を返す。
    ///
    /// # Returns
    ///
    /// `Success` は 0、`Failure` は 1、`Usage` は 2、`AuthenticationFailed` は 3、`Interrupted` は 130。
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Success => 0,
            Self::Failure => 1,
            Self::Usage => 2,
            Self::AuthenticationFailed => 3,
            Self::Interrupted => 130,
        }
    }
}

impl From<ExitCategory> for ExitCode {
    fn from(category: ExitCategory) -> Self {
        Self::from(category.code())
    }
}

#[cfg(test)]
mod tests {
    use super::ExitCategory;

    const ALL_CATEGORIES: [ExitCategory; 5] = [
        ExitCategory::Success,
        ExitCategory::Failure,
        ExitCategory::Usage,
        ExitCategory::AuthenticationFailed,
        ExitCategory::Interrupted,
    ];

    #[test]
    fn test_exit_codes_match_convention() {
        assert_eq!(ExitCategory::Success.code(), 0);
        assert_eq!(ExitCategory::Failure.code(), 1);
        assert_eq!(ExitCategory::Usage.code(), 2);
        assert_eq!(ExitCategory::AuthenticationFailed.code(), 3);
        assert_eq!(ExitCategory::Interrupted.code(), 130);
    }

    #[test]
    fn test_exit_codes_are_distinct() {
        for (index, left) in ALL_CATEGORIES.iter().enumerate() {
            for right in &ALL_CATEGORIES[index + 1..] {
                assert_ne!(
                    left.code(),
                    right.code(),
                    "{left:?} と {right:?} の終了コードが重複しています。",
                );
            }
        }
    }
}
