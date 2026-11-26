//! # テスト専用の失敗点 (`failpoint`)
//!
//! プロセスを特定の位置で停止させ、テストが外から状態を調べるための停止位置を置く。
//! 保存の途中で強制終了した状況の再現と、起動直後の保護の確認に使う。
//! このモジュールは OS に依存しない。
//!
//! ## 有効になる条件
//!
//! フィーチャー `test-hooks` を有効にした、デバッグアサーションのあるビルドに限る。
//! それ以外のビルド (`--all-features` を付けたリリースビルドを含む) では、環境変数を読まず、何もしない。
//!
//! ## 動作
//!
//! 環境変数 `FIDELOGIC_CLI_FAILPOINT` が失敗点の名前と一致する場合、その位置で次の順に動く。
//!
//! 1. 標準エラー出力に `failpoint:<名前>` を 1 行で書く。
//! 2. `before-args` の場合は、続けて `protections:<現在の保護の状態>` を 1 行で書く
//!    ([`crate::sys::process`] が読み取る)。
//! 3. 標準入力が終端に達するまで停止する。テストは、この間にファイルとロックを調べ、`SIGKILL` を送る。
//! 4. 終端に達した場合 (テストの失敗などで親が先に終了した場合) は、続きを実行せず、終了コード 70 で終了する。
//!
//! | 名前 | 位置 |
//! | :-- | :-- |
//! | `before-args` | 引数の解析を始める直前 |
//! | `after-lock` | 排他ロックを取得した直後 |
//! | `partial-temp-write` | 一時ファイルに内容の前半を書き込んだ直後 |
//! | `before-rename` | 一時ファイルを永続化した後、Vault のパスへ改名する直前 |

use std::io::{self, Write};

/// 停止位置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailPoint {
    /// 引数の解析を始める直前。
    BeforeArgs,
    /// 排他ロックを取得した直後。
    AfterLock,
    /// 一時ファイルに内容の前半を書き込んだ直後。
    // 失敗点を含まないビルドでは、この位置を参照しない。
    #[cfg_attr(not(all(feature = "test-hooks", debug_assertions)), allow(dead_code))]
    PartialTempWrite,
    /// 一時ファイルを永続化した後、Vault のパスへ改名する直前。
    BeforeRename,
}

/// 失敗点が指定されていれば停止し、戻らない。指定されていなければ何もしない。
pub(crate) fn hit(point: FailPoint) {
    #[cfg(all(feature = "test-hooks", debug_assertions))]
    if enabled::is_selected(point) {
        enabled::halt(point);
    }
    #[cfg(not(all(feature = "test-hooks", debug_assertions)))]
    let _ = point;
}

/// `contents` の全体を `writer` に書き込む。
///
/// [`FailPoint::PartialTempWrite`] が指定された場合は、前半を書き込んだ時点で停止し、戻らない。
///
/// # Errors
///
/// 書き込みの失敗を返す。
pub(crate) fn write_all(writer: &mut impl Write, contents: &[u8]) -> io::Result<()> {
    #[cfg(all(feature = "test-hooks", debug_assertions))]
    if enabled::is_selected(FailPoint::PartialTempWrite) {
        let (head, _) = contents.split_at(contents.len() / 2);
        writer.write_all(head)?;
        enabled::halt(FailPoint::PartialTempWrite);
    }
    writer.write_all(contents)
}

/// 失敗点が有効なビルドの処理。
#[cfg(all(feature = "test-hooks", debug_assertions))]
mod enabled {
    use std::io::{self, Read, Write};

    use super::FailPoint;

    /// 停止する失敗点の名前を指定する環境変数。
    const VARIABLE: &str = "FIDELOGIC_CLI_FAILPOINT";

    /// 停止中に標準入力が終端に達した場合の終了コード。
    const ABANDONED_EXIT_CODE: i32 = 70;

    /// 環境変数と、停止の通知に使う名前を返す。
    const fn name(point: FailPoint) -> &'static str {
        match point {
            FailPoint::BeforeArgs => "before-args",
            FailPoint::AfterLock => "after-lock",
            FailPoint::PartialTempWrite => "partial-temp-write",
            FailPoint::BeforeRename => "before-rename",
        }
    }

    /// 環境変数が `point` を指定しているかを返す。
    pub(super) fn is_selected(point: FailPoint) -> bool {
        std::env::var_os(VARIABLE).is_some_and(|value| value == name(point))
    }

    /// 停止を通知し、強制終了されるのを待つ。
    pub(super) fn halt(point: FailPoint) -> ! {
        // 通知を書けない場合は親が待ち続けるが、親が標準入力を閉じれば終了する。
        let _ = writeln!(io::stderr(), "failpoint:{}", name(point));
        if point == FailPoint::BeforeArgs {
            let protections = crate::sys::process::describe_protections();
            let _ = writeln!(io::stderr(), "protections:{protections}");
        }
        let _ = io::stdin().read_to_end(&mut Vec::new());
        // 続きを実行すると、強制終了を想定したテストが成功しうるため、ここで終了する。
        std::process::exit(ABANDONED_EXIT_CODE)
    }
}
