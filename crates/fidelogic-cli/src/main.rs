//! # fidelogic-cli (実行ファイル)
//!
//! 処理の本体は [`fidelogic_cli::run`] にある。ここでは呼び出して終了コードを返すだけとする。

use std::process::ExitCode;

/// CLI アプリケーションのエントリポイント。
///
/// 引数の解析を含むすべての処理より前に、[`fidelogic_cli::run`] がプロセス硬化を適用する。
fn main() -> ExitCode {
    fidelogic_cli::run()
}
