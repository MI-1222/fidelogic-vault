//! # fidelogic-cli
//!
//! Fidelogic Vault のローカル運用および暗号鍵ライフサイクル管理を行うネイティブ CLI ツール。
//!
//! ## Overview
//!
//! 本ツールは、ファイルシステム上に永続化された暗号化ストレージ (Vault) の作成、スロット構成の更新
//! (Argon2id パスワード、WebAuthn PRF 鍵、リカバリーコード)、機密エントリの安全な格納・抽出を
//! コマンドラインから実行するための管理者向けインターフェースを目指している。
//! 現時点で実装済みなのは、プロセス硬化と、リンクしているコアのプロファイル表示のみである。
//!
//! 実行ファイル (`main.rs`) は [`run`] を呼ぶだけの薄い入口であり、処理の本体はこのライブラリに置く。
//! これにより、統合テストから各処理を直接呼び出せる。
//!
//! ## ネイティブ環境におけるセキュリティアーキテクチャ
//!
//! - **プロセス硬化 (実装済み)**: [`run`] は引数の解析より前に [`sys::process::harden_process`] を実行し、
//!   コアダンプの抑止、`umask(0077)`、デバッガーのアタッチ拒否を適用する。
//! - **OS 依存処理の境界**: OS の API の呼び出しと、OS を判別する条件付きコンパイルは [`sys`] の配下に閉じ込める。
//!   それ以外のモジュールは OS に依存しない。
//! - **メモリ保護 (未実装)**: 機密データを保持するバッファに `fidelogic_core` の `LockedBuffer` を用い、
//!   `mlock` (スワップアウト抑止) と `MADV_DONTDUMP` (コアダンプ抑止) を適用する方針である。
//! - **プロファイル連携**: [`fidelogic_core`] を `profile-vault` でリンクしている。
//!   暗号処理とゼロ消去はコアが担い、CLI から呼び出す処理は今後追加する。
//!
//! ## 対応環境
//!
//! POSIX 環境 (macOS / Linux) のみを対象とする。それ以外の環境では [`sys`] がコンパイルを拒否する。

#![deny(unsafe_code)]

pub mod sys;

use std::io::Write;
use std::process::ExitCode;

use fidelogic_core::active_profile;

/// CLI アプリケーションの実処理。
///
/// 最初にプロセス硬化を適用し、失敗した場合は何も処理せずに失敗終了する。
/// 硬化に成功した後に、リンクされているコアエンジンのプロファイル状態を表示する。
///
/// # Returns
///
/// 正常終了なら `ExitCode::SUCCESS`。プロセス硬化または出力に失敗した場合は `ExitCode::FAILURE`。
pub fn run() -> ExitCode {
    if let Err(error) = sys::process::harden_process() {
        // 標準エラー出力への書き込み失敗は報告先が無いため、結果を無視する。
        let _ = writeln!(std::io::stderr(), "{error}");
        return ExitCode::FAILURE;
    }

    let mut stdout = std::io::stdout();
    match writeln!(
        stdout,
        "fidelogic-cli (fidelogic-core: {})",
        active_profile()
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
