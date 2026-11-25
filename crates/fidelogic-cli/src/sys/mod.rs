//! # OS 依存処理の境界 (`sys`)
//!
//! OS の API を呼び出す処理と、OS を判別する条件付きコンパイルを、このモジュールの配下に閉じ込める。
//! 上位の処理 (サブコマンド、エントリの組み立て、リカバリーコードの計算など) は、
//! ここが公開する関数と型だけを使い、OS を判別する `#[cfg]` を書かない。
//! 将来 Windows に対応するときの差分は、この配下に限られる。
//!
//! ## 境界の規則
//!
//! - OS を判別する `cfg` (`unix`, `windows`, `target_os`, `target_family`, `target_vendor`) は `sys` 配下だけに書く
//! - `libc` と `std::os` を使うのは `sys` 配下だけとする
//! - `unsafe` を許す (`#![allow(unsafe_code)]`) のは、`sys` 配下で OS の API を直接呼ぶモジュールだけとする。
//!   クレート全体は `#![deny(unsafe_code)]` である
//! - 公開する関数と型は、OS によらず同じ形にする。OS 固有の値 (`errno` など) は診断用の数値として持たせる
//!
//! これらの規則は、統合テスト `tests/sys_boundary.rs` が `src/` 配下のソースを走査して検査する。
//! `unsafe` を許すモジュールは、同テストの `UNSAFE_ALLOWED_FILES` に列挙したものに限る。
//!
//! ## 構成
//!
//! | モジュール | 責務 | 状態 |
//! | :-- | :-- | :-- |
//! | [`process`] | プロセス硬化 (コアダンプの抑止、`umask`、ダンプとデバッガーのアタッチの拒否) | 実装済み |
//! | [`storage`] | Vault ファイルの排他ロック、読み込み、アトミックな保存 | 実装済み |
//! | [`signal`] | 中断シグナルの捕捉と、入力と中断の待機 | 実装済み |
//! | [`tty`] | 端末と非対話の入力元からの読み込み (エコーの抑止、端末属性の復元) | 実装済み |
//! | [`clipboard`] | クリップボードへのコピーと自動消去 (ワーカープロセスの起動を含む) | 実装済み |
//!
//! ## 対応環境
//!
//! POSIX 環境 (macOS / Linux) のみを実装する。それ以外の環境ではコンパイルを拒否する。

#[cfg(not(unix))]
compile_error!("fidelogic-cli は POSIX 環境 (macOS / Linux) のみに対応しています。");

pub mod clipboard;
pub mod process;
pub mod signal;
pub mod storage;
pub mod tty;
