//! # クリップボードへのコピーと自動消去 (`sys::clipboard`)
//!
//! 秘密をクリップボードへコピーし、[`CLEAR_DELAY`] (30 秒) の後に、内容が変わっていなければ消去する。
//! クリップボードの操作は `arboard` が行う。
//!
//! ## 構成
//!
//! コピーと消去は、本プロセスから起動するワーカープロセスが行う。
//! 呼び出し側 (サブコマンド) は [`copy_with_auto_clear`] を呼ぶ。この関数はコピーの成否を受け取った時点で戻り、
//! 30 秒の待機と消去はワーカーが引き受ける。
//!
//! 1. 呼び出し側は、鍵 (DEK) を消去してから [`copy_with_auto_clear`] を呼ぶ。
//! 2. [`copy_with_auto_clear`] は、実行ファイル自身 (`current_exe()`) を隠しサブコマンド [`WORKER_SUBCOMMAND`] で起動する。
//!    `fork` は使わない。親のメモリ (鍵を保持していたページを含む) を子に複製しないためである。
//! 3. 親は秘密を子の標準入力へ書いて閉じ、子が標準出力に返す 1 バイトの応答 (コピーの成否) を読んで戻る。
//! 4. 子 ([`run_worker`]) は、起動時にプロセス硬化を受けた後 (`crate::run` の先頭で行う)、
//!    秘密を `mlock` したバッファへ読み込み、クリップボードへコピーして応答を返す。
//! 5. 子は 30 秒待つ。待機中に中断のシグナル (`SIGINT`, `SIGTERM`, `SIGHUP`, `SIGQUIT`) を受けた場合は、待機を切り上げる。
//! 6. 子は、クリップボードの内容がコピーした秘密と一致する場合 (定数時間で比較する) だけ消去し、終了する。
//!    待機中に利用者が別の内容をコピーしていた場合は、その内容を消さない。
//!
//! 子は新しいプロセスグループで起動する。端末を閉じたときの `SIGHUP` や、端末からの `Ctrl+C` が子に届かず、
//! 消去の前に子が終了しないようにするためである。子のカレントディレクトリは `/` にする。
//!
//! ## OS ごとの差
//!
//! | 処理 | Linux (X11 / Wayland) | macOS | Windows (未対応) |
//! | :-- | :-- | :-- | :-- |
//! | 内容の保持 | コピー元のプロセスが保持する。子が終了すると内容は失われる | ペーストボードのサーバーが保持する | OS が保持する |
//! | 履歴からの除外 | MIME タイプ `x-kde-passwordManagerHint` | 型 `org.nspasteboard.ConcealedType` | 履歴とクラウド同期を除外するフォーマット |
//! | 消去 | 選択の所有権を手放す (X11)、選択を空にする (Wayland) | `clearContents` | - |
//!
//! 消去の手順はどの OS でも同じである。`arboard` の Linux 向けの `wait_until` は使わない。
//! Wayland のバックエンドが期限を参照せず、直ちに戻るためである (`arboard` 3.7.0 のソースで確認した)。
//! X11 では、履歴から除外した内容は、`arboard` の破棄時にクリップボードマネージャーへ引き渡されず、所有権を手放す。
//!
//! ## 限界
//!
//! - 履歴の除外指定を見ずに内容を記録するクリップボードマネージャーには、どの OS でも防御できない。
//!   内容を定期的に読み取って保存するものは、消去の前に記録を終えている。案内には [`HISTORY_WARNING`] を使う。
//! - `arboard` と OS は、秘密の複写を消去されない領域に持つ (Linux の `arboard` 内部の `Vec`、macOS の `NSString`)。
//!   子のプロセスは硬化 (コアダンプの抑止、ダンプとアタッチの拒否) を受けているが、30 秒の間はメモリ上に残る。
//! - 子が `SIGKILL` などで消去の前に終了した場合、macOS では内容がペーストボードに残る。Linux では子の終了とともに失われる。
//! - 待機中に、利用者が同じ内容を別の場所から再びコピーした場合も、一致するため消去する。

use std::fmt;
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use arboard::SetExtApple;
#[cfg(all(unix, not(target_os = "macos")))]
use arboard::SetExtLinux;
use fidelogic_core::{LockedBuffer, ct_eq_bytes_bool, volatile_zeroize};

use super::signal::InterruptWatcher;

/// コピーしてから消去するまでの時間。
pub const CLEAR_DELAY: Duration = Duration::from_secs(30);

/// コピーできる秘密の上限 (バイト)。
pub const MAX_TEXT_LEN: usize = 4096;

/// ワーカーを起動する隠しサブコマンドの名前。ヘルプには表示しない。
pub const WORKER_SUBCOMMAND: &str = "__clipboard-worker";

/// ワーカーに、クリップボードの履歴からの除外を指示するフラグの名前 (先頭の `--` を除く)。
pub const EXCLUDE_FROM_HISTORY_FLAG: &str = "exclude-from-history";

/// クリップボードの履歴による漏洩についての警告。コピーを行うサブコマンドのヘルプに表示する。
pub const HISTORY_WARNING: &str = concat!(
    "コピーした内容は 30 秒後に消去します。",
    "ただし、履歴からの除外の指定を無視して内容を記録するクリップボードマネージャーは、",
    "消去の前に内容を保存します。",
);

/// 読み込みバッファの容量。上限を 1 バイト超えて読めるようにし、超過を検出する。
const INPUT_CAPACITY: usize = MAX_TEXT_LEN + 1;

/// 待機中に中断を確認する間隔。
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// クリップボードの履歴からの除外の扱い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryPolicy {
    /// 履歴からの除外を指定する。パスワード、TOTP、リカバリーコードなど、秘密のフィールドに使う。
    Exclude,
    /// 除外を指定しない。ユーザー名や URL に使う。
    ///
    /// macOS の Chromium 系ブラウザーは、除外を指定した内容のアドレスバーへの「貼り付けて移動」を無効にする。
    Allow,
}

/// OS の呼び出しが失敗した段階。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardStep {
    /// 実行ファイルのパスの取得 (`current_exe`)。
    LocateExecutable,
    /// ワーカーの起動。
    Spawn,
    /// ワーカーへの秘密の書き込み。
    SendText,
    /// ワーカーからの応答の読み込み。
    ReceiveStatus,
    /// ワーカーでの、標準入力からの秘密の読み込み。
    ReadInput,
}

/// クリップボードへのコピーの失敗。
///
/// 秘密の内容や長さを持たせない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardError {
    /// コピーする内容が空である。
    Empty,
    /// コピーする内容が [`MAX_TEXT_LEN`] を超える。
    TooLong,
    /// ワーカーが受け取った内容が UTF-8 でないか、標準入力が端末である。
    InvalidInput,
    /// 秘密を保持するバッファの `mlock` に失敗した。
    MemoryLockFailed,
    /// クリップボードに接続できない (ディスプレイの無い環境など)。
    Unavailable,
    /// クリップボードへの書き込みに失敗した。
    CopyFailed,
    /// クリップボードの消去に失敗した。
    ClearFailed,
    /// ワーカーが応答を返さずに終了したか、不明な応答を返した。
    WorkerFailed,
    /// OS の呼び出しが失敗した。`errno` は診断用の値で、取得できない場合は 0。
    Os {
        /// 失敗した段階。
        step: ClipboardStep,
        /// OS のエラー番号。
        errno: i32,
    },
}

impl fmt::Display for ClipboardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("コピーする内容が空です。"),
            Self::TooLong => write!(
                formatter,
                "コピーする内容が上限 ({MAX_TEXT_LEN} バイト) を超えています。"
            ),
            Self::InvalidInput => {
                formatter.write_str("クリップボードのワーカーへの入力が不正です。")
            }
            Self::MemoryLockFailed => formatter
                .write_str("コピーする内容を保持するメモリのロック (mlock) に失敗しました。"),
            Self::Unavailable => formatter.write_str("クリップボードを利用できません。"),
            Self::CopyFailed => formatter.write_str("クリップボードへのコピーに失敗しました。"),
            Self::ClearFailed => formatter.write_str("クリップボードの消去に失敗しました。"),
            Self::WorkerFailed => {
                formatter.write_str("クリップボードのワーカーが応答せずに終了しました。")
            }
            Self::Os { step, errno } => {
                let action = match step {
                    ClipboardStep::LocateExecutable => "実行ファイルのパスの取得",
                    ClipboardStep::Spawn => "クリップボードのワーカーの起動",
                    ClipboardStep::SendText => "クリップボードのワーカーへの書き込み",
                    ClipboardStep::ReceiveStatus => "クリップボードのワーカーからの読み込み",
                    ClipboardStep::ReadInput => "標準入力からの読み込み",
                };
                write!(formatter, "{action}に失敗しました (errno {errno})。")
            }
        }
    }
}

impl std::error::Error for ClipboardError {}

/// ワーカーが親へ返す応答。標準出力に 1 バイトで書く。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum WorkerStatus {
    /// コピーに成功した。
    Copied = 1,
    /// 入力が不正である。
    InvalidInput = 2,
    /// `mlock` に失敗した。
    MemoryLockFailed = 3,
    /// クリップボードに接続できない。
    Unavailable = 4,
    /// 書き込みに失敗した。
    CopyFailed = 5,
    /// 上記以外の準備 (シグナルの捕捉、入力の読み込み) に失敗した。
    SetupFailed = 6,
}

impl WorkerStatus {
    /// ワーカーでの失敗を、親へ返す応答に変換する。
    const fn from_error(error: ClipboardError) -> Self {
        match error {
            ClipboardError::Empty | ClipboardError::TooLong | ClipboardError::InvalidInput => {
                Self::InvalidInput
            }
            ClipboardError::MemoryLockFailed => Self::MemoryLockFailed,
            ClipboardError::Unavailable => Self::Unavailable,
            ClipboardError::CopyFailed => Self::CopyFailed,
            ClipboardError::ClearFailed
            | ClipboardError::WorkerFailed
            | ClipboardError::Os { .. } => Self::SetupFailed,
        }
    }

    /// 親が受け取った 1 バイトを、コピーの結果に変換する。
    ///
    /// 応答が無い (`None`) 場合と不明な値は [`ClipboardError::WorkerFailed`] にする。
    const fn decode(byte: Option<u8>) -> Result<(), ClipboardError> {
        match byte {
            Some(value) if value == Self::Copied as u8 => Ok(()),
            Some(value) if value == Self::InvalidInput as u8 => Err(ClipboardError::InvalidInput),
            Some(value) if value == Self::MemoryLockFailed as u8 => {
                Err(ClipboardError::MemoryLockFailed)
            }
            Some(value) if value == Self::Unavailable as u8 => Err(ClipboardError::Unavailable),
            Some(value) if value == Self::CopyFailed as u8 => Err(ClipboardError::CopyFailed),
            _ => Err(ClipboardError::WorkerFailed),
        }
    }
}

/// 秘密をクリップボードへコピーし、[`CLEAR_DELAY`] の後に消去するワーカーを起動する。
///
/// 実行ファイル自身 (`current_exe()`) をワーカーとして起動する。
/// ワーカーがコピーの成否を返した時点で戻り、ワーカーの終了は待たない。
///
/// # Args
///
/// - `text`: コピーする内容。空でなく、[`MAX_TEXT_LEN`] バイト以下であること。
/// - `policy`: クリップボードの履歴からの除外の扱い。
///
/// # Errors
///
/// - 内容が空の場合は [`ClipboardError::Empty`]、上限を超える場合は [`ClipboardError::TooLong`]。
///   どちらもワーカーを起動しない。
/// - ワーカーの起動と入出力に失敗した場合は [`ClipboardError::Os`]。
/// - ワーカーがコピーに失敗した場合は、その理由 ([`ClipboardError::Unavailable`] など)。
///
/// # Notes
///
/// - 呼び出す前に、鍵 (DEK) と、コピーする内容以外の秘密を消去しておくこと。
///   ワーカーの起動と応答を待つ間に、親のメモリに不要な秘密を残さないためである。
/// - 戻った後もワーカーは動き続ける。この関数はワーカーを回収しないため、
///   長く動く親 (対話モード) は、[`reap_finished_workers`] を呼んで終了したワーカーを回収する。
/// - 実行ファイルが起動後に置き換えられていた場合は、置き換え後のファイルを起動する。
pub fn copy_with_auto_clear(text: &str, policy: HistoryPolicy) -> Result<(), ClipboardError> {
    let program = std::env::current_exe()
        .map_err(|error| os_error(ClipboardStep::LocateExecutable, &error))?;
    copy_via_worker(&program, text, policy)
}

/// `program` をワーカーとして起動し、秘密をクリップボードへコピーさせる。
///
/// 動作は [`copy_with_auto_clear`] と同じで、起動する実行ファイルだけを指定できる。
/// 統合テストでは、テストのバイナリではなく `fidelogic-cli` の実行ファイルを指定するために使う。
///
/// # Args
///
/// - `program`: 隠しサブコマンド [`WORKER_SUBCOMMAND`] を持つ `fidelogic-cli` の実行ファイル。
/// - `text`, `policy`: [`copy_with_auto_clear`] と同じ。
///
/// # Errors
///
/// [`copy_with_auto_clear`] と同じ。
pub fn copy_via_worker(
    program: &Path,
    text: &str,
    policy: HistoryPolicy,
) -> Result<(), ClipboardError> {
    check_text_len(text.len())?;

    let mut child = worker_command(program, policy)
        .spawn()
        .map_err(|error| os_error(ClipboardStep::Spawn, &error))?;

    if let Err(error) = send_text(&mut child, text) {
        // 書き込みの途中で入力を閉じると、ワーカーは途中までの内容をコピーしてしまう。
        // 入力を閉じる前にワーカーを終了させる。ワーカーが既に終了している場合の失敗は無視する。
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = receive_status(&mut child);
    if status.is_err() {
        // コピーに失敗したワーカーは直ちに終了する。回収して、子プロセスを残さない。
        let _ = child.wait();
    } else {
        // 消去まで動き続けるワーカーは、終了した後に `reap_finished_workers` で回収する。
        running_workers().push(child);
    }
    status
}

/// コピーに成功し、まだ回収していないワーカー。
static RUNNING_WORKERS: Mutex<Vec<Child>> = Mutex::new(Vec::new());

fn running_workers() -> MutexGuard<'static, Vec<Child>> {
    // 一覧への追加と削除の途中で中断する状態は無いため、ポイズンされていても使える。
    RUNNING_WORKERS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// 終了したワーカーを回収する。実行中のワーカーは待たずに残す。
///
/// 長く動く親 (対話モード) が、回収されない子プロセス (ゾンビ) を残さないために呼ぶ。
pub fn reap_finished_workers() {
    // 状態を確認できないワーカーは、回収の対象から外す。
    running_workers().retain_mut(|worker| matches!(worker.try_wait(), Ok(None)));
}

/// ワーカーを起動するコマンドを組み立てる。
///
/// 標準入力と標準出力は親とつなぎ、標準エラー出力は捨てる。
/// 新しいプロセスグループで起動し、カレントディレクトリは `/` にする。
fn worker_command(program: &Path, policy: HistoryPolicy) -> Command {
    let mut command = Command::new(program);
    command.arg(WORKER_SUBCOMMAND);
    if policy == HistoryPolicy::Exclude {
        command.arg(format!("--{EXCLUDE_FROM_HISTORY_FLAG}"));
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .current_dir("/")
        .process_group(0);
    command
}

/// ワーカーの標準入力へ秘密を書き、全量を書き終えた場合に限り閉じる。
///
/// 失敗した場合は入力を `child` に残す。呼び出し側は、ワーカーを終了させてから入力を閉じる。
fn send_text(child: &mut Child, text: &str) -> Result<(), ClipboardError> {
    let input = child.stdin.as_mut().ok_or(ClipboardError::Os {
        step: ClipboardStep::SendText,
        errno: 0,
    })?;
    input
        .write_all(text.as_bytes())
        .and_then(|()| input.flush())
        .map_err(|error| os_error(ClipboardStep::SendText, &error))?;
    // 書き込み側を閉じて、ワーカーに入力の終端を伝える。
    drop(child.stdin.take());
    Ok(())
}

/// ワーカーの標準出力から 1 バイトの応答を読み、コピーの結果に変換する。
fn receive_status(child: &mut Child) -> Result<(), ClipboardError> {
    let mut output = child.stdout.take().ok_or(ClipboardError::Os {
        step: ClipboardStep::ReceiveStatus,
        errno: 0,
    })?;
    let mut status = [0u8; 1];
    loop {
        match output.read(&mut status) {
            Ok(0) => return WorkerStatus::decode(None),
            Ok(_) => return WorkerStatus::decode(Some(status[0])),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(os_error(ClipboardStep::ReceiveStatus, &error)),
        }
    }
}

/// ワーカーの本体。隠しサブコマンド [`WORKER_SUBCOMMAND`] から呼ばれる。
///
/// 標準入力から秘密を読み込んでクリップボードへコピーし、成否を `status` に 1 バイトで書く。
/// コピーに成功した場合は、[`CLEAR_DELAY`] の間 (中断のシグナルを受けた場合はその時点まで) 待ち、
/// クリップボードの内容がコピーした秘密と一致すれば消去してから戻る。
///
/// # Args
///
/// - `policy`: クリップボードの履歴からの除外の扱い。
/// - `status`: 応答の書き込み先 (親とつながる標準出力)。書き込みの失敗は無視する。
///
/// # Errors
///
/// - 標準入力が端末の場合と、内容が空・上限超過・UTF-8 でない場合は [`ClipboardError::InvalidInput`] など。
/// - バッファの `mlock` に失敗した場合は [`ClipboardError::MemoryLockFailed`]。
/// - クリップボードに接続できない場合は [`ClipboardError::Unavailable`]、
///   書き込みに失敗した場合は [`ClipboardError::CopyFailed`]、消去に失敗した場合は [`ClipboardError::ClearFailed`]。
pub fn run_worker(policy: HistoryPolicy, status: &mut impl Write) -> Result<(), ClipboardError> {
    // 秘密を読み込む前に捕捉を始め、待機中のシグナルで消去の前に終了しないようにする。
    let watcher = match InterruptWatcher::install() {
        Ok(watcher) => watcher,
        Err(_) => {
            report_status(status, WorkerStatus::SetupFailed);
            return Err(ClipboardError::WorkerFailed);
        }
    };
    let mut input = match worker_input() {
        Ok(input) => input,
        Err(error) => {
            report_status(status, WorkerStatus::from_error(error));
            return Err(error);
        }
    };
    serve(
        SystemClipboard::open,
        &mut input,
        status,
        policy,
        CLEAR_DELAY,
        &|| watcher.is_interrupted(),
    )
}

/// ワーカーの標準入力を、バッファを介さずに読むためのファイルとして返す。
///
/// `std::io::stdin()` は内部のバッファに読み込んだ内容を消去しないため使わない。
fn worker_input() -> Result<File, ClipboardError> {
    let standard_input = io::stdin();
    // 利用者が端末から直接起動した場合に、エコーされる入力を秘密として扱わない。
    if standard_input.is_terminal() {
        return Err(ClipboardError::InvalidInput);
    }
    let descriptor = standard_input
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| os_error(ClipboardStep::ReadInput, &error))?;
    Ok(File::from(descriptor))
}

/// クリップボードの操作。テストで差し替えるために分けている。
trait ClipboardBackend {
    /// `text` をクリップボードへ書き込む。
    fn set_text(&mut self, text: &str, policy: HistoryPolicy) -> Result<(), ClipboardError>;

    /// クリップボードの現在の内容が `expected` と一致するかを、定数時間で比較する。
    ///
    /// 内容を読めない場合 (空、テキスト以外) は一致しないとみなす。
    fn content_matches(&mut self, expected: &[u8]) -> bool;

    /// クリップボードを消去する。
    fn clear(&mut self) -> Result<(), ClipboardError>;
}

/// `arboard` によるクリップボードの操作。
struct SystemClipboard {
    clipboard: arboard::Clipboard,
}

impl SystemClipboard {
    /// クリップボードに接続する。
    fn open() -> Result<Self, ClipboardError> {
        arboard::Clipboard::new()
            .map(|clipboard| Self { clipboard })
            .map_err(|_| ClipboardError::Unavailable)
    }
}

impl ClipboardBackend for SystemClipboard {
    fn set_text(&mut self, text: &str, policy: HistoryPolicy) -> Result<(), ClipboardError> {
        let request = self.clipboard.set();
        let request = match policy {
            HistoryPolicy::Exclude => request.exclude_from_history(),
            HistoryPolicy::Allow => request,
        };
        request.text(text).map_err(|_| ClipboardError::CopyFailed)
    }

    fn content_matches(&mut self, expected: &[u8]) -> bool {
        match self.clipboard.get_text() {
            Ok(current) => compare_and_erase(current, expected),
            Err(_) => false,
        }
    }

    fn clear(&mut self) -> Result<(), ClipboardError> {
        self.clipboard
            .clear()
            .map_err(|_| ClipboardError::ClearFailed)
    }
}

/// クリップボードから読み取った `current` が `expected` と一致するかを定数時間で比較し、`current` を消去する。
///
/// `current` はコピーした秘密か利用者の内容のため、解放の前に消去する。
fn compare_and_erase(current: String, expected: &[u8]) -> bool {
    let mut current = current.into_bytes();
    let matches = ct_eq_bytes_bool(&current, expected);
    volatile_zeroize(&mut current);
    matches
}

/// ワーカーが読み込んだ秘密。`mlock` したページに保持し、破棄時に消去する。
struct ClipboardText {
    buffer: LockedBuffer<INPUT_CAPACITY>,
    len: usize,
}

impl ClipboardText {
    /// 秘密のバイト列を返す。
    fn as_bytes(&self) -> &[u8] {
        // `len` は容量以下に保つため、`None` にはならない。
        self.buffer.as_slice().get(..self.len).unwrap_or_default()
    }
}

/// ワーカーの処理の流れ (読み込み、コピー、応答、待機、消去)。
///
/// # Args
///
/// - `open`: クリップボードに接続する関数。
/// - `input`: 秘密の読み込み元。
/// - `status`: 応答の書き込み先。
/// - `policy`: 履歴からの除外の扱い。
/// - `clear_after`: コピーから消去までの時間。
/// - `is_interrupted`: 中断のシグナルを受けたかを返す関数。
fn serve<B: ClipboardBackend>(
    open: impl FnOnce() -> Result<B, ClipboardError>,
    input: &mut impl Read,
    status: &mut impl Write,
    policy: HistoryPolicy,
    clear_after: Duration,
    is_interrupted: &dyn Fn() -> bool,
) -> Result<(), ClipboardError> {
    let copied = read_text(input).and_then(|text| {
        let content =
            core::str::from_utf8(text.as_bytes()).map_err(|_| ClipboardError::InvalidInput)?;
        let mut backend = open()?;
        backend.set_text(content, policy)?;
        Ok((backend, text))
    });
    let (mut backend, text) = match copied {
        Ok(copied) => copied,
        Err(error) => {
            report_status(status, WorkerStatus::from_error(error));
            return Err(error);
        }
    };
    let deadline = Instant::now().checked_add(clear_after);
    // 親が既に終了していても、消去は行う。
    report_status(status, WorkerStatus::Copied);

    wait_until(deadline, is_interrupted);
    if backend.content_matches(text.as_bytes()) {
        backend.clear()?;
    }
    Ok(())
}

/// 期限まで、または中断のシグナルを受けるまで待つ。
///
/// 期限が表現できない (`None`) 場合は、中断のシグナルを受けるまで待つ。
fn wait_until(deadline: Option<Instant>, is_interrupted: &dyn Fn() -> bool) {
    while !is_interrupted() {
        let remaining = match deadline {
            Some(deadline) => deadline.saturating_duration_since(Instant::now()),
            None => POLL_INTERVAL,
        };
        if remaining.is_zero() {
            return;
        }
        std::thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

/// 入力の終端まで、秘密を `mlock` したバッファへ読み込む。
///
/// # Errors
///
/// バッファの確保に失敗した場合は [`ClipboardError::MemoryLockFailed`]、
/// 読み込みに失敗した場合は [`ClipboardError::Os`]、長さが不正な場合は [`check_text_len`] のエラー。
fn read_text(input: &mut impl Read) -> Result<ClipboardText, ClipboardError> {
    // 失敗した場合も含めて、バッファは破棄時に全体を消去する。
    let mut buffer = LockedBuffer::<INPUT_CAPACITY>::zero_strict()
        .map_err(|_| ClipboardError::MemoryLockFailed)?;
    let mut len = 0usize;
    while let Some(rest) = buffer
        .as_mut_slice()
        .get_mut(len..)
        .filter(|rest| !rest.is_empty())
    {
        match input.read(rest) {
            Ok(0) => break,
            Ok(count) => len = len.saturating_add(count).min(INPUT_CAPACITY),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(os_error(ClipboardStep::ReadInput, &error)),
        }
    }
    check_text_len(len)?;
    Ok(ClipboardText { buffer, len })
}

/// コピーする内容の長さを検査する。
fn check_text_len(len: usize) -> Result<(), ClipboardError> {
    match len {
        0 => Err(ClipboardError::Empty),
        len if len > MAX_TEXT_LEN => Err(ClipboardError::TooLong),
        _ => Ok(()),
    }
}

/// 応答を 1 バイトで書く。親が既に終了している場合などの失敗は無視する。
fn report_status(status: &mut impl Write, value: WorkerStatus) {
    let _ = status
        .write_all(&[value as u8])
        .and_then(|()| status.flush());
}

/// `io::Error` を、段階と `errno` を持つ [`ClipboardError::Os`] に変換する。
fn os_error(step: ClipboardStep, error: &io::Error) -> ClipboardError {
    ClipboardError::Os {
        step,
        errno: error.raw_os_error().unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::io::{self, Cursor, Read};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use super::{
        ClipboardBackend, ClipboardError, ClipboardStep, HISTORY_WARNING, HistoryPolicy,
        MAX_TEXT_LEN, WorkerStatus, check_text_len, compare_and_erase, read_text, send_text, serve,
        worker_command,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// 操作の記録を共有する、テスト用のクリップボード。
    #[derive(Default)]
    struct FakeState {
        content: Vec<u8>,
        policy: Option<HistoryPolicy>,
        cleared: bool,
        fail_set: bool,
        fail_clear: bool,
    }

    struct FakeClipboard {
        state: Rc<std::cell::RefCell<FakeState>>,
        /// 待機中に利用者が別の内容をコピーしたことを模す。比較の直前に内容を置き換える。
        replace_before_check: Option<Vec<u8>>,
    }

    impl ClipboardBackend for FakeClipboard {
        fn set_text(&mut self, text: &str, policy: HistoryPolicy) -> Result<(), ClipboardError> {
            let mut state = self.state.borrow_mut();
            if state.fail_set {
                return Err(ClipboardError::CopyFailed);
            }
            state.content = text.as_bytes().to_vec();
            state.policy = Some(policy);
            Ok(())
        }

        fn content_matches(&mut self, expected: &[u8]) -> bool {
            let mut state = self.state.borrow_mut();
            if let Some(replacement) = self.replace_before_check.take() {
                state.content = replacement;
            }
            state.content == expected
        }

        fn clear(&mut self) -> Result<(), ClipboardError> {
            let mut state = self.state.borrow_mut();
            if state.fail_clear {
                return Err(ClipboardError::ClearFailed);
            }
            state.content.clear();
            state.cleared = true;
            Ok(())
        }
    }

    /// テスト用のクリップボードでワーカーの処理を実行し、応答のバイト列と結果を返す。
    fn run_serve(
        input: &[u8],
        state: &Rc<std::cell::RefCell<FakeState>>,
        replace_before_check: Option<Vec<u8>>,
        clear_after: Duration,
        is_interrupted: &dyn Fn() -> bool,
    ) -> (Vec<u8>, Result<(), ClipboardError>) {
        let mut status = Vec::new();
        let backend = FakeClipboard {
            state: Rc::clone(state),
            replace_before_check,
        };
        let result = serve(
            move || Ok(backend),
            &mut Cursor::new(input.to_vec()),
            &mut status,
            HistoryPolicy::Exclude,
            clear_after,
            is_interrupted,
        );
        (status, result)
    }

    #[test]
    fn test_unchanged_content_is_cleared_after_delay() {
        let state = Rc::default();
        let started = Instant::now();
        let (status, result) =
            run_serve(b"s3cret", &state, None, Duration::from_millis(50), &|| {
                false
            });
        assert_eq!(result, Ok(()));
        assert_eq!(status, [WorkerStatus::Copied as u8]);
        assert!(started.elapsed() >= Duration::from_millis(50));
        let state = state.borrow();
        assert!(state.cleared, "一致する内容の消去に失敗。");
        assert!(state.content.is_empty());
        assert_eq!(state.policy, Some(HistoryPolicy::Exclude));
    }

    #[test]
    fn test_replaced_content_is_not_cleared() {
        let state = Rc::default();
        let (status, result) = run_serve(
            b"s3cret",
            &state,
            Some(b"user copied this".to_vec()),
            Duration::ZERO,
            &|| false,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(status, [WorkerStatus::Copied as u8]);
        let state = state.borrow();
        assert!(
            !state.cleared,
            "置き換えられた内容を消去しないことの確認に失敗。"
        );
        assert_eq!(state.content, b"user copied this");
    }

    #[test]
    fn test_interrupt_shortens_wait_and_still_clears() {
        let state = Rc::default();
        let started = Instant::now();
        let checks = Cell::new(0u32);
        // 2 回目の確認で中断を受けたことにする。
        let interrupted = || {
            checks.set(checks.get() + 1);
            checks.get() >= 2
        };
        let (status, result) = run_serve(
            b"s3cret",
            &state,
            None,
            Duration::from_secs(30),
            &interrupted,
        );
        assert_eq!(result, Ok(()));
        assert_eq!(status, [WorkerStatus::Copied as u8]);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "中断による待機の切り上げに失敗。"
        );
        assert!(state.borrow().cleared);
    }

    #[test]
    fn test_copy_failure_is_reported_without_waiting() {
        let state: Rc<std::cell::RefCell<FakeState>> = Rc::default();
        state.borrow_mut().fail_set = true;
        let started = Instant::now();
        let (status, result) =
            run_serve(b"s3cret", &state, None, Duration::from_secs(30), &|| false);
        assert_eq!(result, Err(ClipboardError::CopyFailed));
        assert_eq!(status, [WorkerStatus::CopyFailed as u8]);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_clear_failure_is_returned_after_copy_status() {
        let state: Rc<std::cell::RefCell<FakeState>> = Rc::default();
        state.borrow_mut().fail_clear = true;
        let (status, result) = run_serve(b"s3cret", &state, None, Duration::ZERO, &|| false);
        assert_eq!(result, Err(ClipboardError::ClearFailed));
        // コピーの成否は、消去の前に親へ返し終えている。
        assert_eq!(status, [WorkerStatus::Copied as u8]);
    }

    #[test]
    fn test_compare_and_erase_matches_only_identical_content() {
        assert!(compare_and_erase("s3cret".to_owned(), b"s3cret"));
        for current in ["", "s3cre", "s3cret ", "S3cret", "user copied this"] {
            assert!(
                !compare_and_erase(current.to_owned(), b"s3cret"),
                "{current:?} を不一致とすることの確認に失敗。"
            );
        }
    }

    #[test]
    fn test_unavailable_clipboard_is_reported() {
        let mut status = Vec::new();
        let result = serve(
            || Err::<FakeClipboard, _>(ClipboardError::Unavailable),
            &mut Cursor::new(b"s3cret".to_vec()),
            &mut status,
            HistoryPolicy::Allow,
            Duration::from_secs(30),
            &|| false,
        );
        assert_eq!(result, Err(ClipboardError::Unavailable));
        assert_eq!(status, [WorkerStatus::Unavailable as u8]);
    }

    #[test]
    fn test_invalid_input_is_rejected_before_opening_clipboard() {
        for input in [&b""[..], &[0xff, 0xfe][..], &[b'a'; MAX_TEXT_LEN + 1][..]] {
            let mut status = Vec::new();
            let opened = Cell::new(false);
            let result = serve(
                || {
                    opened.set(true);
                    Err::<FakeClipboard, _>(ClipboardError::Unavailable)
                },
                &mut Cursor::new(input.to_vec()),
                &mut status,
                HistoryPolicy::Exclude,
                Duration::ZERO,
                &|| false,
            );
            assert!(result.is_err(), "長さ {} の入力の拒否に失敗。", input.len());
            assert_eq!(status, [WorkerStatus::InvalidInput as u8]);
            assert!(
                !opened.get(),
                "不正な入力でクリップボードに接続しないことの確認に失敗。"
            );
        }
    }

    /// 少しずつ返し、途中で `EINTR` を挟む読み込み元。
    struct ChunkedReader {
        data: Vec<u8>,
        position: usize,
        interrupted_once: bool,
    }

    impl Read for ChunkedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted_once {
                self.interrupted_once = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let rest = self.data.get(self.position..).unwrap_or_default();
            let count = rest.len().min(buffer.len()).min(3);
            buffer[..count].copy_from_slice(&rest[..count]);
            self.position += count;
            Ok(count)
        }
    }

    #[test]
    fn test_read_text_handles_short_reads_and_eintr() -> TestResult {
        let mut reader = ChunkedReader {
            data: b"correct horse battery staple".to_vec(),
            position: 0,
            interrupted_once: false,
        };
        let text = read_text(&mut reader)?;
        assert_eq!(text.as_bytes(), b"correct horse battery staple");
        Ok(())
    }

    #[test]
    fn test_read_text_accepts_limit_and_rejects_beyond() -> TestResult {
        let text = read_text(&mut Cursor::new(vec![b'a'; MAX_TEXT_LEN]))?;
        assert_eq!(text.as_bytes().len(), MAX_TEXT_LEN);
        assert_eq!(
            read_text(&mut Cursor::new(vec![b'a'; MAX_TEXT_LEN * 2])).err(),
            Some(ClipboardError::TooLong)
        );
        Ok(())
    }

    #[test]
    fn test_read_text_reports_io_error_with_errno() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(5))
            }
        }
        assert_eq!(
            read_text(&mut FailingReader).err(),
            Some(ClipboardError::Os {
                step: ClipboardStep::ReadInput,
                errno: 5
            })
        );
    }

    /// 書き込みに失敗した場合は、呼び出し側がワーカーを終了させるまで入力を閉じない。
    #[test]
    fn test_failed_send_keeps_input_open_until_worker_is_stopped() -> TestResult {
        // 標準入力を閉じてから合図を返し、生き続けるプロセス。書き込みは必ず失敗する。
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exec 0<&-; echo ready; exec sleep 10"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let mut ready = [0u8; 1];
        child
            .stdout
            .as_mut()
            .ok_or("標準出力の取得に失敗。")?
            .read_exact(&mut ready)?;

        let result = send_text(&mut child, "s3cret");
        let input_is_open = child.stdin.is_some();
        child.kill()?;
        child.wait()?;

        assert!(
            matches!(
                result,
                Err(ClipboardError::Os {
                    step: ClipboardStep::SendText,
                    ..
                })
            ),
            "書き込みの失敗の検出に失敗: {result:?}"
        );
        assert!(
            input_is_open,
            "失敗後に入力を開いたまま残すことの確認に失敗。"
        );
        Ok(())
    }

    #[test]
    fn test_worker_command_passes_history_policy() {
        let program = Path::new("/usr/local/bin/fidelogic-cli");
        let concealed = worker_command(program, HistoryPolicy::Exclude);
        assert_eq!(concealed.get_program(), program.as_os_str());
        assert_eq!(
            concealed.get_args().collect::<Vec<_>>(),
            ["__clipboard-worker", "--exclude-from-history"]
        );
        assert_eq!(concealed.get_current_dir(), Some(Path::new("/")));

        let plain = worker_command(program, HistoryPolicy::Allow);
        assert_eq!(plain.get_args().collect::<Vec<_>>(), ["__clipboard-worker"]);
    }

    #[test]
    fn test_check_text_len_bounds() {
        assert_eq!(check_text_len(0), Err(ClipboardError::Empty));
        assert_eq!(check_text_len(1), Ok(()));
        assert_eq!(check_text_len(MAX_TEXT_LEN), Ok(()));
        assert_eq!(
            check_text_len(MAX_TEXT_LEN + 1),
            Err(ClipboardError::TooLong)
        );
    }

    #[test]
    fn test_status_roundtrip_and_unknown_values() {
        let errors = [
            ClipboardError::InvalidInput,
            ClipboardError::MemoryLockFailed,
            ClipboardError::Unavailable,
            ClipboardError::CopyFailed,
        ];
        for error in errors {
            let byte = WorkerStatus::from_error(error) as u8;
            assert_eq!(
                WorkerStatus::decode(Some(byte)),
                Err(error),
                "{error:?} の応答の往復に失敗。"
            );
        }
        assert_eq!(
            WorkerStatus::decode(Some(WorkerStatus::Copied as u8)),
            Ok(())
        );
        for byte in [
            None,
            Some(0),
            Some(WorkerStatus::SetupFailed as u8),
            Some(0xff),
        ] {
            assert_eq!(
                WorkerStatus::decode(byte),
                Err(ClipboardError::WorkerFailed)
            );
        }
    }

    #[test]
    fn test_messages_end_with_japanese_period() {
        let errors = [
            ClipboardError::Empty,
            ClipboardError::TooLong,
            ClipboardError::InvalidInput,
            ClipboardError::MemoryLockFailed,
            ClipboardError::Unavailable,
            ClipboardError::CopyFailed,
            ClipboardError::ClearFailed,
            ClipboardError::WorkerFailed,
            ClipboardError::Os {
                step: ClipboardStep::LocateExecutable,
                errno: 2,
            },
            ClipboardError::Os {
                step: ClipboardStep::Spawn,
                errno: 2,
            },
            ClipboardError::Os {
                step: ClipboardStep::SendText,
                errno: 32,
            },
            ClipboardError::Os {
                step: ClipboardStep::ReceiveStatus,
                errno: 5,
            },
            ClipboardError::Os {
                step: ClipboardStep::ReadInput,
                errno: 5,
            },
        ];
        for error in errors {
            let message = error.to_string();
            assert!(
                message.ends_with('。'),
                "{error:?} の文末の確認に失敗: {message}"
            );
        }
        assert!(HISTORY_WARNING.ends_with('。'));
    }
}
