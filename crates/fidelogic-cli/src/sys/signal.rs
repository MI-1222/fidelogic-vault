//! # 中断シグナルの捕捉 (`sys::signal`)
//!
//! 秘密を保持している間にシグナルを受けると、既定の動作ではプロセスが即座に終了し、
//! 端末の属性が戻らず、秘密の消去 (`Drop`) も実行されない。
//! [`InterruptWatcher`] は、中断のシグナルを記録するだけに置き換え、通常の経路で後始末できるようにする。
//!
//! ## 対象のシグナル
//!
//! | シグナル | 主な発生の契機 |
//! | :-- | :-- |
//! | `SIGINT` | `Ctrl+C` |
//! | `SIGTERM` | `kill` などによる終了の要求 |
//! | `SIGHUP` | 端末の切断 |
//! | `SIGQUIT` | `Ctrl+\` |
//!
//! 呼び出し元がシグナルを無視する設定 (`nohup` など) で起動した場合は、そのシグナルを置き換えず、無視したままにする。
//! `SIGKILL` は捕捉できない。`SIGTSTP` (`Ctrl+Z`) などの停止のシグナルは扱わない。
//!
//! ## 使い方
//!
//! 秘密を扱う処理の前に [`InterruptWatcher::install`] を呼び、秘密を破棄し終えるまで値を保持する。
//! 保持している間は、対象のシグナルでプロセスが終了しない。
//! 時間のかかる処理の区切りと、処理の最後に [`InterruptWatcher::is_interrupted`] を確認し、
//! 中断されていたら秘密を破棄して終了する。
//!
//! ## 取りこぼしの防止
//!
//! シグナルハンドラーは、フラグを立てて、起床用のパイプに 1 バイトを書くだけである。
//! 入出力の待機は、対象の記述子とパイプの両方を `select` で監視する。
//! このため、フラグの確認と待機の開始の間にシグナルを受けても、待ち続けることはない。
//! `SA_RESTART` を指定しないため、シグナルを処理したスレッドのシステムコールの待機は `EINTR` で中断される。
//! 別のスレッドが処理した場合は中断されないため、中断に対応する入出力は、非ブロッキングの記述子と `select` で待つ。
//!
//! ## OS ごとの差
//!
//! | 処理 | POSIX | Windows (未対応) |
//! | :-- | :-- | :-- |
//! | 中断の捕捉 | `sigaction` | `SetConsoleCtrlHandler` |
//! | 入出力と中断の待機 | `select` と起床用のパイプ。macOS の `poll` は `/dev/tty` を扱えないため使わない | `WaitForMultipleObjects` |

#![allow(unsafe_code)]

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::io;
use std::os::fd::RawFd;
use std::sync::Mutex;

/// 中断として扱うシグナル。
const WATCHED_SIGNALS: [libc::c_int; 4] =
    [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT];

/// 中断のシグナルを受けたことを示すフラグ。
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// [`InterruptWatcher`] が存在することを示すフラグ。
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// 起床用のパイプの書き込み側。未作成の場合は -1。シグナルハンドラーから参照する。
static WAKE_WRITER: AtomicI32 = AtomicI32::new(-1);

/// 起床用のパイプ。プロセスで 1 度だけ作成し、閉じない。
///
/// 閉じると、別のスレッドで実行中のシグナルハンドラーが、再利用された記述子へ書き込む恐れがある。
static WAKE_PIPE: Mutex<Option<WakePipe>> = Mutex::new(None);

/// 起床用のパイプの記述子。
#[derive(Debug, Clone, Copy)]
struct WakePipe {
    reader: RawFd,
    writer: RawFd,
}

/// 中断の捕捉の開始に失敗したことを表すエラー。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalError {
    /// すでに [`InterruptWatcher`] が存在する。
    AlreadyActive,
    /// OS の API の呼び出しが失敗した。
    Os {
        /// OS が返したエラー番号。取得できなかった場合は 0。
        errno: i32,
    },
}

impl SignalError {
    /// 直前に失敗した OS の API のエラー番号を持つ値を作る。
    fn last_os() -> Self {
        Self::Os {
            errno: io::Error::last_os_error().raw_os_error().unwrap_or(0),
        }
    }
}

impl fmt::Display for SignalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyActive => formatter.write_str("中断の捕捉はすでに開始しています。"),
            Self::Os { errno } => {
                write!(
                    formatter,
                    "中断の捕捉の開始に失敗しました (errno: {errno})。"
                )
            }
        }
    }
}

impl std::error::Error for SignalError {}

/// 待つ記述子の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Interest {
    /// 読み込める状態。
    Readable,
    /// 書き込める状態。
    Writable,
}

/// 待機を終えた理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Wakeup {
    /// 記述子が、待っていた状態になった。
    Ready,
    /// 中断のシグナルを受けた。
    Interrupted,
}

/// 中断のシグナルを捕捉している間だけ存在する値。
///
/// プロセス全体で同時に 1 つだけ作成できる。破棄すると、シグナルの扱いを作成前の状態に戻す。
#[must_use = "値を破棄すると、直ちに中断の捕捉を終える。"]
pub struct InterruptWatcher {
    /// 起床用のパイプの読み込み側。
    wake_reader: RawFd,
    /// 置き換える前の設定。置き換えていないシグナルは `None`。
    previous: [Option<libc::sigaction>; WATCHED_SIGNALS.len()],
}

impl fmt::Debug for InterruptWatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InterruptWatcher")
            .field("interrupted", &self.is_interrupted())
            .finish_non_exhaustive()
    }
}

impl InterruptWatcher {
    /// 中断のシグナルの捕捉を開始する。
    ///
    /// 以前の [`InterruptWatcher`] が記録した中断は引き継がない。
    ///
    /// # Errors
    ///
    /// - すでに値が存在する場合は [`SignalError::AlreadyActive`]。
    /// - パイプの作成やシグナルハンドラーの登録に失敗した場合は [`SignalError::Os`]。
    ///   このとき、シグナルの扱いは呼び出し前の状態のままである。
    pub fn install() -> Result<Self, SignalError> {
        if ACTIVE.swap(true, Ordering::SeqCst) {
            return Err(SignalError::AlreadyActive);
        }
        // 以降の失敗では、この値の `Drop` が登録済みのハンドラーを戻し、`ACTIVE` を下ろす。
        let mut watcher = Self {
            wake_reader: -1,
            previous: [None; WATCHED_SIGNALS.len()],
        };
        let pipe = wake_pipe()?;
        watcher.wake_reader = pipe.reader;
        drain(pipe.reader);
        INTERRUPTED.store(false, Ordering::SeqCst);

        for (signal, slot) in WATCHED_SIGNALS.iter().zip(watcher.previous.iter_mut()) {
            *slot = replace_handler(*signal)?;
        }
        Ok(watcher)
    }

    /// 捕捉を開始してから、中断のシグナルを受けたかを返す。
    #[must_use]
    pub fn is_interrupted(&self) -> bool {
        INTERRUPTED.load(Ordering::SeqCst)
    }

    /// `descriptor` が `interest` の状態になるか、中断のシグナルを受けるまで待つ。
    ///
    /// 中断を先に確認するため、両方が成立している場合は [`Wakeup::Interrupted`] を返す。
    ///
    /// # Errors
    ///
    /// `descriptor` が `select` で扱える範囲 (0 以上 `FD_SETSIZE` 未満) に無い場合と、
    /// `select` が `EINTR` 以外の理由で失敗した場合。
    pub(super) fn wait(&self, descriptor: RawFd, interest: Interest) -> io::Result<Wakeup> {
        if !is_selectable(descriptor) || !is_selectable(self.wake_reader) {
            return Err(io::Error::from_raw_os_error(libc::EBADF));
        }
        loop {
            if self.is_interrupted() {
                return Ok(Wakeup::Interrupted);
            }
            // SAFETY: `fd_set` は整数の配列だけを持ち、全ビット 0 は有効な値である。
            let mut readable: libc::fd_set = unsafe { core::mem::zeroed() };
            // SAFETY: 同上。
            let mut writable: libc::fd_set = unsafe { core::mem::zeroed() };
            let target = match interest {
                Interest::Readable => &mut readable,
                Interest::Writable => &mut writable,
            };
            // SAFETY: `target` は有効な `fd_set` である。
            // `descriptor` は、`is_selectable` により `FD_SETSIZE` 未満であることを確認している。
            unsafe {
                libc::FD_ZERO(target);
                libc::FD_SET(descriptor, target);
            }
            // SAFETY: `readable` は全ビット 0 か、上で記述子を加えた有効な集合である。
            // 起床用の記述子も、`FD_SETSIZE` 未満であることを確認している。
            unsafe { libc::FD_SET(self.wake_reader, &mut readable) };
            let limit = descriptor.max(self.wake_reader) + 1;
            // SAFETY: 2 つの集合は呼び出しの間生存し、例外の集合とタイムアウトには null を渡す。
            let ready = unsafe {
                libc::select(
                    limit,
                    &mut readable,
                    &mut writable,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                )
            };
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if self.is_interrupted() {
                return Ok(Wakeup::Interrupted);
            }
            // SAFETY: `readable` は `select` が更新した有効な集合で、記述子は範囲内である。
            if unsafe { libc::FD_ISSET(self.wake_reader, &readable) } {
                // フラグが立っていない起床は、以前の中断で残ったバイトである。読み捨てて待ち直す。
                drain(self.wake_reader);
                continue;
            }
            let target = match interest {
                Interest::Readable => &readable,
                Interest::Writable => &writable,
            };
            // SAFETY: 同上。
            if unsafe { libc::FD_ISSET(descriptor, target) } {
                return Ok(Wakeup::Ready);
            }
        }
    }
}

impl Drop for InterruptWatcher {
    fn drop(&mut self) {
        for (signal, previous) in WATCHED_SIGNALS.iter().zip(self.previous.iter()) {
            if let Some(action) = previous {
                // SAFETY: `action` は `sigaction` が返した値そのものである。第 3 引数には null を渡す。
                // 戻す処理の失敗は報告先が無いため、結果を無視する。
                let _ = unsafe { libc::sigaction(*signal, action, core::ptr::null_mut()) };
            }
        }
        ACTIVE.store(false, Ordering::SeqCst);
    }
}

/// `select` で監視できる記述子かを判定する。
pub(super) fn is_selectable(descriptor: RawFd) -> bool {
    usize::try_from(descriptor).is_ok_and(|value| value < libc::FD_SETSIZE)
}

/// 現在のスレッドの `errno` の格納先を返す。
#[cfg(target_vendor = "apple")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__error` は引数を取らず、現在のスレッドの `errno` を指す有効なポインターを返す。
    unsafe { libc::__error() }
}

/// 現在のスレッドの `errno` の格納先を返す。
#[cfg(not(target_vendor = "apple"))]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: `__errno_location` は引数を取らず、現在のスレッドの `errno` を指す有効なポインターを返す。
    unsafe { libc::__errno_location() }
}

/// 中断を記録するシグナルハンドラー。
///
/// 非同期シグナルセーフな操作 (アトミック変数の読み書きと `write`) だけを行う。
extern "C" fn record_interrupt(_signal: libc::c_int) {
    let errno = errno_location();
    // SAFETY: `errno` は現在のスレッドの `errno` を指す。割り込まれた処理のために、値を退避する。
    let saved = unsafe { *errno };
    INTERRUPTED.store(true, Ordering::SeqCst);
    let writer = WAKE_WRITER.load(Ordering::SeqCst);
    if writer >= 0 {
        let byte = 1u8;
        // SAFETY: `byte` は 1 バイトの有効な領域である。`writer` は閉じないパイプの非ブロッキングな書き込み側で、
        // パイプが満杯で失敗しても、読み込み側はすでに起床できる状態である。
        let _ = unsafe { libc::write(writer, core::ptr::from_ref(&byte).cast(), 1) };
    }
    // SAFETY: 同上。退避した値を戻す。
    unsafe { *errno = saved };
}

/// `signal` のハンドラーを [`record_interrupt`] に置き換える。
///
/// # Returns
///
/// 置き換える前の設定。無視する設定だった場合は置き換えず、`None` を返す。
fn replace_handler(signal: libc::c_int) -> Result<Option<libc::sigaction>, SignalError> {
    // SAFETY: `sigaction` 構造体は整数、シグナル集合、省略可能な関数ポインターだけを持ち、
    // 全ビット 0 は有効な値である。
    let mut previous: libc::sigaction = unsafe { core::mem::zeroed() };
    // SAFETY: 第 2 引数が null の場合は現在の設定を `previous` に書き込むだけである。
    if unsafe { libc::sigaction(signal, core::ptr::null(), &mut previous) } != 0 {
        return Err(SignalError::last_os());
    }
    if previous.sa_sigaction == libc::SIG_IGN {
        return Ok(None);
    }

    // SAFETY: 同上。
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    let handler: extern "C" fn(libc::c_int) = record_interrupt;
    action.sa_sigaction = handler as *const () as libc::sighandler_t;
    // `SA_RESTART` を指定せず、待機中のシステムコールを `EINTR` で中断させる。
    action.sa_flags = 0;
    // SAFETY: `action.sa_mask` は書き込み可能な有効なシグナル集合である。
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(SignalError::last_os());
    }
    // SAFETY: `action` は初期化済みで、ハンドラーは非同期シグナルセーフな操作だけを行う。
    if unsafe { libc::sigaction(signal, &action, core::ptr::null_mut()) } != 0 {
        return Err(SignalError::last_os());
    }
    Ok(Some(previous))
}

/// 起床用のパイプを返す。未作成の場合は作成する。
fn wake_pipe() -> Result<WakePipe, SignalError> {
    // 保持する値は `Copy` で、途中の状態を持たないため、ポイズンされていても使える。
    let mut stored = WAKE_PIPE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(pipe) = *stored {
        return Ok(pipe);
    }
    let pipe = create_wake_pipe()?;
    WAKE_WRITER.store(pipe.writer, Ordering::SeqCst);
    *stored = Some(pipe);
    Ok(pipe)
}

/// 両端が非ブロッキングで、`exec` で閉じる (`FD_CLOEXEC`) パイプを作成する。
///
/// macOS には `pipe2` が無いため、作成してから属性を設定する。
fn create_wake_pipe() -> Result<WakePipe, SignalError> {
    let mut descriptors: [libc::c_int; 2] = [-1, -1];
    // SAFETY: `descriptors` は 2 要素の書き込み可能な配列である。
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(SignalError::last_os());
    }
    let [reader, writer] = descriptors;
    for descriptor in [reader, writer] {
        // SAFETY: `fcntl` は整数引数だけを取り、直前に作成した記述子の属性を変更する。
        let configured = unsafe {
            libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && libc::fcntl(descriptor, libc::F_SETFL, libc::O_NONBLOCK) == 0
        };
        if !configured || !is_selectable(descriptor) {
            let error = SignalError::last_os();
            // SAFETY: どちらも直前に作成し、まだ他へ渡していない記述子である。
            unsafe {
                libc::close(reader);
                libc::close(writer);
            }
            return Err(error);
        }
    }
    Ok(WakePipe { reader, writer })
}

/// 起床用のパイプに残ったバイトを読み捨てる。
fn drain(reader: RawFd) {
    let mut sink = [0u8; 64];
    loop {
        // SAFETY: `sink` は指定した長さの書き込み可能な領域である。`reader` は非ブロッキングである。
        let read = unsafe { libc::read(reader, sink.as_mut_ptr().cast(), sink.len()) };
        if read <= 0 {
            return;
        }
    }
}
