//! # 端末と入力元からの読み込み (`sys::tty`)
//!
//! マスターパスワードなどの秘密を読み込むための、OS によって手順が異なる処理を置く。
//! 読み込んだ内容は解釈しない。行の編集と長さの検査は [`crate::secret_input`] が行う。
//!
//! ## 担う処理
//!
//! - 制御端末 ([`Terminal`])。標準入力ではなく `/dev/tty` を開き、エコーと行入力モードを止めて読み込む ([`HiddenInput`])。
//! - 非対話の入力元 ([`InputStream`])。引き継いだファイル記述子と、権限を検査したパスワードファイル。
//! - 入出力の中断。入力の読み込みと端末への書き込みは、[`InterruptWatcher`] と合わせて待機する。
//!
//! ## 行入力モードを止める理由
//!
//! 端末の行入力モード (`ICANON`) には、OS が定める 1 行の長さの上限がある。
//! macOS では、上限を超えた分が改行を含めて捨てられ、文字を消して改行すると、切り詰められた行がそのまま渡る。
//! パスワードが黙って切り詰められることを避けるため、1 バイトずつ読み込み、行の編集と上限の検査を CLI 側で行う。
//! 端末のシグナル生成 (`ISIG`) は有効にするため、`Ctrl+C` は `SIGINT` になる。
//!
//! ## 端末属性の復元
//!
//! [`HiddenInput`] は、破棄するときに属性を元に戻す。戻す前に、読み残した入力を捨てる。
//! 入力途中の秘密が、後続のシェルに渡らないようにするためである。
//! 対象のシグナルは [`InterruptWatcher`] が記録するだけにするため、中断した場合も通常の経路で復元する。
//! `SIGKILL` などでプロセスが終了した場合は復元できない。
//!
//! ## OS ごとの差
//!
//! | 処理 | POSIX | Windows (未対応) |
//! | :-- | :-- | :-- |
//! | 制御端末 | `/dev/tty` | `CONIN$` |
//! | エコーの停止と復元 | `termios` の `ECHO` と `ICANON` を `tcsetattr` で切り替える | `SetConsoleMode` で `ENABLE_ECHO_INPUT` と `ENABLE_LINE_INPUT` を外す |
//! | 引き継いだ入力元 | ファイル記述子の番号 | ハンドル |
//! | パスワードファイルの権限 | グループと他者の権限が無いことを検査する | ACL を検査する |

#![allow(unsafe_code)]

use core::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use super::signal::{Interest, InterruptWatcher, Wakeup, is_selectable};

/// 制御端末のパス。
const CONTROLLING_TERMINAL: &str = "/dev/tty";

/// パスワードファイルに許さない権限 (グループと他者の読み書き実行)。
const FORBIDDEN_PASSWORD_FILE_MODE: u32 = 0o077;

/// OS の API の呼び出しが失敗した手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyStep {
    /// 端末属性の取得。
    ReadAttributes,
    /// 端末属性の変更。
    WriteAttributes,
    /// 端末への書き込み。
    WriteTerminal,
    /// パスワードファイルを開く処理と、属性の確認。
    OpenPasswordFile,
    /// 引き継いだファイル記述子の確認。
    InspectDescriptor,
    /// 入力の読み込み。
    Read,
}

impl TtyStep {
    /// 手順の名称を日本語で返す。
    const fn label(self) -> &'static str {
        match self {
            Self::ReadAttributes => "端末属性の取得",
            Self::WriteAttributes => "端末属性の変更",
            Self::WriteTerminal => "端末への書き込み",
            Self::OpenPasswordFile => "パスワードファイルを開く処理",
            Self::InspectDescriptor => "ファイル記述子の確認",
            Self::Read => "入力の読み込み",
        }
    }
}

/// 端末と入力元の操作の失敗を表すエラー。
///
/// パスや秘密情報は含まない。`errno` は OS が返したエラー番号であり、診断のためだけに保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TtyError {
    /// 制御端末を開けない。
    NoTerminal {
        /// OS が返したエラー番号。取得できなかった場合は 0。
        errno: i32,
    },
    /// 端末属性を変更した後も、エコーまたは行入力モードが有効である。
    EchoNotDisabled,
    /// ファイル記述子の番号が、扱える範囲に無い。
    UnsupportedDescriptor,
    /// ファイル記述子が、呼び出し元から引き継いだものではない。
    DescriptorNotInherited,
    /// 非対話の入力元に、端末が指定された。
    DescriptorIsTerminal,
    /// パスワードファイルが通常のファイルではない。
    PasswordFileNotRegular,
    /// パスワードファイルに、グループまたは他者の権限がある。
    PasswordFilePermissions,
    /// OS の API の呼び出しが失敗した。
    Os {
        /// 失敗した手順。
        step: TtyStep,
        /// OS が返したエラー番号。取得できなかった場合は 0。
        errno: i32,
    },
}

impl TtyError {
    /// `std::io::Error` から、失敗した手順とエラー番号を取り出す。
    fn os(step: TtyStep, error: &io::Error) -> Self {
        Self::Os {
            step,
            errno: error.raw_os_error().unwrap_or(0),
        }
    }

    /// 直前に失敗した OS の API のエラー番号を持つ値を作る。
    fn last_os(step: TtyStep) -> Self {
        Self::os(step, &io::Error::last_os_error())
    }
}

impl fmt::Display for TtyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTerminal { errno } => write!(
                f,
                "端末を開けません (errno: {errno})。端末が無い環境では、`--password-stdin` などで入力してください。"
            ),
            Self::EchoNotDisabled => f.write_str("端末のエコーを無効にできませんでした。"),
            Self::UnsupportedDescriptor => {
                f.write_str("指定されたファイル記述子の番号は扱えません。")
            }
            Self::DescriptorNotInherited => f.write_str(
                "指定されたファイル記述子は、呼び出し元から引き継いだものではありません。",
            ),
            Self::DescriptorIsTerminal => f.write_str(
                "非対話の入力元に端末は指定できません。端末から入力する場合は、指定を省略してください。",
            ),
            Self::PasswordFileNotRegular => {
                f.write_str("パスワードファイルが通常のファイルではありません。")
            }
            Self::PasswordFilePermissions => f.write_str(
                "パスワードファイルにグループまたは他者の権限があります。権限を `0600` にしてください。",
            ),
            Self::Os { step, errno } => {
                write!(f, "{}に失敗しました (errno: {errno})。", step.label())
            }
        }
    }
}

impl std::error::Error for TtyError {}

/// 端末の行編集に使う制御文字。無効化されているキーは `None`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditKeys {
    /// 直前の 1 文字を消すキー (`VERASE`)。
    pub erase: Option<u8>,
    /// 行全体を消すキー (`VKILL`)。
    pub kill: Option<u8>,
    /// 入力の終わりを示すキー (`VEOF`)。
    pub end_of_input: Option<u8>,
}

/// 1 回の読み込みの結果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadOutcome {
    /// 読み込んだバイト数 (1 以上)。
    Data(usize),
    /// 入力の終端。端末の場合は切断である。
    EndOfInput,
    /// 中断のシグナルを受けた。読み込みは行っていない。
    Interrupted,
}

/// `descriptor` が読み込めるようになるまで待ち、1 回読み込む。
///
/// `buffer` は空でないこと。空の場合は [`ReadOutcome::EndOfInput`] になる。
fn read_descriptor(
    descriptor: RawFd,
    buffer: &mut [u8],
    watcher: &InterruptWatcher,
) -> Result<ReadOutcome, TtyError> {
    loop {
        let wakeup = watcher
            .wait(descriptor, Interest::Readable)
            .map_err(|error| TtyError::os(TtyStep::Read, &error))?;
        if wakeup == Wakeup::Interrupted {
            return Ok(ReadOutcome::Interrupted);
        }
        // 秘密を中間バッファに置かないよう、呼び出し側の領域へ直接読み込む。
        // SAFETY: `buffer` は `buffer.len()` バイトの書き込み可能な領域であり、呼び出しの間は生存している。
        let read = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
        match usize::try_from(read) {
            Ok(0) => return Ok(ReadOutcome::EndOfInput),
            Ok(count) => return Ok(ReadOutcome::Data(count)),
            Err(_) => {
                let error = io::Error::last_os_error();
                // 中断と、非ブロッキングの記述子で内容がまだ無い場合は、待機からやり直す。
                if !matches!(
                    error.kind(),
                    io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                ) {
                    return Err(TtyError::os(TtyStep::Read, &error));
                }
            }
        }
    }
}

/// 切断した端末の読み込みの失敗を、入力の終端にそろえる。
///
/// Linux では、切断の処理の途中で読み込むと、終端ではなく `EIO` になることがある。
/// 端末以外の入力元の `EIO` は、読み込みの失敗のまま返すため、この変換を適用しない。
fn end_of_input_on_hangup(result: Result<ReadOutcome, TtyError>) -> Result<ReadOutcome, TtyError> {
    match result {
        Err(TtyError::Os {
            step: TtyStep::Read,
            errno: libc::EIO,
        }) => Ok(ReadOutcome::EndOfInput),
        other => other,
    }
}

/// 非対話の入力元の持ち主。
#[derive(Debug)]
enum Source {
    /// 本プロセスが開いたファイル。破棄時に閉じる。
    Owned(File),
    /// 呼び出し元から引き継いだ記述子。閉じない。
    Inherited(RawFd),
}

/// 非対話の入力元。
#[derive(Debug)]
pub struct InputStream {
    source: Source,
}

impl InputStream {
    /// 呼び出し元から引き継いだファイル記述子を入力元にする。記述子は閉じない。
    ///
    /// `/proc/self/fd` などから開き直さず、番号のまま読み込む。
    ///
    /// # Errors
    ///
    /// - 番号が 0 以上 `FD_SETSIZE` 未満でない場合は [`TtyError::UnsupportedDescriptor`]。
    /// - 記述子が開いていない場合は [`TtyError::Os`]。
    /// - `FD_CLOEXEC` が設定されている場合は [`TtyError::DescriptorNotInherited`]。
    ///   `exec` をまたいで引き継いだ記述子には設定されていないため、本プロセスが内部で開いた記述子である。
    /// - 記述子が端末を指す場合は [`TtyError::DescriptorIsTerminal`]。そのまま読むと入力がエコーされるためである。
    pub fn inherited(descriptor: i32) -> Result<Self, TtyError> {
        if !is_selectable(descriptor) {
            return Err(TtyError::UnsupportedDescriptor);
        }
        // SAFETY: `F_GETFD` は整数引数だけを取り、記述子の属性を読み取る。無効な番号は `EBADF` になる。
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0 {
            return Err(TtyError::last_os(TtyStep::InspectDescriptor));
        }
        if flags & libc::FD_CLOEXEC != 0 {
            return Err(TtyError::DescriptorNotInherited);
        }
        // SAFETY: `isatty` は整数引数だけを取る。
        if unsafe { libc::isatty(descriptor) } == 1 {
            return Err(TtyError::DescriptorIsTerminal);
        }
        Ok(Self {
            source: Source::Inherited(descriptor),
        })
    }

    /// パスワードファイルを開く。シンボリックリンクは参照先を開く。
    ///
    /// 種別と権限は、開いた後の記述子に対して検査する。検査と読み込みの対象がずれないようにするためである。
    /// 権限はモードのビットだけを見る。macOS の拡張 ACL は検査しないため、ACL で他者に読み取りを許可したファイルも受け付ける。
    ///
    /// # Errors
    ///
    /// - 開けない場合と、属性を取得できない場合は [`TtyError::Os`]。
    /// - 通常のファイル以外 (ディレクトリ、FIFO など) の場合は [`TtyError::PasswordFileNotRegular`]。
    ///   FIFO は `O_NONBLOCK` で開くため、書き込み側を待たずに失敗する。
    /// - グループまたは他者の権限がある場合は [`TtyError::PasswordFilePermissions`]。
    pub fn password_file(path: &Path) -> Result<Self, TtyError> {
        let open_error = |error: io::Error| TtyError::os(TtyStep::OpenPasswordFile, &error);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
            .open(path)
            .map_err(open_error)?;
        let metadata = file.metadata().map_err(open_error)?;
        if !metadata.is_file() {
            return Err(TtyError::PasswordFileNotRegular);
        }
        if metadata.permissions().mode() & FORBIDDEN_PASSWORD_FILE_MODE != 0 {
            return Err(TtyError::PasswordFilePermissions);
        }
        Ok(Self {
            source: Source::Owned(file),
        })
    }

    /// 入力元が読み込めるようになるまで待ち、1 回読み込む。
    ///
    /// # Args
    ///
    /// - `buffer`: 読み込み先。空でないこと。
    ///
    /// # Errors
    ///
    /// 待機または読み込みに失敗した場合は [`TtyError::Os`]。
    pub fn read(
        &mut self,
        buffer: &mut [u8],
        watcher: &InterruptWatcher,
    ) -> Result<ReadOutcome, TtyError> {
        let descriptor = match &self.source {
            Source::Owned(file) => file.as_raw_fd(),
            Source::Inherited(descriptor) => *descriptor,
        };
        read_descriptor(descriptor, buffer, watcher)
    }
}

/// 制御端末。
#[derive(Debug)]
pub struct Terminal {
    device: File,
}

impl Terminal {
    /// 制御端末 `/dev/tty` を開く。標準入出力のリダイレクトの影響を受けない。
    ///
    /// 出力が停止した端末で書き込みが戻らなくならないよう、非ブロッキングで開く。
    /// 本プロセスが開いた記述子の設定であり、シェルなどが持つ端末の記述子には影響しない。
    ///
    /// # Errors
    ///
    /// 制御端末が無いなどの理由で開けない場合は [`TtyError::NoTerminal`]。
    pub fn open() -> Result<Self, TtyError> {
        let device = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(CONTROLLING_TERMINAL)
            .map_err(|error| TtyError::NoTerminal {
                errno: error.raw_os_error().unwrap_or(0),
            })?;
        Ok(Self { device })
    }

    /// 端末に `text` を書く。
    ///
    /// # Returns
    ///
    /// 書き終えた場合は `true`。書き終える前に中断のシグナルを受けた場合は `false`。
    ///
    /// # Errors
    ///
    /// 書き込みに失敗した場合は [`TtyError::Os`]。
    pub fn write(&self, text: &str, watcher: &InterruptWatcher) -> Result<bool, TtyError> {
        let write_error = |error: io::Error| TtyError::os(TtyStep::WriteTerminal, &error);
        let mut remaining = text.as_bytes();
        while !remaining.is_empty() {
            let wakeup = watcher
                .wait(self.device.as_raw_fd(), Interest::Writable)
                .map_err(write_error)?;
            if wakeup == Wakeup::Interrupted {
                return Ok(false);
            }
            match self.write_once(remaining) {
                Ok(written) => remaining = remaining.get(written..).unwrap_or_default(),
                // 中断と、空きがまだ無い場合は、待機からやり直す。
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(write_error(error)),
            }
        }
        Ok(true)
    }

    /// 端末で改行する。入力の後始末に使い、中断されていても 1 回だけ試みる。
    ///
    /// 待たずに戻るため、出力が停止した端末では改行されないことがある。
    /// 失敗しても入力の結果は変わらないため、結果を返さない。
    pub fn end_line(&self) {
        let _ = self.write_once(b"\n");
    }

    /// `write` を 1 回呼ぶ。`EINTR` を再試行しない。
    fn write_once(&self, bytes: &[u8]) -> io::Result<usize> {
        // SAFETY: `bytes` は `bytes.len()` バイトの読み取り可能な領域であり、呼び出しの間は生存している。
        let written =
            unsafe { libc::write(self.device.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        usize::try_from(written).map_err(|_| io::Error::last_os_error())
    }

    /// エコーと行入力モードを止める。読み残していた入力は捨てる。
    ///
    /// # Errors
    ///
    /// - 端末属性の取得や変更に失敗した場合は [`TtyError::Os`]。
    /// - 変更後もエコーまたは行入力モードが有効な場合は [`TtyError::EchoNotDisabled`]。
    ///
    /// いずれの場合も、端末属性は呼び出し前の状態に戻す。
    pub fn hide_input(&self) -> Result<HiddenInput<'_>, TtyError> {
        let descriptor = self.device.as_raw_fd();
        let original = read_attributes(descriptor)?;
        // 以降の失敗では、この値の `Drop` が属性を元に戻す。
        let hidden = HiddenInput {
            terminal: self,
            original,
            restored: false,
        };

        let mut silent = original;
        silent.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON);
        silent.c_lflag |= libc::ISIG;
        // 1 バイト届くまで待つ。
        silent.c_cc[libc::VMIN] = 1;
        silent.c_cc[libc::VTIME] = 0;
        apply_attributes(descriptor, &silent)?;

        // `tcsetattr` は、一部の変更だけに成功しても成功を返すため、読み戻して確認する。
        let applied = read_attributes(descriptor)?;
        if applied.c_lflag & (libc::ECHO | libc::ICANON) != 0 {
            return Err(TtyError::EchoNotDisabled);
        }
        Ok(hidden)
    }
}

/// エコーと行入力モードを止めている間だけ存在する値。破棄すると端末属性を元に戻す。
#[must_use = "値を破棄すると、直ちに端末属性を元に戻す。"]
pub struct HiddenInput<'a> {
    terminal: &'a Terminal,
    /// 変更前の端末属性。
    original: libc::termios,
    /// 元に戻し終えたか。
    restored: bool,
}

impl HiddenInput<'_> {
    /// 変更前の端末属性が定める、行編集のキーを返す。
    #[must_use]
    pub fn edit_keys(&self) -> EditKeys {
        let key = |index: usize| {
            self.original
                .c_cc
                .get(index)
                .copied()
                .filter(|&value| value != libc::_POSIX_VDISABLE)
        };
        EditKeys {
            erase: key(libc::VERASE),
            kill: key(libc::VKILL),
            end_of_input: key(libc::VEOF),
        }
    }

    /// 端末が読み込めるようになるまで待ち、1 回読み込む。
    ///
    /// 端末が切断された場合は [`ReadOutcome::EndOfInput`] を返す。
    ///
    /// # Args
    ///
    /// - `buffer`: 読み込み先。空でないこと。
    ///
    /// # Errors
    ///
    /// 待機または読み込みに失敗した場合は [`TtyError::Os`]。
    pub fn read(
        &mut self,
        buffer: &mut [u8],
        watcher: &InterruptWatcher,
    ) -> Result<ReadOutcome, TtyError> {
        end_of_input_on_hangup(read_descriptor(
            self.terminal.device.as_raw_fd(),
            buffer,
            watcher,
        ))
    }

    /// 読み残した入力を捨て、端末属性を元に戻す。
    ///
    /// # Errors
    ///
    /// 戻せなかった場合は [`TtyError::Os`]。このとき、値の破棄でもう一度試みる。
    pub fn restore(mut self) -> Result<(), TtyError> {
        self.restore_attributes()
    }

    fn restore_attributes(&mut self) -> Result<(), TtyError> {
        apply_attributes(self.terminal.device.as_raw_fd(), &self.original)?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for HiddenInput<'_> {
    fn drop(&mut self) {
        if !self.restored {
            // 失敗した場合は報告先が無いため、結果を無視する。
            let _ = self.restore_attributes();
        }
    }
}

/// 端末属性を取得する。
fn read_attributes(descriptor: RawFd) -> Result<libc::termios, TtyError> {
    // SAFETY: `termios` は整数と整数の配列だけを持ち、全ビット 0 は有効な値である。
    let mut attributes: libc::termios = unsafe { core::mem::zeroed() };
    // SAFETY: `attributes` は書き込み可能な有効な構造体であり、呼び出しの間は生存している。
    if unsafe { libc::tcgetattr(descriptor, &mut attributes) } != 0 {
        return Err(TtyError::last_os(TtyStep::ReadAttributes));
    }
    Ok(attributes)
}

/// 読み残した入力を捨て、端末属性を直ちに適用する。
///
/// `TCSAFLUSH` は出力の完了を待つため、出力が停止した端末では戻らなくなる。
/// そのため、入力の破棄 (`tcflush`) と適用 (`TCSANOW`) を分けて行う。
/// 破棄を先にし、その間に届いた入力がエコーされない順にする。
/// 属性の復元を優先するため、破棄に失敗しても適用は試みる。
///
/// # Errors
///
/// 破棄と適用のいずれかに失敗した場合は [`TtyError::Os`]。
fn apply_attributes(descriptor: RawFd, attributes: &libc::termios) -> Result<(), TtyError> {
    let flushed = retry_on_interrupt(|| {
        // SAFETY: `tcflush` は整数引数だけを取る。
        unsafe { libc::tcflush(descriptor, libc::TCIFLUSH) }
    });
    let applied = retry_on_interrupt(|| {
        // SAFETY: `attributes` は有効な `termios` への参照で、呼び出しの間は生存している。
        unsafe { libc::tcsetattr(descriptor, libc::TCSANOW, attributes) }
    });
    flushed.and(applied)
}

/// 端末属性を操作するシステムコールを、`EINTR` の間は再試行する。
///
/// 属性の復元は、中断のシグナルを受けた後にも完了させる必要がある。
fn retry_on_interrupt(mut call: impl FnMut() -> libc::c_int) -> Result<(), TtyError> {
    loop {
        if call() == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(TtyError::os(TtyStep::WriteAttributes, &error));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ReadOutcome, TtyError, TtyStep, end_of_input_on_hangup};

    /// OS の API の失敗を表す結果。
    fn os_error(step: TtyStep, errno: i32) -> Result<ReadOutcome, TtyError> {
        Err(TtyError::Os { step, errno })
    }

    #[test]
    fn test_only_read_failure_with_eio_is_end_of_input() {
        assert_eq!(
            end_of_input_on_hangup(os_error(TtyStep::Read, libc::EIO)),
            Ok(ReadOutcome::EndOfInput),
            "切断した端末の読み込みの変換に失敗。"
        );
        for unchanged in [
            os_error(TtyStep::Read, libc::EBADF),
            os_error(TtyStep::WriteTerminal, libc::EIO),
            Err(TtyError::EchoNotDisabled),
            Ok(ReadOutcome::Data(1)),
            Ok(ReadOutcome::EndOfInput),
            Ok(ReadOutcome::Interrupted),
        ] {
            assert_eq!(
                end_of_input_on_hangup(unchanged),
                unchanged,
                "{unchanged:?} を変えないことの確認に失敗。"
            );
        }
    }
}
