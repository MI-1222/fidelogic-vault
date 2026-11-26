//! # 利用者とのやり取り (`interaction`)
//!
//! 複数のサブコマンドが使う、パスワードの入力、同意の確認、リカバリーキットの表示と控えの確認、
//! 書き出した HTML の後始末、中断できる結果の出力、警告と結果の出力を置く。
//! このモジュールは OS に依存しない。端末とファイルの操作は [`crate::sys`] が行う。
//! 端末の表示の限界は、[`crate::init`] の説明を参照する。

use std::io::Write;
use std::path::Path;

use fidelogic_core::{SecretVec, ct_eq_bytes_bool};

use crate::error::CliError;
use crate::password::canonicalize_password;
use crate::recovery_code::RecoveryCode;
use crate::recovery_kit::{screen_parts, write_html};
use crate::secret_input::{PasswordSource, SecretInputError, read_password};
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{DirectorySync, StorageError, write_new_private_file};
use crate::sys::tty::Terminal;

/// 端末から新しいマスターパスワードを読み込むときのプロンプト。
const NEW_PASSWORD_PROMPT: &str = "新しいマスターパスワード: ";

/// 端末から新しいマスターパスワードを再入力させるときのプロンプト。
const REPEAT_PASSWORD_PROMPT: &str = "確認のため、もう一度入力してください: ";

/// リカバリーコードの末尾を再入力させるときのプロンプト。
const CONFIRMATION_PROMPT: &str = "末尾 5 文字 (入力は表示されません): ";

/// 再入力が一致しなかったときに、画面の末尾に表示する案内。
const MISMATCH_NOTICE: &str = "一致しません。もう一度入力してください。\n";

/// 代替画面に切り替える制御列。
const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h";

/// カーソルを左上に移して画面を消去する制御列。
const CLEAR_SCREEN: &str = "\x1b[H\x1b[2J";

/// 画面を消去してから、元の画面に戻る制御列。
const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[H\x1b[2J\x1b[?1049l";

/// 新しいマスターパスワードを読み込んで正準化する。端末の場合は 2 回入力させ、一致を確かめる。
///
/// # Errors
///
/// - 端末から入力した 2 回のパスワードが異なる場合は [`CliError::PasswordMismatch`]。
/// - 読み込みと正準化の失敗は [`read_canonical_password`] と同じ。
pub(crate) fn read_new_password(
    source: &PasswordSource,
    watcher: &InterruptWatcher,
) -> Result<SecretVec, CliError> {
    let password = read_canonical_password(source, NEW_PASSWORD_PROMPT, watcher)?;
    if *source == PasswordSource::Terminal {
        let repeated = read_canonical_password(source, REPEAT_PASSWORD_PROMPT, watcher)?;
        if !ct_eq_bytes_bool(password.as_slice(), repeated.as_slice()) {
            return Err(CliError::PasswordMismatch);
        }
    }
    Ok(password)
}

/// パスワードを 1 回読み込んで正準化する。読み込んだ内容は、戻る前に消去する。
///
/// # Errors
///
/// 読み込みの失敗は [`CliError::SecretInput`]、正準化の失敗は [`CliError::Password`]。
pub(crate) fn read_canonical_password(
    source: &PasswordSource,
    prompt: &str,
    watcher: &InterruptWatcher,
) -> Result<SecretVec, CliError> {
    let input = read_password(source, prompt, watcher)?;
    Ok(canonicalize_password(input.as_bytes())?)
}

/// 秘密の出力に使う、中断で書き込みをやめる書き込み先。
///
/// 中断のシグナルは記録するだけにするため、読み手が止まった出力先への書き込みは、既定では再試行され続ける。
/// この型は、中断を記録した後の書き込みと、中断で戻った書き込みを、再試行されない失敗にする。
/// 確認と書き込みの開始の間にシグナルを受けた場合は、書き込みが戻るか、次のシグナルを受けるまで待つ。
/// 内部のバッファは持たない。
pub(crate) struct InterruptibleWriter<'a, W, F> {
    inner: &'a mut W,
    is_interrupted: F,
}

impl<'a, W: Write, F: Fn() -> bool> InterruptibleWriter<'a, W, F> {
    /// `inner` へ書く値を作る。`is_interrupted` は、中断のシグナルを受けたかを返す。
    pub(crate) fn new(inner: &'a mut W, is_interrupted: F) -> Self {
        Self {
            inner,
            is_interrupted,
        }
    }
}

impl<W: Write, F: Fn() -> bool> Write for InterruptibleWriter<'_, W, F> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if (self.is_interrupted)() {
            return Err(interrupted_output());
        }
        match self.inner.write(buffer) {
            Err(error)
                if error.kind() == std::io::ErrorKind::Interrupted && (self.is_interrupted)() =>
            {
                Err(interrupted_output())
            }
            result => result,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// 中断で書き込みをやめたことを表す失敗。`write_all` が再試行しない種類にする。
fn interrupted_output() -> std::io::Error {
    std::io::Error::other("中断のシグナルを受けたため、出力をやめました。")
}

/// 秘密を含みうる結果を、中断できる形で書き出す。
///
/// # Args
///
/// - `stdout`: 書き込み先。
/// - `is_interrupted`: 中断のシグナルを受けたかを返す処理。
/// - `write`: 内容を書く処理。
///
/// # Errors
///
/// 中断のシグナルを受けた場合は [`CliError::Interrupted`]、それ以外の書き込みの失敗は [`CliError::OutputFailed`]。
pub(crate) fn write_output<W: Write>(
    stdout: &mut W,
    is_interrupted: &dyn Fn() -> bool,
    write: impl FnOnce(&mut dyn Write) -> std::io::Result<()>,
) -> Result<(), CliError> {
    let mut guarded = InterruptibleWriter::new(stdout, is_interrupted);
    write(&mut guarded)
        .and_then(|()| guarded.flush())
        .map_err(|_| {
            if is_interrupted() {
                CliError::Interrupted
            } else {
                CliError::OutputFailed
            }
        })
}

/// 端末で同意を求める。`y` または `yes` (大文字と小文字を区別しない) を同意とする。
///
/// 応答は秘密ではないが、読み込みの手順は端末からのパスワードの入力と同じで、表示しない。
///
/// # Returns
///
/// 同意した場合は `true`。空の応答、他の応答、入力の終端は `false`。
///
/// # Errors
///
/// 中断のシグナルを受けた場合と、端末を使えない場合は [`CliError::SecretInput`]。
pub(crate) fn ask_consent(prompt: &str, watcher: &InterruptWatcher) -> Result<bool, CliError> {
    match read_password(&PasswordSource::Terminal, prompt, watcher) {
        Ok(answer) => Ok(is_consent(answer.as_bytes())),
        Err(SecretInputError::Empty | SecretInputError::TooLong | SecretInputError::EndOfInput) => {
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

/// 応答が同意かを返す。
fn is_consent(answer: &[u8]) -> bool {
    answer.eq_ignore_ascii_case(b"y") || answer.eq_ignore_ascii_case(b"yes")
}

/// 中断のシグナルを受けていた場合は失敗する。
pub(crate) fn ensure_not_interrupted(watcher: &InterruptWatcher) -> Result<(), CliError> {
    if watcher.is_interrupted() {
        Err(CliError::Interrupted)
    } else {
        Ok(())
    }
}

/// `--kit-html` の出力先が空いていることを確かめる。シンボリックリンクはたどらない。
///
/// 秘密を入力させる前に失敗するための事前の確認である。書き出しは、既存のファイルを上書きしない。
///
/// # Errors
///
/// 出力先にファイルなどがある場合は [`CliError::KitAlreadyExists`]。
pub(crate) fn ensure_kit_destination_is_free(kit_html: Option<&Path>) -> Result<(), CliError> {
    if kit_html.is_some_and(|path| path.symlink_metadata().is_ok()) {
        Err(CliError::KitAlreadyExists)
    } else {
        Ok(())
    }
}

/// 代替画面にリカバリーキットを表示し、コードの末尾が正しく再入力されるまで繰り返す。
///
/// 成否によらず、戻る前に画面を消去して元の画面に戻す。
///
/// # Args
///
/// - `grouped`: 表示用の、区切りを含むコード。
///
/// # Errors
///
/// - 再入力の前に端末の入力が終わった場合 (`Ctrl+D`、切断) は [`CliError::RecoveryKitNotConfirmed`]。
/// - 中断のシグナルを受けた場合は、中断を示すエラー。
/// - 端末の読み書きに失敗した場合は、対応するエラー。
pub(crate) fn confirm_recovery_kit(
    terminal: &Terminal,
    grouped: &str,
    code: &RecoveryCode,
    watcher: &InterruptWatcher,
) -> Result<(), CliError> {
    let screen = AlternateScreen::enter(terminal, watcher)?;
    let mut notice = "";
    loop {
        // 失敗の案内でコードが画面の外に流れないように、毎回描き直す。
        screen.draw(screen_parts(grouped), notice)?;
        // 読み込みの手順は、端末からのパスワードの入力と同じである。
        match read_password(&PasswordSource::Terminal, CONFIRMATION_PROMPT, watcher) {
            Ok(input) if code.confirms_suffix(input.as_bytes()) => return Ok(()),
            Ok(_) | Err(SecretInputError::Empty | SecretInputError::TooLong) => {
                notice = MISMATCH_NOTICE;
            }
            Err(SecretInputError::EndOfInput) => return Err(CliError::RecoveryKitNotConfirmed),
            Err(error) => return Err(error.into()),
        }
    }
}

/// 端末の代替画面を使っている間だけ存在する値。破棄すると、画面を消去して元の画面に戻る。
struct AlternateScreen<'a> {
    terminal: &'a Terminal,
    watcher: &'a InterruptWatcher,
}

impl<'a> AlternateScreen<'a> {
    /// 代替画面に切り替える。
    fn enter(terminal: &'a Terminal, watcher: &'a InterruptWatcher) -> Result<Self, CliError> {
        // 切り替えの書き込みが途中で失敗しても、破棄の処理で元の画面に戻す。
        let screen = Self { terminal, watcher };
        screen.write(ENTER_ALTERNATE_SCREEN)?;
        Ok(screen)
    }

    /// 画面を消去し、`parts` と `notice` を順に書く。
    fn draw(&self, parts: [&str; 3], notice: &str) -> Result<(), CliError> {
        self.write(CLEAR_SCREEN)?;
        for part in parts {
            self.write(part)?;
        }
        self.write(notice)
    }

    fn write(&self, text: &str) -> Result<(), CliError> {
        if self.terminal.write(text, self.watcher)? {
            Ok(())
        } else {
            Err(CliError::Interrupted)
        }
    }
}

impl Drop for AlternateScreen<'_> {
    fn drop(&mut self) {
        // 中断した後にも書き込めるように、中断の確認を伴わない書き込みを使う。
        self.terminal.write_without_waiting(LEAVE_ALTERNATE_SCREEN);
    }
}

/// 書き出した HTML のリカバリーキット。[`PendingKit::keep`] を呼ばずに破棄すると、ファイルを削除する。
pub(crate) struct PendingKit<'a> {
    path: &'a Path,
    directory_sync: DirectorySync,
    keep: bool,
}

impl<'a> PendingKit<'a> {
    /// HTML を新規に書き出す。
    ///
    /// # Errors
    ///
    /// 出力先にファイルがある場合は [`CliError::KitAlreadyExists`]、書き出しの失敗は [`CliError::Storage`]。
    pub(crate) fn write(path: &'a Path, grouped: &str) -> Result<Self, CliError> {
        let directory_sync = write_new_private_file(path, |file| write_html(file, grouped))
            .map_err(|error| match error {
                StorageError::AlreadyExists => CliError::KitAlreadyExists,
                other => CliError::from(other),
            })?;
        Ok(Self {
            path,
            directory_sync,
            keep: false,
        })
    }

    /// ファイルを残し、親ディレクトリの同期の結果を返す。
    pub(crate) fn keep(mut self) -> DirectorySync {
        self.keep = true;
        self.directory_sync
    }
}

impl Drop for PendingKit<'_> {
    fn drop(&mut self) {
        if !self.keep {
            // 削除に失敗した場合も、元の失敗を報告する。残るコードに対応するスロットは保存されていない。
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// 親ディレクトリの同期に失敗した場合に、警告を書く。
pub(crate) fn warn_if_directory_not_synced(stderr: &mut impl Write, sync: DirectorySync) {
    if let DirectorySync::Failed { errno } = sync {
        let message = format!(
            "警告: 親ディレクトリの同期に失敗しました (errno: {errno})。直後に電源が切れると、書き込んだ内容が失われる可能性があります。"
        );
        write_warning(stderr, &message);
    }
}

/// 警告を 1 行で書く。
pub(crate) fn write_warning(stderr: &mut impl Write, message: &str) {
    // 警告の書き込みに失敗しても、処理の結果は変わらないため、結果を無視する。
    let _ = crate::write_error_line(stderr, message);
}

/// `--kit-html` の指定がある場合に、書き出した HTML の扱いを書く。
pub(crate) fn report_kit(stdout: &mut impl Write, kit_html: Option<&Path>) -> std::io::Result<()> {
    if let Some(path) = kit_html {
        writeln!(
            stdout,
            "リカバリーキットを書き出しました: {}",
            path.display()
        )?;
        writeln!(stdout, "印刷した後は、このファイルを削除してください。")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use std::cell::Cell;
    use std::io::{self, Write};

    use super::{InterruptibleWriter, is_consent, warn_if_directory_not_synced, write_output};
    use crate::error::CliError;
    use crate::sys::storage::DirectorySync;

    type TestResult = Result<(), Box<dyn Error>>;

    /// 指定した回数だけ `EINTR` を返してから、書き込みを受け付ける出力先。
    /// `EINTR` を返すときに、`interrupts` が真であれば中断を記録する。
    struct Flaky<'a> {
        failures: usize,
        interrupts: bool,
        interrupted: &'a Cell<bool>,
        written: Vec<u8>,
    }

    impl Write for Flaky<'_> {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.failures > 0 {
                self.failures -= 1;
                if self.interrupts {
                    self.interrupted.set(true);
                }
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// 中断の有無と `EINTR` の組ごとに、`write_all` の結果と、書き込んだ内容を返す。
    fn write_through(
        interrupted_before: bool,
        failures: usize,
        interrupts: bool,
    ) -> (io::Result<()>, Vec<u8>) {
        let interrupted = Cell::new(interrupted_before);
        let mut sink = Flaky {
            failures,
            interrupts,
            interrupted: &interrupted,
            written: Vec::new(),
        };
        let result = InterruptibleWriter::new(&mut sink, || interrupted.get()).write_all(b"secret");
        (result, sink.written)
    }

    #[test]
    fn test_interruptible_writer_retries_unrelated_interrupts() -> TestResult {
        for failures in [0, 3] {
            let (result, written) = write_through(false, failures, false);
            result?;
            assert_eq!(written, b"secret", "{failures} 回の再試行に失敗。");
        }
        Ok(())
    }

    #[test]
    fn test_interruptible_writer_stops_after_an_interrupt() {
        for (name, before, failures, interrupts) in [
            ("書き込みの前に中断", true, 0, false),
            ("書き込み中に中断", false, 1, true),
        ] {
            let (result, written) = write_through(before, failures, interrupts);
            let kind = result.map_err(|error| error.kind());
            assert!(
                matches!(kind, Err(kind) if kind != io::ErrorKind::Interrupted),
                "{name}の中止に失敗: {kind:?}"
            );
            assert!(written.is_empty(), "{name}の後に書かないことの確認に失敗。");
        }
    }

    #[test]
    fn test_consent_accepts_only_yes() {
        for answer in [&b"y"[..], b"Y", b"yes", b"YES", b"Yes"] {
            assert!(is_consent(answer), "{answer:?} の受理に失敗。");
        }
        for answer in [
            &b""[..],
            b"n",
            b"no",
            b"yy",
            b"ye",
            b" y",
            b"y ",
            "ｙ".as_bytes(),
        ] {
            assert!(!is_consent(answer), "{answer:?} の拒否に失敗。");
        }
    }

    #[test]
    fn test_write_output_distinguishes_interrupt_from_failure() {
        let mut stdout = Vec::new();
        let written = write_output(&mut stdout, &|| false, |out| out.write_all(b"value"));
        assert_eq!(written, Ok(()));
        assert_eq!(stdout, b"value");

        let failed = write_output(&mut Vec::new(), &|| false, |_| {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        });
        assert_eq!(failed, Err(CliError::OutputFailed));

        let interrupted = write_output(&mut Vec::new(), &|| true, |out| out.write_all(b"value"));
        assert_eq!(interrupted, Err(CliError::Interrupted));
    }

    #[test]
    fn test_directory_sync_failure_is_warned_in_one_line() -> TestResult {
        let mut stderr = Vec::new();
        warn_if_directory_not_synced(&mut stderr, DirectorySync::Synced);
        assert!(
            stderr.is_empty(),
            "同期の成功で警告しないことの確認に失敗。"
        );

        warn_if_directory_not_synced(&mut stderr, DirectorySync::Failed { errno: 5 });
        let warning = String::from_utf8(stderr)?;
        assert!(
            warning.starts_with("fidelogic-cli: 警告: ")
                && warning.contains("errno: 5")
                && warning.lines().count() == 1,
            "警告の出力の確認に失敗: {warning}"
        );
        Ok(())
    }
}
