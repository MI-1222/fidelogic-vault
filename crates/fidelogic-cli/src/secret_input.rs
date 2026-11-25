//! # 秘密の入力 (`secret_input`)
//!
//! マスターパスワードなどの秘密を、指定された入力元 ([`PasswordSource`]) から読み込む。
//! リカバリーコードや、確認の応答を端末から読み込む処理も、同じ手順を使う。
//! 読み込んだ内容は、`mlock` したバッファ ([`SecretInput`]) にだけ置き、破棄時に消去する。
//! 端末やファイル記述子の操作は [`crate::sys::tty`] が行い、このモジュールは OS に依存しない。
//!
//! ## 入力元
//!
//! | 入力元 | 指定 | 内容の扱い |
//! | :-- | :-- | :-- |
//! | 制御端末 | (指定なし) | プロンプトを表示し、エコーせずに 1 行を読み込む |
//! | 標準入力 | `--password-stdin` | 終端まで読み込む |
//! | ファイル | `--password-file <PATH>` | グループと他者の権限が無いことを検査して、終端まで読み込む |
//! | 引き継いだ記述子 | `--password-fd <FD>` | 終端まで読み込む |
//!
//! ## 長さと行の規則
//!
//! - パスワードは、行の終端を除いて [`MAX_PASSWORD_LEN`] バイトまで受け付ける。超える入力は、切り詰めずに拒否する。
//! - 非対話の入力は、末尾の `\n` または `\r\n` を 1 つだけ取り除く。それ以外の空白は内容とする。
//! - 空の入力と、複数行の入力は拒否する。
//! - 端末の入力は、改行の前に端末が切断された場合と、空の行で終了キー (`Ctrl+D`) を押した場合に中止する。
//!
//! 読み込むのはバイト列である。UTF-8 の検査と PRECIS 正準化は、呼び出し側が行う。
//!
//! ## 中断
//!
//! [`read_password`] は [`InterruptWatcher`] を受け取る。中断のシグナルを受けた場合は、
//! 端末属性を元に戻し、読み込み途中の内容を消去して [`SecretInputError::Interrupted`] を返す。
//! 呼び出し側は、返った秘密を破棄し終えるまで [`InterruptWatcher`] を保持する。

use core::fmt;
use std::path::PathBuf;

use fidelogic_core::{LockedBuffer, volatile_zeroize};

use crate::sys::signal::InterruptWatcher;
use crate::sys::tty::{EditKeys, HiddenInput, InputStream, ReadOutcome, Terminal, TtyError};

/// 受け付けるパスワードの最大のバイト数 (行の終端を除く)。
pub const MAX_PASSWORD_LEN: usize = 1024;

/// 読み込みバッファの容量。
///
/// 上限ちょうどのパスワードと `\r\n` に、上限超過を判定する 1 バイトを加える。
/// このバッファが満杯になるまで読めた入力は、上限を超えている。
const INPUT_CAPACITY: usize = MAX_PASSWORD_LEN + 3;

/// `Delete` キーが送る文字。端末の設定によらず、1 文字の消去として扱う。
const DELETE: u8 = 0x7f;

/// `Backspace` の制御文字。端末の設定によらず、1 文字の消去として扱う。
const BACKSPACE: u8 = 0x08;

/// パスワードの入力元。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PasswordSource {
    /// 制御端末から対話的に読み込む。
    #[default]
    Terminal,
    /// 標準入力から読み込む。
    StandardInput,
    /// ファイルから読み込む。
    File(PathBuf),
    /// 呼び出し元から引き継いだファイル記述子から読み込む。
    Descriptor(i32),
}

impl PasswordSource {
    /// 標準入力を消費する入力元かを返す。
    ///
    /// 記述子 0 の指定は、標準入力の指定と同じである。
    /// `/dev/stdin` などのパスをファイルとして指定した場合は、判定しない。
    #[must_use]
    pub const fn reads_standard_input(&self) -> bool {
        matches!(self, Self::StandardInput | Self::Descriptor(0))
    }
}

/// 読み込んだ秘密。`mlock` したページに保持し、破棄時に消去する。
pub struct SecretInput {
    buffer: LockedBuffer<INPUT_CAPACITY>,
    len: usize,
}

impl SecretInput {
    /// 秘密のバイト列を返す。行の終端は含まない。
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        // `len` は容量以下に保つため、`None` にはならない。
        self.buffer.as_slice().get(..self.len).unwrap_or_default()
    }
}

impl fmt::Debug for SecretInput {
    /// 内容と長さを表示しない。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput(..)")
    }
}

/// 秘密の入力の失敗を表すエラー。秘密情報は含まない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretInputError {
    /// 中断のシグナルを受けた。
    Interrupted,
    /// 入力が空である。
    Empty,
    /// 入力が上限を超える。
    TooLong,
    /// 入力が複数行である。
    MultipleLines,
    /// 行の終端の前に入力が終わった。
    EndOfInput,
    /// 入力バッファのメモリロックに失敗した。
    MemoryLockFailed,
    /// 端末または入力元の操作に失敗した。
    Tty(TtyError),
}

impl From<TtyError> for SecretInputError {
    fn from(error: TtyError) -> Self {
        Self::Tty(error)
    }
}

impl fmt::Display for SecretInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Interrupted => formatter.write_str("入力を中断しました。"),
            Self::Empty => formatter.write_str("パスワードが空です。"),
            Self::TooLong => write!(
                formatter,
                "パスワードが上限の {MAX_PASSWORD_LEN} バイトを超えています。"
            ),
            Self::MultipleLines => formatter.write_str("パスワードの入力が複数行です。"),
            Self::EndOfInput => formatter.write_str("パスワードの入力が途中で終了しました。"),
            Self::MemoryLockFailed => {
                formatter.write_str("入力バッファのメモリロックに失敗しました。")
            }
            Self::Tty(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SecretInputError {}

/// 指定された入力元から、パスワードを読み込む。
///
/// # Args
///
/// - `source`: 入力元。
/// - `prompt`: 端末に表示する文字列。端末以外の入力元では使わない。
/// - `watcher`: 中断の捕捉。返った値を破棄し終えるまで保持する。
///
/// # Errors
///
/// - 中断のシグナルを受けた場合 (呼び出し前に受けていた場合を含む) は [`SecretInputError::Interrupted`]。
/// - 入力バッファを `mlock` できない場合は [`SecretInputError::MemoryLockFailed`]。
/// - 内容が規則に合わない場合は [`SecretInputError::Empty`]、[`SecretInputError::TooLong`]、
///   [`SecretInputError::MultipleLines`]、[`SecretInputError::EndOfInput`]。
/// - 端末や入力元を使えない場合は [`SecretInputError::Tty`]。
pub fn read_password(
    source: &PasswordSource,
    prompt: &str,
    watcher: &InterruptWatcher,
) -> Result<SecretInput, SecretInputError> {
    if watcher.is_interrupted() {
        return Err(SecretInputError::Interrupted);
    }
    // 失敗した場合も含めて、バッファは破棄時に全体を消去する。
    let mut buffer = LockedBuffer::<INPUT_CAPACITY>::zero_strict()
        .map_err(|_| SecretInputError::MemoryLockFailed)?;
    let destination = buffer.as_mut_slice();
    let len = match source {
        PasswordSource::Terminal => read_terminal(prompt, destination, watcher),
        PasswordSource::StandardInput => {
            read_stream(InputStream::inherited(0)?, destination, watcher)
        }
        PasswordSource::File(path) => {
            read_stream(InputStream::password_file(path)?, destination, watcher)
        }
        PasswordSource::Descriptor(descriptor) => {
            read_stream(InputStream::inherited(*descriptor)?, destination, watcher)
        }
    }?;
    // 読み込みの完了と同時に受けた中断も、取りこぼさない。
    if watcher.is_interrupted() {
        return Err(SecretInputError::Interrupted);
    }
    Ok(SecretInput { buffer, len })
}

/// 非対話の入力元を終端まで読み込み、パスワードの長さを返す。
fn read_stream(
    mut stream: InputStream,
    buffer: &mut [u8],
    watcher: &InterruptWatcher,
) -> Result<usize, SecretInputError> {
    let mut filled = 0usize;
    while let Some(rest) = buffer.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match stream.read(rest, watcher)? {
            ReadOutcome::Data(count) => filled = filled.saturating_add(count),
            ReadOutcome::EndOfInput => break,
            ReadOutcome::Interrupted => return Err(SecretInputError::Interrupted),
        }
    }
    password_len(buffer.get(..filled).unwrap_or(buffer))
}

/// 非対話の入力から、行の終端を除いたパスワードの長さを求める。
///
/// # Args
///
/// - `input`: 読み込んだ内容。長さが [`INPUT_CAPACITY`] 以上の場合は、読み込みを打ち切ったものとして扱う。
///
/// # Errors
///
/// 上限を超える場合は `TooLong`、複数行の場合は `MultipleLines`、終端を除いて空の場合は `Empty`。
fn password_len(input: &[u8]) -> Result<usize, SecretInputError> {
    if input.len() >= INPUT_CAPACITY {
        return Err(SecretInputError::TooLong);
    }
    let content = match input.strip_suffix(b"\n") {
        Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
        None => input,
    };
    if content.contains(&b'\n') {
        return Err(SecretInputError::MultipleLines);
    }
    match content.len() {
        0 => Err(SecretInputError::Empty),
        len if len > MAX_PASSWORD_LEN => Err(SecretInputError::TooLong),
        len => Ok(len),
    }
}

/// 制御端末にプロンプトを表示し、エコーせずに 1 行を読み込んで、長さを返す。
///
/// 成否によらず、端末属性を元に戻してから改行する。
fn read_terminal(
    prompt: &str,
    buffer: &mut [u8],
    watcher: &InterruptWatcher,
) -> Result<usize, SecretInputError> {
    let terminal = Terminal::open()?;
    // プロンプトより先にエコーを止め、プロンプトを見てからの入力が表示されないようにする。
    let mut hidden = terminal.hide_input()?;
    let outcome = prompt_line(&terminal, &mut hidden, prompt, buffer, watcher);
    let restored = hidden.restore();
    terminal.end_line();
    let len = outcome?;
    restored?;
    Ok(len)
}

/// プロンプトを表示し、改行までの入力を行編集して読み込む。
fn prompt_line(
    terminal: &Terminal,
    hidden: &mut HiddenInput<'_>,
    prompt: &str,
    buffer: &mut [u8],
    watcher: &InterruptWatcher,
) -> Result<usize, SecretInputError> {
    if !terminal.write(prompt, watcher)? {
        return Err(SecretInputError::Interrupted);
    }
    let keys = hidden.edit_keys();
    let mut editor = LineEditor::default();
    // 上限を超えた後の入力は、行の末尾まで読み捨てる。後続のシェルに渡さないためである。
    let mut byte = [0u8; 1];
    let outcome = loop {
        match hidden.read(&mut byte, watcher) {
            Ok(ReadOutcome::Data(_)) => {
                let [value] = byte;
                match editor.feed(buffer, value, keys) {
                    LineStatus::Editing => {}
                    LineStatus::Submitted => break editor.finish(),
                    LineStatus::Cancelled => break Err(SecretInputError::EndOfInput),
                }
            }
            Ok(ReadOutcome::EndOfInput) => break Err(SecretInputError::EndOfInput),
            Ok(ReadOutcome::Interrupted) => break Err(SecretInputError::Interrupted),
            Err(error) => break Err(SecretInputError::from(error)),
        }
    };
    volatile_zeroize(&mut byte);
    outcome
}

/// 1 バイトを解釈した後の、行の状態。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineStatus {
    /// 入力の途中。
    Editing,
    /// 改行で確定した。
    Submitted,
    /// 空の行で、入力の終わりを指示された。
    Cancelled,
}

/// 端末の 1 行の編集状態。内容は呼び出し側のバッファに置く。
#[derive(Debug, Default)]
struct LineEditor {
    /// バッファに置いた内容の長さ。
    len: usize,
    /// 上限を超える入力があったか。行全体を消すまで保持する。
    overflowed: bool,
}

impl LineEditor {
    /// 端末から読んだ 1 バイトを反映する。
    ///
    /// `\n` と `\r` は確定、消去キーは UTF-8 の 1 文字の消去、行消去キーは全体の消去とする。
    /// その他のバイトは内容に加える。内容の上限は、[`MAX_PASSWORD_LEN`] と `buffer` の長さの小さい方である。
    fn feed(&mut self, buffer: &mut [u8], byte: u8, keys: EditKeys) -> LineStatus {
        match byte {
            b'\n' | b'\r' => return LineStatus::Submitted,
            DELETE | BACKSPACE => self.erase_last_character(buffer),
            _ if keys.erase == Some(byte) => self.erase_last_character(buffer),
            _ if keys.kill == Some(byte) => self.clear(buffer),
            _ if keys.end_of_input == Some(byte) => {
                if self.len == 0 && !self.overflowed {
                    return LineStatus::Cancelled;
                }
            }
            _ => match buffer.get_mut(self.len) {
                Some(slot) if self.len < MAX_PASSWORD_LEN => {
                    *slot = byte;
                    self.len += 1;
                }
                _ => self.overflowed = true,
            },
        }
        LineStatus::Editing
    }

    /// 末尾の UTF-8 の 1 文字を消去する。上限を超えた行は変更しない。
    fn erase_last_character(&mut self, buffer: &mut [u8]) {
        if self.overflowed {
            return;
        }
        while let Some(last) = self.len.checked_sub(1) {
            let Some(slot) = buffer.get_mut(last) else {
                return;
            };
            // 継続バイト (`10xxxxxx`) の間は、先頭のバイトまで続けて消す。
            let is_continuation = *slot & 0xc0 == 0x80;
            volatile_zeroize(core::slice::from_mut(slot));
            self.len = last;
            if !is_continuation {
                return;
            }
        }
    }

    /// 行全体を消去する。
    fn clear(&mut self, buffer: &mut [u8]) {
        if let Some(content) = buffer.get_mut(..self.len) {
            volatile_zeroize(content);
        }
        self.len = 0;
        self.overflowed = false;
    }

    /// 確定した行の長さを返す。
    ///
    /// # Errors
    ///
    /// 上限を超える入力があった場合は `TooLong`、内容が空の場合は `Empty`。
    fn finish(&self) -> Result<usize, SecretInputError> {
        if self.overflowed {
            Err(SecretInputError::TooLong)
        } else if self.len == 0 {
            Err(SecretInputError::Empty)
        } else {
            Ok(self.len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LineEditor, LineStatus, MAX_PASSWORD_LEN, PasswordSource, SecretInputError, password_len,
    };
    use crate::sys::tty::{EditKeys, TtyError, TtyStep};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// 一般的な端末の既定の制御文字 (`DEL`, `Ctrl+U`, `Ctrl+D`)。
    const KEYS: EditKeys = EditKeys {
        erase: Some(0x7f),
        kill: Some(0x15),
        end_of_input: Some(0x04),
    };

    /// `a` を `len` バイト並べ、末尾に `suffix` を付ける。
    fn long_input(len: usize, suffix: &[u8]) -> Vec<u8> {
        let mut input = vec![b'a'; len];
        input.extend_from_slice(suffix);
        input
    }

    #[test]
    fn test_password_len_strips_one_line_terminator() {
        let cases: [(&str, &[u8], &[u8]); 7] = [
            ("終端なし", b"pw", b"pw"),
            ("LF", b"pw\n", b"pw"),
            ("CRLF", b"pw\r\n", b"pw"),
            ("単独の CR は内容", b"pw\r", b"pw\r"),
            ("前後の空白は内容", b" p w \n", b" p w "),
            ("1 バイト", b"x", b"x"),
            ("マルチバイト", "鍵🔑\n".as_bytes(), "鍵🔑".as_bytes()),
        ];
        for (name, input, expected) in cases {
            let result = password_len(input).map(|len| input.get(..len));
            assert_eq!(result, Ok(Some(expected)), "{name} の長さの判定に失敗。");
        }
    }

    #[test]
    fn test_password_len_accepts_maximum_with_any_terminator() {
        for suffix in [&b""[..], b"\n", b"\r\n"] {
            let input = long_input(MAX_PASSWORD_LEN, suffix);
            assert_eq!(
                password_len(&input),
                Ok(MAX_PASSWORD_LEN),
                "終端 {suffix:?} の上限ちょうどの入力の受理に失敗。"
            );
        }
    }

    #[test]
    fn test_password_len_rejects_invalid_input() {
        let cases: [(&str, Vec<u8>, SecretInputError); 9] = [
            ("空", Vec::new(), SecretInputError::Empty),
            ("LF のみ", b"\n".to_vec(), SecretInputError::Empty),
            ("CRLF のみ", b"\r\n".to_vec(), SecretInputError::Empty),
            ("2 行", b"a\nb".to_vec(), SecretInputError::MultipleLines),
            (
                "空行が続く",
                b"a\n\n".to_vec(),
                SecretInputError::MultipleLines,
            ),
            (
                "上限 + 1",
                long_input(MAX_PASSWORD_LEN + 1, b""),
                SecretInputError::TooLong,
            ),
            (
                "上限 + 1 と LF",
                long_input(MAX_PASSWORD_LEN + 1, b"\n"),
                SecretInputError::TooLong,
            ),
            (
                "上限 + 1 と CRLF",
                long_input(MAX_PASSWORD_LEN + 1, b"\r\n"),
                SecretInputError::TooLong,
            ),
            // 読み込みが途中で打ち切られた入力は、末尾が改行に見えても上限超過とする。
            (
                "打ち切られた入力の末尾が LF",
                long_input(MAX_PASSWORD_LEN + 2, b"\n"),
                SecretInputError::TooLong,
            ),
        ];
        for (name, input, expected) in cases {
            assert_eq!(password_len(&input), Err(expected), "{name} の拒否に失敗。");
        }
    }

    /// バイト列を順に与え、最後の状態と、確定した内容を返す。
    fn edit(input: &[u8], keys: EditKeys) -> (LineStatus, Result<Vec<u8>, SecretInputError>) {
        let mut buffer = [0u8; MAX_PASSWORD_LEN];
        let mut editor = LineEditor::default();
        let mut status = LineStatus::Editing;
        for &byte in input {
            status = editor.feed(&mut buffer, byte, keys);
            if status != LineStatus::Editing {
                break;
            }
        }
        let content = editor
            .finish()
            .map(|len| buffer.iter().copied().take(len).collect());
        (status, content)
    }

    #[test]
    fn test_line_editor_submits_on_either_line_terminator() {
        for input in [&b"abc\n"[..], b"abc\r", b"abc\nignored"] {
            assert_eq!(
                edit(input, KEYS),
                (LineStatus::Submitted, Ok(b"abc".to_vec())),
                "{input:?} の確定に失敗。"
            );
        }
    }

    #[test]
    fn test_line_editor_applies_editing_keys() {
        let cases: [(&str, &[u8], &[u8]); 9] = [
            ("DEL で 1 文字消去", b"ab\x7fc\n", b"ac"),
            ("BS で 1 文字消去", b"ab\x08c\n", b"ac"),
            ("空の行の消去は無視", b"\x7fa\n", b"a"),
            ("行の消去", b"abc\x15de\n", b"de"),
            ("入力途中の終了キーは無視", b"a\x04b\n", b"ab"),
            (
                "3 バイト文字の消去",
                "あい\u{7f}\n".as_bytes(),
                "あ".as_bytes(),
            ),
            ("4 バイト文字の消去", "a🔑\u{7f}\n".as_bytes(), b"a"),
            ("他の制御文字は内容", b"a\tb\n", b"a\tb"),
            ("継続バイトだけの消去", b"\x80\x80\x7fz\n", b"z"),
        ];
        for (name, input, expected) in cases {
            assert_eq!(
                edit(input, KEYS),
                (LineStatus::Submitted, Ok(expected.to_vec())),
                "{name} に失敗。"
            );
        }
    }

    #[test]
    fn test_line_editor_follows_terminal_settings() {
        let custom = EditKeys {
            erase: Some(b'#'),
            kill: Some(b'@'),
            end_of_input: Some(b'!'),
        };
        assert_eq!(
            edit(b"ab#c@de\n", custom),
            (LineStatus::Submitted, Ok(b"de".to_vec()))
        );
        assert_eq!(edit(b"!", custom).0, LineStatus::Cancelled);

        let disabled = EditKeys {
            erase: None,
            kill: None,
            end_of_input: None,
        };
        assert_eq!(
            edit(b"a\x15\x04b\n", disabled),
            (LineStatus::Submitted, Ok(b"a\x15\x04b".to_vec()))
        );
    }

    #[test]
    fn test_line_editor_cancels_on_end_of_input_only_when_empty() {
        assert_eq!(edit(b"\x04", KEYS).0, LineStatus::Cancelled);
        assert_eq!(edit(b"ab\x15\x04", KEYS).0, LineStatus::Cancelled);
    }

    #[test]
    fn test_line_editor_rejects_empty_line() {
        assert_eq!(
            edit(b"\n", KEYS),
            (LineStatus::Submitted, Err(SecretInputError::Empty))
        );
    }

    #[test]
    fn test_line_editor_limits_length_without_truncating() -> TestResult {
        let maximum = long_input(MAX_PASSWORD_LEN, b"\n");
        assert_eq!(
            edit(&maximum, KEYS).1.map(|content| content.len()),
            Ok(MAX_PASSWORD_LEN)
        );

        // 上限を超えた後は、改行まで読み続け、文字を消しても受理しない。
        for suffix in [&b"\n"[..], b"\x7f\x7f\n", b"\x04\n"] {
            let input = long_input(MAX_PASSWORD_LEN + 1, suffix);
            assert_eq!(
                edit(&input, KEYS),
                (LineStatus::Submitted, Err(SecretInputError::TooLong)),
                "終端 {suffix:?} の上限超過の拒否に失敗。"
            );
        }

        // 行全体を消せば、入力し直せる。
        let retyped = long_input(MAX_PASSWORD_LEN + 1, b"\x15ok\n");
        assert_eq!(
            edit(&retyped, KEYS),
            (LineStatus::Submitted, Ok(b"ok".to_vec()))
        );
        Ok(())
    }

    #[test]
    fn test_line_editor_zeroes_erased_bytes() {
        let mut buffer = [0u8; MAX_PASSWORD_LEN];
        let mut editor = LineEditor::default();
        for &byte in b"abc\x7f" {
            editor.feed(&mut buffer, byte, KEYS);
        }
        assert_eq!(buffer.get(..3), Some(&b"ab\0"[..]));
        editor.feed(&mut buffer, 0x15, KEYS);
        assert_eq!(buffer.get(..3), Some(&b"\0\0\0"[..]));
    }

    #[test]
    fn test_only_stdin_sources_consume_standard_input() {
        let cases = [
            (PasswordSource::Terminal, false),
            (PasswordSource::StandardInput, true),
            (PasswordSource::Descriptor(0), true),
            (PasswordSource::Descriptor(3), false),
            (PasswordSource::File("password.txt".into()), false),
        ];
        for (source, expected) in cases {
            assert_eq!(
                source.reads_standard_input(),
                expected,
                "{source:?} の判定に失敗。"
            );
        }
        assert_eq!(PasswordSource::default(), PasswordSource::Terminal);
    }

    #[test]
    fn test_error_messages_end_with_japanese_period() {
        let errors = [
            SecretInputError::Interrupted,
            SecretInputError::Empty,
            SecretInputError::TooLong,
            SecretInputError::MultipleLines,
            SecretInputError::EndOfInput,
            SecretInputError::MemoryLockFailed,
            SecretInputError::Tty(TtyError::NoTerminal { errno: 6 }),
            SecretInputError::Tty(TtyError::EchoNotDisabled),
            SecretInputError::Tty(TtyError::UnsupportedDescriptor),
            SecretInputError::Tty(TtyError::DescriptorNotInherited),
            SecretInputError::Tty(TtyError::DescriptorIsTerminal),
            SecretInputError::Tty(TtyError::PasswordFileNotRegular),
            SecretInputError::Tty(TtyError::PasswordFilePermissions),
            SecretInputError::Tty(TtyError::Os {
                step: TtyStep::Read,
                errno: 9,
            }),
        ];
        for error in errors {
            assert!(
                error.to_string().ends_with('。'),
                "{error:?} の文末の確認に失敗。"
            );
        }
    }
}
