//! # 対話モード (`unlock`)
//!
//! `unlock` サブコマンドの処理を置く。このモジュールは OS に依存しない。
//!
//! マスターパスワードで 1 回解錠し、標準入力から読むコマンドを、1 行ずつ実行する。
//! コマンドの書式は、`help` で表示する。項目の入力と削除の同意は、標準入力ではなく制御端末で行う。
//! コマンドの結果は標準出力に、案内と失敗は標準エラー出力に書く。入力の案内 (`fidelogic> `) は、
//! 標準入力が端末の場合だけ表示する。
//!
//! ## ロックと読み直し
//!
//! 保持するのは DEK だけで、Vault の内容は保持しない。コマンドのたびにサイドカーロックを待たずに取得し、
//! Vault を読み直して、コマンドを終えたら解放する。`set` と `delete` は、入力と同意の間もロックを保持する。
//! 他の処理がロックを保持している場合、そのコマンドは失敗し、対話モードは続く。
//!
//! 読み直した Vault の世代がこのセッションで確認した世代より戻っている場合は [`CliError::RollbackDetected`]、
//! 保持する DEK で復号できない場合 (`rotate-key --full-dek` の後、改ざん) は [`CliError::AuthenticationFailed`] で終了する。
//! 対話モードを始める前に古いスナップショットへ置き換えられた場合は、検知できない。
//!
//! ## 状態と終了
//!
//! | 起きたこと | 扱い | 終了コード |
//! | :-- | :-- | --: |
//! | コマンドの成功 | 次のコマンドを待つ | |
//! | 書式の誤り、エントリが無い、入力の誤り、ロックの競合など | 失敗を表示して、次のコマンドを待つ | |
//! | `lock`, `exit`、入力の終端 | 施錠して終了する | 0 |
//! | 無操作の時間が上限に達した | 施錠して終了する | 0 |
//! | 中断のシグナル (`Ctrl+C` など) | 施錠して終了する | 130 |
//! | 世代の巻き戻し、出力の失敗 | 施錠して終了する | 1 |
//! | 保持する DEK で復号できない | 施錠して終了する | 3 |
//!
//! 施錠は、[`fidelogic_core::VaultEngine::zeroize_key`] で DEK を消去することである。
//!
//! ## 無操作の時間
//!
//! コマンドの入力、項目の入力、同意の入力を待つ時間が上限に達すると終了する。入力が進むたびに測り直す。
//! 標準入力が端末の場合、コマンドは改行を押すまで届かないため、打ち込みの途中も無操作に数える。
//! スリープしていた時間も数える。上限は既定で [`DEFAULT_IDLE_TIMEOUT_SECONDS`] 秒である。
//!
//! ## 限界
//!
//! - DEK は `mlock` せず、対話モードの間、通常のメモリに保持する。
//! - プロセスが停止 (`Ctrl+Z`) している間は、DEK を消去できない。再開した時点で上限を超えていれば終了する。
//! - 結果の出力先の読み手が止まっている間は、無操作の時間を数えない。中断のシグナルでは終了する。

use std::io::Write;
use std::path::Path;
use std::time::Duration;

use fidelogic_core::Credential;

use crate::delete;
use crate::display::write_list;
use crate::entry_session::{EntryKey, load_locked, open_vault, require_vault};
use crate::error::CliError;
use crate::get;
use crate::interaction::{
    ensure_not_interrupted, warn_if_directory_not_synced, write_output, write_warning,
};
use crate::repl_command::{ReplCommand, parse_command};
use crate::secret_input::{PasswordSource, SecretInputError};
use crate::set::{self, NotesSource, SetOutcome};
use crate::sys::clipboard::{HISTORY_WARNING, copy_with_auto_clear, reap_finished_workers};
use crate::sys::signal::InterruptWatcher;
use crate::sys::storage::{VaultLock, VaultPath};
use crate::sys::tty::{InputStream, ReadOutcome, TtyError};
use crate::vault_file::LoadedVault;

/// 対話モードで受け付ける、1 行の最大のバイト数 (行の終端を除く)。
pub const MAX_COMMAND_LEN: usize = 4096;

/// 無操作の時間の上限の既定値 (秒)。
pub const DEFAULT_IDLE_TIMEOUT_SECONDS: u64 = 300;

/// 無操作の時間の上限に指定できる最大値 (秒)。24 時間である。
pub const MAX_IDLE_TIMEOUT_SECONDS: u64 = 86_400;

/// 端末からコマンドを読むときの案内。
const COMMAND_PROMPT: &str = "fidelogic> ";

/// `help` で表示するコマンドの一覧。
const COMMAND_HELP: &str = "\
list                                          一覧を表示する
get <ENTRY> [--field <項目> | --clip <項目>]  表示する、値を出力する、コピーする
set <ENTRY>                                   追加または更新する
delete <ENTRY>                                削除する
help                                          この一覧を表示する
lock, exit                                    施錠して終了する
項目: username, password, url, totp, notes
`-` で始まるタイトルは `--` の後に書きます。
";

/// `unlock` サブコマンドの指定。
#[derive(Debug, Clone, Copy)]
pub struct UnlockRequest<'a> {
    /// `--vault` で指定された Vault のパス。
    pub vault: Option<&'a Path>,
    /// マスターパスワードの入力元。標準入力は指定できない。
    pub password_source: &'a PasswordSource,
    /// 無操作の時間の上限。
    pub idle_timeout: Duration,
}

/// 対話モードを施錠して終了した理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockReason {
    /// `lock`、`exit`、または入力の終端。
    Requested,
    /// 無操作の時間が上限に達した。
    Idle,
}

/// Vault を解錠して、対話モードを実行する。
///
/// # Args
///
/// - `request`: サブコマンドの指定。
/// - `stdout`: コマンドの結果の書き込み先。バッファを持たない出力先を渡す。
/// - `stderr`: 案内と失敗の書き込み先。
///
/// # Errors
///
/// - `--vault` の指定が無い場合は [`CliError::VaultPathRequired`]。
/// - Vault が無い場合は [`CliError::VaultNotFound`]。
/// - 誤ったパスワード、改ざんされた Vault、読み直した Vault を復号できない場合は [`CliError::AuthenticationFailed`]。
/// - 読み直した Vault の世代が戻っている場合は [`CliError::RollbackDetected`]。
/// - 中断のシグナルを受けた場合は、[`CliError::Interrupted`] または中断を示す入力のエラー。
/// - 結果を書き込めない場合は [`CliError::OutputFailed`]。
/// - 標準入力を読めない場合は [`CliError::Terminal`]。
/// - その他の読み込みとロックの失敗は、対応する [`CliError`]。
///
/// コマンドの失敗のうち、対話モードを続けられるものは `stderr` に書き、戻り値にしない。
/// 無操作の時間の上限による終了は、成功とする。
pub fn run(
    request: UnlockRequest<'_>,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<(), CliError> {
    let vault = require_vault(request.vault)?;
    // DEK を保持している間は、中断のシグナルでプロセスを終了させない。
    let watcher = InterruptWatcher::install()?;
    let mut session = Session::start(vault, request.password_source, &watcher)?;
    let mut commands = CommandReader::new(InputStream::commands()?);
    watcher.set_idle_limit(Some(request.idle_timeout));
    write_notice(
        stderr,
        &format!(
            "解錠しました。{} 秒間操作が無いと施錠します。`help` でコマンドの一覧を表示します。",
            request.idle_timeout.as_secs()
        ),
    );
    let ended = session.serve(&mut commands, stdout, stderr);
    watcher.set_idle_limit(None);
    // 終了の理由を表示する前に、DEK を消去する。
    drop(session);
    match ended? {
        LockReason::Requested => write_notice(stderr, "施錠しました。"),
        LockReason::Idle => write_notice(stderr, "無操作の時間が上限に達したため、施錠しました。"),
    }
    Ok(())
}

/// 案内を 1 行で書く。書き込みに失敗しても、処理の結果は変わらないため、結果を無視する。
fn write_notice(stderr: &mut impl Write, message: &str) {
    let _ = writeln!(stderr, "{message}").and_then(|()| stderr.flush());
}

/// 解錠している間の状態。破棄すると DEK を消去する。
struct Session<'a> {
    /// 対象の Vault。開始時に解決したパスを使い続ける。
    path: VaultPath,
    key: EntryKey,
    /// このセッションで確認した、最も新しい世代。
    last_epoch: u64,
    watcher: &'a InterruptWatcher,
}

impl<'a> Session<'a> {
    /// Vault を読み込んで解錠し、全エントリを検査する。
    fn start(
        vault: &Path,
        password_source: &PasswordSource,
        watcher: &'a InterruptWatcher,
    ) -> Result<Self, CliError> {
        let (lock, loaded) = open_vault(vault)?;
        let path = lock.vault_path().clone();
        drop(lock);
        let key = EntryKey::unlock_with_password(&loaded, password_source, watcher)?;
        // 復号した平文は、この文の終わりで消去する。
        key.credentials(&loaded)?;
        Ok(Self {
            path,
            key,
            last_epoch: loaded.header().epoch_id,
            watcher,
        })
    }

    /// 施錠する理由が生じるまで、コマンドを読んで実行する。
    fn serve(
        &mut self,
        commands: &mut CommandReader,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<LockReason, CliError> {
        let interactive = commands.is_terminal();
        loop {
            reap_finished_workers();
            ensure_not_interrupted(self.watcher)?;
            if interactive {
                // 案内を書けなくても、コマンドは実行できるため、結果を無視する。
                let _ = write!(stderr, "{COMMAND_PROMPT}").and_then(|()| stderr.flush());
            }
            let line = match commands.next(self.watcher) {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(LockReason::Requested),
                Err(error) => return end_of_session(error),
            };
            let text = match &line {
                InputLine::Text(text) => text,
                InputLine::TooLong => {
                    write_warning(stderr, "コマンドの行が長すぎます。");
                    continue;
                }
                InputLine::NotUtf8 => {
                    write_warning(stderr, "コマンドの行が UTF-8 ではありません。");
                    continue;
                }
            };
            let command = match parse_command(text) {
                Ok(ReplCommand::Quit) => return Ok(LockReason::Requested),
                Ok(ReplCommand::Empty) => continue,
                Ok(command) => command,
                Err(error) => {
                    write_warning(stderr, &error.to_string());
                    continue;
                }
            };
            if let Err(error) = self.execute(command, stdout, stderr) {
                match after_error(error) {
                    AfterError::Continue => write_warning(stderr, &error.to_string()),
                    AfterError::LockForIdle | AfterError::Abort => return end_of_session(error),
                }
            }
        }
    }

    /// コマンドを 1 つ実行する。ロックは、戻るときに解放する。
    fn execute(
        &mut self,
        command: ReplCommand<'_>,
        stdout: &mut impl Write,
        stderr: &mut impl Write,
    ) -> Result<(), CliError> {
        let watcher = self.watcher;
        let is_interrupted = || watcher.is_interrupted();
        match command {
            // `serve` が処理する。
            ReplCommand::Empty | ReplCommand::Quit => Ok(()),
            ReplCommand::Help => write_output(stdout, &is_interrupted, |out| {
                out.write_all(COMMAND_HELP.as_bytes())?;
                writeln!(out, "{HISTORY_WARNING}")
            }),
            ReplCommand::List => {
                let (lock, _, credentials) = self.reload()?;
                drop(lock);
                write_output(stdout, &is_interrupted, |out| write_list(out, &credentials))
            }
            ReplCommand::Get { title, action } => {
                let (lock, _, credentials) = self.reload()?;
                drop(lock);
                let credential = get::select(credentials, title)?;
                get::present(
                    credential,
                    action,
                    true,
                    stdout,
                    &is_interrupted,
                    copy_with_auto_clear,
                )
            }
            ReplCommand::Set { title } => {
                let (lock, loaded, credentials) = self.reload()?;
                drop(credentials);
                let outcome = set::edit_entry(
                    &lock,
                    &loaded,
                    &self.key,
                    title,
                    &NotesSource::Prompt,
                    watcher,
                )?;
                if let SetOutcome::Added(saved) | SetOutcome::Updated(saved) = &outcome {
                    self.last_epoch = saved.vault.header().epoch_id;
                }
                set::report(stdout, stderr, title, &outcome).map_err(|_| CliError::OutputFailed)
            }
            ReplCommand::Delete { title } => {
                let (lock, loaded, credentials) = self.reload()?;
                drop(credentials);
                let saved = delete::remove_entry(&lock, &loaded, &self.key, title, false, watcher)?;
                self.last_epoch = saved.vault.header().epoch_id;
                warn_if_directory_not_synced(stderr, saved.directory_sync);
                delete::report(stdout, title).map_err(|_| CliError::OutputFailed)
            }
        }
    }

    /// ロックを取得して Vault を読み直し、世代と鍵を確かめて、全エントリを返す。
    fn reload(&mut self) -> Result<(VaultLock, LoadedVault, Vec<Credential>), CliError> {
        let (lock, loaded) = load_locked(self.path.clone())?;
        let epoch = loaded.header().epoch_id;
        ensure_epoch_not_rewound(self.last_epoch, epoch)?;
        let credentials = self.key.credentials(&loaded)?;
        self.last_epoch = epoch;
        Ok((lock, loaded, credentials))
    }
}

/// 対話モードを続けない失敗を、終了の結果にする。無操作の上限は、施錠による正常な終了である。
const fn end_of_session(error: CliError) -> Result<LockReason, CliError> {
    match after_error(error) {
        AfterError::LockForIdle => Ok(LockReason::Idle),
        AfterError::Continue | AfterError::Abort => Err(error),
    }
}

/// コマンドの入力元から、1 行ずつ読み込む。
struct CommandReader {
    stream: InputStream,
    lines: LineBuffer,
    /// 入力の終端に達したか。端末は終端の後も読めるため、記録して読み直さない。
    ended: bool,
}

impl CommandReader {
    fn new(stream: InputStream) -> Self {
        Self {
            stream,
            lines: LineBuffer::default(),
            ended: false,
        }
    }

    /// コマンドの入力元が端末かを返す。
    const fn is_terminal(&self) -> bool {
        self.stream.is_terminal()
    }

    /// 次の 1 行を返す。入力の終端では `None`。
    ///
    /// # Errors
    ///
    /// 中断のシグナルを受けた場合は [`CliError::Interrupted`]、読み込みの失敗と無操作の上限は [`CliError::Terminal`]。
    fn next(&mut self, watcher: &InterruptWatcher) -> Result<Option<InputLine>, CliError> {
        let mut chunk = [0u8; 512];
        loop {
            if let Some(line) = self.lines.next_line() {
                return Ok(Some(line));
            }
            if self.ended {
                return Ok(self.lines.finish());
            }
            match self.stream.read(&mut chunk, watcher)? {
                ReadOutcome::Data(count) => self
                    .lines
                    .push(chunk.get(..count).ok_or(CliError::InvalidState)?),
                ReadOutcome::EndOfInput => self.ended = true,
                ReadOutcome::Interrupted => return Err(CliError::Interrupted),
            }
        }
    }
}

/// コマンドが失敗した後の、対話モードの扱い。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AfterError {
    /// 失敗を表示して、次のコマンドを待つ。
    Continue,
    /// 無操作の時間が上限に達したため、施錠して正常に終了する。
    LockForIdle,
    /// 施錠して、この失敗で終了する。
    Abort,
}

/// コマンドの失敗から、対話モードの扱いを定める。
pub(crate) const fn after_error(error: CliError) -> AfterError {
    match error {
        CliError::SecretInput(SecretInputError::Tty(TtyError::IdleTimeout))
        | CliError::Terminal(TtyError::IdleTimeout) => AfterError::LockForIdle,
        // 中断、鍵が使えなくなる失敗、結果を表示できない失敗は、続けずに終了する。
        CliError::Interrupted
        | CliError::SecretInput(SecretInputError::Interrupted)
        | CliError::AuthenticationFailed
        | CliError::RollbackDetected
        | CliError::InvalidState
        | CliError::OutputFailed => AfterError::Abort,
        CliError::SecretInput(_)
        | CliError::Terminal(_)
        | CliError::Hardening(_)
        | CliError::Clipboard(_)
        | CliError::Signal(_)
        | CliError::TerminalRequired
        | CliError::Storage(_)
        | CliError::VaultPathRequired
        | CliError::VaultAlreadyExists
        | CliError::KitAlreadyExists
        | CliError::KitPathConflictsWithVault
        | CliError::RecoveryKitNotConfirmed
        | CliError::Password(_)
        | CliError::PasswordMismatch
        | CliError::RecoveryCode(_)
        | CliError::EntropySourceFailed
        | CliError::VaultCreationFailed
        | CliError::VaultNotFound
        | CliError::VaultFile(_)
        | CliError::VaultSaveFailed
        | CliError::RecoveryCodeNotEntered
        | CliError::PrfSlotRequiresDrop
        | CliError::PrfSlotDropDeclined
        | CliError::EntryNotFound
        | CliError::EntryAmbiguous
        | CliError::InvalidEntryName
        | CliError::MalformedEntry
        | CliError::FieldNotSet
        | CliError::InvalidField(_)
        | CliError::FieldTooLong(_)
        | CliError::EntryInputAborted
        | CliError::NotesTooLong
        | CliError::NotesEmpty
        | CliError::DeletionDeclined
        | CliError::ExportDeclined
        | CliError::ExportDestinationExists => AfterError::Continue,
    }
}

/// 読み直した Vault の世代が、このセッションで確認した世代より戻っていないことを確かめる。
///
/// # Errors
///
/// 世代が戻っている場合は [`CliError::RollbackDetected`]。
pub(crate) const fn ensure_epoch_not_rewound(last_seen: u64, loaded: u64) -> Result<(), CliError> {
    if loaded < last_seen {
        Err(CliError::RollbackDetected)
    } else {
        Ok(())
    }
}

/// 1 行を取り出した結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InputLine {
    /// 行の終端を除いた 1 行。
    Text(String),
    /// [`MAX_COMMAND_LEN`] を超えるため捨てた行。
    TooLong,
    /// UTF-8 でない行。
    NotUtf8,
}

/// 読み込んだバイト列を、行に分ける。
#[derive(Debug, Default)]
pub(crate) struct LineBuffer {
    /// 行として取り出していないバイト列。
    pending: Vec<u8>,
    /// 上限を超えた行を、終端まで捨てている途中か。
    discarding: bool,
}

impl LineBuffer {
    /// 読み込んだバイト列を加える。[`LineBuffer::next_line`] が `None` を返した後に呼ぶ。
    pub(crate) fn push(&mut self, chunk: &[u8]) {
        self.pending.extend_from_slice(chunk);
    }

    /// 終端のある行を 1 つ取り出す。無い場合は `None`。
    pub(crate) fn next_line(&mut self) -> Option<InputLine> {
        let Some(end) = self.pending.iter().position(|&byte| byte == b'\n') else {
            // 終端の前に上限を超えた行は、内容を捨てて、終端が現れた時点で報告する。
            // 行の終端が `\r\n` の場合に備え、末尾の `\r` の 1 バイトまでは待つ。
            let excess = self.pending.len() > MAX_COMMAND_LEN + 1;
            let ends_with_carriage_return = self.pending.last() == Some(&b'\r');
            if self.discarding
                || excess
                || (self.pending.len() > MAX_COMMAND_LEN && !ends_with_carriage_return)
            {
                self.discarding = true;
                self.pending.clear();
            }
            return None;
        };
        let line = classify(self.pending.get(..end).unwrap_or_default(), self.discarding);
        self.pending.drain(..=end);
        self.discarding = false;
        Some(line)
    }

    /// 入力の終端で、終端の無い最後の行を取り出す。残りが無い場合は `None`。
    pub(crate) fn finish(&mut self) -> Option<InputLine> {
        if self.pending.is_empty() && !self.discarding {
            return None;
        }
        let line = classify(&self.pending, self.discarding);
        self.pending.clear();
        self.discarding = false;
        Some(line)
    }
}

/// 終端の `\n` を除いた 1 行を分類する。`discarded` は、行の前半を上限超過で捨てたことを示す。
fn classify(line: &[u8], discarded: bool) -> InputLine {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    if discarded || line.len() > MAX_COMMAND_LEN {
        return InputLine::TooLong;
    }
    match core::str::from_utf8(line) {
        Ok(text) => InputLine::Text(text.to_owned()),
        Err(_) => InputLine::NotUtf8,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AfterError, InputLine, LineBuffer, MAX_COMMAND_LEN, after_error, ensure_epoch_not_rewound,
    };
    use crate::entry_ops::EntryField;
    use crate::error::CliError;
    use crate::secret_input::SecretInputError;
    use crate::sys::clipboard::ClipboardError;
    use crate::sys::storage::StorageError;
    use crate::sys::tty::TtyError;
    use crate::vault_file::VaultFileError;

    #[test]
    fn test_errors_that_keep_the_session() {
        for error in [
            CliError::EntryNotFound,
            CliError::EntryAmbiguous,
            CliError::InvalidEntryName,
            CliError::MalformedEntry,
            CliError::FieldNotSet,
            CliError::InvalidField(EntryField::Url),
            CliError::FieldTooLong(EntryField::Url),
            CliError::EntryInputAborted,
            CliError::PasswordMismatch,
            CliError::DeletionDeclined,
            CliError::TerminalRequired,
            CliError::Storage(StorageError::Locked),
            CliError::VaultNotFound,
            CliError::VaultFile(VaultFileError::ModifiedExternally),
            CliError::VaultSaveFailed,
            CliError::EntropySourceFailed,
            CliError::Clipboard(ClipboardError::Unavailable),
            CliError::SecretInput(SecretInputError::TooLong),
            CliError::SecretInput(SecretInputError::MemoryLockFailed),
        ] {
            assert_eq!(
                after_error(error),
                AfterError::Continue,
                "{error:?} の後の継続の確認に失敗。"
            );
        }
    }

    #[test]
    fn test_idle_timeout_locks_the_session() {
        for error in [
            CliError::SecretInput(SecretInputError::Tty(TtyError::IdleTimeout)),
            CliError::Terminal(TtyError::IdleTimeout),
        ] {
            assert_eq!(
                after_error(error),
                AfterError::LockForIdle,
                "{error:?} の後の施錠の確認に失敗。"
            );
        }
    }

    #[test]
    fn test_errors_that_abort_the_session() {
        for error in [
            CliError::Interrupted,
            CliError::SecretInput(SecretInputError::Interrupted),
            CliError::AuthenticationFailed,
            CliError::RollbackDetected,
            CliError::InvalidState,
            CliError::OutputFailed,
        ] {
            assert_eq!(
                after_error(error),
                AfterError::Abort,
                "{error:?} の後の中止の確認に失敗。"
            );
        }
    }

    #[test]
    fn test_epoch_may_stay_or_advance_but_not_rewind() {
        let cases = [
            (5, 4, Err(CliError::RollbackDetected)),
            (5, 5, Ok(())),
            (5, 6, Ok(())),
            (0, 0, Ok(())),
            (u64::MAX, u64::MAX - 1, Err(CliError::RollbackDetected)),
        ];
        for (last_seen, loaded, expected) in cases {
            assert_eq!(
                ensure_epoch_not_rewound(last_seen, loaded),
                expected,
                "{last_seen} の後の {loaded} の判定に失敗。"
            );
        }
    }

    fn text(line: &str) -> InputLine {
        InputLine::Text(line.to_owned())
    }

    /// 分割した入力を順に与えて、取り出せる行をすべて返す。
    fn lines(chunks: &[&[u8]]) -> Vec<InputLine> {
        let mut buffer = LineBuffer::default();
        let mut result = Vec::new();
        for chunk in chunks {
            buffer.push(chunk);
            while let Some(line) = buffer.next_line() {
                result.push(line);
            }
        }
        result.extend(buffer.finish());
        assert_eq!(
            buffer.finish(),
            None,
            "終端の後に残らないことの確認に失敗。"
        );
        result
    }

    #[test]
    fn test_line_buffer_splits_lines() {
        let cases: [(&[&[u8]], Vec<InputLine>); 8] = [
            (&[], vec![]),
            (&[b""], vec![]),
            (&[b"list\n"], vec![text("list")]),
            (&[b"list\r\nexit\n"], vec![text("list"), text("exit")]),
            (
                &[b"li", b"st", b"\nex", b"it"],
                vec![text("list"), text("exit")],
            ),
            (&[b"\n\n"], vec![text(""), text("")]),
            (
                &[
                    "鍵".as_bytes().split_at(1).0,
                    "鍵".as_bytes().split_at(1).1,
                    b"\n",
                ],
                vec![text("鍵")],
            ),
            (&[b"a\xff\nok\n"], vec![InputLine::NotUtf8, text("ok")]),
        ];
        for (chunks, expected) in cases {
            assert_eq!(lines(chunks), expected, "{chunks:?} の分割に失敗。");
        }
    }

    #[test]
    fn test_line_buffer_limits_length() {
        let maximum = vec![b'a'; MAX_COMMAND_LEN];
        let maximum_text = text(&"a".repeat(MAX_COMMAND_LEN));
        let over = vec![b'a'; MAX_COMMAND_LEN + 1];
        let expected = core::slice::from_ref(&maximum_text);
        assert_eq!(lines(&[&maximum, b"\n"]), expected);
        assert_eq!(lines(&[&maximum, b"\r\n"]), expected);
        assert_eq!(lines(&[&maximum]), [maximum_text]);
        // 超えた行は 1 回だけ報告し、終端の後の行は読める。
        assert_eq!(
            lines(&[&over, b"\nlist\n"]),
            [InputLine::TooLong, text("list")]
        );
        assert_eq!(
            lines(&[&over, &over, &over, b"tail\nlist\n"]),
            [InputLine::TooLong, text("list")]
        );
        assert_eq!(lines(&[&over]), [InputLine::TooLong]);
        assert_eq!(lines(&[&over, &over]), [InputLine::TooLong]);
        // 超えた行を捨てている間は、メモリを増やさない。
        let mut buffer = LineBuffer::default();
        for _ in 0..100 {
            buffer.push(&over);
            assert_eq!(buffer.next_line(), None);
        }
        assert!(buffer.pending.len() <= MAX_COMMAND_LEN + 1);
    }
}
