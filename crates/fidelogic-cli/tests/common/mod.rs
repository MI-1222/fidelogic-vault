//! 実行ファイルを疑似端末で動かす統合テストの共通部分。
//!
//! 親が疑似端末を作成し、シェルを子の制御端末のセッションリーダーとして起動して、その下で実行ファイルを動かす。
//! 親は疑似端末のマスター側から入力し、画面の内容と、作成されたファイルを確かめる。
//! シェルは実行ファイルの終了コードを報告した後、親が許可するまで終了しない。
//! macOS では、セッションリーダーが終了すると端末が無効になるため、終了の前に端末属性を調べる必要がある。

// テストのクレートごとに使う項目が異なるため、未使用の項目を許す。
#![allow(dead_code)]

use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fidelogic_core::{Vault, deserialize};

pub mod entry_vault;
pub mod fixture;

pub type TestResult = Result<(), Box<dyn Error>>;

/// 子の応答を待つ上限。最適化しないビルドの鍵導出の時間を含む。
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// 実行ファイルを起動し、終了コードを報告して、親の許可を待つシェルの処理。
///
/// シグナルは無視せず捕捉する。無視の設定は実行ファイルに引き継がれ、中断を試せなくなるためである。
pub const SHELL_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
"$0" "$@"
printf 'STATUS %s\n' "$?"
read -r release < /dev/tty
"#;

/// [`SHELL_SCRIPT`] と同じ処理で、実行ファイルの標準出力を、読み手のいないパイプにする。
///
/// パイプの読み手の `true` は、入力を読まずに直ちに終了する。終了コードの報告は、元の標準出力に書く。
pub const BROKEN_STDOUT_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
exec 3>&1
{ "$0" "$@"; printf 'STATUS %s\n' "$?" >&3; } | true
read -r release < /dev/tty
"#;

/// [`SHELL_SCRIPT`] と同じ処理で、記述子 3 を [`DESCRIPTOR_SOURCE`] のファイルにして実行ファイルを起動する。
pub const DESCRIPTOR_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
"$0" "$@" 3<"$FIDELOGIC_CLI_INIT_DESCRIPTOR_SOURCE"
printf 'STATUS %s\n' "$?"
read -r release < /dev/tty
"#;

/// [`SHELL_SCRIPT`] と同じ処理で、実行ファイルの標準入出力をすべて制御端末にする。
pub const TERMINAL_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
"$0" "$@" </dev/tty >/dev/tty 2>/dev/tty
printf 'STATUS %s\n' "$?"
read -r release < /dev/tty
"#;

/// [`DESCRIPTOR_SCRIPT`] が記述子 3 に開くファイルを指定する環境変数の名前。
pub const DESCRIPTOR_SOURCE: &str = "FIDELOGIC_CLI_INIT_DESCRIPTOR_SOURCE";
pub const NEW_PASSWORD_PROMPT: &str = "新しいマスターパスワード: ";
pub const REPEAT_PASSWORD_PROMPT: &str = "もう一度入力してください: ";
pub const CONFIRMATION_PROMPT: &str = "末尾 5 文字 (入力は表示されません): ";
pub const KIT_HEADING: &str = "リカバリーキット ==";
pub const WARNING: &str = "このコードは、単独で Vault 全体を復号できます。";
pub const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h";
pub const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[H\x1b[2J\x1b[?1049l";

/// 表示用のリカバリーコードの文字数。
pub const GROUPED_CODE_LEN: usize = 35;

pub const PASSWORD: &str = "correct horse battery staple";

/// テスト用の一時ディレクトリ。破棄するときに中身ごと削除する。
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fidelogic-cli-init-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// 中にあるファイルの名前を、整列して返す。
    pub fn names(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = fs::read_dir(&self.0)?
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect::<Result<Vec<_>, std::io::Error>>()?;
        names.sort();
        Ok(names)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
/// 端末属性を読み取る。
pub fn attributes(descriptor: RawFd) -> Result<libc::termios, Box<dyn Error>> {
    // SAFETY: 全ビット 0 は `termios` の有効な値である。
    let mut value: libc::termios = unsafe { core::mem::zeroed() };
    // SAFETY: `value` は書き込み可能な有効な構造体である。
    if unsafe { libc::tcgetattr(descriptor, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}

/// 端末属性が同じかを判定する。`PENDIN` は、BSD 系のカーネルが立てることがあるため除く。
pub fn same_attributes(left: &libc::termios, right: &libc::termios) -> bool {
    left.c_iflag == right.c_iflag
        && left.c_oflag == right.c_oflag
        && left.c_cflag == right.c_cflag
        && left.c_lflag & !libc::PENDIN == right.c_lflag & !libc::PENDIN
        && left.c_cc == right.c_cc
}

/// macOS の `openpty` がまれに返すエラー番号。公開のヘッダー (`sys/errno.h`) に定義が無い。
pub const TRANSIENT_OPENPTY_ERRNO: i32 = -6;

/// `openpty` を呼ぶ回数の上限。
pub const OPENPTY_ATTEMPTS: u32 = 5;

/// 疑似端末の作成 `open` を実行し、[`TRANSIENT_OPENPTY_ERRNO`] で失敗した場合だけやり直す。
///
/// # Args
///
/// - `open`: 疑似端末を作る処理。
/// - `report`: やり直す前に、失敗したのが何回目の呼び出しかを受け取る処理。
///
/// # Errors
///
/// 他の失敗は直ちに返す。[`OPENPTY_ATTEMPTS`] 回続けて失敗した場合は、最後の失敗を返す。
pub fn retry_transient_openpty<T>(
    mut open: impl FnMut() -> std::io::Result<T>,
    mut report: impl FnMut(u32),
) -> std::io::Result<T> {
    let mut attempt = 1;
    loop {
        match open() {
            Err(error)
                if error.raw_os_error() == Some(TRANSIENT_OPENPTY_ERRNO)
                    && attempt < OPENPTY_ATTEMPTS =>
            {
                report(attempt);
                attempt += 1;
                // 同じ状態にすぐ当たらないように、短い間を置く。
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
}

/// `openpty` で、マスター側とスレーブ側の記述子を作る。
fn open_pty_descriptors() -> std::io::Result<(OwnedFd, OwnedFd)> {
    let (mut master, mut slave) = (-1, -1);
    // SAFETY: 2 つの出力先は有効で、名前、端末属性、窓の大きさには null を渡す。
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `openpty` が成功した直後の記述子で、所有者は他に無い。
    Ok(unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) })
}

/// 疑似端末の両端。
pub struct Pty {
    /// 利用者の側。読み込みは非ブロッキングである。
    pub master: OwnedFd,
    /// プログラムの側。子の終了まで開いておく。
    pub slave: OwnedFd,
    /// 画面に出力された内容。
    pub screen: Vec<u8>,
}

impl Pty {
    pub fn open() -> Result<Self, Box<dyn Error>> {
        let (master, slave) = retry_transient_openpty(open_pty_descriptors, |attempt| {
            // 標準エラー出力に直接書き、テストの出力の捕捉を受けずに残す。書けない場合も続ける。
            let _ = writeln!(
                std::io::stderr(),
                "openpty が errno {TRANSIENT_OPENPTY_ERRNO} で失敗したため、やり直します ({attempt} 回目の失敗)。"
            );
        })?;
        for descriptor in [master.as_raw_fd(), slave.as_raw_fd()] {
            // SAFETY: 整数引数だけで、記述子の属性を変更する。
            if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        // SAFETY: 同上。
        if unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self {
            master,
            slave,
            screen: Vec::new(),
        })
    }

    /// 画面に出力された内容を取り込む。
    pub fn drain_screen(&mut self) -> TestResult {
        let mut chunk = [0u8; 4096];
        loop {
            // SAFETY: `chunk` は指定した長さの書き込み可能な領域で、記述子は非ブロッキングである。
            let read = unsafe {
                libc::read(
                    self.master.as_raw_fd(),
                    chunk.as_mut_ptr().cast(),
                    chunk.len(),
                )
            };
            match usize::try_from(read) {
                Ok(count) if count > 0 => self
                    .screen
                    .extend_from_slice(chunk.get(..count).ok_or("読み込み長が不正です。")?),
                _ => return Ok(()),
            }
        }
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.screen).into_owned()
    }
}
/// 実行ファイルの起動の指定。
#[derive(Default)]
pub struct Options<'a> {
    /// 標準入力に渡す内容。`None` の場合は空の入力にする。
    pub stdin: Option<&'a [u8]>,
    /// `RLIMIT_MEMLOCK` の上限。`None` の場合は変更しない。
    pub memlock_limit: Option<libc::rlim_t>,
    /// カレントディレクトリ。`None` の場合は変更しない。
    pub current_dir: Option<&'a Path>,
    /// 実行ファイルの記述子の付け替え。
    pub redirect: Redirect<'a>,
}

/// 実行ファイルの記述子の付け替え。
#[derive(Default, Clone, Copy)]
pub enum Redirect<'a> {
    /// 付け替えない。
    #[default]
    None,
    /// 標準出力を、書き込めないパイプにする。
    BrokenStdout,
    /// 記述子 3 を、指定したファイルの読み込みにする。
    DescriptorThreeFrom(&'a Path),
    /// 標準入力、標準出力、標準エラー出力を、制御端末にする。
    Terminal,
}

/// `RLIMIT_MEMLOCK` のソフトとハードの上限を `limit` にする。`fork` 後の子プロセスで呼べる。
pub fn set_memory_lock_limit(limit: libc::rlim_t) -> std::io::Result<()> {
    let limit = libc::rlimit {
        rlim_cur: limit,
        rlim_max: limit,
    };
    // SAFETY: `limit` は有効な構造体で、呼び出しの間は生存している。
    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 子の起動と、後から `FD_CLOEXEC` を付ける記述子の作成を、並行するテストの間で直列化する。
///
/// macOS には `pipe2` が無く、パイプの作成と `FD_CLOEXEC` の設定の間に別のスレッドが子を起動すると、
/// 記述子が引き継がれる。引き継がれると、読み手を閉じたパイプへの書き込みが失敗せず、
/// 入力を閉じても終端が届かない。
pub fn spawn_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    // 保護する状態は無いため、他のテストが失敗していても使える。
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 疑似端末で実行ファイルを動かしているシェル。破棄時に、プロセスグループごと強制終了する。
pub struct Session {
    pub shell: Child,
    pub pty: Pty,
    pub initial: libc::termios,
    pub lines: Receiver<String>,
}

/// 終了した実行ファイルの結果。
pub struct Outcome {
    pub status: i32,
    /// 終了コードの報告より前の標準出力。
    pub stdout: String,
    pub stderr: String,
    pub screen: String,
}

impl Session {
    pub fn spawn(args: &[&str], options: &Options<'_>) -> Result<Self, Box<dyn Error>> {
        let guard = spawn_lock();
        let pty = Pty::open()?;
        let initial = attributes(pty.slave.as_raw_fd())?;
        let slave = pty.slave.as_raw_fd();
        let memlock_limit = options.memlock_limit;
        let script = match options.redirect {
            Redirect::None => SHELL_SCRIPT,
            Redirect::BrokenStdout => BROKEN_STDOUT_SCRIPT,
            Redirect::DescriptorThreeFrom(_) => DESCRIPTOR_SCRIPT,
            Redirect::Terminal => TERMINAL_SCRIPT,
        };
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script, env!("CARGO_BIN_EXE_fidelogic-cli")])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
        // `setsid`、`ioctl`、`setrlimit` は非同期シグナルセーフで、ヒープ確保などは行わない。
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // 要求番号の型は OS によって異なるため、引数の型に合わせて変換する。
                if libc::ioctl(slave, libc::TIOCSCTTY as _, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(limit) = memlock_limit {
                    set_memory_lock_limit(limit)?;
                }
                Ok(())
            });
        }
        if let Redirect::DescriptorThreeFrom(source) = options.redirect {
            command.env(DESCRIPTOR_SOURCE, source);
        }
        if let Some(directory) = options.current_dir {
            command.current_dir(directory);
        }
        let mut shell = command.spawn()?;
        drop(guard);
        let mut stdin = shell.stdin.take().ok_or("子の標準入力がありません。")?;
        if let Some(contents) = options.stdin {
            stdin.write_all(contents)?;
        }
        drop(stdin);
        let stdout = shell.stdout.take().ok_or("子の標準出力がありません。")?;
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            shell,
            pty,
            initial,
            lines,
        })
    }

    /// 画面に `text` が `count` 回出るまで待つ。先に実行ファイルが終了した場合は失敗する。
    pub fn wait_for_screen(&mut self, text: &str, count: usize) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            self.pty.drain_screen()?;
            if self.pty.text().matches(text).count() >= count {
                return Ok(());
            }
            if let Ok(line) = self.lines.try_recv() {
                return Err(format!(
                    "{text} の表示の前に出力がありました: {line}。画面: {}",
                    self.pty.text()
                )
                .into());
            }
            if Instant::now() > deadline {
                return Err(format!("{text} が表示されませんでした: {}", self.pty.text()).into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 利用者の入力として、`input` を書き込む。
    pub fn type_input(&mut self, input: &[u8]) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        let mut remaining = input;
        while !remaining.is_empty() {
            // SAFETY: `remaining` は指定した長さの読み取り可能な領域である。
            let written = unsafe {
                libc::write(
                    self.pty.master.as_raw_fd(),
                    remaining.as_ptr().cast(),
                    remaining.len(),
                )
            };
            match usize::try_from(written) {
                Ok(count) => {
                    remaining = remaining.get(count..).ok_or("書き込み長が不正です。")?;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
            self.pty.drain_screen()?;
            if Instant::now() > deadline {
                return Err("端末への入力が時間内に終わりませんでした。".into());
            }
        }
        Ok(())
    }

    /// プロンプトを待って、1 行を入力する。
    pub fn answer(&mut self, prompt: &str, line: &str) -> TestResult {
        self.wait_for_screen(prompt, 1)?;
        self.type_input(format!("{line}\r").as_bytes())
    }

    /// 新しいパスワードを 2 回入力し、再入力の案内が出るまで待って、表示されたコードを返す。
    pub fn enter_password_and_read_code(&mut self) -> Result<String, Box<dyn Error>> {
        self.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
        self.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
        self.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
        displayed_code(&self.pty.text())
    }

    /// シェルを含むプロセスグループにシグナルを送る。
    pub fn send_signal(&self, signal: libc::c_int) -> TestResult {
        let group = i32::try_from(self.shell.id())?;
        // SAFETY: 起動したプロセスグループへシグナルを送るだけで、メモリを参照しない。
        if unsafe { libc::kill(-group, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// 実行ファイルの終了を待ち、端末属性の復元を確かめてから、シェルを終了させる。
    pub fn finish(mut self) -> Result<Outcome, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        let mut stdout = String::new();
        let status = loop {
            self.pty.drain_screen()?;
            match self.lines.recv_timeout(Duration::from_millis(5)) {
                Ok(line) => match line.strip_prefix("STATUS ") {
                    Some(status) => break status.parse::<i32>()?,
                    None => {
                        stdout.push_str(&line);
                        stdout.push('\n');
                    }
                },
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    return Err("終了コードの報告の前にシェルが終了しました。".into());
                }
            }
            if Instant::now() > deadline {
                return Err(format!("実行ファイルが終了しません: {}", self.pty.text()).into());
            }
        };
        self.pty.drain_screen()?;
        assert!(
            same_attributes(&self.initial, &attributes(self.pty.slave.as_raw_fd())?),
            "端末属性の復元に失敗。"
        );
        let screen = self.pty.text();
        self.type_input(b"\r")?;
        while self.shell.try_wait()?.is_none() {
            self.pty.drain_screen()?;
            if Instant::now() > deadline {
                return Err("シェルが時間内に終了しませんでした。".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut stderr = String::new();
        self.shell
            .stderr
            .take()
            .ok_or("子の標準エラー出力がありません。")?
            .read_to_string(&mut stderr)?;
        Ok(Outcome {
            status,
            stdout,
            stderr,
            screen,
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // 失敗したテストで子が残らないようにする。端末の出力待ちで停止しうるため、終了は待たない。
        if matches!(self.shell.try_wait(), Ok(None)) {
            let _ = self.send_signal(libc::SIGKILL);
        }
        let _ = self.shell.try_wait();
    }
}

/// 画面の、リカバリーキットの見出しより後にある最初のコードを返す。
pub fn displayed_code(screen: &str) -> Result<String, Box<dyn Error>> {
    let (_, after) = screen
        .split_once(KIT_HEADING)
        .ok_or("リカバリーキットの見出しがありません。")?;
    let start = after.find("FL").ok_or("コードがありません。")?;
    let code = after
        .get(start..start + GROUPED_CODE_LEN)
        .ok_or("コードが途中で切れています。")?;
    Ok(code.to_owned())
}

/// コードの末尾 5 文字を返す。
pub fn suffix(code: &str) -> Result<&str, Box<dyn Error>> {
    Ok(code
        .get(GROUPED_CODE_LEN - 5..)
        .ok_or("コードが短すぎます。")?)
}

pub fn read_vault(path: &Path) -> Result<Vault, Box<dyn Error>> {
    let contents = fs::read(path)?;
    let (vault, rest) = deserialize(&contents).map_err(|error| format!("{error}"))?;
    assert!(
        rest.is_empty(),
        "末尾の余分なバイトが無いことの確認に失敗。"
    );
    Ok(vault)
}
pub fn mode_of(path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
}

pub fn text(path: &Path) -> Result<&str, Box<dyn Error>> {
    Ok(path.to_str().ok_or("パスが UTF-8 ではありません。")?)
}

/// 失敗の終了コードと、1 行のエラー出力を確かめる。
pub fn assert_failure(outcome: &Outcome, status: i32, message: &str) {
    assert_eq!(
        outcome.status, status,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(outcome.stdout.is_empty(), "標準出力が空ではありません。");
    assert!(
        outcome.stderr.starts_with("fidelogic-cli: ")
            && outcome.stderr.lines().count() == 1
            && outcome.stderr.contains(message),
        "エラー出力の確認に失敗: {}",
        outcome.stderr
    );
}

/// 代替画面に入ってからコードを表示し、画面を消去して戻った後には、コードが出ないこと。
pub fn assert_code_only_on_alternate_screen(screen: &str, code: &str) -> TestResult {
    let (before, inside) = screen
        .split_once(ENTER_ALTERNATE_SCREEN)
        .ok_or("代替画面への切り替えがありません。")?;
    let (inside, after) = inside
        .split_once(LEAVE_ALTERNATE_SCREEN)
        .ok_or("画面の消去と、元の画面への復帰がありません。")?;
    assert!(!before.contains(code) && !after.contains(code));
    assert!(inside.contains(code), "代替画面でのコードの表示に失敗。");
    assert!(inside.contains(WARNING), "警告の表示に失敗。");
    Ok(())
}
