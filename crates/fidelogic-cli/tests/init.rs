//! `init` サブコマンドの統合テスト。
//!
//! 親が疑似端末を作成し、シェルを子の制御端末のセッションリーダーとして起動して、その下で実行ファイルを動かす。
//! 親は疑似端末のマスター側から入力し、画面の内容と、作成されたファイルを確かめる。
//! シェルは実行ファイルの終了コードを報告した後、親が許可するまで終了しない。
//! macOS では、セッションリーダーが終了すると端末が無効になるため、終了の前に端末属性を調べる必要がある。

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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fidelogic_cli::sys::storage::{VaultLock, VaultPath};
use fidelogic_core::{
    Argon2Params, Argon2idSlotPayload, KekSlots, LockedBuffer, SlotStatus, Vault, VaultEngine,
    deserialize,
};

type TestResult = Result<(), Box<dyn Error>>;

/// 子の応答を待つ上限。最適化しないビルドの鍵導出の時間を含む。
const TIMEOUT: Duration = Duration::from_secs(120);

/// 実行ファイルを起動し、終了コードを報告して、親の許可を待つシェルの処理。
///
/// シグナルは無視せず捕捉する。無視の設定は実行ファイルに引き継がれ、中断を試せなくなるためである。
const SHELL_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
"$0" "$@"
printf 'STATUS %s\n' "$?"
read -r release < /dev/tty
"#;

/// [`SHELL_SCRIPT`] と同じ処理で、実行ファイルの標準出力を、読み手のいないパイプにする。
///
/// パイプの読み手の `true` は、入力を読まずに直ちに終了する。終了コードの報告は、元の標準出力に書く。
const BROKEN_STDOUT_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
exec 3>&1
{ "$0" "$@"; printf 'STATUS %s\n' "$?" >&3; } | true
read -r release < /dev/tty
"#;

/// [`SHELL_SCRIPT`] と同じ処理で、記述子 3 を [`DESCRIPTOR_SOURCE`] のファイルにして実行ファイルを起動する。
const DESCRIPTOR_SCRIPT: &str = r#"trap ':' INT QUIT TERM HUP
"$0" "$@" 3<"$FIDELOGIC_CLI_INIT_DESCRIPTOR_SOURCE"
printf 'STATUS %s\n' "$?"
read -r release < /dev/tty
"#;

/// [`DESCRIPTOR_SCRIPT`] が記述子 3 に開くファイルを指定する環境変数の名前。
const DESCRIPTOR_SOURCE: &str = "FIDELOGIC_CLI_INIT_DESCRIPTOR_SOURCE";

/// `mlock` の可否を調べる子プロセスであることを示す環境変数の名前。
const PROBE_MARKER: &str = "FIDELOGIC_CLI_INIT_MEMLOCK_PROBE";

/// 調べた子プロセスで、`mlock` に成功したことを示す出力。
const PROBE_LOCKED: &str = "init-probe:locked";

/// 調べた子プロセスで、`mlock` に失敗したことを示す出力。
const PROBE_REFUSED: &str = "init-probe:refused";

const NEW_PASSWORD_PROMPT: &str = "新しいマスターパスワード: ";
const REPEAT_PASSWORD_PROMPT: &str = "もう一度入力してください: ";
const CONFIRMATION_PROMPT: &str = "末尾 5 文字 (入力は表示されません): ";
const KIT_HEADING: &str = "リカバリーキット ==";
const WARNING: &str = "このコードは、単独で Vault 全体を復号できます。";
const ENTER_ALTERNATE_SCREEN: &str = "\x1b[?1049h";
const LEAVE_ALTERNATE_SCREEN: &str = "\x1b[H\x1b[2J\x1b[?1049l";

/// 表示用のリカバリーコードの文字数。
const GROUPED_CODE_LEN: usize = 35;

const PASSWORD: &str = "correct horse battery staple";

/// テスト用の一時ディレクトリ。破棄するときに中身ごと削除する。
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, Box<dyn Error>> {
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

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// 中にあるファイルの名前を、整列して返す。
    fn names(&self) -> Result<Vec<String>, Box<dyn Error>> {
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
fn attributes(descriptor: RawFd) -> Result<libc::termios, Box<dyn Error>> {
    // SAFETY: 全ビット 0 は `termios` の有効な値である。
    let mut value: libc::termios = unsafe { core::mem::zeroed() };
    // SAFETY: `value` は書き込み可能な有効な構造体である。
    if unsafe { libc::tcgetattr(descriptor, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(value)
}

/// 端末属性が同じかを判定する。`PENDIN` は、BSD 系のカーネルが立てることがあるため除く。
fn same_attributes(left: &libc::termios, right: &libc::termios) -> bool {
    left.c_iflag == right.c_iflag
        && left.c_oflag == right.c_oflag
        && left.c_cflag == right.c_cflag
        && left.c_lflag & !libc::PENDIN == right.c_lflag & !libc::PENDIN
        && left.c_cc == right.c_cc
}

/// 疑似端末の両端。
struct Pty {
    /// 利用者の側。読み込みは非ブロッキングである。
    master: OwnedFd,
    /// プログラムの側。子の終了まで開いておく。
    slave: OwnedFd,
    /// 画面に出力された内容。
    screen: Vec<u8>,
}

impl Pty {
    fn open() -> Result<Self, Box<dyn Error>> {
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
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: `openpty` が成功した直後の記述子で、所有者は他に無い。
        let (master, slave) =
            unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
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
    fn drain_screen(&mut self) -> TestResult {
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

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.screen).into_owned()
    }
}

/// 実行ファイルの起動の指定。
#[derive(Default)]
struct Options<'a> {
    /// 標準入力に渡す内容。`None` の場合は空の入力にする。
    stdin: Option<&'a [u8]>,
    /// `RLIMIT_MEMLOCK` の上限。`None` の場合は変更しない。
    memlock_limit: Option<libc::rlim_t>,
    /// カレントディレクトリ。`None` の場合は変更しない。
    current_dir: Option<&'a Path>,
    /// 実行ファイルの記述子の付け替え。
    redirect: Redirect<'a>,
}

/// 実行ファイルの記述子の付け替え。
#[derive(Default, Clone, Copy)]
enum Redirect<'a> {
    /// 付け替えない。
    #[default]
    None,
    /// 標準出力を、書き込めないパイプにする。
    BrokenStdout,
    /// 記述子 3 を、指定したファイルの読み込みにする。
    DescriptorThreeFrom(&'a Path),
}

/// `RLIMIT_MEMLOCK` のソフトとハードの上限を `limit` にする。`fork` 後の子プロセスで呼べる。
fn set_memory_lock_limit(limit: libc::rlim_t) -> std::io::Result<()> {
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

/// 疑似端末で `init` を実行しているシェル。破棄時に、プロセスグループごと強制終了する。
struct Session {
    shell: Child,
    pty: Pty,
    initial: libc::termios,
    lines: Receiver<String>,
}

/// 終了した `init` の結果。
struct Outcome {
    status: i32,
    /// 終了コードの報告より前の標準出力。
    stdout: String,
    stderr: String,
    screen: String,
}

impl Session {
    fn spawn(args: &[&str], options: &Options<'_>) -> Result<Self, Box<dyn Error>> {
        let pty = Pty::open()?;
        let initial = attributes(pty.slave.as_raw_fd())?;
        let slave = pty.slave.as_raw_fd();
        let memlock_limit = options.memlock_limit;
        let script = match options.redirect {
            Redirect::None => SHELL_SCRIPT,
            Redirect::BrokenStdout => BROKEN_STDOUT_SCRIPT,
            Redirect::DescriptorThreeFrom(_) => DESCRIPTOR_SCRIPT,
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
    fn wait_for_screen(&mut self, text: &str, count: usize) -> TestResult {
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
    fn type_input(&mut self, input: &[u8]) -> TestResult {
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
    fn answer(&mut self, prompt: &str, line: &str) -> TestResult {
        self.wait_for_screen(prompt, 1)?;
        self.type_input(format!("{line}\r").as_bytes())
    }

    /// 新しいパスワードを 2 回入力し、再入力の案内が出るまで待って、表示されたコードを返す。
    fn enter_password_and_read_code(&mut self) -> Result<String, Box<dyn Error>> {
        self.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
        self.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
        self.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
        displayed_code(&self.pty.text())
    }

    /// シェルを含むプロセスグループにシグナルを送る。
    fn send_signal(&self, signal: libc::c_int) -> TestResult {
        let group = i32::try_from(self.shell.id())?;
        // SAFETY: 起動したプロセスグループへシグナルを送るだけで、メモリを参照しない。
        if unsafe { libc::kill(-group, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// 実行ファイルの終了を待ち、端末属性の復元を確かめてから、シェルを終了させる。
    fn finish(mut self) -> Result<Outcome, Box<dyn Error>> {
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
fn displayed_code(screen: &str) -> Result<String, Box<dyn Error>> {
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
fn suffix(code: &str) -> Result<&str, Box<dyn Error>> {
    Ok(code
        .get(GROUPED_CODE_LEN - 5..)
        .ok_or("コードが短すぎます。")?)
}

fn read_vault(path: &Path) -> Result<Vault, Box<dyn Error>> {
    let contents = fs::read(path)?;
    let (vault, rest) = deserialize(&contents).map_err(|error| format!("{error}"))?;
    assert!(
        rest.is_empty(),
        "末尾の余分なバイトが無いことの確認に失敗。"
    );
    Ok(vault)
}

fn engine() -> VaultEngine {
    VaultEngine::new(KekSlots::new(
        SlotStatus::Valid,
        SlotStatus::Unset,
        SlotStatus::Valid,
    ))
}

/// 作成された Vault を、パスワードと、表示されたリカバリーコードのそれぞれで解錠できること。
fn assert_vault_unlocks(path: &Path, password: &str, code: &str) -> TestResult {
    let vault = read_vault(path)?;
    assert_eq!(vault.header.epoch_id, 1);
    // 作成した Vault が、ネイティブ向けの鍵導出パラメータを使うこと。
    let password_slot = vault.slots.first().ok_or("Slot 0 がありません。")?;
    let params = Argon2idSlotPayload::from_slot_entry(password_slot)
        .map_err(|error| format!("{error}"))?
        .params;
    let expected = Argon2Params::for_native();
    assert_eq!(
        (params.m_cost(), params.t_cost(), params.p_cost()),
        (expected.m_cost(), expected.t_cost(), expected.p_cost()),
        "鍵導出パラメータの確認に失敗。"
    );
    engine()
        .unlock_vault_with_password(&vault, password.as_bytes())
        .map_err(|error| format!("パスワードでの解錠に失敗: {error}"))?;
    engine()
        .unlock_vault_with_recovery_code(&vault, code.as_bytes())
        .map_err(|error| format!("リカバリーコードでの解錠に失敗: {error}"))?;
    assert!(
        engine()
            .unlock_vault_with_password(&vault, b"wrong password")
            .is_err(),
        "誤ったパスワードの拒否に失敗。"
    );
    Ok(())
}

fn mode_of(path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(fs::symlink_metadata(path)?.permissions().mode() & 0o7777)
}

fn text(path: &Path) -> Result<&str, Box<dyn Error>> {
    Ok(path.to_str().ok_or("パスが UTF-8 ではありません。")?)
}

/// 失敗の終了コードと、1 行のエラー出力を確かめる。
fn assert_failure(outcome: &Outcome, status: i32, message: &str) {
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
fn assert_code_only_on_alternate_screen(screen: &str, code: &str) -> TestResult {
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

#[test]
fn test_init_creates_vault_after_confirmation() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let mut session = Session::spawn(&["init", "--vault", text(&vault)?], &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    assert_eq!(
        dir.names()?,
        ["vault.fvl.lock"],
        "確認の前に Vault を作らないことの確認に失敗。"
    );
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    assert!(outcome.stdout.contains("Vault を作成しました"));
    assert!(!outcome.stdout.contains(&code));
    assert!(
        !outcome.screen.contains(PASSWORD),
        "パスワードが表示されないことの確認に失敗。"
    );
    // コードの全体に含まれる分の他に、再入力した末尾が表示されないこと。
    assert_eq!(
        outcome.screen.matches(suffix(&code)?).count(),
        1,
        "再入力が表示されないことの確認に失敗。"
    );
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    assert_eq!(mode_of(&vault)?, 0o600);
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

#[test]
fn test_init_writes_html_kit_with_password_file() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let password_file = dir.path("password");
    fs::write(&password_file, format!("{PASSWORD}\n"))?;
    fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600))?;
    let args = [
        "init",
        "--vault",
        text(&vault)?,
        "--kit-html",
        text(&kit)?,
        "--password-file",
        text(&password_file)?,
    ];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    assert!(
        !vault.exists() && kit.exists(),
        "確認の前の状態の確認に失敗。"
    );
    // 小文字と、区切りの `-` と空白を含む形でも、確認を通ること。
    let spaced: String = suffix(&code)?
        .to_lowercase()
        .chars()
        .flat_map(|symbol| [symbol, ' ', '-'])
        .collect();
    session.type_input(format!(" {spaced}\r").as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert!(outcome.stdout.contains("リカバリーキットを書き出しました"));
    assert_eq!(mode_of(&kit)?, 0o600);
    let html = fs::read_to_string(&kit)?;
    assert_eq!(
        html.matches(&code).count(),
        1,
        "HTML のコードの確認に失敗。"
    );
    assert!(html.contains(WARNING));
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

#[test]
fn test_init_accepts_relative_paths() -> TestResult {
    let dir = TempDir::new()?;
    let options = Options {
        current_dir: Some(&dir.0),
        ..Options::default()
    };
    let args = ["init", "--vault", "vault.fvl", "--kit-html", "kit.html"];
    let mut session = Session::spawn(&args, &options)?;
    let code = session.enter_password_and_read_code()?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    // 親ディレクトリの同期の失敗は、警告として標準エラー出力に出る。
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    assert_eq!(dir.names()?, ["kit.html", "vault.fvl", "vault.fvl.lock"]);
    assert_vault_unlocks(&dir.path("vault.fvl"), PASSWORD, &code)
}

#[test]
fn test_init_reads_password_from_standard_input() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    // 全角の空白は ASCII の空白に正準化する。
    let input = format!("{}\n", PASSWORD.replace(' ', "\u{3000}"));
    let options = Options {
        stdin: Some(input.as_bytes()),
        ..Options::default()
    };
    let args = ["init", "--vault", text(&vault)?, "--password-stdin"];
    let mut session = Session::spawn(&args, &options)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 引き継いだ記述子から読む場合も、本体が開く端末やロックファイルと取り違えずに作成できること。
#[test]
fn test_init_reads_password_from_inherited_descriptor() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let password_source = dir.path("password");
    fs::write(&password_source, format!("{PASSWORD}\n"))?;
    let options = Options {
        redirect: Redirect::DescriptorThreeFrom(&password_source),
        ..Options::default()
    };
    let args = ["init", "--vault", text(&vault)?, "--password-fd", "3"];
    let mut session = Session::spawn(&args, &options)?;
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    let code = displayed_code(&session.pty.text())?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

#[test]
fn test_wrong_confirmation_redraws_kit_and_asks_again() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let mut session = Session::spawn(&["init", "--vault", text(&vault)?], &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    let too_long = "A".repeat(2000);
    for (attempt, wrong) in ["UUUUU", "", too_long.as_str()].into_iter().enumerate() {
        session.type_input(format!("{wrong}\r").as_bytes())?;
        session.wait_for_screen(CONFIRMATION_PROMPT, attempt + 2)?;
        assert!(
            !vault.exists(),
            "不一致で Vault を作らないことの確認に失敗。"
        );
    }
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert_eq!(outcome.screen.matches("一致しません。").count(), 3);
    assert_eq!(
        outcome.screen.matches(&code).count(),
        4,
        "同じコードの描き直しの確認に失敗。"
    );
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 作成の後に結果を書き込めない場合は失敗を報告し、作成した Vault と HTML を残すこと。
#[test]
fn test_output_failure_after_creation_keeps_vault_and_kit() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let options = Options {
        redirect: Redirect::BrokenStdout,
        ..Options::default()
    };
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &options)?;
    let code = session.enter_password_and_read_code()?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "標準出力への書き込みに失敗しました");
    assert_eq!(dir.names()?, ["kit.html", "vault.fvl", "vault.fvl.lock"]);
    assert!(fs::read_to_string(&kit)?.contains(&code));
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 再入力の前に中止した場合は、Vault も HTML も残さず、画面を消去して元の画面に戻ること。
fn assert_abort_during_confirmation(
    abort: impl FnOnce(&mut Session) -> TestResult,
    status: i32,
    message: &str,
) -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    abort(&mut session)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, status, message);
    assert_code_only_on_alternate_screen(&outcome.screen, &code)?;
    assert_eq!(
        dir.names()?,
        ["vault.fvl.lock"],
        "中止後のファイルの確認に失敗。"
    );
    Ok(())
}

#[test]
fn test_interrupt_key_during_confirmation_leaves_nothing() -> TestResult {
    assert_abort_during_confirmation(|session| session.type_input(b"\x03"), 130, "中断")
}

#[test]
fn test_termination_signal_during_confirmation_leaves_nothing() -> TestResult {
    assert_abort_during_confirmation(|session| session.send_signal(libc::SIGTERM), 130, "中断")
}

#[test]
fn test_end_of_input_during_confirmation_leaves_nothing() -> TestResult {
    assert_abort_during_confirmation(
        |session| session.type_input(b"\x04"),
        1,
        "リカバリーコードの控えを確認できないため",
    )
}

#[test]
fn test_vault_created_during_confirmation_is_not_replaced() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    let code = session.enter_password_and_read_code()?;
    // ロックに従わない処理が、確認の間にファイルを作る。
    fs::write(&vault, b"created by another program")?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "ファイルがすでに存在するため");
    assert_eq!(fs::read(&vault)?, b"created by another program");
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

/// パスワードの入力の段階で失敗する場合は、リカバリーキットを表示せず、ファイルを作らないこと。
fn assert_password_failure(
    input: impl FnOnce(&mut Session) -> TestResult,
    status: i32,
    message: &str,
) -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    input(&mut session)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, status, message);
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_mismatched_passwords_create_nothing() -> TestResult {
    assert_password_failure(
        |session| {
            session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
            session.answer(REPEAT_PASSWORD_PROMPT, &PASSWORD.to_uppercase())
        },
        1,
        "2 つのパスワードが一致しません",
    )
}

#[test]
fn test_disallowed_password_creates_nothing() -> TestResult {
    assert_password_failure(
        |session| session.answer(NEW_PASSWORD_PROMPT, "a\tb"),
        1,
        "使用できない文字",
    )
}

#[test]
fn test_empty_password_creates_nothing() -> TestResult {
    assert_password_failure(
        |session| session.answer(NEW_PASSWORD_PROMPT, ""),
        1,
        "パスワードが空です",
    )
}

#[test]
fn test_interrupt_during_password_input_creates_nothing() -> TestResult {
    assert_password_failure(
        |session| {
            session.wait_for_screen(NEW_PASSWORD_PROMPT, 1)?;
            session.type_input(b"partial\x03")
        },
        130,
        "中断",
    )
}

/// パスワードの入力より前に失敗する場合は、何も入力を求めないこと。
fn assert_rejected_before_password(args: &[&str], message: &str) -> TestResult {
    let outcome = Session::spawn(args, &Options::default())?.finish()?;
    assert_failure(&outcome, 1, message);
    assert!(
        !outcome.screen.contains(NEW_PASSWORD_PROMPT),
        "入力を求めないことの確認に失敗: {}",
        outcome.screen
    );
    Ok(())
}

#[test]
fn test_existing_vault_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    fs::write(&vault, b"existing")?;
    assert_rejected_before_password(
        &["init", "--vault", text(&vault)?],
        "ファイルがすでに存在するため",
    )?;
    assert_eq!(fs::read(&vault)?, b"existing");
    Ok(())
}

#[test]
fn test_existing_kit_destination_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    fs::write(&kit, b"existing")?;
    assert_rejected_before_password(
        &["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?],
        "出力先にファイルがすでに存在するため",
    )?;
    assert_eq!(fs::read(&kit)?, b"existing");
    assert_eq!(dir.names()?, ["kit.html", "vault.fvl.lock"]);
    Ok(())
}

/// 出力先がディレクトリ、または参照先の無いシンボリックリンクの場合も、パスワードを読み込む前に拒否すること。
#[test]
fn test_kit_destination_with_other_entry_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let target = dir.path("target");
    let link = dir.path("link.html");
    std::os::unix::fs::symlink(&target, &link)?;
    let directory = dir.path("directory");
    fs::create_dir(&directory)?;
    for kit in [&link, &directory] {
        assert_rejected_before_password(
            &["init", "--vault", text(&vault)?, "--kit-html", text(kit)?],
            "出力先にファイルがすでに存在するため",
        )?;
    }
    assert!(
        fs::symlink_metadata(&link)?.file_type().is_symlink() && !target.exists(),
        "リンクと参照先を変えないことの確認に失敗。"
    );
    assert_eq!(dir.names()?, ["directory", "link.html", "vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_locked_vault_is_rejected_without_waiting() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let lock = VaultLock::try_acquire(VaultPath::resolve(&vault)?)?;
    assert_rejected_before_password(
        &["init", "--vault", text(&vault)?],
        "他の処理が Vault を使用中です",
    )?;
    drop(lock);
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_kit_destination_equal_to_vault_is_rejected() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    // 異なる表記で、同じファイルを指定する。
    let kit = dir.0.join(".").join("vault.fvl");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "出力先が Vault のパスと重なっています");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_unwritable_kit_destination_fails_before_display() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("missing").join("kit.html");
    let args = ["init", "--vault", text(&vault)?, "--kit-html", text(&kit)?];
    let mut session = Session::spawn(&args, &Options::default())?;
    session.answer(NEW_PASSWORD_PROMPT, PASSWORD)?;
    session.answer(REPEAT_PASSWORD_PROMPT, PASSWORD)?;
    let outcome = session.finish()?;

    assert_failure(&outcome, 1, "出力先のファイルの作成に失敗しました");
    assert!(!outcome.screen.contains(ENTER_ALTERNATE_SCREEN));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

/// 非特権の環境の標準的な上限 (64 KiB) でも、鍵導出と秘密のバッファの確保が両立すること。
#[test]
fn test_init_succeeds_with_small_memory_lock_limit() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let options = Options {
        memlock_limit: Some(64 * 1024),
        ..Options::default()
    };
    let mut session = Session::spawn(&["init", "--vault", text(&vault)?], &options)?;
    let code = session.enter_password_and_read_code()?;
    session.type_input(format!("{}\r", suffix(&code)?).as_bytes())?;
    let outcome = session.finish()?;

    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert_vault_unlocks(&vault, PASSWORD, &code)
}

/// 子プロセスの中で、`mlock` できるかを報告する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_probe_memory_lock() -> TestResult {
    if std::env::var_os(PROBE_MARKER).is_none() {
        return Ok(());
    }
    let report = if LockedBuffer::<1>::zero_strict().is_ok() {
        PROBE_LOCKED
    } else {
        PROBE_REFUSED
    };
    writeln!(std::io::stdout(), "\n{report}")?;
    Ok(())
}

/// `RLIMIT_MEMLOCK` を 0 にしたプロセスで、`mlock` が失敗する環境かを返す。
///
/// 検査する実行ファイルの振る舞いに依存しないよう、テストバイナリを子プロセスとして再実行して調べる。
/// `CAP_IPC_LOCK` を持つプロセスなどは、上限を 0 にしても `mlock` が成功する。
fn memory_lock_can_be_refused() -> Result<bool, Box<dyn Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "child_probe_memory_lock",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(PROBE_MARKER, "1");
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setrlimit` は非同期シグナルセーフで、ヒープ確保などは行わない。
    unsafe {
        command.pre_exec(|| set_memory_lock_limit(0));
    }
    let output = command.output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let reported = |report: &str| stdout.lines().any(|line| line == report);
    match (reported(PROBE_REFUSED), reported(PROBE_LOCKED)) {
        (true, false) if output.status.success() => Ok(true),
        (false, true) if output.status.success() => Ok(false),
        _ => Err(format!("mlock の可否の確認に失敗しました: {stdout}").into()),
    }
}

/// 秘密のバッファを `mlock` できない場合は、入力を求めずに中止すること。
///
/// 上の上限のテストが、上限を実際に適用していることの対照でもある。
/// 上限を 0 にしても `mlock` が成功する環境では、スキップする。
#[test]
fn test_init_fails_closed_without_memory_lock() -> TestResult {
    if !memory_lock_can_be_refused()? {
        writeln!(
            std::io::stderr(),
            "スキップ: この環境では mlock の失敗を再現できません。"
        )?;
        return Ok(());
    }
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let options = Options {
        memlock_limit: Some(0),
        ..Options::default()
    };
    let outcome = Session::spawn(&["init", "--vault", text(&vault)?], &options)?.finish()?;

    assert_failure(&outcome, 1, "メモリロックに失敗しました");
    assert!(!outcome.screen.contains(NEW_PASSWORD_PROMPT));
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

/// 端末の無い環境では、入力元の指定があっても作成せず、ファイルに触れないこと。
#[test]
fn test_init_requires_controlling_terminal() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.path("vault.fvl");
    let kit = dir.path("kit.html");
    let mut command = Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"));
    command
        .args(["init", "--vault", text(&vault)?, "--password-stdin"])
        .args(["--kit-html", text(&kit)?])
        .stdin(Stdio::null());
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setsid` は非同期シグナルセーフである。新しいセッションは制御端末を持たない。
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr)?,
        "fidelogic-cli: リカバリーコードの表示と確認に端末が必要です。端末から実行してください。\n"
    );
    assert!(
        dir.names()?.is_empty(),
        "ファイルに触れないことの確認に失敗。"
    );
    Ok(())
}
