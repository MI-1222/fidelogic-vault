//! 制御端末からの入力の統合テスト。
//!
//! 親が疑似端末を作成し、テストバイナリを子プロセスとして再実行して、疑似端末を子の制御端末にする。
//! 子は [`read_password`] で `/dev/tty` から読み込み、結果と端末属性の復元を標準出力に報告する。
//! 親は疑似端末のマスター側から入力し、画面に出る内容と端末属性を確かめる。

use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use fidelogic_cli::error::CliError;
use fidelogic_cli::secret_input::{MAX_PASSWORD_LEN, PasswordSource, read_password};
use fidelogic_cli::sys::signal::InterruptWatcher;

type TestResult = Result<(), Box<dyn Error>>;

/// 子プロセスとして動作することを示す環境変数の名前。
const CHILD_MARKER: &str = "FIDELOGIC_CLI_TTY_CHILD";

/// 子が端末に表示するプロンプト。
const PROMPT: &str = "PASSWORD> ";

/// 子がプロンプトの後ろに足す文字数を指定する環境変数の名前。
const CHILD_PROMPT_PADDING: &str = "FIDELOGIC_CLI_TTY_PROMPT_PADDING";

/// 疑似端末の出力バッファに収まらない、プロンプトの追加の文字数。
const STALLING_PROMPT_PADDING: usize = 1 << 20;

/// 子の応答を待つ上限。
const TIMEOUT: Duration = Duration::from_secs(30);

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

/// 端末属性が同じかを判定する。
///
/// BSD 系のカーネルは、行入力モードへ戻すときに `PENDIN` を立てることがあるため、比較から除く。
fn same_attributes(left: &libc::termios, right: &libc::termios) -> bool {
    left.c_iflag == right.c_iflag
        && left.c_oflag == right.c_oflag
        && left.c_cflag == right.c_cflag
        && left.c_lflag & !libc::PENDIN == right.c_lflag & !libc::PENDIN
        && left.c_cc == right.c_cc
}

/// 子プロセスの中で実行する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_read_from_terminal() -> TestResult {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return Ok(());
    }
    // 親が無視する設定でも、子では既定の扱いから始める。
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: `SIG_DFL` の設定は、ハンドラーの関数を持たない。
        unsafe { libc::signal(signal, libc::SIG_DFL) };
    }
    let watcher = InterruptWatcher::install()?;
    let terminal = std::fs::File::open("/dev/tty").ok();
    let before = match &terminal {
        Some(file) => Some(attributes(file.as_raw_fd())?),
        None => None,
    };

    let padding = std::env::var(CHILD_PROMPT_PADDING)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(0);
    let prompt = format!("{PROMPT}{}", ".".repeat(padding));

    let result = read_password(&PasswordSource::Terminal, &prompt, &watcher);

    // 切断された端末からは属性を読めないため、その場合は復元を報告しない。
    let restored = match (&terminal, &before) {
        (Some(file), Some(before)) => attributes(file.as_raw_fd())
            .ok()
            .map(|after| same_attributes(before, &after)),
        _ => None,
    };
    let (outcome, exit_code) = match &result {
        Ok(secret) => {
            let hex: String = secret
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            (format!("Ok({hex})"), None)
        }
        Err(error) => (
            format!("Err({error:?})"),
            Some(CliError::from(*error).exit_category().code()),
        ),
    };
    drop(result);
    {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "\nOUTCOME {outcome}")?;
        writeln!(stdout, "RESTORED {restored:?}")?;
        stdout.flush()?;
    }
    // 親が端末の状態を調べ終えるまで待つ。
    let mut release = String::new();
    std::io::stdin().read_line(&mut release)?;
    drop(watcher);
    // 中断した場合は、CLI と同じ終了コードで終了する。
    if let Some(code @ 130) = exit_code {
        std::process::exit(i32::from(code));
    }
    Ok(())
}

/// 疑似端末の両端。
struct Pty {
    /// 利用者の側。読み込みは非ブロッキングである。
    master: Option<OwnedFd>,
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
            master: Some(master),
            slave,
            screen: Vec::new(),
        })
    }

    fn master(&self) -> Result<RawFd, Box<dyn Error>> {
        self.master
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .ok_or_else(|| "マスター側は閉じています。".into())
    }

    /// 画面に出力された内容を取り込む。
    fn drain_screen(&mut self) -> TestResult {
        let master = self.master()?;
        let mut chunk = [0u8; 4096];
        loop {
            // SAFETY: `chunk` は指定した長さの書き込み可能な領域で、記述子は非ブロッキングである。
            let read = unsafe { libc::read(master, chunk.as_mut_ptr().cast(), chunk.len()) };
            match usize::try_from(read) {
                Ok(count) if count > 0 => self
                    .screen
                    .extend_from_slice(chunk.get(..count).ok_or("読み込み長が不正です。")?),
                _ => return Ok(()),
            }
        }
    }

    /// 利用者の入力として、`input` を書き込む。
    fn type_input(&mut self, input: &[u8]) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        let mut remaining = input;
        while !remaining.is_empty() {
            // SAFETY: `remaining` は指定した長さの読み取り可能な領域である。
            let written =
                unsafe { libc::write(self.master()?, remaining.as_ptr().cast(), remaining.len()) };
            match usize::try_from(written) {
                Ok(count) => {
                    remaining = remaining.get(count..).ok_or("書き込み長が不正です。")?;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(5)),
            }
            self.drain_screen()?;
            if Instant::now() > deadline {
                return Err("端末への入力が時間内に終わりませんでした。".into());
            }
        }
        Ok(())
    }

    /// 画面にプロンプトが出るまで待つ。
    fn wait_for_prompt(&mut self) -> TestResult {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            self.drain_screen()?;
            if String::from_utf8_lossy(&self.screen).contains(PROMPT) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err("プロンプトが表示されませんでした。".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 後続のプログラム (シェルなど) が受け取る内容を調べる。改行を入力し、その 1 行を読む。
    fn next_line_for_following_program(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        self.type_input(b"\r")?;
        let mut line = [0u8; 4096];
        // SAFETY: `line` は指定した長さの書き込み可能な領域である。行入力モードで 1 行がそろっている。
        let read =
            unsafe { libc::read(self.slave.as_raw_fd(), line.as_mut_ptr().cast(), line.len()) };
        let count = usize::try_from(read).map_err(|_| std::io::Error::last_os_error())?;
        Ok(line.get(..count).ok_or("読み込み長が不正です。")?.to_vec())
    }
}

/// 端末から入力を読み込んでいる子プロセス。破棄時に強制終了する。
struct Reader {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Reader {
    /// 子プロセスを起動する。`pty` があれば子の制御端末にし、無ければ制御端末の無い状態にする。
    fn spawn(pty: Option<&Pty>) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_prompt_padding(pty, 0)
    }

    /// プロンプトの後ろに `padding` 文字を足す子プロセスを起動する。
    fn spawn_with_prompt_padding(
        pty: Option<&Pty>,
        padding: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let slave = pty.map(|pty| pty.slave.as_raw_fd());
        let mut command = Command::new(std::env::current_exe()?);
        command
            .args([
                "--exact",
                "child_read_from_terminal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_MARKER, "1")
            .env(CHILD_PROMPT_PADDING, padding.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped());
        // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
        // `setsid` と `ioctl` は非同期シグナルセーフで、ヒープ確保などの安全でない処理は行わない。
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // 要求番号の型は OS によって異なるため、引数の型に合わせて変換する。
                if let Some(slave) = slave
                    && libc::ioctl(slave, libc::TIOCSCTTY as _, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn()?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or("子の標準出力がありません。")?;
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
        })
    }

    /// `prefix` で始まる行を待ち、残りの部分を返す。
    fn wait_for(&self, prefix: &str) -> Result<String, Box<dyn Error>> {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(remaining) {
                Ok(line) => {
                    if let Some(rest) = line.strip_prefix(prefix) {
                        return Ok(rest.to_owned());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("{prefix} の報告が時間内にありませんでした。").into());
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!("{prefix} の報告の前に子が終了しました。").into());
                }
            }
        }
    }

    /// 読み込みの結果と、端末属性を復元したかを受け取る。
    fn outcome(&self) -> Result<(String, String), Box<dyn Error>> {
        Ok((self.wait_for("OUTCOME ")?, self.wait_for("RESTORED ")?))
    }

    fn send_signal(&self, signal: libc::c_int) -> TestResult {
        let pid = i32::try_from(self.child.id())?;
        // SAFETY: 起動した子プロセスへシグナルを送るだけで、メモリを参照しない。
        if unsafe { libc::kill(pid, signal) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    /// 子を先へ進め、終了コードを返す。
    ///
    /// macOS では、制御端末を持つ子の終了は、端末の出力が読み取られるまで完了しない。
    /// そのため、待つ間も画面の内容を取り込む。
    fn release(mut self, mut pty: Option<&mut Pty>) -> Result<Option<i32>, Box<dyn Error>> {
        if let Some(mut stdin) = self.stdin.take() {
            stdin.write_all(b"\n")?;
        }
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(pty) = pty.as_deref_mut()
                && pty.master.is_some()
            {
                pty.drain_screen()?;
            }
            if let Some(status) = self.child.try_wait()? {
                return Ok(status.code());
            }
            if Instant::now() > deadline {
                return Err("子プロセスが時間内に終了しませんでした。".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        // 失敗したテストで子が残らないようにする。端末の出力待ちで停止しうるため、終了は待たない。
        let _ = self.child.kill();
        let _ = self.child.try_wait();
    }
}

/// 成功した読み込みの報告の形にする。
fn ok_outcome(content: &[u8]) -> String {
    let hex: String = content.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("Ok({hex})")
}

/// 端末からの 1 回の読み込みで観測した内容。
struct Observation {
    /// 子が報告した結果。
    outcome: String,
    /// 読み込みを終えるまでに画面に出た内容。
    screen: String,
}

/// 子がプロンプトを表示した後に `input` を入力し、結果を返す。
///
/// 読み込み中はエコーと行入力モードが無効で、終了後は端末属性が元に戻ることと、
/// 読み込みの後に入力が残らないことも確かめる。
fn read_with_input(input: &[u8]) -> Result<Observation, Box<dyn Error>> {
    let mut pty = Pty::open()?;
    let initial = attributes(pty.slave.as_raw_fd())?;
    let reader = Reader::spawn(Some(&pty))?;
    pty.wait_for_prompt()?;

    let during = attributes(pty.slave.as_raw_fd())?;
    assert_eq!(
        during.c_lflag & (libc::ECHO | libc::ECHONL | libc::ICANON),
        0,
        "読み込み中のエコーと行入力モードの無効化に失敗。"
    );
    assert_ne!(
        during.c_lflag & libc::ISIG,
        0,
        "読み込み中のシグナル生成の有効化に失敗。"
    );

    pty.type_input(input)?;
    let (outcome, restored) = reader.outcome()?;
    assert_eq!(restored, "Some(true)", "端末属性の復元に失敗。");
    assert!(
        same_attributes(&initial, &attributes(pty.slave.as_raw_fd())?),
        "親から見た端末属性の復元に失敗。"
    );
    pty.drain_screen()?;
    let screen = String::from_utf8_lossy(&pty.screen).into_owned();
    // macOS では、制御端末を持つ子が終了すると端末が無効になるため、終了の前に調べる。
    assert_eq!(
        pty.next_line_for_following_program()?,
        b"\n",
        "読み残した入力の破棄に失敗。"
    );
    assert_eq!(reader.release(Some(&mut pty))?, Some(0));
    Ok(Observation { outcome, screen })
}

/// 画面の内容が、プロンプトと改行だけであることを確かめる。
fn assert_screen_shows_only_prompt(observation: &Observation) {
    assert_eq!(
        observation.screen,
        format!("{PROMPT}\r\n"),
        "入力が表示されないことの確認に失敗。"
    );
}

#[test]
fn test_terminal_input_is_not_echoed() -> TestResult {
    let observation = read_with_input(b"s3cret-pw\r")?;
    assert_eq!(observation.outcome, ok_outcome(b"s3cret-pw"));
    assert_screen_shows_only_prompt(&observation);
    Ok(())
}

#[test]
fn test_terminal_input_supports_line_editing() -> TestResult {
    let cases: [(&str, &[u8], &str); 3] = [
        ("1 文字の消去", b"abx\x7fc\r", "abc"),
        ("行の消去", b"wrong\x15right\r", "right"),
        (
            "マルチバイトの消去",
            "鍵ab鍵\x7f\x7f\x7f\r".as_bytes(),
            "鍵",
        ),
    ];
    for (name, input, expected) in cases {
        let observation = read_with_input(input)?;
        assert_eq!(
            observation.outcome,
            ok_outcome(expected.as_bytes()),
            "{name} に失敗。"
        );
        assert_screen_shows_only_prompt(&observation);
    }
    Ok(())
}

#[test]
fn test_terminal_input_accepts_maximum_length_and_rejects_longer() -> TestResult {
    let mut maximum = vec![b'a'; MAX_PASSWORD_LEN];
    maximum.push(b'\r');
    let observation = read_with_input(&maximum)?;
    assert_eq!(
        observation.outcome,
        ok_outcome(&vec![b'a'; MAX_PASSWORD_LEN])
    );

    // 上限を超えた後に文字を消しても、切り詰めた内容を受理しない。
    for suffix in [&b"\r"[..], b"\x7f\x7f\r"] {
        let mut longer = vec![b'a'; MAX_PASSWORD_LEN + 400];
        longer.extend_from_slice(suffix);
        let observation = read_with_input(&longer)?;
        assert_eq!(observation.outcome, "Err(TooLong)");
        assert_screen_shows_only_prompt(&observation);
    }
    Ok(())
}

#[test]
fn test_terminal_input_rejects_empty_line_and_end_of_input() -> TestResult {
    assert_eq!(read_with_input(b"\r")?.outcome, "Err(Empty)");
    assert_eq!(read_with_input(b"\x04")?.outcome, "Err(EndOfInput)");
    Ok(())
}

#[test]
fn test_input_after_line_is_not_passed_to_following_program() -> TestResult {
    // 読み残しが無いことは、`read_with_input` が確かめる。
    let observation = read_with_input(b"first\rleftover")?;
    assert_eq!(observation.outcome, ok_outcome(b"first"));
    assert_screen_shows_only_prompt(&observation);
    Ok(())
}

/// 中断の起こし方。
#[derive(Debug, Clone, Copy)]
enum Interrupt {
    /// 端末のキー入力。端末がシグナルを生成する。
    Key(u8),
    /// 他のプロセスからのシグナル。
    Signal(libc::c_int),
}

#[test]
fn test_interrupt_restores_terminal_and_discards_partial_input() -> TestResult {
    let interrupts = [
        Interrupt::Key(0x03),
        Interrupt::Key(0x1c),
        Interrupt::Signal(libc::SIGINT),
        Interrupt::Signal(libc::SIGTERM),
        Interrupt::Signal(libc::SIGHUP),
        Interrupt::Signal(libc::SIGQUIT),
    ];
    for interrupt in interrupts {
        let mut pty = Pty::open()?;
        let initial = attributes(pty.slave.as_raw_fd())?;
        let reader = Reader::spawn(Some(&pty))?;
        pty.wait_for_prompt()?;
        pty.type_input(b"partial-secret")?;
        std::thread::sleep(Duration::from_millis(50));
        match interrupt {
            Interrupt::Key(key) => pty.type_input(&[key])?,
            Interrupt::Signal(signal) => reader.send_signal(signal)?,
        }

        let (outcome, restored) = reader.outcome()?;
        assert_eq!(outcome, "Err(Interrupted)", "{interrupt:?} の中断に失敗。");
        assert_eq!(restored, "Some(true)", "{interrupt:?} の端末の復元に失敗。");
        assert!(
            same_attributes(&initial, &attributes(pty.slave.as_raw_fd())?),
            "{interrupt:?} の後の端末属性の確認に失敗。"
        );
        pty.drain_screen()?;
        assert!(
            !String::from_utf8_lossy(&pty.screen).contains("partial"),
            "{interrupt:?} の入力が表示されないことの確認に失敗。"
        );
        assert_eq!(
            pty.next_line_for_following_program()?,
            b"\n",
            "{interrupt:?} の読み込み途中の入力の破棄に失敗。"
        );
        assert_eq!(
            reader.release(Some(&mut pty))?,
            Some(130),
            "{interrupt:?} の終了コードの確認に失敗。"
        );
    }
    Ok(())
}

#[test]
fn test_single_interrupt_returns_while_terminal_output_is_stalled() -> TestResult {
    let mut pty = Pty::open()?;
    let initial = attributes(pty.slave.as_raw_fd())?;
    let reader = Reader::spawn_with_prompt_padding(Some(&pty), STALLING_PROMPT_PADDING)?;
    // プロンプトの先頭が出た後は画面を読み取らず、子の書き込みを停止させる。
    pty.wait_for_prompt()?;
    std::thread::sleep(Duration::from_millis(200));
    reader.send_signal(libc::SIGTERM)?;

    let (outcome, restored) = reader.outcome()?;
    assert_eq!(outcome, "Err(Interrupted)");
    assert_eq!(restored, "Some(true)", "端末属性の復元に失敗。");
    assert!(
        same_attributes(&initial, &attributes(pty.slave.as_raw_fd())?),
        "親から見た端末属性の復元に失敗。"
    );
    assert_eq!(reader.release(Some(&mut pty))?, Some(130));
    Ok(())
}

#[test]
fn test_terminal_hangup_ends_input_without_killing_process() -> TestResult {
    let mut pty = Pty::open()?;
    let reader = Reader::spawn(Some(&pty))?;
    pty.wait_for_prompt()?;
    pty.type_input(b"partial")?;
    // マスター側を閉じると、端末の切断になる。
    pty.master = None;
    let (outcome, _) = reader.outcome()?;
    // 切断のシグナルを先に受ければ中断、入力の終端を先に読めば途中終了になる。
    match outcome.as_str() {
        "Err(Interrupted)" => assert_eq!(
            reader.release(None)?,
            Some(130),
            "切断の後の終了コードの確認に失敗。"
        ),
        // 終端を先に読んだ場合、切断のシグナルは捕捉を終えた後に届くことがある。
        // その場合はシグナルで終了するため、終了の仕方は確かめない。
        "Err(EndOfInput)" => {
            reader.release(None)?;
        }
        other => return Err(format!("切断の扱いに失敗: {other}").into()),
    }
    Ok(())
}

#[test]
fn test_missing_controlling_terminal_is_reported() -> TestResult {
    let reader = Reader::spawn(None)?;
    let (outcome, _) = reader.outcome()?;
    assert!(
        outcome.starts_with("Err(Tty(NoTerminal"),
        "制御端末が無い場合の報告に失敗: {outcome}"
    );
    reader.release(None)?;
    Ok(())
}
