//! 非対話の入力元と、中断シグナルの捕捉の統合テスト。端末からの入力は `tty_input.rs` が扱う。
//!
//! シグナルの扱いと引き継いだ記述子はプロセス全体の状態に依存する。
//! このため、テストバイナリを子プロセスとして再実行し、子プロセスの中で確かめる。

use std::error::Error;
use std::fs::{self, File, Permissions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use fidelogic_cli::error::CliError;
use fidelogic_cli::secret_input::{
    MAX_PASSWORD_LEN, PasswordSource, SecretInput, SecretInputError, read_password,
};
use fidelogic_cli::sys::signal::{InterruptWatcher, SignalError};
use fidelogic_cli::sys::tty::{TtyError, TtyStep};
use fidelogic_core::LockedBuffer;

type TestResult = Result<(), Box<dyn Error>>;

/// 子プロセスで実行する場面を指定する環境変数の名前。
const CHILD_SCENARIO: &str = "FIDELOGIC_CLI_INPUT_CHILD";

/// 子プロセスへ引き継ぐ記述子の番号。
const INHERITED_DESCRIPTOR: RawFd = 100;

/// 子プロセスの終了を待つ上限。超えた場合は、読み込みが戻らないとみなす。
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// 子プロセスが入力を待ち始める前に出力する目印。
const READY_MARKER: &str = "READY";

/// 子プロセスが、条件を再現できないことを知らせる目印。
const SKIP_MARKER: &str = "SKIP";

/// [`InterruptWatcher`] はプロセスで 1 つだけのため、同じプロセスで使うテストを直列にする。
static WATCHER_LOCK: Mutex<()> = Mutex::new(());

/// テストの一時ディレクトリ。破棄時に削除する。
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self, Box<dyn Error>> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "fidelogic-cli-secret-input-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }

    /// 指定した内容と権限のファイルを作る。
    fn file(&self, name: &str, contents: &[u8], mode: u32) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.0.join(name);
        fs::write(&path, contents)?;
        fs::set_permissions(&path, Permissions::from_mode(mode))?;
        Ok(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 中断の捕捉を開始して、ファイルからパスワードを読み込む。
fn read_file(path: &Path) -> Result<Result<SecretInput, SecretInputError>, Box<dyn Error>> {
    let _serial = WATCHER_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    let watcher = InterruptWatcher::install()?;
    Ok(read_password(
        &PasswordSource::File(path.to_path_buf()),
        "",
        &watcher,
    ))
}

/// 読み込みの結果を、内容かエラーの組にする。
fn content(result: Result<SecretInput, SecretInputError>) -> Result<Vec<u8>, SecretInputError> {
    result.map(|secret| secret.as_bytes().to_vec())
}

/// 読み込みの期待値。
type Expected<'a> = Result<&'a [u8], SecretInputError>;

#[test]
fn test_password_file_content_follows_line_rules() -> TestResult {
    let directory = TempDir::new()?;
    let maximum = vec![b'a'; MAX_PASSWORD_LEN];
    let with_crlf = [maximum.as_slice(), b"\r\n"].concat();
    let too_long = vec![b'a'; MAX_PASSWORD_LEN + 1];
    let huge = vec![b'a'; 64 * 1024];
    let cases: [(&str, &[u8], Expected); 8] = [
        ("終端なし", b"s3cret", Ok(b"s3cret")),
        ("LF", b"s3cret\n", Ok(b"s3cret")),
        ("空白を含む", b" s3 cret \r\n", Ok(b" s3 cret ")),
        ("上限と CRLF", &with_crlf, Ok(&maximum)),
        ("上限超過", &too_long, Err(SecretInputError::TooLong)),
        ("巨大な内容", &huge, Err(SecretInputError::TooLong)),
        ("複数行", b"a\nb\n", Err(SecretInputError::MultipleLines)),
        ("空", b"", Err(SecretInputError::Empty)),
    ];
    for (name, written, expected) in cases {
        let path = directory.file("password", written, 0o600)?;
        assert_eq!(
            content(read_file(&path)?),
            expected.map(<[u8]>::to_vec),
            "{name} の読み込みに失敗。"
        );
    }
    Ok(())
}

#[test]
fn test_password_file_requires_owner_only_permissions() -> TestResult {
    let directory = TempDir::new()?;
    for mode in [0o600, 0o400, 0o700] {
        let path = directory.file(&format!("allowed-{mode:o}"), b"s3cret", mode)?;
        assert_eq!(
            content(read_file(&path)?),
            Ok(b"s3cret".to_vec()),
            "権限 {mode:o} の受理に失敗。"
        );
    }
    for mode in [0o640, 0o620, 0o610, 0o604, 0o602, 0o601, 0o644, 0o666] {
        let path = directory.file(&format!("denied-{mode:o}"), b"s3cret", mode)?;
        assert_eq!(
            content(read_file(&path)?),
            Err(SecretInputError::Tty(TtyError::PasswordFilePermissions)),
            "権限 {mode:o} の拒否に失敗。"
        );
    }
    Ok(())
}

#[test]
fn test_password_file_checks_the_target_of_symbolic_link() -> TestResult {
    let directory = TempDir::new()?;
    for (name, mode, expected) in [
        ("private", 0o600, Ok(b"s3cret".to_vec())),
        (
            "public",
            0o644,
            Err(SecretInputError::Tty(TtyError::PasswordFilePermissions)),
        ),
    ] {
        let target = directory.file(name, b"s3cret", mode)?;
        let link = directory.0.join(format!("{name}-link"));
        std::os::unix::fs::symlink(&target, &link)?;
        assert_eq!(
            content(read_file(&link)?),
            expected,
            "{name} を指すリンクの検査に失敗。"
        );
    }
    Ok(())
}

#[test]
fn test_password_file_rejects_non_regular_and_missing_files() -> TestResult {
    let directory = TempDir::new()?;
    let fifo = directory.0.join("fifo");
    assert!(
        Command::new("mkfifo").arg(&fifo).status()?.success(),
        "FIFO の作成に失敗。"
    );
    // FIFO は、書き込み側を待たずに失敗する。
    for path in [directory.0.clone(), fifo, PathBuf::from("/dev/null")] {
        assert_eq!(
            content(read_file(&path)?),
            Err(SecretInputError::Tty(TtyError::PasswordFileNotRegular)),
            "{} の拒否に失敗。",
            path.display()
        );
    }
    assert_eq!(
        content(read_file(&directory.0.join("missing"))?),
        Err(SecretInputError::Tty(TtyError::Os {
            step: TtyStep::OpenPasswordFile,
            errno: libc::ENOENT,
        }))
    );
    Ok(())
}

#[test]
fn test_secret_input_debug_hides_content() -> TestResult {
    let directory = TempDir::new()?;
    let path = directory.file("password", b"s3cret", 0o600)?;
    let secret = read_file(&path)??;
    assert_eq!(format!("{secret:?}"), "SecretInput(..)");
    Ok(())
}

/// 子プロセスの中で目印を出力する。
fn report(line: &str) -> TestResult {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{line}")?;
    stdout.flush()?;
    Ok(())
}

/// 子プロセスで、引き継いだ記述子と、指定できない記述子を確かめる。
fn verify_descriptors(watcher: &InterruptWatcher) -> TestResult {
    let read = |descriptor| {
        content(read_password(
            &PasswordSource::Descriptor(descriptor),
            "",
            watcher,
        ))
    };
    assert_eq!(read(INHERITED_DESCRIPTOR), Ok(b"s3cret".to_vec()));
    // 記述子は閉じず、続きは終端になる。
    assert_eq!(read(INHERITED_DESCRIPTOR), Err(SecretInputError::Empty));

    // 本プロセスが開いたファイルは `FD_CLOEXEC` を持つため、引き継いだものとして扱わない。
    let opened = File::open("/dev/null")?;
    assert_eq!(
        read(opened.as_raw_fd()),
        Err(SecretInputError::Tty(TtyError::DescriptorNotInherited))
    );
    assert_eq!(
        read(900),
        Err(SecretInputError::Tty(TtyError::Os {
            step: TtyStep::InspectDescriptor,
            errno: libc::EBADF,
        }))
    );
    for descriptor in [-1, i32::try_from(libc::FD_SETSIZE)?, i32::MAX] {
        assert_eq!(
            read(descriptor),
            Err(SecretInputError::Tty(TtyError::UnsupportedDescriptor)),
            "記述子 {descriptor} の拒否に失敗。"
        );
    }

    let (mut master, mut slave) = (-1, -1);
    // SAFETY: 2 つの出力先は有効で、名前、端末属性、窓の大きさには null を渡す。
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(opened, 0, "疑似端末の作成に失敗。");
    assert_eq!(
        read(slave),
        Err(SecretInputError::Tty(TtyError::DescriptorIsTerminal))
    );
    Ok(())
}

/// 子プロセスで、中断の捕捉の開始、終了、無視されたシグナルの扱いを確かめる。
fn verify_watcher() -> TestResult {
    /// `signal` の現在のハンドラーを返す。
    fn disposition(signal: libc::c_int) -> Result<libc::sighandler_t, Box<dyn Error>> {
        // SAFETY: 全ビット 0 は `sigaction` の有効な値である。
        let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
        // SAFETY: 第 2 引数が null の場合は、現在の設定を書き込むだけである。
        if unsafe { libc::sigaction(signal, core::ptr::null(), &mut action) } != 0 {
            return Err("シグナルの設定の取得に失敗しました。".into());
        }
        Ok(action.sa_sigaction)
    }

    // 無視する設定で起動した場合を再現する。
    // SAFETY: `SIG_IGN` と `SIG_DFL` の設定は、ハンドラーの関数を持たない。
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGINT, libc::SIG_DFL);
        libc::signal(libc::SIGTERM, libc::SIG_DFL);
        libc::signal(libc::SIGQUIT, libc::SIG_DFL);
    }

    let watcher = InterruptWatcher::install()?;
    assert_eq!(
        InterruptWatcher::install().err(),
        Some(SignalError::AlreadyActive)
    );
    assert_eq!(disposition(libc::SIGHUP)?, libc::SIG_IGN);
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
        assert_ne!(disposition(signal)?, libc::SIG_DFL);
    }
    // SAFETY: 無視する設定のシグナルは、何も起こさない。
    unsafe { libc::raise(libc::SIGHUP) };
    assert!(!watcher.is_interrupted(), "無視するシグナルの扱いに失敗。");
    // SAFETY: ハンドラーを登録したシグナルは、記録するだけである。
    unsafe { libc::raise(libc::SIGTERM) };
    assert!(watcher.is_interrupted(), "中断の記録に失敗。");

    // 中断の後の呼び出しは、入力元を開かずに中断を返す。
    assert_eq!(
        content(read_password(
            &PasswordSource::File("/nonexistent".into()),
            "",
            &watcher
        )),
        Err(SecretInputError::Interrupted)
    );

    drop(watcher);
    assert_eq!(disposition(libc::SIGHUP)?, libc::SIG_IGN);
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
        assert_eq!(disposition(signal)?, libc::SIG_DFL, "設定の復元に失敗。");
    }

    // 次の捕捉は、以前の中断を引き継がず、読み込める。
    let watcher = InterruptWatcher::install()?;
    assert!(!watcher.is_interrupted());
    assert_eq!(
        content(read_password(
            &PasswordSource::Descriptor(INHERITED_DESCRIPTOR),
            "",
            &watcher
        )),
        Ok(b"s3cret".to_vec())
    );
    Ok(())
}

/// 子プロセスで `mlock` を禁止し、入力を中止することを確かめる。
///
/// 上限を 0 にしても `mlock` が成功する環境 (`CAP_IPC_LOCK` を持つプロセスなど) では、
/// 失敗を再現できないため [`SKIP_MARKER`] を報告する。
fn verify_memory_lock_failure(watcher: &InterruptWatcher) -> TestResult {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` は有効な構造体で、呼び出しの間は生存している。
    let result = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if result != 0 || LockedBuffer::<1>::zero_strict().is_ok() {
        return report(SKIP_MARKER);
    }
    // 入力元には内容があるため、ロックしないバッファへの代替があれば読み込みに成功する。
    assert_eq!(
        content(read_password(
            &PasswordSource::Descriptor(INHERITED_DESCRIPTOR),
            "",
            watcher
        )),
        Err(SecretInputError::MemoryLockFailed)
    );
    Ok(())
}

/// 子プロセスの中で実行する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_run_input_scenario() -> TestResult {
    let Ok(scenario) = std::env::var(CHILD_SCENARIO) else {
        return Ok(());
    };
    match scenario.as_str() {
        "descriptors" => verify_descriptors(&InterruptWatcher::install()?),
        "watcher" => verify_watcher(),
        "memory-lock-denied" => verify_memory_lock_failure(&InterruptWatcher::install()?),
        // 標準入力か記述子から読み込み、結果を報告する。中断した場合は、CLI の終了コードで終了する。
        "stdin" | "nonblocking-descriptor" => {
            let watcher = InterruptWatcher::install()?;
            let source = if scenario == "stdin" {
                PasswordSource::StandardInput
            } else {
                // SAFETY: 整数引数だけで、引き継いだ記述子を非ブロッキングにする。
                let result =
                    unsafe { libc::fcntl(INHERITED_DESCRIPTOR, libc::F_SETFL, libc::O_NONBLOCK) };
                assert_eq!(result, 0, "非ブロッキングの設定に失敗。");
                PasswordSource::Descriptor(INHERITED_DESCRIPTOR)
            };
            report(READY_MARKER)?;
            match content(read_password(&source, "", &watcher)) {
                Ok(bytes) => report(&format!("OK {}", String::from_utf8(bytes)?)),
                Err(error) => {
                    report(&format!("ERR {error:?}"))?;
                    if error == SecretInputError::Interrupted {
                        let code = CliError::from(error).exit_category().code();
                        drop(watcher);
                        std::process::exit(i32::from(code));
                    }
                    Ok(())
                }
            }
        }
        other => Err(format!("未知の場面です: {other}").into()),
    }
}

/// 子プロセスを、指定した場面で起動する準備をする。
fn child_command(scenario: &str) -> Result<Command, Box<dyn Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "child_run_input_scenario",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_SCENARIO, scenario)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    Ok(command)
}

/// `source` を、子プロセスの [`INHERITED_DESCRIPTOR`] に引き継がせる。
fn inherit_descriptor(command: &mut Command, source: RawFd) {
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `dup2` と `fcntl` は非同期シグナルセーフで、ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(move || {
            // `dup2` は複製先の `FD_CLOEXEC` を外す。番号が同じ場合は何もしないため、明示的に外す。
            if libc::dup2(source, INHERITED_DESCRIPTOR) < 0
                || libc::fcntl(INHERITED_DESCRIPTOR, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// 子プロセスが目印を出力するまで待つ。読み込んだ内容は捨てる。
fn wait_for_ready(
    child: &mut Child,
) -> Result<BufReader<std::process::ChildStdout>, Box<dyn Error>> {
    let stdout = child.stdout.take().ok_or("子の標準出力がありません。")?;
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err("子プロセスが目印を出力せずに終了しました。".into());
        }
        if line.trim_end() == READY_MARKER {
            return Ok(reader);
        }
    }
}

/// 子プロセスの終了を、上限を設けて待つ。
fn wait_with_timeout(mut child: Child) -> Result<Output, Box<dyn Error>> {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    while child.try_wait()?.is_none() {
        if Instant::now() > deadline {
            child.kill()?;
            child.wait()?;
            return Err("子プロセスが時間内に終了しませんでした。".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(child.wait_with_output()?)
}

/// 子プロセスの残りの標準出力を読み、終了を待つ。
fn finish(
    child: Child,
    mut reader: BufReader<std::process::ChildStdout>,
) -> Result<(Output, String), Box<dyn Error>> {
    let output = wait_with_timeout(child)?;
    let mut remaining = String::new();
    std::io::Read::read_to_string(&mut reader, &mut remaining)?;
    Ok((output, remaining))
}

/// 本体テストが実行され、成功したことを確かめる。
fn assert_child_passed(output: &Output, stdout: &str) {
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "子プロセスの検証に失敗しました。\nstatus: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn test_inherited_descriptor_is_read_and_others_are_rejected() -> TestResult {
    for scenario in ["descriptors", "watcher"] {
        let (reader, mut writer) = std::io::pipe()?;
        writer.write_all(b"s3cret\n")?;
        // `watcher` の場面は、中断の確認の後に読み込むため、内容は 1 回分でよい。
        drop(writer);
        let mut command = child_command(scenario)?;
        inherit_descriptor(&mut command, reader.as_raw_fd());
        let output = wait_with_timeout(command.spawn()?)?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert_child_passed(&output, &stdout);
    }
    Ok(())
}

#[test]
fn test_input_stops_when_memory_cannot_be_locked() -> TestResult {
    let (reader, mut writer) = std::io::pipe()?;
    writer.write_all(b"s3cret\n")?;
    drop(writer);
    let mut command = child_command("memory-lock-denied")?;
    inherit_descriptor(&mut command, reader.as_raw_fd());
    let output = wait_with_timeout(command.spawn()?)?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert_child_passed(&output, &stdout);
    if stdout.lines().any(|line| line == SKIP_MARKER) {
        writeln!(
            std::io::stderr(),
            "スキップ: この環境では mlock の失敗を再現できません。"
        )?;
    }
    Ok(())
}

#[test]
fn test_standard_input_is_read_until_end_across_multiple_writes() -> TestResult {
    let long = vec![b'a'; 4096];
    let cases: [(&str, &[&[u8]], &str); 3] = [
        ("分割した書き込み", &[b"s3", b"cret", b"\n"], "OK s3cret"),
        ("上限超過", &[&long], "ERR TooLong"),
        ("空", &[], "ERR Empty"),
    ];
    for (name, chunks, expected) in cases {
        let mut child = child_command("stdin")?.spawn()?;
        let reader = wait_for_ready(&mut child)?;
        let mut stdin = child.stdin.take().ok_or("子の標準入力がありません。")?;
        for chunk in chunks {
            stdin.write_all(chunk)?;
            stdin.flush()?;
            std::thread::sleep(Duration::from_millis(20));
        }
        drop(stdin);
        let (output, stdout) = finish(child, reader)?;
        assert_child_passed(&output, &stdout);
        assert!(
            stdout.contains(expected),
            "{name} の結果の確認に失敗: {stdout}"
        );
    }
    Ok(())
}

#[test]
fn test_nonblocking_descriptor_waits_for_content() -> TestResult {
    let (reader, mut writer) = std::io::pipe()?;
    let mut command = child_command("nonblocking-descriptor")?;
    inherit_descriptor(&mut command, reader.as_raw_fd());
    let mut child = command.spawn()?;
    let output_reader = wait_for_ready(&mut child)?;
    std::thread::sleep(Duration::from_millis(100));
    writer.write_all(b"s3cret")?;
    drop(writer);
    let (output, stdout) = finish(child, output_reader)?;
    assert_child_passed(&output, &stdout);
    assert!(
        stdout.contains("OK s3cret"),
        "非ブロッキングの記述子の読み込みに失敗: {stdout}"
    );
    Ok(())
}

#[test]
fn test_signals_interrupt_waiting_input_with_exit_code_130() -> TestResult {
    // 待機の開始の前後のどちらで受けても中断する。
    for delay in [Duration::ZERO, Duration::from_millis(100)] {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            let mut command = child_command("stdin")?;
            // 親が無視する設定でも、子では既定の扱いから始める。
            // SAFETY: `signal` は非同期シグナルセーフで、`SIG_DFL` はハンドラーの関数を持たない。
            unsafe {
                command.pre_exec(move || {
                    libc::signal(signal, libc::SIG_DFL);
                    Ok(())
                });
            }
            let mut child = command.spawn()?;
            let reader = wait_for_ready(&mut child)?;
            // 書き込み側は閉じず、途中の内容がある状態で入力を待たせる。
            let mut stdin = child.stdin.take().ok_or("子の標準入力がありません。")?;
            stdin.write_all(b"partial")?;
            stdin.flush()?;
            std::thread::sleep(delay);
            let pid = i32::try_from(child.id())?;
            // SAFETY: 起動した子プロセスへシグナルを送るだけで、メモリを参照しない。
            assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
            let (output, stdout) = finish(child, reader)?;
            drop(stdin);
            assert_eq!(
                output.status.code(),
                Some(130),
                "シグナル {signal} (遅延 {delay:?}) の終了コードの確認に失敗: {:?}\n{stdout}",
                output.status,
            );
            assert!(
                stdout.contains("ERR Interrupted"),
                "中断の報告の確認に失敗: {stdout}"
            );
        }
    }
    Ok(())
}
