//! Vault のパスの正規化と、サイドカーロックの統合テスト。
//!
//! プロセス間の排他は、テストバイナリを子プロセスとして再実行して確認する。
//! `umask` はプロセス全体の状態のため、変更は子プロセスに対してだけ行う。

use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fidelogic_cli::sys::storage::{StorageError, StorageStep, VaultLock, VaultPath};

type TestResult = Result<(), Box<dyn Error>>;

/// 子プロセスに実行させる操作を渡す環境変数の名前。
const CHILD_ACTION: &str = "FIDELOGIC_CLI_LOCK_CHILD_ACTION";
/// 子プロセスに対象の Vault のパスを渡す環境変数の名前。
const CHILD_VAULT: &str = "FIDELOGIC_CLI_LOCK_CHILD_VAULT";

/// 子プロセスがロックを取得できたことを示す出力。
const MARKER_ACQUIRED: &str = "lock-child:acquired";
/// 子プロセスが、他の保持者を理由にロックを取得できなかったことを示す出力。
const MARKER_BUSY: &str = "lock-child:busy";
/// 子プロセスがロックを保持して待機していることを示す出力。
const MARKER_HOLDING: &str = "lock-child:holding";
/// 子プロセスが解決した Vault ファイルのパスの前に付ける出力。
const MARKER_RESOLVED: &str = "lock-child:resolved=";

/// 取得待ちが戻らないことを確認する時間。
const BLOCKED_OBSERVATION: Duration = Duration::from_millis(300);
/// 解放後に取得待ちが戻るまでの許容時間。
const RELEASE_DEADLINE: Duration = Duration::from_secs(30);

/// テスト用の一時ディレクトリ。破棄するときに中身ごと削除する。
struct TempDir(PathBuf);

impl TempDir {
    /// 一時ディレクトリを作成する。保持するパスはシンボリックリンクを解決したものである。
    fn new() -> Result<Self, Box<dyn Error>> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fidelogic-cli-lock-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }

    fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// パスを解決し、失敗することを前提にエラーを取り出す。
fn resolve_error(path: &Path) -> Result<StorageError, Box<dyn Error>> {
    match VaultPath::resolve(path) {
        Ok(resolved) => {
            Err(format!("{path:?} の解決が拒否されずに失敗しました: {resolved:?}").into())
        }
        Err(error) => Ok(error),
    }
}

/// ロックを待たずに取得し、失敗することを前提にエラーを取り出す。
fn try_acquire_error(path: VaultPath) -> Result<StorageError, Box<dyn Error>> {
    match VaultLock::try_acquire(path) {
        Ok(lock) => Err(format!("ロックが拒否されずに失敗しました: {lock:?}").into()),
        Err(error) => Ok(error),
    }
}

fn os_error(step: StorageStep, errno: libc::c_int) -> StorageError {
    StorageError::Os { step, errno }
}

#[test]
fn test_resolve_relative_name_uses_current_directory() -> TestResult {
    // ファイルを作成しないため、カレントディレクトリは変化しない。
    let name = "fidelogic-cli-nonexistent-vault.fvl";
    let current = fs::canonicalize(std::env::current_dir()?)?;
    for input in [name.to_string(), format!("./{name}")] {
        let path = VaultPath::resolve(Path::new(&input))?;
        assert_eq!(path.directory(), current);
        assert_eq!(path.file(), current.join(name));
        assert_eq!(path.lock_file(), current.join(format!("{name}.lock")));
        assert!(!path.file().exists() && !path.lock_file().exists());
    }
    Ok(())
}

#[test]
fn test_resolve_relative_path_to_existing_vault() -> TestResult {
    let dir = TempDir::new()?;
    fs::write(dir.join("vault.fvl"), b"")?;
    symlink("vault.fvl", dir.join("alias"))?;
    let expected = format!("{MARKER_RESOLVED}{}\n", dir.join("vault.fvl").display());

    // カレントディレクトリはプロセス全体の状態のため、子プロセスに対してだけ変更する。
    for input in ["vault.fvl", "./vault.fvl", "alias"] {
        let mut command = child_command("resolve", input)?;
        command.current_dir(&dir.0);
        assert_child_output(command, &expected)?;
    }
    Ok(())
}

#[test]
fn test_resolve_rejects_paths_without_file_name() -> TestResult {
    let dir = TempDir::new()?;
    let base = dir.0.display();
    let cases = [
        String::new(),
        ".".to_string(),
        "..".to_string(),
        "/".to_string(),
        format!("{base}/"),
        format!("{base}/vault/"),
        format!("{base}/vault/."),
        format!("{base}/vault/.."),
    ];
    for case in cases {
        assert_eq!(
            resolve_error(Path::new(&case))?,
            StorageError::InvalidPath,
            "`{case}` の拒否に失敗。"
        );
    }
    Ok(())
}

#[test]
fn test_resolve_rejects_lock_suffix_including_symlink_target() -> TestResult {
    let dir = TempDir::new()?;
    for name in ["vault.lock", "vault.LOCK", ".lock"] {
        assert_eq!(
            resolve_error(&dir.join(name))?,
            StorageError::ReservedName,
            "`{name}` の拒否に失敗。"
        );
    }

    fs::write(dir.join("target.lock"), b"")?;
    symlink("target.lock", dir.join("alias"))?;
    assert_eq!(
        resolve_error(&dir.join("alias"))?,
        StorageError::ReservedName
    );
    Ok(())
}

#[test]
fn test_resolve_follows_relative_symlink_to_existing_vault() -> TestResult {
    let dir = TempDir::new()?;
    fs::create_dir(dir.join("real"))?;
    fs::create_dir(dir.join("links"))?;
    fs::write(dir.join("real/vault.fvl"), b"")?;
    symlink("../real/vault.fvl", dir.join("links/alias"))?;

    let path = VaultPath::resolve(&dir.join("links/alias"))?;
    assert_eq!(path.directory(), dir.join("real"));
    assert_eq!(path.file(), dir.join("real/vault.fvl"));
    assert_eq!(path.lock_file(), dir.join("real/vault.fvl.lock"));
    assert_eq!(path, VaultPath::resolve(&dir.join("real/vault.fvl"))?);
    Ok(())
}

#[test]
fn test_resolve_follows_symlinked_parent_for_new_vault() -> TestResult {
    let dir = TempDir::new()?;
    fs::create_dir(dir.join("real"))?;
    symlink("real", dir.join("alias"))?;

    let path = VaultPath::resolve(&dir.join("alias/new.fvl"))?;
    assert_eq!(path.directory(), dir.join("real"));
    assert_eq!(path.file(), dir.join("real/new.fvl"));
    assert!(
        !path.file().exists(),
        "解決だけでファイルが作成されたため失敗しました。"
    );
    Ok(())
}

#[test]
fn test_resolve_rejects_unresolvable_paths() -> TestResult {
    let dir = TempDir::new()?;
    symlink("missing-target", dir.join("dangling"))?;
    symlink("loop-b", dir.join("loop-a"))?;
    symlink("loop-a", dir.join("loop-b"))?;
    fs::write(dir.join("plain"), b"")?;

    let cases = [
        ("dangling", libc::ENOENT),
        ("loop-a", libc::ELOOP),
        ("missing-directory/vault.fvl", libc::ENOENT),
        ("plain/vault.fvl", libc::ENOTDIR),
    ];
    for (name, errno) in cases {
        assert_eq!(
            resolve_error(&dir.join(name))?,
            os_error(StorageStep::ResolvePath, errno),
            "`{name}` の拒否に失敗。"
        );
    }
    assert!(
        !dir.join("missing-target").exists(),
        "参照先の無いリンクの解決でファイルが作成されたため失敗しました。"
    );
    Ok(())
}

#[test]
fn test_resolve_rejects_non_regular_vault() -> TestResult {
    let dir = TempDir::new()?;
    fs::create_dir(dir.join("directory"))?;
    symlink("directory", dir.join("directory-link"))?;
    make_fifo(&dir.join("fifo"))?;

    for name in ["directory", "directory-link", "fifo"] {
        assert_eq!(
            resolve_error(&dir.join(name))?,
            StorageError::VaultNotRegularFile,
            "`{name}` の拒否に失敗。"
        );
    }
    Ok(())
}

/// `mkfifo` コマンドで FIFO を作成する。
fn make_fifo(path: &Path) -> TestResult {
    let status = Command::new("mkfifo").arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("FIFO の作成に失敗しました: {status}").into())
    }
}

#[test]
fn test_lock_keeps_existing_lock_file_content_and_inode() -> TestResult {
    let dir = TempDir::new()?;
    let path = VaultPath::resolve(&dir.join("vault.fvl"))?;
    fs::write(path.lock_file(), b"keep")?;
    fs::set_permissions(path.lock_file(), fs::Permissions::from_mode(0o640))?;
    let before = fs::metadata(path.lock_file())?;

    for _ in 0..2 {
        let lock = VaultLock::try_acquire(path.clone())?;
        assert_eq!(lock.vault_path(), &path);
        drop(lock);
    }
    drop(VaultLock::acquire(path.clone())?);

    let after = fs::metadata(path.lock_file())?;
    assert_eq!(
        after.ino(),
        before.ino(),
        "ロックファイルが置き換わったため失敗しました。"
    );
    assert_eq!(after.mode() & 0o7777, 0o640);
    assert_eq!(fs::read(path.lock_file())?, b"keep");
    assert!(
        !path.file().exists(),
        "ロックの取得で Vault ファイルが作成されたため失敗しました。"
    );
    Ok(())
}

#[test]
fn test_lock_rejects_symlinked_lock_file() -> TestResult {
    let dir = TempDir::new()?;
    let path = VaultPath::resolve(&dir.join("vault.fvl"))?;
    symlink("elsewhere", path.lock_file())?;

    let expected = os_error(StorageStep::OpenLockFile, libc::ELOOP);
    assert_eq!(try_acquire_error(path.clone())?, expected);
    assert_eq!(
        VaultLock::acquire(path).map(drop),
        Err(expected),
        "シンボリックリンクのロックファイルの拒否に失敗。"
    );
    assert!(
        !dir.join("elsewhere").exists(),
        "シンボリックリンクの参照先が作成されたため失敗しました。"
    );
    Ok(())
}

#[test]
fn test_lock_rejects_non_regular_lock_file() -> TestResult {
    let dir = TempDir::new()?;

    let directory_case = VaultPath::resolve(&dir.join("first"))?;
    fs::create_dir(directory_case.lock_file())?;
    assert_eq!(
        try_acquire_error(directory_case)?,
        os_error(StorageStep::OpenLockFile, libc::EISDIR)
    );

    let fifo_case = VaultPath::resolve(&dir.join("second"))?;
    make_fifo(fifo_case.lock_file())?;
    assert_eq!(
        try_acquire_error(fifo_case)?,
        StorageError::LockFileNotRegularFile
    );
    Ok(())
}

#[test]
fn test_try_acquire_reports_locked_until_release() -> TestResult {
    let dir = TempDir::new()?;
    let path = VaultPath::resolve(&dir.join("vault.fvl"))?;

    let held = VaultLock::acquire(path.clone())?;
    assert_eq!(try_acquire_error(path.clone())?, StorageError::Locked);
    drop(held);

    drop(VaultLock::try_acquire(path.clone())?);
    assert!(
        path.lock_file().is_file(),
        "解放後にロックファイルが残っていないため失敗しました。"
    );
    Ok(())
}

#[test]
fn test_lock_is_shared_between_symlink_and_real_path() -> TestResult {
    let dir = TempDir::new()?;
    fs::write(dir.join("vault.fvl"), b"")?;
    symlink("vault.fvl", dir.join("alias"))?;

    let held = VaultLock::try_acquire(VaultPath::resolve(&dir.join("alias"))?)?;
    let real = VaultPath::resolve(&dir.join("vault.fvl"))?;
    assert_eq!(try_acquire_error(real)?, StorageError::Locked);
    drop(held);
    Ok(())
}

#[test]
fn test_locks_of_different_vaults_are_independent() -> TestResult {
    let dir = TempDir::new()?;
    let first = VaultLock::try_acquire(VaultPath::resolve(&dir.join("first"))?)?;
    let second = VaultLock::try_acquire(VaultPath::resolve(&dir.join("second"))?)?;
    drop(first);
    drop(second);
    Ok(())
}

/// 別のスレッドで `acquire` を呼び、取得できたら直ちに解放して、結果を送る。
fn spawn_waiter(path: VaultPath) -> Receiver<Result<(), StorageError>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        // 受信側が先に終了した場合は、報告先が無い。
        let _ = sender.send(VaultLock::acquire(path).map(drop));
    });
    receiver
}

#[test]
fn test_acquire_waits_until_holder_releases() -> TestResult {
    let dir = TempDir::new()?;
    let path = VaultPath::resolve(&dir.join("vault.fvl"))?;
    let held = VaultLock::acquire(path.clone())?;

    let receiver = spawn_waiter(path);
    assert_eq!(
        receiver.recv_timeout(BLOCKED_OBSERVATION),
        Err(RecvTimeoutError::Timeout),
        "保持中のロックの取得待ちに失敗。"
    );
    drop(held);
    receiver.recv_timeout(RELEASE_DEADLINE)??;
    Ok(())
}

/// ロックを取得して、カウンターのファイルを読み込み、1 増やして書き戻す。
fn increment_under_lock(path: &VaultPath) -> Result<(), String> {
    let lock = VaultLock::acquire(path.clone()).map_err(|error| error.to_string())?;
    let file = lock.vault_path().file();
    let current: u32 = fs::read_to_string(file)
        .map_err(|error| error.to_string())?
        .parse()
        .map_err(|error| format!("カウンターの解析に失敗しました: {error}"))?;
    // 読み込みと書き込みの間に他のスレッドへ実行を譲り、排他が無ければ更新が失われるようにする。
    std::thread::yield_now();
    fs::write(file, (current + 1).to_string()).map_err(|error| error.to_string())
}

#[test]
fn test_updates_under_lock_are_not_lost() -> TestResult {
    const THREADS: u32 = 8;
    const UPDATES: u32 = 50;

    let dir = TempDir::new()?;
    fs::write(dir.join("counter"), "0")?;
    let path = VaultPath::resolve(&dir.join("counter"))?;

    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| scope.spawn(|| (0..UPDATES).try_for_each(|_| increment_under_lock(&path))))
            .collect();
        workers.into_iter().try_for_each(|worker| {
            worker
                .join()
                .map_err(|_| "更新スレッドが異常終了したため失敗しました。".to_string())?
        })
    })?;

    assert_eq!(
        fs::read_to_string(path.file())?,
        (THREADS * UPDATES).to_string(),
        "更新の消失が起きたため失敗しました。"
    );
    Ok(())
}

/// 子プロセスの出力を 1 行書いて、直ちに送り出す。
fn report(marker: &str) -> TestResult {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{marker}")?;
    stdout.flush()?;
    Ok(())
}

/// 子プロセスの中で実行する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_lock_action() -> TestResult {
    let Some(action) = std::env::var_os(CHILD_ACTION) else {
        return Ok(());
    };
    let vault =
        std::env::var_os(CHILD_VAULT).ok_or("対象の Vault の指定が無いため失敗しました。")?;
    let path = VaultPath::resolve(Path::new(&vault))?;

    match action.to_str() {
        Some("resolve") => report(&format!("{MARKER_RESOLVED}{}", path.file().display())),
        Some("try") => match VaultLock::try_acquire(path) {
            Ok(_lock) => report(MARKER_ACQUIRED),
            Err(StorageError::Locked) => report(MARKER_BUSY),
            Err(error) => Err(error.into()),
        },
        Some("hold") => {
            let _lock = VaultLock::acquire(path)?;
            report(MARKER_HOLDING)?;
            // 親が標準入力を閉じるまで保持する。親が先に終了しても、子は残らない。
            std::io::stdin().read_to_end(&mut Vec::new())?;
            Ok(())
        }
        _ => Err(format!("未知の操作のため失敗しました: {action:?}").into()),
    }
}

/// 子プロセスとして [`child_lock_action`] を実行するコマンドを組み立てる。
fn child_command(action: &str, vault: impl AsRef<OsStr>) -> Result<Command, Box<dyn Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "child_lock_action",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ACTION, action)
        .env(CHILD_VAULT, vault);
    Ok(command)
}

/// 子プロセスを実行し、成功して、期待する出力を含むことを確認する。
fn assert_child_output(mut command: Command, expected: &str) -> TestResult {
    let output = command.output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(expected),
        "子プロセスの結果が `{expected}` でないため失敗しました。\nstdout:\n{stdout}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}

#[test]
fn test_lock_excludes_other_process_until_release() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");

    let held = VaultLock::acquire(VaultPath::resolve(&vault)?)?;
    assert_child_output(child_command("try", &vault)?, MARKER_BUSY)?;
    drop(held);
    assert_child_output(child_command("try", &vault)?, MARKER_ACQUIRED)?;
    Ok(())
}

#[test]
fn test_lock_file_is_created_with_owner_only_mode() -> TestResult {
    let dir = TempDir::new()?;
    let path = VaultPath::resolve(&dir.join("vault.fvl"))?;

    // `umask` に頼らず権限を指定していることを確認するため、子の `umask` を 0 にする。
    let mut command = child_command("try", path.file())?;
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `umask` は非同期シグナルセーフであり、ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    assert_child_output(command, MARKER_ACQUIRED)?;

    let metadata = fs::metadata(path.lock_file())?;
    assert_eq!(
        metadata.mode() & 0o7777,
        0o600,
        "ロックファイルの権限が 0600 でないため失敗しました。"
    );
    assert_eq!(metadata.len(), 0);
    Ok(())
}

#[test]
fn test_lock_is_released_when_holder_process_is_killed() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");
    let path = VaultPath::resolve(&vault)?;

    let mut child = child_command("hold", &vault)?
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or("子プロセスの標準出力の取得に失敗しました。")?;
    let mut holding = false;
    for line in BufReader::new(stdout).lines() {
        if line?.contains(MARKER_HOLDING) {
            holding = true;
            break;
        }
    }
    assert!(holding, "子プロセスがロックを保持したことの確認に失敗。");
    assert_eq!(try_acquire_error(path.clone())?, StorageError::Locked);
    let receiver = spawn_waiter(path);
    assert_eq!(
        receiver.recv_timeout(BLOCKED_OBSERVATION),
        Err(RecvTimeoutError::Timeout),
        "他のプロセスが保持するロックの取得待ちに失敗。"
    );

    // `Child::kill` は `SIGKILL` を送るため、子の `Drop` は実行されない。
    child.kill()?;
    child.wait()?;

    receiver.recv_timeout(RELEASE_DEADLINE)??;
    Ok(())
}
