//! プロセス硬化の統合テスト。
//!
//! `harden_process()` はプロセス全体の状態 (`RLIMIT_CORE`, `umask`, `PR_SET_DUMPABLE`) を変更する。
//! テストプロセス自身で呼び出すと並列に動く他のテストへ影響するため、テストバイナリを子プロセスとして
//! 再実行し、子プロセスの中で適用と検証を行う。

use std::error::Error;
use std::os::unix::process::CommandExt;
use std::process::Command;

use fidelogic_cli::sys::process::harden_process;

type TestResult = Result<(), Box<dyn Error>>;

/// 子プロセスとして動作することを示す環境変数の名前。
const CHILD_MARKER: &str = "FIDELOGIC_CLI_HARDENING_CHILD";

/// 子プロセスの起動前に設定する `RLIMIT_CORE` の上限。
/// 親プロセスのハード上限がこれより小さい場合は、親の値を超えない範囲に切り詰める。
const PRE_HARDENING_CORE_LIMIT: libc::rlim_t = 1 << 20;

/// 子プロセスの中で実行する本体。環境変数が無い通常実行では何もしない。
///
/// 適用前に値を非硬化状態へそろえ、`harden_process()` で変わったことを確認する。
#[test]
fn child_apply_and_verify_hardening() -> TestResult {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return Ok(());
    }

    // 適用前の状態を、硬化されていない値へそろえる。
    // SAFETY: `umask` はプロセスの属性を更新するだけで、メモリを参照しない。
    unsafe { libc::umask(0o022) };
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `PR_SET_DUMPABLE` は整数引数のみを取り、ポインターを参照しない。
        let result = unsafe {
            libc::prctl(
                libc::PR_SET_DUMPABLE,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        assert_eq!(result, 0, "適用前のダンプ可設定に失敗しました。");
    }

    harden_process()?;

    // `RLIMIT_CORE` のソフト・ハード上限がともに 0 であること。
    let mut limit = libc::rlimit {
        rlim_cur: libc::rlim_t::MAX,
        rlim_max: libc::rlim_t::MAX,
    };
    // SAFETY: `limit` は書き込み可能な有効な構造体であり、呼び出しの間は生存している。
    let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    assert_eq!(result, 0, "RLIMIT_CORE の取得に失敗しました。");
    assert_eq!(
        limit.rlim_cur, 0,
        "RLIMIT_CORE のソフト上限が 0 でないため失敗しました。"
    );
    assert_eq!(
        limit.rlim_max, 0,
        "RLIMIT_CORE のハード上限が 0 でないため失敗しました。"
    );

    // `umask` が 0077 であること (設定しつつ直前の値を読む)。
    // SAFETY: `umask` はプロセスの属性を更新するだけで、メモリを参照しない。
    let previous_umask = unsafe { libc::umask(0o077) };
    assert_eq!(
        previous_umask, 0o077,
        "umask が 0077 でないため失敗しました。"
    );

    // Linux ではダンプ不可であること。
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `PR_GET_DUMPABLE` は引数を参照せず、現在の設定値を戻り値として返す。
        let dumpable = unsafe {
            libc::prctl(
                libc::PR_GET_DUMPABLE,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        };
        assert_eq!(dumpable, 0, "PR_GET_DUMPABLE が 0 でないため失敗しました。");
    }

    // 複数回の呼び出しでも結果が変わらないこと。
    harden_process()?;
    Ok(())
}

/// 親プロセスの `RLIMIT_CORE` のハード上限を読み取る。
fn parent_core_hard_limit() -> Result<libc::rlim_t, Box<dyn Error>> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` は書き込み可能な有効な構造体であり、呼び出しの間は生存している。
    let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
    if result != 0 {
        return Err("親プロセスの RLIMIT_CORE の取得に失敗しました。".into());
    }
    Ok(limit.rlim_max)
}

#[test]
fn test_harden_process_applies_protections_in_isolated_process() -> TestResult {
    let pre_limit = parent_core_hard_limit()?.min(PRE_HARDENING_CORE_LIMIT);
    if pre_limit == 0 {
        // 親のハード上限が 0 のときは、硬化前に 0 以外の上限を作れない。
        let _ = std::io::Write::write_all(
            &mut std::io::stderr(),
            "親プロセスの RLIMIT_CORE が 0 のため、RLIMIT_CORE の変更は確かめずに続けます。\n"
                .as_bytes(),
        );
    }

    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--exact",
            "child_apply_and_verify_hardening",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_MARKER, "1");
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setrlimit` は非同期シグナルセーフであり、ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(move || {
            let limit = libc::rlimit {
                rlim_cur: pre_limit,
                rlim_max: pre_limit,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }

    let output = command.output()?;
    assert!(
        output.status.success(),
        "子プロセスでのプロセス硬化の検証に失敗しました。\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    // 子プロセスの本体テストが実際に実行されたこと (環境変数が渡らず素通りしていないこと) を確認する。
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("child_apply_and_verify_hardening") && stdout.contains("1 passed"),
        "子プロセスで本体テストが実行されたことの確認に失敗しました。\nstdout:\n{stdout}",
    );
    Ok(())
}

#[test]
fn test_binary_runs_after_hardening_and_prints_profile() -> TestResult {
    let output = Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"))
        .arg("--version")
        .output()?;
    assert!(
        output.status.success(),
        "実行ファイルの起動に失敗しました。stderr:\n{}",
        String::from_utf8_lossy(&output.stderr),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("(fidelogic-core: "),
        "プロファイル表示の確認に失敗しました: {stdout}",
    );
    assert!(
        output.stderr.is_empty(),
        "標準エラー出力が空でないため失敗しました: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    Ok(())
}
