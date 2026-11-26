//! リカバリーコードの統合テスト。OS の乱数源、コアの Slot 2 との接続、メモリロックの失敗を確かめる。

use std::error::Error;
use std::io::Write;
use std::process::Command;

use fidelogic_cli::recovery_code::{RECOVERY_CODE_LEN, RecoveryCode, RecoveryCodeError};
use fidelogic_cli::sys::random::fill_random;
use fidelogic_core::{
    CipherSuiteId, DEK_LEN, LockedBuffer, SLOT2_NONCE_LEN, SLOT2_SALT_LEN, SecretBytes,
    SystemError, VaultHeader, normalize_recovery_code, unwrap_dek_slot2_code_for_header,
    wrap_dek_slot2_code_for_header,
};

type TestResult = Result<(), Box<dyn Error>>;

/// 子プロセスでの実行を指示する環境変数の名前。
const CHILD_MARKER: &str = "FIDELOGIC_CLI_RECOVERY_CODE_CHILD";

/// 子プロセスが、条件を再現できないことを知らせる目印。
const SKIP_MARKER: &str = "SKIP";

#[test]
fn test_fill_random_fills_the_whole_buffer() -> TestResult {
    // 末尾が書かれないと、2 つのバッファの末尾が一致する (偶然の一致は 2^-128)。
    let mut first = [0u8; 4096];
    let mut second = [0u8; 4096];
    fill_random(&mut first)?;
    fill_random(&mut second)?;
    for (index, (left, right)) in first.chunks(16).zip(second.chunks(16)).enumerate() {
        assert_ne!(left, right, "{index} 番目の区間の乱数の取得に失敗。");
    }
    Ok(())
}

#[test]
fn test_fill_random_accepts_empty_buffer() {
    assert_eq!(fill_random(&mut []), Ok(()));
}

#[test]
fn test_generated_codes_differ_and_parse_back() -> TestResult {
    let mut codes = Vec::new();
    for _ in 0..64 {
        let code = RecoveryCode::generate(fill_random)?;
        let grouped = code.grouped()?;
        let parsed = RecoveryCode::parse(grouped.as_slice())?;
        assert_eq!(parsed.as_bytes(), code.as_bytes());
        assert_eq!(code.as_bytes().len(), RECOVERY_CODE_LEN);
        codes.push(code.as_bytes().to_vec());
    }
    codes.sort();
    codes.dedup();
    assert_eq!(codes.len(), 64, "コードの重複の確認に失敗。");
    Ok(())
}

#[test]
fn test_canonical_form_is_unchanged_by_core_normalization() -> TestResult {
    let code = RecoveryCode::generate(fill_random)?;
    let normalized = normalize_recovery_code(code.as_bytes())?;
    assert_eq!(normalized.as_slice(), code.as_bytes());
    Ok(())
}

#[test]
fn test_typed_code_unlocks_slot_wrapped_with_generated_code() -> TestResult {
    // 参照実装で計算した、0 と 1 を含むコード。
    let code = RecoveryCode::generate(|destination| {
        destination.copy_from_slice(&[
            0x00, 0x44, 0x32, 0x14, 0xc7, 0x42, 0x54, 0xb6, 0x35, 0xcf, 0x84, 0x65, 0x3a, 0x56,
            0xd7, 0xc6,
        ]);
        Ok::<(), SystemError>(())
    })?;
    let header = VaultHeader::new(1, CipherSuiteId::XChaCha20Poly1305.as_u8(), 1);
    let dek = SecretBytes::new([0x42; DEK_LEN]);
    let entry = wrap_dek_slot2_code_for_header(
        &dek,
        code.as_bytes(),
        &[0x11; SLOT2_SALT_LEN],
        &[0x22; SLOT2_NONCE_LEN],
        &header,
    )?;

    // 利用者が、小文字、空白区切り、誤読した文字で入力した場合。
    let typed = b"fl ol234 56789 abcde fghjk mnpqr s5x";
    let parsed = RecoveryCode::parse(typed)?;
    let unwrapped = unwrap_dek_slot2_code_for_header(&entry, parsed.as_bytes(), &header)?;
    assert_eq!(unwrapped.as_slice(), dek.as_slice());

    // コアは誤読を補正しないため、読み取りを通さない入力では解錠できない。
    assert!(unwrap_dek_slot2_code_for_header(&entry, typed, &header).is_err());
    Ok(())
}

/// 子プロセスの中で `mlock` を禁止し、各処理が中止することを確かめる。
///
/// 上限を 0 にしても `mlock` が成功する環境 (`CAP_IPC_LOCK` を持つプロセスなど) では、
/// 失敗を再現できないため [`SKIP_MARKER`] を出力する。環境変数が無い通常実行では何もしない。
#[test]
fn child_verify_memory_lock_failure() -> TestResult {
    if std::env::var_os(CHILD_MARKER).is_none() {
        return Ok(());
    }
    // `grouped` の確認に使うコードは、禁止する前に作る。
    let code = RecoveryCode::generate(fill_random)?;
    let canonical = code.as_bytes().to_vec();
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` は有効な構造体で、呼び出しの間は生存している。
    let result = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if result != 0 || LockedBuffer::<1>::zero_strict().is_ok() {
        writeln!(std::io::stdout(), "\n{SKIP_MARKER}")?;
        return Ok(());
    }
    let mut source_called = false;
    let generated = RecoveryCode::generate(|_| {
        source_called = true;
        Ok(())
    });
    assert_eq!(
        generated.map(|_| ()),
        Err(RecoveryCodeError::MemoryLockFailed)
    );
    assert!(
        !source_called,
        "ロックの失敗後の乱数源の未使用の確認に失敗。"
    );
    assert_eq!(
        RecoveryCode::parse(&canonical).map(|_| ()),
        Err(RecoveryCodeError::MemoryLockFailed)
    );
    assert_eq!(
        code.grouped().map(|_| ()),
        Err(RecoveryCodeError::MemoryLockFailed)
    );
    Ok(())
}

#[test]
fn test_operations_stop_when_memory_cannot_be_locked() -> TestResult {
    let output = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "child_verify_memory_lock_failure",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_MARKER, "1")
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "子プロセスの検証に失敗しました。\nstatus: {:?}\nstdout:\n{stdout}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );
    if stdout.lines().any(|line| line == SKIP_MARKER) {
        writeln!(
            std::io::stderr(),
            "スキップ: この環境では mlock の失敗を再現できません。"
        )?;
    }
    Ok(())
}
