//! Vault ファイルの読み込み、アトミックな保存、世代の二重検証の統合テスト。
//!
//! 暗号器と乱数源はテスト用の固定値を使う。乱数源は呼び出しごとに異なるバイト列を返し、ノンスが衝突しない。
//! `umask`、ファイルサイズの上限、シグナルの扱いはプロセス全体の状態のため、変更は子プロセスに対してだけ行う。

use std::error::Error;
use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use fidelogic_cli::sys::storage::{
    DirectorySync, StorageError, StorageStep, VaultLock, VaultPath, create_vault_file_atomically,
    read_vault_file, write_new_private_file, write_vault_file_atomically,
};
use fidelogic_cli::vault_file::{LoadedVault, VaultFileError, save_vault};
use fidelogic_core::{
    CipherSuiteId, CryptoError, EntryId, EntrySource, KekSlotEntry, SystemError, TlvParseError,
    TlvRecord, Vault, VaultCipher, VaultError, VaultHeader, open_entries, seal_entries, serialize,
};

type TestResult = Result<(), Box<dyn Error>>;

/// 子プロセスに書き込ませる Vault のパスを渡す環境変数の名前。
const CHILD_VAULT: &str = "FIDELOGIC_CLI_SAVE_CHILD_VAULT";
/// 子プロセスが書き込みを終えたことを示す出力。
const MARKER_WRITTEN: &str = "save-child:written";
/// 子プロセスに、新規に作成させる Vault のパスを渡す環境変数の名前。
const CHILD_CREATED_VAULT: &str = "FIDELOGIC_CLI_CREATE_CHILD_VAULT";
/// 子プロセスが新規の作成を終えたことを示す出力。
const MARKER_CREATED: &str = "save-child:created";
/// 子プロセスに、書き込みの失敗を確認させる Vault のパスを渡す環境変数の名前。
const CHILD_LIMITED_VAULT: &str = "FIDELOGIC_CLI_SAVE_CHILD_LIMITED_VAULT";
/// 子プロセスで書き込みが失敗したことを確認できたことを示す出力。
const MARKER_WRITE_REJECTED: &str = "save-child:write-rejected";
/// 書き込みを失敗させる子プロセスの、ファイルサイズの上限 (バイト)。
const CHILD_FILE_SIZE_LIMIT: libc::rlim_t = 1024;

/// テストで使う暗号スイート。
const SUITE: CipherSuiteId = CipherSuiteId::XChaCha20Poly1305;
/// テストで使う DEK。
const DEK: [u8; 32] = [0x5A; 32];
/// 最初に書き込む Vault の世代。
const INITIAL_EPOCH: u64 = 5;
/// 未知のタグのレコードのタグ。
const UNKNOWN_TAG: u8 = 0x7F;

const SHORT_ID: EntryId = [1; 16];
const LONG_ID: EntryId = [2; 16];

/// テスト用の一時ディレクトリ。破棄するときに中身ごと削除する。
struct TempDir(PathBuf);

impl TempDir {
    /// 一時ディレクトリを作成する。保持するパスはシンボリックリンクを解決したものである。
    fn new() -> Result<Self, Box<dyn Error>> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "fidelogic-cli-save-{}-{nanos}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(fs::canonicalize(path)?))
    }

    fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.0.join(name)
    }

    /// ディレクトリの中身の名前を並べて返す。
    fn names(&self) -> Result<Vec<String>, Box<dyn Error>> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.0)? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 呼び出しごとに異なるバイト列を返す乱数源。
fn counter_rng(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), SystemError> {
    let mut counter = seed << 32;
    move |buffer| {
        counter += 1;
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = counter.to_le_bytes()[index % 8] ^ (index as u8).wrapping_mul(31);
        }
        Ok(())
    }
}

fn cipher() -> VaultCipher {
    VaultCipher::new(SUITE, &DEK)
}

/// テストで使う KEK スロット。中身は解錠に使わないため、固定のバイト列とする。
fn slots() -> Result<Vec<KekSlotEntry>, Box<dyn Error>> {
    Ok(vec![
        KekSlotEntry::new(0, 1, vec![0xA0; 100])?,
        KekSlotEntry::new(1, 2, vec![0xB1; 104])?,
    ])
}

/// 4 KiB 級のエントリ (複数のチャンクに分かれる) の平文。
fn long_data() -> Vec<u8> {
    (0..4096u32).map(|value| (value % 251) as u8).collect()
}

/// 世代 `epoch_id` の Vault ファイルの内容を作る。エントリ 1 件と未知のタグのレコード 1 件を含む。
fn vault_bytes(epoch_id: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let header = VaultHeader::new(1, SUITE.as_u8(), epoch_id);
    let entries = [EntrySource {
        entry_id: SHORT_ID,
        data: b"old-secret",
    }];
    let mut records = seal_entries(&cipher(), &header, &entries, counter_rng(epoch_id))?;
    records.push(TlvRecord::new_unknown(UNKNOWN_TAG, vec![1, 2, 3])?);
    Ok(serialize(&Vault::new(header, slots()?, records))?)
}

/// 初期の Vault を書き込み、そのロックと読み込んだ Vault を返す。
fn setup(dir: &TempDir) -> Result<(VaultLock, LoadedVault), Box<dyn Error>> {
    fs::write(dir.join("vault.fvl"), vault_bytes(INITIAL_EPOCH)?)?;
    let lock = VaultLock::acquire(VaultPath::resolve(&dir.join("vault.fvl"))?)?;
    let loaded = LoadedVault::read(&lock)?.ok_or("Vault が見つからないため失敗しました。")?;
    Ok((lock, loaded))
}

/// 保存し、失敗することを前提にエラーを取り出す。
fn save_error(
    lock: &VaultLock,
    base: &LoadedVault,
    cipher: &VaultCipher,
) -> Result<VaultFileError, Box<dyn Error>> {
    let entries = [EntrySource {
        entry_id: SHORT_ID,
        data: b"new-secret",
    }];
    match save_vault(
        lock,
        base,
        cipher,
        base.slots().to_vec(),
        &entries,
        counter_rng(99),
    ) {
        Ok(saved) => Err(format!("保存が拒否されずに失敗しました: {saved:?}").into()),
        Err(error) => Ok(error),
    }
}

/// エントリのレコードの暗号文を並べて返す。
fn entry_payloads(records: &[TlvRecord]) -> Vec<Vec<u8>> {
    records
        .iter()
        .filter_map(|record| match record {
            TlvRecord::Entry(payload) => Some(payload.ciphertext.clone()),
            TlvRecord::Unknown { .. } => None,
        })
        .collect()
}

#[test]
fn test_save_advances_epoch_and_reencrypts_all_entries() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    let long = long_data();
    let entries = [
        EntrySource {
            entry_id: SHORT_ID,
            data: b"new-secret",
        },
        EntrySource {
            entry_id: LONG_ID,
            data: &long,
        },
    ];

    let saved = save_vault(
        &lock,
        &loaded,
        &cipher(),
        loaded.slots().to_vec(),
        &entries,
        counter_rng(1),
    )?;
    assert_eq!(saved.directory_sync, DirectorySync::Synced);
    assert_eq!(saved.vault.header().epoch_id, INITIAL_EPOCH + 1);

    let reread =
        LoadedVault::read(&lock)?.ok_or("保存後の Vault が見つからないため失敗しました。")?;
    let header = reread.header();
    assert_eq!(
        header.epoch_id,
        INITIAL_EPOCH + 1,
        "世代を進めることに失敗。"
    );
    assert_eq!(
        (header.version, header.suite_id),
        (loaded.header().version, loaded.header().suite_id)
    );
    assert!(reread.slots() == loaded.slots(), "スロットの保持に失敗。");
    assert!(
        reread.records() == saved.vault.records(),
        "戻り値と書き込んだ内容の一致に失敗。"
    );

    let opened = open_entries(&cipher(), header, reread.records())?;
    let contents: Vec<(EntryId, &[u8])> = opened
        .iter()
        .map(|entry| (entry.entry_id, entry.data.as_slice()))
        .collect();
    assert_eq!(
        contents,
        [(SHORT_ID, &b"new-secret"[..]), (LONG_ID, &long[..])]
    );

    // 新しいレコードは新しい世代の関連データに結び付いている。
    assert_eq!(
        open_entries(&cipher(), loaded.header(), reread.records()).err(),
        Some(VaultError::AuthenticationFailed)
    );
    // 未知のタグのレコードは、末尾にそのまま残る。
    let unknown: Vec<&TlvRecord> = reread
        .records()
        .iter()
        .filter(|record| matches!(record, TlvRecord::Unknown { .. }))
        .collect();
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].tag(), UNKNOWN_TAG);
    assert_eq!(unknown[0].raw_bytes(), Some(&[1u8, 2, 3][..]));
    assert!(matches!(
        reread.records().last(),
        Some(TlvRecord::Unknown { .. })
    ));
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_saving_same_entries_uses_new_nonces() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    let entries = [EntrySource {
        entry_id: SHORT_ID,
        data: b"old-secret",
    }];

    let first = save_vault(
        &lock,
        &loaded,
        &cipher(),
        loaded.slots().to_vec(),
        &entries,
        counter_rng(1),
    )?;
    let second = save_vault(
        &lock,
        &first.vault,
        &cipher(),
        first.vault.slots().to_vec(),
        &entries,
        counter_rng(2),
    )?;
    assert_eq!(second.vault.header().epoch_id, INITIAL_EPOCH + 2);

    let before = entry_payloads(loaded.records());
    let after_first = entry_payloads(first.vault.records());
    let after_second = entry_payloads(second.vault.records());
    assert_eq!(before.len(), after_second.len());
    for (index, payload) in after_second.iter().enumerate() {
        assert!(
            payload != &before[index] && payload != &after_first[index],
            "レコード {index} の再暗号化に失敗。"
        );
    }
    let opened = open_entries(&cipher(), second.vault.header(), second.vault.records())?;
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].data.as_slice(), b"old-secret");
    Ok(())
}

#[test]
fn test_save_writes_given_slots_and_removes_omitted_entries() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    // スロット 0 を差し替え、スロット 1 とすべてのエントリを除いて保存する。
    let new_slots = vec![KekSlotEntry::new(0, 1, vec![0xC2; 100])?];

    let _ = save_vault(
        &lock,
        &loaded,
        &cipher(),
        new_slots.clone(),
        &[],
        counter_rng(1),
    )?;

    let reread =
        LoadedVault::read(&lock)?.ok_or("保存後の Vault が見つからないため失敗しました。")?;
    assert!(
        reread.slots() == new_slots.as_slice(),
        "指定したスロットの書き込みに失敗。"
    );
    let opened = open_entries(&cipher(), reread.header(), reread.records())?;
    assert!(opened.is_empty(), "省いたエントリの削除に失敗。");
    // 残るのは、空のマニフェストと未知のタグのレコードである。
    assert_eq!(reread.records().len(), 2);
    Ok(())
}

#[test]
fn test_save_rejects_newer_vault_written_without_lock() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    // ロックを取得しない外部のツールが、読み込んだ後に更新した状況。
    let external = vault_bytes(INITIAL_EPOCH + 1)?;
    fs::write(dir.join("vault.fvl"), &external)?;

    assert_eq!(
        save_error(&lock, &loaded, &cipher())?,
        VaultFileError::ModifiedExternally
    );
    assert_eq!(fs::read(dir.join("vault.fvl"))?, external);
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_save_rejects_older_snapshot_as_rollback() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    let snapshot = vault_bytes(INITIAL_EPOCH - 1)?;
    fs::write(dir.join("vault.fvl"), &snapshot)?;

    assert_eq!(
        save_error(&lock, &loaded, &cipher())?,
        VaultFileError::Vault(VaultError::RollbackDetected)
    );
    assert_eq!(fs::read(dir.join("vault.fvl"))?, snapshot);
    Ok(())
}

#[test]
fn test_save_rejects_vault_removed_after_reading() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    fs::remove_file(dir.join("vault.fvl"))?;

    assert_eq!(
        save_error(&lock, &loaded, &cipher())?,
        VaultFileError::ModifiedExternally
    );
    assert_eq!(dir.names()?, ["vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_save_rejects_lock_of_other_vault() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    drop(lock);
    fs::write(dir.join("other.fvl"), vault_bytes(INITIAL_EPOCH)?)?;
    let other = VaultLock::acquire(VaultPath::resolve(&dir.join("other.fvl"))?)?;

    assert_eq!(
        save_error(&other, &loaded, &cipher())?,
        VaultFileError::PathMismatch
    );
    assert_eq!(
        fs::read(dir.join("other.fvl"))?,
        vault_bytes(INITIAL_EPOCH)?
    );
    Ok(())
}

#[test]
fn test_save_failures_before_writing_keep_vault() -> TestResult {
    let dir = TempDir::new()?;
    let (lock, loaded) = setup(&dir)?;
    let original = fs::read(dir.join("vault.fvl"))?;

    // 暗号スイートがヘッダーと異なる暗号器。
    let mismatched = VaultCipher::new(CipherSuiteId::Aes256GcmSiv, &DEK);
    assert_eq!(
        save_error(&lock, &loaded, &mismatched)?,
        VaultFileError::Vault(VaultError::Crypto(CryptoError::InvalidParameter))
    );

    // 乱数源の失敗。
    let entries = [EntrySource {
        entry_id: SHORT_ID,
        data: b"new-secret",
    }];
    let failure = save_vault(
        &lock,
        &loaded,
        &cipher(),
        loaded.slots().to_vec(),
        &entries,
        |_: &mut [u8]| Err(SystemError::EntropySourceFailed),
    )
    .err();
    assert_eq!(
        failure,
        Some(VaultFileError::Vault(VaultError::System(
            SystemError::EntropySourceFailed
        )))
    );

    // スロット数が上限を超え、直列化に失敗する。
    let slot = KekSlotEntry::new(0, 1, vec![0xA0; 100])?;
    let failure = save_vault(
        &lock,
        &loaded,
        &cipher(),
        vec![slot; usize::from(u8::MAX) + 1],
        &entries,
        counter_rng(1),
    )
    .err();
    assert_eq!(
        failure,
        Some(VaultFileError::Vault(VaultError::Parse(
            TlvParseError::InvalidLength
        )))
    );

    assert_eq!(fs::read(dir.join("vault.fvl"))?, original);
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

#[test]
fn test_save_rejects_exhausted_epoch() -> TestResult {
    let dir = TempDir::new()?;
    fs::write(dir.join("vault.fvl"), vault_bytes(u64::MAX)?)?;
    let lock = VaultLock::acquire(VaultPath::resolve(&dir.join("vault.fvl"))?)?;
    let loaded = LoadedVault::read(&lock)?.ok_or("Vault が見つからないため失敗しました。")?;

    assert_eq!(
        save_error(&lock, &loaded, &cipher())?,
        VaultFileError::EpochExhausted
    );
    assert_eq!(fs::read(dir.join("vault.fvl"))?, vault_bytes(u64::MAX)?);
    Ok(())
}

#[test]
fn test_read_returns_none_for_missing_vault_and_rejects_malformed() -> TestResult {
    let dir = TempDir::new()?;
    let lock = VaultLock::acquire(VaultPath::resolve(&dir.join("vault.fvl"))?)?;
    assert!(LoadedVault::read(&lock)?.is_none());

    let mut trailing = vault_bytes(INITIAL_EPOCH)?;
    trailing.push(0);
    for (label, contents) in [
        ("空のファイル", Vec::new()),
        ("マジックバイトの誤り", b"XXXX0123456789abcdef".to_vec()),
        ("末尾の余分なバイト", trailing),
    ] {
        fs::write(dir.join("vault.fvl"), contents)?;
        assert!(
            matches!(
                LoadedVault::read(&lock),
                Err(VaultFileError::Vault(VaultError::Parse(_)))
            ),
            "{label}の拒否に失敗。"
        );
    }
    Ok(())
}

#[test]
fn test_read_vault_file_limits_size_and_rejects_non_regular_files() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");
    fs::write(&vault, b"0123456789")?;
    let lock = VaultLock::acquire(VaultPath::resolve(&vault)?)?;

    assert_eq!(read_vault_file(&lock, 10)?, Some(b"0123456789".to_vec()));
    assert_eq!(read_vault_file(&lock, 9), Err(StorageError::VaultTooLarge));

    // 解決した後に、パスをシンボリックリンクに置き換えた場合。
    fs::write(dir.join("elsewhere"), b"other")?;
    fs::remove_file(&vault)?;
    symlink(dir.join("elsewhere"), &vault)?;
    assert_eq!(
        read_vault_file(&lock, 1024),
        Err(StorageError::Os {
            step: StorageStep::ReadVault,
            errno: libc::ELOOP,
        })
    );

    // FIFO は、書き込み側を待たずに拒否する。
    fs::remove_file(&vault)?;
    let status = Command::new("mkfifo").arg(&vault).status()?;
    assert!(status.success(), "FIFO の作成に失敗。");
    assert_eq!(
        read_vault_file(&lock, 1024),
        Err(StorageError::VaultNotRegularFile)
    );

    fs::remove_file(&vault)?;
    fs::create_dir(&vault)?;
    assert_eq!(
        read_vault_file(&lock, 1024),
        Err(StorageError::VaultNotRegularFile)
    );
    Ok(())
}

#[test]
fn test_atomic_write_replaces_vault_inode_and_keeps_lock_file() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");
    fs::write(&vault, b"old")?;
    let lock = VaultLock::acquire(VaultPath::resolve(&vault)?)?;
    let vault_inode = fs::metadata(&vault)?.ino();
    let lock_inode = fs::metadata(dir.join("vault.fvl.lock"))?.ino();

    assert_eq!(
        write_vault_file_atomically(&lock, b"new")?,
        DirectorySync::Synced
    );
    assert_eq!(fs::read(&vault)?, b"new");
    assert_ne!(
        fs::metadata(&vault)?.ino(),
        vault_inode,
        "`rename` による置換の確認に失敗。"
    );
    assert_eq!(fs::metadata(dir.join("vault.fvl.lock"))?.ino(), lock_inode);
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);

    // 保持しているロックは、置換の後も有効である。
    assert_eq!(
        VaultLock::try_acquire(VaultPath::resolve(&vault)?).err(),
        Some(StorageError::Locked)
    );
    Ok(())
}

#[test]
fn test_atomic_write_removes_temp_file_when_rename_fails() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");
    fs::write(&vault, b"old")?;
    let lock = VaultLock::acquire(VaultPath::resolve(&vault)?)?;
    // 解決した後に、Vault のパスを空でないディレクトリに置き換え、`rename` を失敗させる。
    fs::remove_file(&vault)?;
    fs::create_dir(&vault)?;
    fs::write(vault.join("keep"), b"")?;

    let error = write_vault_file_atomically(&lock, b"new")
        .err()
        .ok_or("置換の失敗を成功として扱ったため失敗しました。")?;
    assert!(
        matches!(
            error,
            StorageError::Os {
                step: StorageStep::Rename,
                ..
            }
        ),
        "置換の手順での失敗の報告に失敗: {error:?}"
    );
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    assert!(vault.join("keep").exists());
    Ok(())
}

#[test]
fn test_atomic_write_reports_errno_when_temp_file_cannot_be_created() -> TestResult {
    let dir = TempDir::new()?;
    fs::create_dir(dir.join("store"))?;
    let lock = VaultLock::acquire(VaultPath::resolve(&dir.join("store/vault.fvl"))?)?;
    // 解決した後にディレクトリを移し、一時ファイルを作成できない状態にする。
    // 権限の変更は、`root` で実行する環境では失敗を再現できないため使わない。
    fs::rename(dir.join("store"), dir.join("moved"))?;

    assert_eq!(
        write_vault_file_atomically(&lock, b"new"),
        Err(StorageError::Os {
            step: StorageStep::CreateTempFile,
            errno: libc::ENOENT,
        })
    );
    Ok(())
}

/// 子プロセスの中で実行する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_save_action() -> TestResult {
    let Some(vault) = std::env::var_os(CHILD_VAULT) else {
        return Ok(());
    };
    let lock = VaultLock::acquire(VaultPath::resolve(Path::new(&vault))?)?;
    let _ = write_vault_file_atomically(&lock, b"written-by-child")?;
    println!("{MARKER_WRITTEN}");
    Ok(())
}

/// テストバイナリを再実行し、子用のテスト `test_name` を実行するコマンドを組み立てる。
fn child_command(test_name: &str, variable: &str, vault: &Path) -> Result<Command, Box<dyn Error>> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(variable, vault);
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
fn test_atomic_write_creates_owner_only_file_regardless_of_umask() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");

    // `umask` に頼らず権限を指定していることを確認するため、子の `umask` を 0 にする。
    let mut command = child_command("child_save_action", CHILD_VAULT, &vault)?;
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `umask` は非同期シグナルセーフであり、ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    assert_child_output(command, MARKER_WRITTEN)?;

    assert_eq!(fs::read(&vault)?, b"written-by-child");
    assert_eq!(
        fs::metadata(&vault)?.mode() & 0o7777,
        0o600,
        "Vault ファイルの権限が 0600 でないため失敗しました。"
    );
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}

/// 子プロセスの中で、Vault と秘密を含むファイルを新規に作成する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_create_action() -> TestResult {
    let Some(vault) = std::env::var_os(CHILD_CREATED_VAULT) else {
        return Ok(());
    };
    let vault = PathBuf::from(vault);
    let lock = VaultLock::acquire(VaultPath::resolve(&vault)?)?;
    assert_eq!(
        create_vault_file_atomically(&lock, b"created-by-child")?,
        DirectorySync::Synced
    );
    assert_eq!(
        write_new_private_file(&vault.with_extension("html"), |file| {
            std::io::Write::write_all(file, b"private")
        })?,
        DirectorySync::Synced
    );
    println!("{MARKER_CREATED}");
    Ok(())
}

#[test]
fn test_new_files_are_owner_only_regardless_of_umask() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");

    // `umask` に頼らず権限を指定していることを確認するため、子の `umask` を 0 にする。
    let mut command = child_command("child_create_action", CHILD_CREATED_VAULT, &vault)?;
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `umask` は非同期シグナルセーフであり、ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(|| {
            libc::umask(0);
            Ok(())
        });
    }
    assert_child_output(command, MARKER_CREATED)?;

    for name in ["vault.fvl", "vault.html"] {
        assert_eq!(
            fs::metadata(dir.join(name))?.mode() & 0o7777,
            0o600,
            "{name} の権限が 0600 でないため失敗しました。"
        );
    }
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock", "vault.html"]);
    Ok(())
}

/// 子プロセスの中で、ファイルサイズの上限を超える書き込みの失敗を確認する本体。環境変数が無い通常実行では何もしない。
#[test]
fn child_write_failure_action() -> TestResult {
    let Some(vault) = std::env::var_os(CHILD_LIMITED_VAULT) else {
        return Ok(());
    };
    let lock = VaultLock::acquire(VaultPath::resolve(Path::new(&vault))?)?;
    let contents = vec![0u8; 4096];
    assert_eq!(
        write_vault_file_atomically(&lock, &contents),
        Err(StorageError::Os {
            step: StorageStep::WriteTempFile,
            errno: libc::EFBIG,
        })
    );
    println!("{MARKER_WRITE_REJECTED}");
    Ok(())
}

#[test]
fn test_atomic_write_keeps_vault_when_writing_temp_file_fails() -> TestResult {
    let dir = TempDir::new()?;
    let vault = dir.join("vault.fvl");
    fs::write(&vault, b"old")?;

    // 一時ファイルへの書き込みを途中で失敗させるため、子のファイルサイズの上限を小さくする。
    let mut command = child_command("child_write_failure_action", CHILD_LIMITED_VAULT, &vault)?;
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `signal` と `setrlimit` は非同期シグナルセーフであり、`limit` は呼び出しの間有効である。
    // ヒープ確保などの安全でない処理は行わない。
    unsafe {
        command.pre_exec(|| {
            let limit = libc::rlimit {
                rlim_cur: CHILD_FILE_SIZE_LIMIT,
                rlim_max: CHILD_FILE_SIZE_LIMIT,
            };
            // 上限を超えた書き込みでプロセスが終了せず `EFBIG` が返るように、`SIGXFSZ` を無視する。
            if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR
                || libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    assert_child_output(command, MARKER_WRITE_REJECTED)?;

    assert_eq!(fs::read(&vault)?, b"old");
    assert_eq!(dir.names()?, ["vault.fvl", "vault.fvl.lock"]);
    Ok(())
}
