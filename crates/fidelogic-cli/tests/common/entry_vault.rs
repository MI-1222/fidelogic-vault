//! エントリを扱うサブコマンドのテストで使う Vault の作成と読み取り、制御端末の無い実行。
//!
//! Vault は Slot 0 (高速な鍵導出パラメータ) と Slot 2 を持つ。エントリは、コアの型で直接書き込む。

use std::error::Error;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};

use fidelogic_cli::init::build_new_vault;
use fidelogic_cli::recovery_code::RecoveryCode;
use fidelogic_cli::sys::random::fill_random;
use fidelogic_core::{
    Argon2Params, CipherSuiteId, Credential, EntrySource, SecretVec, TlvRecord, Vault, VaultCipher,
    deserialize, open_entries, seal_entries, serialize,
};

use super::fixture::{OLD_CODE, UNKNOWN_TAG, dek_by_password, write_vault};
use super::{PASSWORD, TempDir, TestResult, read_vault, spawn_lock};

/// Vault と、権限 `0600` のパスワードファイルを持つ一時ディレクトリ。
pub struct EntryVault {
    pub directory: TempDir,
    pub vault: std::path::PathBuf,
    pub password_file: std::path::PathBuf,
}

impl EntryVault {
    /// エントリの無い Vault を作り、`credentials` を書き込む。
    pub fn new(credentials: &[Credential]) -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let vault = directory.path("vault.fvl");
        let password_file = directory.path("password");
        write_private(&password_file, format!("{PASSWORD}\n").as_bytes())?;
        let code = RecoveryCode::parse(OLD_CODE.as_bytes())?;
        let contents = build_new_vault(
            PASSWORD.as_bytes(),
            &code,
            &Argon2Params::fast_test(),
            fill_random,
        )
        .map_err(|error| format!("{error}"))?;
        let (mut parsed, _) = deserialize(&contents).map_err(|error| format!("{error}"))?;
        parsed.records.push(
            TlvRecord::new_unknown(UNKNOWN_TAG, b"future record".to_vec())
                .map_err(|error| format!("{error}"))?,
        );
        replace_entries(&mut parsed, credentials)?;
        write_vault(&vault, &parsed)?;
        Ok(Self {
            directory,
            vault,
            password_file,
        })
    }

    pub fn vault_text(&self) -> Result<&str, Box<dyn Error>> {
        super::text(&self.vault)
    }

    pub fn password_file_text(&self) -> Result<&str, Box<dyn Error>> {
        super::text(&self.password_file)
    }

    pub fn contents(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(std::fs::read(&self.vault)?)
    }

    pub fn epoch(&self) -> Result<u64, Box<dyn Error>> {
        Ok(read_vault(&self.vault)?.header.epoch_id)
    }

    /// 保存されているエントリを、記録順に返す。
    pub fn credentials(&self) -> Result<Vec<Credential>, Box<dyn Error>> {
        let vault = read_vault(&self.vault)?;
        let cipher = cipher_of(&vault)?;
        open_entries(&cipher, &vault.header, &vault.records)
            .map_err(|error| format!("エントリの復号に失敗: {error}"))?
            .iter()
            .map(|entry| Ok(Credential::decode_opened(entry).map_err(|error| error.to_string())?))
            .collect()
    }

    /// 指定したタイトルのエントリを返す。
    pub fn credential(&self, title: &str) -> Result<Credential, Box<dyn Error>> {
        Ok(self
            .credentials()?
            .into_iter()
            .find(|credential| credential.title.as_deref() == Some(title))
            .ok_or_else(|| format!("{title} がありません。"))?)
    }

    /// 他の処理の保存を模して、世代を `epoch` にしてエントリを置き換える。
    pub fn overwrite(&self, epoch: u64, credentials: &[Credential]) -> TestResult {
        let mut vault = read_vault(&self.vault)?;
        let cipher = cipher_of(&vault)?;
        vault.header.epoch_id = epoch;
        seal_into(&mut vault, &cipher, credentials)?;
        write_vault(&self.vault, &vault)
    }

    /// 保存後も、Slot と未知のレコードが残り、権限が `0600` であること。
    pub fn assert_preserved(&self, slots_before: &Vault) -> TestResult {
        let vault = read_vault(&self.vault)?;
        // スロットの型は比較を持たないため、スロットだけの Vault を直列化して比べる。
        let slot_bytes = |source: &Vault| {
            serialize(&Vault::new(
                slots_before.header,
                source.slots.clone(),
                Vec::new(),
            ))
            .map_err(|error| format!("{error}"))
        };
        assert!(
            slot_bytes(&vault)? == slot_bytes(slots_before)?,
            "スロットを変えないことの確認に失敗。"
        );
        assert!(
            matches!(
                vault.records.last(),
                Some(TlvRecord::Unknown { tag: UNKNOWN_TAG, raw_bytes })
                    if raw_bytes.as_slice() == b"future record"
            ),
            "未知のレコードの保持の確認に失敗。"
        );
        assert_eq!(super::mode_of(&self.vault)?, 0o600);
        Ok(())
    }
}

fn cipher_of(vault: &Vault) -> Result<VaultCipher, Box<dyn Error>> {
    let dek = dek_by_password(vault, PASSWORD).ok_or("解錠に失敗しました。")?;
    let suite =
        CipherSuiteId::from_u8(vault.header.suite_id).map_err(|error| format!("{error}"))?;
    Ok(VaultCipher::new(suite, &dek))
}

fn replace_entries(vault: &mut Vault, credentials: &[Credential]) -> TestResult {
    let cipher = cipher_of(vault)?;
    seal_into(vault, &cipher, credentials)
}

fn seal_into(vault: &mut Vault, cipher: &VaultCipher, credentials: &[Credential]) -> TestResult {
    let bodies = credentials
        .iter()
        .map(|credential| {
            Ok((
                credential.entry_id,
                credential.encode().map_err(|error| error.to_string())?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let sources: Vec<EntrySource<'_>> = bodies
        .iter()
        .map(|(entry_id, body)| EntrySource {
            entry_id: *entry_id,
            data: body.as_slice(),
        })
        .collect();
    let unknown: Vec<TlvRecord> = vault
        .records
        .iter()
        .filter(|record| matches!(record, TlvRecord::Unknown { .. }))
        .cloned()
        .collect();
    vault.records = seal_entries(cipher, &vault.header, &sources, fill_random)
        .map_err(|error| format!("{error}"))?;
    vault.records.extend(unknown);
    Ok(())
}

/// 全項目を持つエントリを作る。
pub fn credential(id: u8, title: &str) -> Credential {
    let secret = |text: String| Some(SecretVec::from_slice(text.as_bytes()));
    let mut credential = Credential::new([id; 16]);
    credential.title = Some(title.to_owned());
    credential.username = secret(format!("user-of-{title}"));
    credential.password = secret(format!("password-of-{title}"));
    credential.url = Some(format!("https://{id}.example"));
    credential.totp = secret(format!("totp-of-{title}"));
    credential.notes = secret(format!("notes-of-{title}"));
    credential.created_at = Some(100);
    credential.updated_at = Some(200);
    credential
}

/// 権限 `0600` のファイルを書く。
pub fn write_private(path: &Path, contents: &[u8]) -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// 制御端末の無い状態で実行ファイルを起動するコマンドを組み立てる。入出力はすべてパイプにする。
fn command_without_terminal(args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"));
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: `pre_exec` のクロージャーは `fork` 後の子プロセスで実行される。
    // `setsid` は非同期シグナルセーフで、新しいセッションは制御端末を持たない。
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

/// 制御端末の無い状態で実行ファイルを起動し、`stdin` を渡して終了を待つ。
pub fn run_without_terminal(args: &[&str], stdin: &[u8]) -> Result<Output, Box<dyn Error>> {
    let mut child = spawn_without_terminal(args)?;
    let mut input = child.stdin.take().ok_or("子の標準入力がありません。")?;
    // 入力を読まずに終了する場合があるため、書き込みの失敗は結果で確かめる。
    let _ = input.write_all(stdin);
    drop(input);
    Ok(child.wait_with_output()?)
}

/// 制御端末の無い状態で実行ファイルを起動する。標準入力は呼び出し側が書き込む。
pub fn spawn_without_terminal(args: &[&str]) -> Result<Child, Box<dyn Error>> {
    let mut command = command_without_terminal(args);
    // 開発者の環境のクリップボードに、テストから接続しない。
    command.env_remove("DISPLAY").env_remove("WAYLAND_DISPLAY");
    let _guard = spawn_lock();
    Ok(command.spawn()?)
}

/// [`spawn_without_terminal`] と同じ処理で、ディスプレイの指定を引き継ぐ。
///
/// クリップボードを上書きするため、明示して実行するテストだけが使う。
pub fn spawn_with_display(args: &[&str]) -> Result<Child, Box<dyn Error>> {
    let mut command = command_without_terminal(args);
    let _guard = spawn_lock();
    Ok(command.spawn()?)
}

/// 制御端末の無い実行の失敗の終了コードと、1 行のエラー出力を確かめる。
pub fn assert_process_failure(output: &Output, status: i32, message: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(status),
        "終了コードの確認に失敗: {stderr}"
    );
    assert!(output.stdout.is_empty(), "標準出力が空ではありません。");
    let last = stderr.lines().last().unwrap_or_default();
    assert!(
        last.starts_with("fidelogic-cli: ") && last.contains(message),
        "エラー出力の確認に失敗: {stderr}"
    );
}
