//! `init` から `export` までの一連の操作を、1 つの Vault と実行ファイルで確かめる統合テスト。
//!
//! 各段階は、直前の段階が保存した Vault と、画面に表示されたリカバリーコードを引き継ぐ。
//! 端末が要る操作は疑似端末で、要らない操作は制御端末の無いプロセスで実行する。
//! Vault は `init` が作るため、鍵導出はネイティブ向けのパラメータになる。

mod common;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::entry_vault::{assert_process_failure, run_without_terminal, write_private};
use common::fixture::{dek_by_code, slot_ids};
use common::*;
use fidelogic_core::{CipherSuiteId, TlvRecord, chunk_data_capacity};

const USERNAME_PROMPT: &str = "ユーザー名 (空の Enter で";
const PASSWORD_FIELD_PROMPT: &str = "パスワード (空の Enter で";
const REPEAT_FIELD_PROMPT: &str = "確認のため、もう一度入力してください: ";
const URL_PROMPT: &str = "URL (空の Enter で";
const TOTP_PROMPT: &str = "otpauth URI (空の Enter で";
const NOTES_PROMPT: &str = "メモ (1 行) (空の Enter で";
const CURRENT_PASSWORD_PROMPT: &str = "現在のマスターパスワード: ";
const CODE_PROMPT: &str = "リカバリーコード (入力は表示されません): ";
const AUTHENTICATION_FAILED: &str = "Vault の解錠に失敗しました。";

/// 短いエントリのタイトルと、各項目の値。
const SHORT_TITLE: &str = "mail";
const SHORT_FIELDS: [(&str, &str); 5] = [
    ("username", "alice"),
    ("password", "short secret"),
    ("url", "https://mail.example"),
    ("totp", "otpauth://totp/mail?secret=JBSWY3DPEHPK3PXP"),
    ("notes", "short memo"),
];

/// 大きいエントリのタイトルと、ユーザー名。
const LARGE_TITLE: &str = "ssh key";
const LARGE_USERNAME: &str = "deploy";

/// 大きいエントリのメモのバイト数 (4 KiB)。
const LARGE_NOTES_LEN: usize = 4096;

/// `init` の後に、鍵を更新するたびに設定するマスターパスワード。
const SECOND_PASSWORD: &str = "second passphrase after kek rotation";
const THIRD_PASSWORD: &str = "third passphrase after dek rotation";
const FOURTH_PASSWORD: &str = "fourth passphrase after recovery";

/// 行ごとに内容が異なる、4 KiB の複数行のメモ。チャンクの順序の誤りは、内容の不一致になる。
fn large_notes() -> String {
    let mut notes: String = (0..200)
        .map(|index| format!("line {index:04} abcdefghijklmnopqrstuvwxyz\n"))
        .collect();
    notes.truncate(LARGE_NOTES_LEN);
    notes
}

/// 一連の操作の対象。
struct Lifecycle {
    directory: TempDir,
    vault: PathBuf,
}

impl Lifecycle {
    fn new() -> Result<Self, Box<dyn Error>> {
        let directory = TempDir::new()?;
        let vault = directory.path("vault.fvl");
        Ok(Self { directory, vault })
    }

    fn vault_text(&self) -> Result<&str, Box<dyn Error>> {
        text(&self.vault)
    }

    /// `password` を含む権限 `0600` のファイルを作る。
    fn password_file(&self, name: &str, password: &str) -> Result<PathBuf, Box<dyn Error>> {
        let path = self.directory.path(name);
        write_private(&path, format!("{password}\n").as_bytes())?;
        Ok(path)
    }

    /// 端末の無いプロセスで、`arguments` に Vault とパスワードファイルの指定を加えて実行する。
    fn run(&self, arguments: &[&str], password_file: &Path) -> Result<Output, Box<dyn Error>> {
        let mut args = arguments.to_vec();
        args.extend([
            "--vault",
            self.vault_text()?,
            "--password-file",
            text(password_file)?,
        ]);
        run_without_terminal(&args, b"")
    }

    /// [`Lifecycle::run`] の成功を確かめて、標準出力を返す。
    fn read(&self, arguments: &[&str], password_file: &Path) -> Result<String, Box<dyn Error>> {
        let output = self.run(arguments, password_file)?;
        assert_eq!(
            output.status.code(),
            Some(0),
            "{arguments:?} の実行に失敗: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            output.stderr.is_empty(),
            "標準エラー出力が空ではありません。"
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    /// 更新前のパスワードでは、解錠できないこと。
    fn assert_password_rejected(&self, password_file: &Path) -> TestResult {
        let output = self.run(&["list"], password_file)?;
        assert_process_failure(&output, 3, AUTHENTICATION_FAILED);
        Ok(())
    }

    /// 2 件のエントリの秘密を、保存した値のまま取り出せること。
    fn assert_secrets(&self, password_file: &Path) -> TestResult {
        let password = self.read(&["get", SHORT_TITLE, "--field", "password"], password_file)?;
        assert_eq!(password, "short secret");
        let notes = self.read(&["get", LARGE_TITLE, "--field", "notes"], password_file)?;
        assert!(notes == large_notes(), "4 KiB のメモの保持の確認に失敗。");
        Ok(())
    }

    fn assert_epoch(&self, expected: u64) -> TestResult {
        assert_eq!(
            read_vault(&self.vault)?.header.epoch_id,
            expected,
            "世代の確認に失敗。"
        );
        Ok(())
    }

    fn entry_record_count(&self) -> Result<usize, Box<dyn Error>> {
        Ok(read_vault(&self.vault)?
            .records
            .iter()
            .filter(|record| matches!(record, TlvRecord::Entry(_)))
            .count())
    }

    /// `code` で解錠した場合の DEK。解錠できない場合は `None`。
    fn dek(&self, code: &str) -> Result<Option<[u8; 32]>, Box<dyn Error>> {
        Ok(dek_by_code(&read_vault(&self.vault)?, code))
    }

    /// `init` で Vault を作り、表示されたリカバリーコードを返す。
    fn init(&self) -> Result<String, Box<dyn Error>> {
        let mut session = Session::spawn(
            &["init", "--vault", self.vault_text()?],
            &Options::default(),
        )?;
        let code = session.enter_password_and_read_code()?;
        confirm(&mut session, &code)?;
        assert_success(&session.finish()?, "Vault を作成しました");
        Ok(code)
    }

    /// `set` で、全項目を端末から入力して短いエントリを追加する。
    fn set_short_entry(&self, password_file: &Path) -> TestResult {
        let mut session = Session::spawn(
            &[
                "set",
                "--vault",
                self.vault_text()?,
                SHORT_TITLE,
                "--password-file",
                text(password_file)?,
            ],
            &Options::default(),
        )?;
        let [username, password, url, totp, notes] = SHORT_FIELDS.map(|(_, value)| value);
        session.answer(USERNAME_PROMPT, username)?;
        session.answer(PASSWORD_FIELD_PROMPT, password)?;
        session.answer(REPEAT_FIELD_PROMPT, password)?;
        session.answer(URL_PROMPT, url)?;
        session.answer(TOTP_PROMPT, totp)?;
        session.answer(NOTES_PROMPT, notes)?;
        assert_success(&session.finish()?, "エントリを追加しました: mail");
        Ok(())
    }

    /// `set` で、メモをファイルから読み込んで大きいエントリを追加する。
    fn set_large_entry(&self, password_file: &Path) -> TestResult {
        let notes_file = self.directory.path("notes");
        write_private(&notes_file, large_notes().as_bytes())?;
        let mut session = Session::spawn(
            &[
                "set",
                "--vault",
                self.vault_text()?,
                LARGE_TITLE,
                "--notes-file",
                text(&notes_file)?,
                "--password-file",
                text(password_file)?,
            ],
            &Options::default(),
        )?;
        session.answer(USERNAME_PROMPT, LARGE_USERNAME)?;
        session.answer(PASSWORD_FIELD_PROMPT, "")?;
        session.answer(URL_PROMPT, "")?;
        session.answer(TOTP_PROMPT, "")?;
        assert_success(&session.finish()?, "エントリを追加しました: ssh key");
        Ok(())
    }

    /// `rotate-key` を実行する。新しいコードを発行する場合は、確認してから返す。
    fn rotate_key(
        &self,
        mode: &str,
        current_password_file: &Path,
        new_password: &str,
        issues_code: bool,
    ) -> Result<Option<String>, Box<dyn Error>> {
        let mut session = Session::spawn(
            &[
                "rotate-key",
                "--vault",
                self.vault_text()?,
                mode,
                "--password-file",
                text(current_password_file)?,
            ],
            &Options::default(),
        )?;
        enter_new_password(&mut session, new_password)?;
        let code = if issues_code {
            let code = read_code(&mut session)?;
            confirm(&mut session, &code)?;
            Some(code)
        } else {
            None
        };
        let outcome = session.finish()?;
        let summary = if mode == "--full-dek" {
            "DEK を更新し、全エントリを暗号化し直しました"
        } else {
            "鍵を更新しました"
        };
        assert_success(&outcome, summary);
        assert!(!outcome.screen.contains(CURRENT_PASSWORD_PROMPT));
        assert_eq!(
            outcome.screen.contains(ENTER_ALTERNATE_SCREEN),
            issues_code,
            "リカバリーコードの表示の有無の確認に失敗。"
        );
        Ok(code)
    }

    /// `recover` で `old_code` を使ってパスワードを再設定し、新しいコードを返す。
    fn recover(&self, old_code: &str, new_password: &str) -> Result<String, Box<dyn Error>> {
        let mut session = Session::spawn(
            &["recover", "--vault", self.vault_text()?],
            &Options::default(),
        )?;
        session.answer(CODE_PROMPT, old_code)?;
        enter_new_password(&mut session, new_password)?;
        let code = read_code(&mut session)?;
        confirm(&mut session, &code)?;
        assert_success(&session.finish()?, "マスターパスワードを再設定しました");
        Ok(code)
    }
}

fn enter_new_password(session: &mut Session, password: &str) -> TestResult {
    session.answer(NEW_PASSWORD_PROMPT, password)?;
    session.answer(REPEAT_PASSWORD_PROMPT, password)
}

/// 再入力の案内を待ち、表示されたコードを返す。
fn read_code(session: &mut Session) -> Result<String, Box<dyn Error>> {
    session.wait_for_screen(CONFIRMATION_PROMPT, 1)?;
    displayed_code(&session.pty.text())
}

fn confirm(session: &mut Session, code: &str) -> TestResult {
    session.type_input(format!("{}\r", suffix(code)?).as_bytes())
}

fn assert_success(outcome: &Outcome, message: &str) {
    assert_eq!(
        outcome.status, 0,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains(message),
        "結果の表示の確認に失敗: {}",
        outcome.stdout
    );
}

#[test]
fn test_lifecycle_from_init_to_export() -> TestResult {
    let target = Lifecycle::new()?;

    // 作成。
    let first_code = target.init()?;
    let first_password = target.password_file("password-1", PASSWORD)?;
    target.assert_epoch(1)?;
    assert_eq!(slot_ids(&read_vault(&target.vault)?), [0, 2]);
    let first_dek = target
        .dek(&first_code)?
        .ok_or("作成時のコードでの解錠に失敗。")?;

    // 短いエントリと、4 KiB のエントリの追加。
    target.set_short_entry(&first_password)?;
    target.set_large_entry(&first_password)?;
    target.assert_epoch(3)?;
    // マニフェストと短いエントリの各 1 件以上に加えて、4 KiB のメモは容量ごとのレコードに分かれる。
    let capacity = chunk_data_capacity(CipherSuiteId::XChaCha20Poly1305);
    assert!(
        target.entry_record_count()? >= 2 + LARGE_NOTES_LEN.div_ceil(capacity),
        "エントリの分割の確認に失敗。"
    );

    // 一覧と取り出し。
    assert_eq!(
        target.read(&["list"], &first_password)?,
        "mail\talice\thttps://mail.example\nssh key\tdeploy\t\n"
    );
    for (field, expected) in SHORT_FIELDS {
        let value = target.read(&["get", SHORT_TITLE, "--field", field], &first_password)?;
        assert_eq!(value, expected, "{field} の取り出しに失敗。");
    }
    let summary = target.read(&["get", SHORT_TITLE], &first_password)?;
    assert!(
        summary.contains("ユーザー名: alice\n") && summary.contains("パスワード: ********\n"),
        "要約の確認に失敗: {summary}"
    );
    assert!(!summary.contains("short secret") && !summary.contains("short memo"));
    let notes = target.read(&["get", LARGE_TITLE, "--field", "notes"], &first_password)?;
    assert!(notes == large_notes(), "4 KiB のメモの往復に失敗。");
    target.assert_epoch(3)?;

    // DEK を変えない更新。リカバリーコードも変えない。
    let code = target.rotate_key("--kek-only", &first_password, SECOND_PASSWORD, false)?;
    assert!(code.is_none());
    let second_password = target.password_file("password-2", SECOND_PASSWORD)?;
    target.assert_epoch(4)?;
    assert_eq!(
        target.dek(&first_code)?,
        Some(first_dek),
        "DEK とリカバリーコードの維持の確認に失敗。"
    );
    target.assert_password_rejected(&first_password)?;
    target.assert_secrets(&second_password)?;

    // DEK の作り直し。リカバリーコードも作り直す。
    let second_code = target
        .rotate_key("--full-dek", &second_password, THIRD_PASSWORD, true)?
        .ok_or("新しいコードがありません。")?;
    let third_password = target.password_file("password-3", THIRD_PASSWORD)?;
    target.assert_epoch(5)?;
    assert_eq!(target.dek(&first_code)?, None);
    let second_dek = target
        .dek(&second_code)?
        .ok_or("作り直したコードでの解錠に失敗。")?;
    assert_ne!(second_dek, first_dek, "DEK を作り直すことの確認に失敗。");
    target.assert_password_rejected(&second_password)?;
    target.assert_secrets(&third_password)?;

    // 直前の更新で表示されたコードによる再設定。
    let third_code = target.recover(&second_code, FOURTH_PASSWORD)?;
    let fourth_password = target.password_file("password-4", FOURTH_PASSWORD)?;
    target.assert_epoch(6)?;
    assert_eq!(target.dek(&second_code)?, None);
    assert_eq!(
        target.dek(&third_code)?,
        Some(second_dek),
        "再設定で DEK を維持することの確認に失敗。"
    );
    target.assert_password_rejected(&third_password)?;
    target.assert_secrets(&fourth_password)?;

    // 削除。
    assert_eq!(
        target.read(&["delete", SHORT_TITLE, "--yes"], &fourth_password)?,
        "エントリを削除しました: mail\n"
    );
    target.assert_epoch(7)?;
    assert_eq!(
        target.read(&["list"], &fourth_password)?,
        "ssh key\tdeploy\t\n"
    );
    assert_process_failure(
        &target.run(&["get", SHORT_TITLE], &fourth_password)?,
        1,
        "指定されたエントリがありません。",
    );

    // 平文の書き出し。
    let destination = target.directory.path("export.json");
    let output = target.run(
        &[
            "export",
            "--output",
            text(&destination)?,
            "--confirm-plaintext",
        ],
        &fourth_password,
    )?;
    assert_eq!(
        output.status.code(),
        Some(0),
        "書き出しに失敗: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(mode_of(&destination)?, 0o600);
    let json = fs::read_to_string(&destination)?;
    let escaped_notes = large_notes().replace('\n', "\\n");
    for expected in [
        format!("\"title\": \"{LARGE_TITLE}\""),
        format!("\"username\": \"{LARGE_USERNAME}\""),
        format!("\"notes\": \"{escaped_notes}\""),
    ] {
        assert!(
            json.contains(&expected),
            "書き出しの内容の確認に失敗: {json}"
        );
    }
    assert!(
        !json.contains("short secret") && !json.contains("\"title\": \"mail\""),
        "削除したエントリを書き出さないことの確認に失敗。"
    );
    target.assert_epoch(7)?;

    // 一時ファイルを残さないこと。
    assert_eq!(
        target.directory.names()?,
        [
            "export.json",
            "notes",
            "password-1",
            "password-2",
            "password-3",
            "password-4",
            "vault.fvl",
            "vault.fvl.lock",
        ]
    );
    Ok(())
}
