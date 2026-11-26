//! 誤った秘密、未設定のスロット、改ざんが、理由とサブコマンドによらず同じ出力になることを、
//! 実行ファイルで確かめる統合テスト。
//!
//! 出力の違いは、攻撃者が改ざんの結果やスロットの有無を調べる手掛かり (オラクル) になる。
//! 比較するのは、終了コード、標準出力、標準エラー出力である。
//! 画面の入力の案内は比較しない。ファイル形式として解析できない Vault は、秘密を尋ねる前に拒否するためである。
//! 形式は公開されており、解析できるかどうかは秘密を使わずに調べられる。

mod common;

use std::error::Error;
use std::io::{BufRead, BufReader, Read, Write};

use common::entry_vault::{
    EntryVault, credential, run_without_terminal, spawn_without_terminal, write_private,
};
use common::fixture::{OLD_CODE, PRF_SECRET};
use common::{Options, PASSWORD, Session, TestResult, text};
use fidelogic_cli::recovery_code::RecoveryCode;
use fidelogic_cli::sys::random::fill_random;
use fidelogic_core::{
    CipherSuiteId, Credential, SecretVec, TlvRecord, VAULT_HEADER_LEN, Vault, chunk_data_capacity,
    deserialize, record_serialized_len, serialize, unwrap_dek_slot0_for_header,
    wrap_dek_slot1_for_header,
};

const AUTHENTICATION_FAILED_LINE: &str = "fidelogic-cli: Vault の解錠に失敗しました。\n";
const ROLLBACK_LINE: &str =
    "fidelogic-cli: Vault の世代が以前に読み込んだものより古いため、処理を中止しました。\n";

const UNLOCKED: &str = "解錠しました。";
const PASSWORD_PROMPT: &str = "マスターパスワード: ";
const CODE_PROMPT: &str = "リカバリーコード (入力は表示されません): ";
const NEW_PASSWORD_PROMPT: &str = common::NEW_PASSWORD_PROMPT;
const USERNAME_PROMPT: &str = "ユーザー名 (空の Enter で";
const CONSENT_PROMPT: &str = "y/N";

/// 端末の無いプロセスで実行するサブコマンドと、改ざんの無い Vault での終了コード。
///
/// `{output}` は、書き出し先のパスに置き換える。
const WITHOUT_TERMINAL: [(&[&str], i32); 7] = [
    (&["list"], 0),
    (&["get", "first"], 0),
    // 存在しないタイトルは、改ざんが無い場合だけ、エントリが無いことを報告する。
    (&["get", "missing"], 1),
    (&["delete", "first", "--yes"], 0),
    (&["export", "--stdout", "--confirm-plaintext"], 0),
    (
        &["export", "--output", "{output}", "--confirm-plaintext"],
        0,
    ),
    // 標準入力が空のため、解錠の直後に施錠して終了する。
    (&["unlock"], 0),
];

/// 端末が必要で、マスターパスワードをファイルから読むサブコマンドと、
/// 改ざんの無い Vault で解錠した後の次の入力の案内。
const WITH_TERMINAL: [(&[&str], &str); 4] = [
    (&["set", "first"], USERNAME_PROMPT),
    (&["rotate-key", "--kek-only"], NEW_PASSWORD_PROMPT),
    (
        &["rotate-key", "--kek-only", "--new-recovery-code"],
        NEW_PASSWORD_PROMPT,
    ),
    (&["rotate-key", "--full-dek"], NEW_PASSWORD_PROMPT),
];

/// マスターパスワードを端末から入力するサブコマンドと、改ざんの無い Vault で解錠した後の進み方。
///
/// 対話の `delete` は、パスワードの入力元を指定できないため、この形でだけ実行できる。
const WITH_TYPED_PASSWORD: [(&[&str], AfterUnlock); 9] = [
    (&["list"], AfterUnlock::Succeeds),
    (&["get", "first"], AfterUnlock::Succeeds),
    // 標準入力が空のため、解錠の直後に施錠して終了する。
    (&["unlock"], AfterUnlock::Succeeds),
    (&["export", "--stdout"], AfterUnlock::AsksConsent),
    (&["delete", "first"], AfterUnlock::AsksConsent),
    (&["set", "first"], AfterUnlock::Asks(USERNAME_PROMPT)),
    (
        &["rotate-key", "--kek-only"],
        AfterUnlock::Asks(NEW_PASSWORD_PROMPT),
    ),
    (
        &["rotate-key", "--kek-only", "--new-recovery-code"],
        AfterUnlock::Asks(NEW_PASSWORD_PROMPT),
    ),
    (
        &["rotate-key", "--full-dek"],
        AfterUnlock::Asks(NEW_PASSWORD_PROMPT),
    ),
];

/// 対話モードで、解錠の後に Vault を読み直すコマンド。
const SESSION_COMMANDS: [&str; 4] = ["list", "get first", "set first", "delete first"];

/// 改ざんの無い Vault で、解錠した後の進み方。
#[derive(Debug, Clone, Copy)]
enum AfterUnlock {
    /// 入力を求めずに成功する。
    Succeeds,
    /// 同意を求める。拒むと、一般の失敗になる。
    AsksConsent,
    /// 指定の案内で次の入力を求める。中断して終了する。
    Asks(&'static str),
}

/// 失敗したコマンドの、外から観測できる結果。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Observation {
    fn authentication_failure() -> Self {
        Self {
            status: Some(3),
            stdout: String::new(),
            stderr: AUTHENTICATION_FAILED_LINE.to_owned(),
        }
    }
}

/// 改ざんした Vault ファイルの内容。
struct Tampered {
    name: &'static str,
    contents: Vec<u8>,
}

/// 対象の Vault と、改ざん前の内容。
struct Target {
    files: EntryVault,
    original: Vec<u8>,
    /// 複数のレコードに分かれるエントリの、レコードの件数。
    large_records: usize,
}

impl Target {
    /// エントリが、1 レコード、複数のレコード、1 レコードの順に並ぶ Vault を作る。
    ///
    /// レコードの並びは、マニフェスト (位置 0)、`first` (位置 1)、`large`、`last`、未知のレコードになる。
    /// `large` は、位置 2 から `large_records` 件を占める。
    fn new() -> Result<Self, Box<dyn Error>> {
        let mut large = credential(2, "large");
        large.notes = Some(SecretVec::from_slice(
            &(0..4096u32)
                .map(|index| b'a' + (index % 23) as u8)
                .collect::<Vec<_>>(),
        ));
        let entries = [credential(1, "first"), large, credential(3, "last")];
        let capacity = chunk_data_capacity(CipherSuiteId::XChaCha20Poly1305);
        let record_counts = entries
            .iter()
            .map(|entry: &Credential| {
                let body = entry.encode().map_err(|error| error.to_string())?;
                Ok(body.len().div_ceil(capacity))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let [1, large_records, 1] = record_counts[..] else {
            return Err(
                format!("エントリのレコード数が前提と異なります: {record_counts:?}").into(),
            );
        };
        assert!(large_records >= 3, "複数のレコードへの分割の確認に失敗。");

        let files = EntryVault::new(&entries)?;
        let original = files.contents()?;
        let vault = parse(&original)?;
        assert_eq!(vault.header.epoch_id, 1, "改ざん前の世代の確認に失敗。");
        let entry_records = vault
            .records
            .iter()
            .take_while(|record| matches!(record, TlvRecord::Entry(_)))
            .count();
        assert_eq!(
            entry_records,
            3 + large_records,
            "レコードの並びの確認に失敗。"
        );
        assert_eq!(vault.records.len(), entry_records + 1);
        Ok(Self {
            files,
            original,
            large_records,
        })
    }

    /// 改ざん前の内容を解析して `change` を適用し、直列化して返す。
    fn rewrite(&self, change: impl FnOnce(&mut Vault)) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut vault = parse(&self.original)?;
        change(&mut vault);
        Ok(serialize(&vault).map_err(|error| format!("{error}"))?)
    }

    /// 改ざん前の内容に、WebAuthn PRF のスロット (Slot 1) を加えた内容を返す。
    fn with_prf_slot(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let vault = parse(&self.original)?;
        let password_slot = vault.slots.first().ok_or("Slot 0 がありません。")?;
        let dek = unwrap_dek_slot0_for_header(password_slot, PASSWORD.as_bytes(), &vault.header)
            .map_err(|error| format!("{error}"))?;
        let prf_slot =
            wrap_dek_slot1_for_header(&dek, &PRF_SECRET, &[3; 32], &[4; 24], &vault.header)
                .map_err(|error| format!("{error}"))?;
        self.rewrite(|vault| vault.slots.insert(1, prf_slot))
    }

    /// チャンクの入れ替え、切り詰め、エントリ単位の削除、世代の改ざんを加えた内容を返す。
    fn tampered(&self) -> Result<Vec<Tampered>, Box<dyn Error>> {
        let large_first = 2;
        let large_last = 1 + self.large_records;
        let last = 2 + self.large_records;
        let mut cases = Vec::new();
        let mut add = |name, contents| cases.push(Tampered { name, contents });

        for (name, left, right) in [
            ("同じエントリの隣り合うチャンクの入れ替え", large_first, 3),
            (
                "同じエントリの両端のチャンクの入れ替え",
                large_first,
                large_last,
            ),
            ("エントリをまたぐチャンクの入れ替え", 1, large_first),
            ("エントリどうしの入れ替え", 1, last),
            ("マニフェストとエントリの入れ替え", 0, 1),
        ] {
            add(name, self.rewrite(|vault| vault.records.swap(left, right))?);
        }

        add(
            "エントリの末尾のチャンクの切り詰め",
            self.rewrite(|vault| {
                vault.records.remove(large_last);
            })?,
        );
        add(
            "エントリの途中より後のレコードの切り詰め",
            self.rewrite(|vault| vault.records.truncate(large_first + 1))?,
        );
        add(
            "全レコードの切り詰め",
            self.rewrite(|vault| vault.records.clear())?,
        );
        let unknown = parse(&self.original)?
            .records
            .pop()
            .ok_or("未知のレコードがありません。")?;
        let unknown_len = record_serialized_len(&unknown).map_err(|error| format!("{error}"))?;
        let len = self.original.len();
        for (name, kept) in [
            ("空のファイル", 0),
            ("ヘッダーの途中での切り詰め", VAULT_HEADER_LEN / 2),
            ("ヘッダーの直後での切り詰め", VAULT_HEADER_LEN),
            ("ファイルの中央での切り詰め", len / 2),
            ("レコードの境界での切り詰め", len - unknown_len),
            ("末尾の 1 バイトの切り詰め", len - 1),
        ] {
            let contents = self
                .original
                .get(..kept)
                .ok_or("切り詰めの位置が不正です。")?;
            add(name, contents.to_vec());
        }

        add(
            "先頭のエントリの削除",
            self.rewrite(|vault| {
                vault.records.remove(1);
            })?,
        );
        add(
            "複数のチャンクを持つエントリの削除",
            self.rewrite(|vault| {
                vault.records.drain(large_first..=large_last);
            })?,
        );
        add(
            "末尾のエントリの削除",
            self.rewrite(|vault| {
                vault.records.remove(last);
            })?,
        );
        add(
            "全エントリの削除",
            self.rewrite(|vault| {
                vault.records.drain(1..=last);
            })?,
        );

        for (name, epoch) in [
            ("世代の加算", 2),
            ("世代の減算", 0),
            ("世代の最大値への変更", u64::MAX),
        ] {
            add(name, self.rewrite(|vault| vault.header.epoch_id = epoch)?);
        }

        for case in &cases {
            assert!(
                case.contents != self.original,
                "{}で内容が変わることの確認に失敗。",
                case.name
            );
        }
        Ok(cases)
    }

    fn write(&self, contents: &[u8]) -> TestResult {
        Ok(std::fs::write(&self.files.vault, contents)?)
    }

    /// 書き出し先のパス。
    fn output_path(&self) -> std::path::PathBuf {
        self.files.directory.path("export.json")
    }

    /// `command` に、Vault とパスワードファイルの指定を加えた引数を返す。
    fn arguments(
        &self,
        command: &[&str],
        password_file: &str,
    ) -> Result<Vec<String>, Box<dyn Error>> {
        let output = self.output_path();
        let output = text(&output)?;
        let mut args: Vec<String> = command
            .iter()
            .map(|argument| argument.replace("{output}", output))
            .collect();
        args.extend(
            [
                "--vault",
                self.files.vault_text()?,
                "--password-file",
                password_file,
            ]
            .map(str::to_owned),
        );
        Ok(args)
    }

    fn without_terminal(
        &self,
        command: &[&str],
        password_file: &str,
    ) -> Result<Observation, Box<dyn Error>> {
        let args = self.arguments(command, password_file)?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = run_without_terminal(&args, b"")?;
        Ok(Observation {
            status: output.status.code(),
            stdout: String::from_utf8(output.stdout)?,
            stderr: String::from_utf8(output.stderr)?,
        })
    }

    fn spawn(&self, command: &[&str], password_file: &str) -> Result<Session, Box<dyn Error>> {
        let args = self.arguments(command, password_file)?;
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        Session::spawn(&args, &Options::default())
    }

    /// 端末で実行し、入力を求めずに終了した結果を返す。
    fn with_terminal(
        &self,
        command: &[&str],
        password_file: &str,
    ) -> Result<Observation, Box<dyn Error>> {
        let outcome = self.spawn(command, password_file)?.finish()?;
        for prompt in [NEW_PASSWORD_PROMPT, USERNAME_PROMPT, CONSENT_PROMPT] {
            assert!(
                !outcome.screen.contains(prompt),
                "{command:?} が次の入力を求めないことの確認に失敗: {}",
                outcome.screen
            );
        }
        Ok(Observation {
            status: Some(outcome.status),
            stdout: outcome.stdout,
            stderr: outcome.stderr,
        })
    }

    /// Vault の指定だけを加えて、端末で起動する。秘密は端末から入力する。
    fn spawn_interactive(&self, command: &[&str]) -> Result<Session, Box<dyn Error>> {
        let mut args = command.to_vec();
        args.extend(["--vault", self.files.vault_text()?]);
        Session::spawn(&args, &Options::default())
    }

    /// 秘密を端末から入力するサブコマンドを実行する。
    ///
    /// Vault を解析できる場合は、`prompt` を待って `secret` を入力する。
    /// 解析できない場合は、秘密を尋ねずに終了することを確かめる。
    fn with_typed_secret(
        &self,
        command: &[&str],
        prompt: &str,
        secret: &str,
    ) -> Result<Observation, Box<dyn Error>> {
        let parses = parse(&self.files.contents()?).is_ok();
        let mut session = self.spawn_interactive(command)?;
        if parses {
            session.answer(prompt, secret)?;
        }
        let outcome = session.finish()?;
        if !parses {
            assert!(
                !outcome.screen.contains(PASSWORD_PROMPT) && !outcome.screen.contains(CODE_PROMPT),
                "{command:?} が秘密を尋ねないことの確認に失敗: {}",
                outcome.screen
            );
        }
        for next in [NEW_PASSWORD_PROMPT, USERNAME_PROMPT, CONSENT_PROMPT] {
            assert!(
                !outcome.screen.contains(next),
                "{command:?} が次の入力を求めないことの確認に失敗: {}",
                outcome.screen
            );
        }
        Ok(Observation {
            status: Some(outcome.status),
            stdout: outcome.stdout,
            stderr: outcome.stderr,
        })
    }

    /// パスワードで解錠する全サブコマンドが、認証の失敗になり、ファイルを変えないこと。
    ///
    /// `password_file` の内容と `typed_password` には、同じパスワードを指定する。
    fn assert_password_commands_fail(
        &self,
        name: &str,
        contents: &[u8],
        password_file: &str,
        typed_password: &str,
    ) -> TestResult {
        self.write(contents)?;
        let expected = Observation::authentication_failure();
        for (command, _) in WITHOUT_TERMINAL {
            let observed = self.without_terminal(command, password_file)?;
            assert_eq!(
                observed, expected,
                "{name}: {command:?} の出力の確認に失敗。"
            );
        }
        for (command, _) in WITH_TERMINAL {
            let observed = self.with_terminal(command, password_file)?;
            assert_eq!(
                observed, expected,
                "{name}: {command:?} の出力の確認に失敗。"
            );
        }
        for (command, _) in WITH_TYPED_PASSWORD {
            let observed = self.with_typed_secret(command, PASSWORD_PROMPT, typed_password)?;
            assert_eq!(
                observed, expected,
                "{name}: 端末から入力する {command:?} の出力の確認に失敗。"
            );
        }
        self.assert_untouched(name, contents)
    }

    fn assert_recover_fails(&self, name: &str, contents: &[u8], code: &str) -> TestResult {
        self.write(contents)?;
        assert_eq!(
            self.with_typed_secret(&["recover"], CODE_PROMPT, code)?,
            Observation::authentication_failure(),
            "{name}: recover の出力の確認に失敗。"
        );
        self.assert_untouched(name, contents)
    }

    /// Vault ファイルが変わらず、書き出し先や一時ファイルが作られていないこと。
    fn assert_untouched(&self, name: &str, contents: &[u8]) -> TestResult {
        assert!(
            self.files.contents()? == contents,
            "{name}: Vault を変えないことの確認に失敗。"
        );
        assert!(
            !self.output_path().exists(),
            "{name}: 書き出さないことの確認に失敗。"
        );
        for file in self.files.directory.names()? {
            assert!(
                ["password", "vault.fvl", "vault.fvl.lock", "wrong"].contains(&file.as_str()),
                "{name}: 余分なファイルがあります: {file}"
            );
        }
        Ok(())
    }
}

/// 末尾に余分なバイトの無い Vault として解析する。
fn parse(contents: &[u8]) -> Result<Vault, Box<dyn Error>> {
    let (vault, rest) = deserialize(contents).map_err(|error| format!("{error}"))?;
    if !rest.is_empty() {
        return Err("末尾に余分なバイトがあります。".into());
    }
    Ok(vault)
}

/// 解錠した後の `session` を、`after` に応じて終了させ、終了コードを確かめる。
fn finish_untampered(mut session: Session, after: AfterUnlock) -> TestResult {
    let expected = match after {
        AfterUnlock::Succeeds => 0,
        AfterUnlock::AsksConsent => {
            session.answer(CONSENT_PROMPT, "n")?;
            1
        }
        AfterUnlock::Asks(prompt) => {
            session.wait_for_screen(prompt, 1)?;
            session.send_signal(libc::SIGINT)?;
            130
        }
    };
    let outcome = session.finish()?;
    assert_eq!(
        outcome.status, expected,
        "終了コードの確認に失敗: {}",
        outcome.stderr
    );
    Ok(())
}

/// 改ざんの無い Vault では、同じサブコマンドが解錠と検査を通過すること。
///
/// 他のテストの失敗が、改ざんと無関係な原因 (引数やパスワードの誤り) でないことを保証する。
#[test]
fn test_every_command_passes_the_untampered_vault() -> TestResult {
    let target = Target::new()?;
    let password = target.files.password_file_text()?;

    for (command, status) in WITHOUT_TERMINAL {
        target.write(&target.original)?;
        let observed = target.without_terminal(command, password)?;
        assert_eq!(
            observed.status,
            Some(status),
            "{command:?} の実行に失敗: {}",
            observed.stderr
        );
        assert!(!observed.stderr.contains(AUTHENTICATION_FAILED_LINE));
    }

    // 次の入力を求めるコマンドは、解錠と検査を通過している。中断と同意の拒否では、Vault を変えない。
    target.write(&target.original)?;
    for (command, prompt) in WITH_TERMINAL {
        let session = target.spawn(command, password)?;
        finish_untampered(session, AfterUnlock::Asks(prompt))
            .map_err(|error| format!("{command:?}: {error}"))?;
    }
    for (command, after) in WITH_TYPED_PASSWORD {
        let mut session = target.spawn_interactive(command)?;
        session.answer(PASSWORD_PROMPT, PASSWORD)?;
        finish_untampered(session, after).map_err(|error| format!("{command:?}: {error}"))?;
    }

    let mut session = Session::spawn(
        &["recover", "--vault", target.files.vault_text()?],
        &Options::default(),
    )?;
    session.answer(CODE_PROMPT, OLD_CODE)?;
    session.wait_for_screen(NEW_PASSWORD_PROMPT, 1)?;
    session.send_signal(libc::SIGINT)?;
    assert_eq!(session.finish()?.status, 130);
    assert!(target.files.contents()? == target.original);

    // 対話モードは、端末が必要なコマンドを中止しても、解錠を続けて入力の終端で終了する。
    for command in SESSION_COMMANDS {
        let observed = observe_session(&target, password, &target.original, command)?;
        assert_eq!(
            observed.status,
            Some(0),
            "対話モードの {command} の実行に失敗: {}",
            observed.stderr
        );
        assert!(!observed.stderr.contains(AUTHENTICATION_FAILED_LINE));
    }
    assert!(target.files.contents()? == target.original);
    Ok(())
}

#[test]
fn test_tampered_vaults_fail_alike_with_password() -> TestResult {
    let target = Target::new()?;
    let password = target.files.password_file_text()?;
    for case in target.tampered()? {
        target.assert_password_commands_fail(case.name, &case.contents, password, PASSWORD)?;
    }
    Ok(())
}

#[test]
fn test_tampered_vaults_fail_alike_with_recovery_code() -> TestResult {
    let target = Target::new()?;
    for case in target.tampered()? {
        target.assert_recover_fails(case.name, &case.contents, OLD_CODE)?;
    }
    Ok(())
}

/// 誤った秘密と、未設定のスロットは、改ざんと同じ出力になること。
#[test]
fn test_wrong_secrets_and_missing_slots_fail_like_tampering() -> TestResult {
    let target = Target::new()?;
    let password = target.files.password_file_text()?;
    let wrong = target.files.directory.path("wrong");
    write_private(&wrong, b"wrong password\n")?;
    target.assert_password_commands_fail(
        "誤ったパスワード",
        &target.original,
        text(&wrong)?,
        "wrong password",
    )?;

    let without_password_slot =
        target.rewrite(|vault| vault.slots.retain(|slot| slot.slot_id() != 0))?;
    assert!(without_password_slot != target.original);
    target.assert_password_commands_fail(
        "Slot 0 が未設定",
        &without_password_slot,
        password,
        PASSWORD,
    )?;

    let other = RecoveryCode::generate(fill_random)?;
    let other = other.grouped()?;
    let other = core::str::from_utf8(other.as_slice())?;
    assert!(other != OLD_CODE);
    target.assert_recover_fails("誤ったリカバリーコード", &target.original, other)?;

    let without_recovery_slot =
        target.rewrite(|vault| vault.slots.retain(|slot| slot.slot_id() != 2))?;
    assert!(without_recovery_slot != target.original);
    target.assert_recover_fails("Slot 2 が未設定", &without_recovery_slot, OLD_CODE)?;
    Ok(())
}

/// WebAuthn PRF のスロットがあることは、認証に成功するまで出力に現れないこと。
///
/// 非対話の `rotate-key --full-dek` は、`--drop-prf-slot` の指定が無ければ中止する。
/// この中止は解錠の後で、誤ったパスワードと改ざんでは認証の失敗になる。
/// 端末からパスワードを入力する場合の同意の案内は、`rotate-key` の統合テストが確かめる。
#[test]
fn test_prf_slot_is_not_revealed_before_authentication() -> TestResult {
    let mut target = Target::new()?;
    target.original = target.with_prf_slot()?;
    let password = target.files.password_file_text()?;
    let command = ["rotate-key", "--full-dek"];

    target.write(&target.original)?;
    let observed = target.with_terminal(&command, password)?;
    assert_eq!(observed.status, Some(1), "{}", observed.stderr);
    assert!(
        observed
            .stderr
            .contains("`--drop-prf-slot` を指定してください"),
        "認証の後の中止の確認に失敗: {}",
        observed.stderr
    );

    let wrong = target.files.directory.path("wrong");
    write_private(&wrong, b"wrong password\n")?;
    assert_eq!(
        target.with_terminal(&command, text(&wrong)?)?,
        Observation::authentication_failure(),
        "誤ったパスワードの出力の確認に失敗。"
    );
    target.assert_untouched("誤ったパスワード", &target.original)?;

    for case in target.tampered()? {
        target.write(&case.contents)?;
        assert_eq!(
            target.with_terminal(&command, password)?,
            Observation::authentication_failure(),
            "{}の出力の確認に失敗。",
            case.name
        );
        target.assert_untouched(case.name, &case.contents)?;
    }
    Ok(())
}

/// 対話モードで解錠した後の改ざんは、次のコマンドで同じ認証の失敗になること。
///
/// 世代が戻った場合だけは、対話モードの仕様として、巻き戻しの検知を別の出力で報告する。
#[test]
fn test_tampering_during_a_session_ends_it_alike() -> TestResult {
    let target = Target::new()?;
    let password = target.files.password_file_text()?;
    for case in target.tampered()? {
        let expected = match parse(&case.contents) {
            Ok(vault) if vault.header.epoch_id < 1 => Observation {
                status: Some(1),
                stdout: String::new(),
                stderr: ROLLBACK_LINE.to_owned(),
            },
            _ => Observation::authentication_failure(),
        };
        for command in SESSION_COMMANDS {
            target.write(&target.original)?;
            let observed = observe_session(&target, password, &case.contents, command)?;
            assert_eq!(
                observed, expected,
                "{}: {command} の出力の確認に失敗。",
                case.name
            );
            target.assert_untouched(case.name, &case.contents)?;
        }
    }
    Ok(())
}

/// 対話モードで解錠し、Vault を `contents` に置き換えてから `command` を渡して、終了までの結果を返す。
///
/// 返す標準エラー出力は、解錠の案内より後の部分である。
fn observe_session(
    target: &Target,
    password_file: &str,
    contents: &[u8],
    command: &str,
) -> Result<Observation, Box<dyn Error>> {
    // 欠陥でコマンドが終了しない場合も、無操作の上限で戻るようにする。
    let args = target.arguments(&["unlock", "--idle-timeout", "60"], password_file)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let mut child = spawn_without_terminal(&args)?;
    let mut stderr = BufReader::new(
        child
            .stderr
            .take()
            .ok_or("子の標準エラー出力がありません。")?,
    );
    let mut notice = String::new();
    stderr.read_line(&mut notice)?;
    assert!(notice.contains(UNLOCKED), "解錠に失敗: {notice}");

    target.write(contents)?;
    let mut stdin = child.stdin.take().ok_or("子の標準入力がありません。")?;
    writeln!(stdin, "{command}")?;
    drop(stdin);
    let mut rest = String::new();
    stderr.read_to_string(&mut rest)?;
    let output = child.wait_with_output()?;
    Ok(Observation {
        status: output.status.code(),
        stdout: String::from_utf8(output.stdout)?,
        stderr: rest,
    })
}
