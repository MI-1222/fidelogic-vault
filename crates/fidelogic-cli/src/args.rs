//! # 引数の定義と解析 (`args`)
//!
//! サブコマンド体系と各サブコマンドの引数を、`bpaf` の combinatoric API (proc-macro を使わない) で定義する。
//! 解析は [`parse`] が行い、結果を [`CommandLine`] で返す。解析は引数の列だけに依存する純粋な処理で、
//! 環境変数、端末、ファイルを読まない。
//!
//! ## サブコマンド
//!
//! | サブコマンド | 引数 | 内容 |
//! | :-- | :-- | :-- |
//! | `init` | | Vault を作成し、リカバリーキットを表示する |
//! | `unlock` | | Vault を解錠し、対話モードに入る |
//! | `list` | | エントリの一覧を表示する (秘密のフィールドは表示しない) |
//! | `get` | `<ENTRY>` | エントリを表示する |
//! | `set` | `<ENTRY>` | エントリを追加・更新する |
//! | `delete` | `<ENTRY>` | エントリを削除する |
//! | `rotate-key` | `--kek-only` (既定) または `--full-dek [--drop-prf-slot]` | 鍵を更新する |
//! | `export` | | Vault の内容を書き出す |
//! | `recover` | | リカバリーコードで解錠し、マスターパスワードを再設定する |
//!
//! すべてのサブコマンドが `--vault <PATH>` を受け付ける。
//! 指定はサブコマンド名の後に置く。
//! (`fidelogic-cli get --vault ./my.vault github`)。省略したときの既定のパスは、Vault を読み書きする処理で決める。
//!
//! ## 秘密を引数と環境変数で受け取らない
//!
//! パスワード、リカバリーコード、エントリの秘密のフィールドを値として受け取る引数は設けない。
//! 引数はプロセス一覧 (`ps`) やシェルの履歴から、環境変数は `/proc/<pid>/environ` や子プロセスへの継承から漏れるためである。
//! `bpaf` の、環境変数から既定値を読む機能 (`NamedArg` の `env`) も使わない。
//! 秘密は端末から読み込む ([`crate::sys::tty`])。

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use bpaf::parsers::NamedArg;
use bpaf::{Args, OptionParser, ParseFailure, Parser, construct, long, positional, pure, short};
use fidelogic_core::active_profile;

/// 解析に成功した引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    /// `--vault` で指定された Vault ファイルのパス。省略時は `None`。
    pub vault: Option<PathBuf>,
    /// 実行するサブコマンド。
    pub subcommand: Subcommand,
}

/// 実行するサブコマンドと、その固有の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subcommand {
    /// `init`: Vault を作成する。
    Init,
    /// `unlock`: Vault を解錠し、対話モードに入る。
    Unlock,
    /// `list`: エントリの一覧を表示する。
    List,
    /// `get <ENTRY>`: エントリを表示する。
    Get {
        /// 対象のエントリ。
        entry: String,
    },
    /// `set <ENTRY>`: エントリを追加・更新する。
    Set {
        /// 対象のエントリ。
        entry: String,
    },
    /// `delete <ENTRY>`: エントリを削除する。
    Delete {
        /// 対象のエントリ。
        entry: String,
    },
    /// `rotate-key`: 鍵を更新する。
    RotateKey {
        /// 更新の方式。
        mode: RotateMode,
    },
    /// `export`: Vault の内容を書き出す。
    Export,
    /// `recover`: リカバリーコードで解錠し、マスターパスワードを再設定する。
    Recover,
}

impl Subcommand {
    /// コマンドラインで指定するサブコマンド名を返す。
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::Unlock => "unlock",
            Self::List => "list",
            Self::Get { .. } => "get",
            Self::Set { .. } => "set",
            Self::Delete { .. } => "delete",
            Self::RotateKey { .. } => "rotate-key",
            Self::Export => "export",
            Self::Recover => "recover",
        }
    }
}

/// `rotate-key` の更新の方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateMode {
    /// `--kek-only` (既定): DEK を変えずに、スロットの KEK だけを更新する。
    KekOnly,
    /// `--full-dek`: 新しい DEK で全エントリを再暗号化する。
    FullDek {
        /// `--drop-prf-slot`: WebAuthn PRF のスロット (Slot 1) を、確認せずに破棄する。
        drop_prf_slot: bool,
    },
}

/// 解析を終えて、サブコマンドを実行せずに終了する場合の内容。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseExit {
    /// `--help` または `--version` が指定された。標準出力に表示して成功終了する。
    Help(String),
    /// 引数が誤っている。標準エラー出力に表示して、引数の誤りとして終了する。
    Invalid(String),
}

impl fmt::Display for ParseExit {
    /// 表示する文字列をそのまま書く。
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Help(text) | Self::Invalid(text) => formatter.write_str(text),
        }
    }
}

impl std::error::Error for ParseExit {}

/// 引数の列を解析する。
///
/// # Args
///
/// - `args`: プログラム名を除いた引数の列 (`std::env::args_os().skip(1)` に相当)
///
/// # Errors
///
/// `--help` / `--version` が指定された場合は [`ParseExit::Help`]、
/// 引数が誤っている場合は [`ParseExit::Invalid`] を返す。いずれも表示する文字列を持つ。
pub fn parse(args: &[OsString]) -> Result<CommandLine, ParseExit> {
    // プログラム名はヘルプの `Usage:` 行に使う。`argv[0]` ではなく固定の名前を使い、表示を起動方法に依存させない。
    let args = Args::from(args).set_name(crate::PROGRAM_NAME);
    parser().run_inner(args).map_err(|failure| match failure {
        // `ParseFailure::print_message` は `println!` で書き込み、出力先が閉じていると panic する。
        // 書き込みは呼び出し側が行い、失敗をエラーとして扱えるよう、ここでは文字列にするだけとする。
        // 補完 (`Completion`) は `autocomplete` フィーチャーを無効にしているため発生しないが、
        // 発生した場合は標準出力に表示する内容として扱う。
        ParseFailure::Stdout(text, full) => ParseExit::Help(text.monochrome(full)),
        ParseFailure::Completion(text) => ParseExit::Help(text),
        ParseFailure::Stderr(message) => ParseExit::Invalid(message.monochrome(true)),
    })
}

/// 引数全体の解析器を組み立てる。
fn parser() -> OptionParser<CommandLine> {
    let init = subcommand(
        "init",
        "Vault を作成し、リカバリーキットを表示する",
        pure(Subcommand::Init),
    );
    let unlock = subcommand(
        "unlock",
        "Vault を解錠し、対話モードに入る",
        pure(Subcommand::Unlock),
    );
    let list = subcommand(
        "list",
        "エントリの一覧を表示する (秘密のフィールドは表示しない)",
        pure(Subcommand::List),
    );
    let get = subcommand(
        "get",
        "エントリを表示する",
        entry_argument().map(|entry| Subcommand::Get { entry }),
    );
    let set = subcommand(
        "set",
        "エントリを追加・更新する",
        entry_argument().map(|entry| Subcommand::Set { entry }),
    );
    let delete = subcommand(
        "delete",
        "エントリを削除する",
        entry_argument().map(|entry| Subcommand::Delete { entry }),
    );
    let rotate_key = subcommand(
        "rotate-key",
        "鍵を更新する",
        rotate_mode().map(|mode| Subcommand::RotateKey { mode }),
    );
    let export = subcommand("export", "Vault の内容を書き出す", pure(Subcommand::Export));
    let recover = subcommand(
        "recover",
        "リカバリーコードで解錠し、マスターパスワードを再設定する",
        pure(Subcommand::Recover),
    );

    let version = format!(
        "{} (fidelogic-core: {})",
        env!("CARGO_PKG_VERSION"),
        active_profile()
    );
    construct!([
        init, unlock, list, get, set, delete, rotate_key, export, recover
    ])
    .to_options()
    .descr("Fidelogic Vault のネイティブ CLI")
    .version(version.as_str())
    .help_parser(help_flag())
    .version_parser(short('V').long("version").help("バージョンを表示する"))
}

/// サブコマンドの解析器を組み立てる。すべてのサブコマンドに `--vault` を付ける。
fn subcommand(
    name: &'static str,
    description: &'static str,
    arguments: impl Parser<Subcommand> + 'static,
) -> impl Parser<CommandLine> {
    let vault = vault_option();
    let subcommand = arguments;
    construct!(CommandLine { vault, subcommand })
        .to_options()
        .descr(description)
        .help_parser(help_flag())
        .command(name)
        .help(description)
}

/// `--help` / `-h` の定義。
fn help_flag() -> NamedArg {
    short('h').long("help").help("ヘルプを表示する")
}

/// `--vault <PATH>` の定義。
fn vault_option() -> impl Parser<Option<PathBuf>> {
    long("vault")
        .help("Vault ファイルのパス")
        .argument::<PathBuf>("PATH")
        .optional()
}

/// `get` / `set` / `delete` が受け取る対象のエントリ。
fn entry_argument() -> impl Parser<String> {
    positional::<String>("ENTRY").help("対象のエントリ")
}

/// `rotate-key` の方式の指定。
///
/// `--kek-only` と `--full-dek` は同時に指定できない。どちらも無い場合は `--kek-only` として扱う。
/// `--drop-prf-slot` は `--full-dek` と組み合わせたときだけ受け付ける。
fn rotate_mode() -> impl Parser<RotateMode> {
    let kek_only = long("kek-only")
        .help("DEK を変えずに、スロットの KEK だけを更新する (既定)")
        .req_flag(RotateMode::KekOnly);
    let full_dek_flag = long("full-dek")
        .help("新しい DEK で全エントリを再暗号化する")
        .req_flag(());
    let drop_prf_slot = long("drop-prf-slot")
        .help("--full-dek と併用し、WebAuthn PRF のスロットを確認せずに破棄する")
        .switch();
    let full_dek = construct!(full_dek_flag, drop_prf_slot)
        .map(|((), drop_prf_slot)| RotateMode::FullDek { drop_prf_slot });
    construct!([kek_only, full_dek]).fallback(RotateMode::KekOnly)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{CommandLine, ParseExit, RotateMode, Subcommand, parse};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// すべてのサブコマンド名と、`--vault` 以外の必須の引数を付けた最小の引数列。
    const MINIMAL_INVOCATIONS: [&[&str]; 9] = [
        &["init"],
        &["unlock"],
        &["list"],
        &["get", "github"],
        &["set", "github"],
        &["delete", "github"],
        &["rotate-key"],
        &["export"],
        &["recover"],
    ];

    fn to_args(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn parse_strs(args: &[&str]) -> Result<CommandLine, ParseExit> {
        parse(&to_args(args))
    }

    fn expect_invalid(args: &[&str]) -> Result<String, String> {
        match parse_strs(args) {
            Err(ParseExit::Invalid(message)) => Ok(message),
            other => Err(format!("{args:?} の拒否に失敗: {other:?}")),
        }
    }

    #[test]
    fn test_every_subcommand_parses_and_reports_its_name() -> TestResult {
        for args in MINIMAL_INVOCATIONS {
            let command_line = parse_strs(args).map_err(|exit| format!("{args:?}: {exit:?}"))?;
            assert_eq!(command_line.subcommand.name(), args[0]);
            assert_eq!(command_line.vault, None);
        }
        Ok(())
    }

    #[test]
    fn test_entry_subcommands_capture_entry() -> TestResult {
        assert_eq!(
            parse_strs(&["get", "github"])?.subcommand,
            Subcommand::Get {
                entry: "github".to_owned()
            }
        );
        assert_eq!(
            parse_strs(&["set", "mail"])?.subcommand,
            Subcommand::Set {
                entry: "mail".to_owned()
            }
        );
        assert_eq!(
            parse_strs(&["delete", "bank"])?.subcommand,
            Subcommand::Delete {
                entry: "bank".to_owned()
            }
        );
        Ok(())
    }

    #[test]
    fn test_entry_subcommands_require_entry() -> TestResult {
        for name in ["get", "set", "delete"] {
            expect_invalid(&[name])?;
        }
        Ok(())
    }

    #[test]
    fn test_vault_option_is_accepted_before_and_after_entry() -> TestResult {
        let expected = Some(PathBuf::from("./my.vault"));
        assert_eq!(
            parse_strs(&["get", "--vault", "./my.vault", "github"])?.vault,
            expected
        );
        assert_eq!(
            parse_strs(&["get", "github", "--vault", "./my.vault"])?.vault,
            expected
        );
        assert_eq!(parse_strs(&["init", "--vault=./my.vault"])?.vault, expected);
        Ok(())
    }

    #[test]
    fn test_vault_option_requires_value() -> TestResult {
        expect_invalid(&["init", "--vault"])?;
        Ok(())
    }

    #[test]
    fn test_repeated_options_are_invalid() -> TestResult {
        expect_invalid(&["init", "--vault", "a", "--vault", "b"])?;
        expect_invalid(&["rotate-key", "--kek-only", "--kek-only"])?;
        expect_invalid(&["rotate-key", "--full-dek", "--full-dek"])?;
        expect_invalid(&[
            "rotate-key",
            "--full-dek",
            "--drop-prf-slot",
            "--drop-prf-slot",
        ])?;
        Ok(())
    }

    #[test]
    fn test_entry_starting_with_hyphen_after_double_dash() -> TestResult {
        assert_eq!(
            parse_strs(&["get", "--", "-foo"])?.subcommand,
            Subcommand::Get {
                entry: "-foo".to_owned()
            }
        );
        Ok(())
    }

    #[test]
    fn test_rotate_key_modes() -> TestResult {
        let cases: [(&[&str], RotateMode); 5] = [
            (&["rotate-key"], RotateMode::KekOnly),
            (&["rotate-key", "--kek-only"], RotateMode::KekOnly),
            (
                &["rotate-key", "--full-dek"],
                RotateMode::FullDek {
                    drop_prf_slot: false,
                },
            ),
            (
                &["rotate-key", "--drop-prf-slot", "--full-dek"],
                RotateMode::FullDek {
                    drop_prf_slot: true,
                },
            ),
            (
                &["rotate-key", "--full-dek", "--drop-prf-slot"],
                RotateMode::FullDek {
                    drop_prf_slot: true,
                },
            ),
        ];
        for (args, expected) in cases {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::RotateKey { mode: expected },
                "{args:?} の解析に失敗。",
            );
        }
        Ok(())
    }

    #[test]
    fn test_rotate_key_rejects_conflicting_or_orphan_flags() -> TestResult {
        expect_invalid(&["rotate-key", "--kek-only", "--full-dek"])?;
        expect_invalid(&["rotate-key", "--drop-prf-slot"])?;
        expect_invalid(&["rotate-key", "--kek-only", "--drop-prf-slot"])?;
        Ok(())
    }

    #[test]
    fn test_missing_or_unknown_subcommand_is_invalid() -> TestResult {
        expect_invalid(&[])?;
        expect_invalid(&["open"])?;
        expect_invalid(&["--vault", "./my.vault", "list"])?;
        Ok(())
    }

    #[test]
    fn test_extra_positional_is_invalid() -> TestResult {
        expect_invalid(&["list", "extra"])?;
        expect_invalid(&["get", "github", "extra"])?;
        Ok(())
    }

    #[test]
    fn test_secret_options_are_rejected_for_every_subcommand() -> TestResult {
        let secret_options: [&[&str]; 5] = [
            &["--password", "hunter2"],
            &["--password=hunter2"],
            &["--master-password", "hunter2"],
            &["--recovery-code", "FL000"],
            &["-p", "hunter2"],
        ];
        for invocation in MINIMAL_INVOCATIONS {
            for option in secret_options {
                let args: Vec<&str> = invocation.iter().chain(option.iter()).copied().collect();
                expect_invalid(&args)?;
            }
        }
        Ok(())
    }

    #[test]
    fn test_help_and_version_are_printed_to_stdout() -> TestResult {
        let help = match parse_strs(&["--help"]) {
            Err(ParseExit::Help(text)) => text,
            other => return Err(format!("--help の解析に失敗: {other:?}").into()),
        };
        for args in MINIMAL_INVOCATIONS {
            assert!(
                help.contains(args[0]),
                "ヘルプに {} が無い: {help}",
                args[0]
            );
        }

        let version = match parse_strs(&["--version"]) {
            Err(ParseExit::Help(text)) => text,
            other => return Err(format!("--version の解析に失敗: {other:?}").into()),
        };
        assert!(version.contains(env!("CARGO_PKG_VERSION")));
        assert!(version.contains("fidelogic-core: "));

        let subcommand_help = match parse_strs(&["rotate-key", "--help"]) {
            Err(ParseExit::Help(text)) => text,
            other => return Err(format!("rotate-key --help の解析に失敗: {other:?}").into()),
        };
        assert!(subcommand_help.contains("--full-dek"));
        assert!(subcommand_help.contains("--vault"));
        Ok(())
    }
}
