//! 実行ファイルの終了コードと出力の規約を、子プロセスとして起動して確かめる統合テスト。
//!
//! - 成功 (`--help`, `--version`) は終了コード 0 で標準出力に書く。
//! - 引数の誤り (必須の `--vault` の指定漏れを含む) は終了コード 2 で、標準エラー出力に `fidelogic-cli: ` で始まる 1 行を書く。
//! - 未実装のサブコマンドは終了コード 1 で、標準エラー出力にサブコマンド名を含む 1 行を書く。
//! - 秘密を環境変数から読む経路 (`bpaf` の環境変数からの既定値) が `src/` に無い。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 本体が未実装のサブコマンドの起動。`init` の振る舞いは `tests/init.rs` で確かめる。
const UNIMPLEMENTED_INVOCATIONS: [&[&str]; 8] = [
    &["unlock"],
    &["list"],
    &["get", "github"],
    &["set", "github"],
    &["delete", "github"],
    &["rotate-key"],
    &["export"],
    &["recover"],
];

fn run_binary(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_fidelogic-cli"))
        .args(args)
        .output()
}

fn exit_code(output: &Output) -> Result<i32, String> {
    output
        .status
        .code()
        .ok_or_else(|| format!("シグナルで終了したため失敗しました: {:?}", output.status))
}

#[test]
fn test_help_and_version_exit_with_zero() -> TestResult {
    for args in [
        &["--help"][..],
        &["-h"],
        &["--version"],
        &["-V"],
        &["get", "--help"],
    ] {
        let output = run_binary(args)?;
        assert_eq!(
            exit_code(&output)?,
            0,
            "{args:?} の終了コードの確認に失敗。"
        );
        assert!(!output.stdout.is_empty(), "{args:?} の標準出力が空です。");
        assert!(
            output.stderr.is_empty(),
            "{args:?} の標準エラー出力が空ではありません。"
        );
    }
    Ok(())
}

#[test]
fn test_invalid_arguments_exit_with_two() -> TestResult {
    let invalid: [&[&str]; 6] = [
        &[],
        &["open"],
        &["get"],
        &["init"],
        &["init", "--password", "hunter2"],
        &["rotate-key", "--kek-only", "--full-dek"],
    ];
    for args in invalid {
        let output = run_binary(args)?;
        let stderr = String::from_utf8(output.stderr.clone())?;
        assert_eq!(
            exit_code(&output)?,
            2,
            "{args:?} の終了コードの確認に失敗。"
        );
        assert!(
            output.stdout.is_empty(),
            "{args:?} の標準出力が空ではありません。"
        );
        assert!(
            stderr.starts_with("fidelogic-cli: ")
                && stderr.lines().count() == 1
                && stderr.trim_end().len() > "fidelogic-cli:".len(),
            "{args:?} のエラー出力の形式の確認に失敗: {stderr}",
        );
    }
    Ok(())
}

#[test]
fn test_unimplemented_subcommands_exit_with_one() -> TestResult {
    for args in UNIMPLEMENTED_INVOCATIONS {
        let output = run_binary(args)?;
        let stderr = String::from_utf8(output.stderr.clone())?;
        assert_eq!(
            exit_code(&output)?,
            1,
            "{args:?} の終了コードの確認に失敗。"
        );
        assert!(
            output.stdout.is_empty(),
            "{args:?} の標準出力が空ではありません。"
        );
        assert_eq!(
            stderr,
            format!(
                "fidelogic-cli: サブコマンド `{}` はまだ実装されていません。\n",
                args[0]
            ),
        );
    }
    Ok(())
}

/// `src/` 配下の Rust ソースを再帰的に集める。
fn collect_sources(dir: &Path, sources: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_sources(&path, sources)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
    Ok(())
}

#[test]
fn test_sources_do_not_use_bpaf_env_fallback() -> TestResult {
    let source_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    collect_sources(&source_dir, &mut sources)?;
    assert!(!sources.is_empty(), "ソースの収集に失敗。");

    // `bpaf` の `NamedArg::env` は、引数が無いときに環境変数から値を読む。
    // 秘密を環境変数で受け取る経路にならないよう、呼び出しそのものを禁止する。
    // メソッド呼び出し (`.env(`) と関数呼び出し (`NamedArg::env(`) の両方を、空白を除いてから探す。
    // `std::env::var` などは検査の対象外とする (Vault の既定のパスの解決に使うため)。
    let forbidden = [concat!(".", "env("), concat!("::", "env(")];
    for path in sources {
        let text = std::fs::read_to_string(&path)?;
        for (index, line) in text.lines().enumerate() {
            let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            for pattern in forbidden {
                assert!(
                    !compact.contains(pattern),
                    "{}:{} に環境変数からの既定値の指定があります: {line}",
                    path.display(),
                    index + 1,
                );
            }
        }
    }
    Ok(())
}
