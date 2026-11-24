//! OS 依存処理の境界 (`src/sys/`) の検査。
//!
//! 次の 2 点を、`src/` のソースを走査して確認する。将来の Windows 対応の差分を `sys` に限定するための検査である。
//!
//! - `sys` の外に、OS を判別する `cfg`、`libc` と `std::os` の利用、`unsafe` が現れないこと
//! - `sys` の中でも、許可した実装モジュール (`UNSAFE_ALLOWED_FILES`) の外に `unsafe` が現れないこと
//!
//! 判定は簡易な字句解析で行う。コメント、文字列リテラル、文字リテラルは読み飛ばし、識別子だけを見る。
//! このため、行をまたぐ記述 (`#[cfg(\n unix \n)]`) や、グループ化した `use` (`use std::{os::unix::...}`)
//! も検出し、コメントや文字列に書かれた語は誤検知しない。

use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

/// OS を判別する `cfg` の検出理由。
const REASON_OS_CFG: &str = "OS を判別する cfg";
/// `libc` の利用の検出理由。
const REASON_LIBC: &str = "libc の利用";
/// `std::os` の利用の検出理由。
const REASON_STD_OS: &str = "std::os の利用";
/// `unsafe` の使用の検出理由。
const REASON_UNSAFE: &str = "unsafe の使用";
/// `unsafe_code` リントの緩和の検出理由。
const REASON_ALLOW_UNSAFE: &str = "unsafe_code リントの緩和";

/// OS を判別する `cfg` の条件名のうち、`target_` で始まるもの。
/// 一般的な変数名 (`target_path` など) を誤検知しないよう、前方一致ではなく完全一致で判定する。
const TARGET_CFG_NAMES: &[&str] = &[
    "target_os",
    "target_family",
    "target_vendor",
    "target_env",
    "target_arch",
    "target_abi",
    "target_endian",
    "target_pointer_width",
    "target_feature",
    "target_has_atomic",
    "target_thread_local",
];

/// `sys` の中で `unsafe` を許す実装モジュール (`src/sys` からの相対パス)。
/// OS の API を直接呼び出すモジュールを実装するときに、レビューを経てここへ加える。
const UNSAFE_ALLOWED_FILES: &[&str] = &["process.rs"];

/// 字句解析で得た要素。
#[derive(Debug, PartialEq, Eq)]
enum Token {
    /// 識別子またはキーワード。
    Ident(String),
    /// 識別子以外の 1 文字の記号。
    Punct(char),
}

/// 字句と、その字句が現れる行 (1 から数える)。
type LocatedToken = (Token, usize);

/// 文字列リテラルの本体を読み飛ばす。
///
/// # Args
///
/// - `start`: 開き引用符の次の位置。
///
/// # Returns
///
/// 閉じ引用符の次の位置。閉じられていなければ末尾。
fn skip_string(chars: &[char], start: usize, line: &mut usize) -> usize {
    let mut index = start;
    while index < chars.len() {
        match chars[index] {
            '\\' => {
                if chars.get(index + 1) == Some(&'\n') {
                    *line += 1;
                }
                index += 2;
            }
            '"' => return index + 1,
            character => {
                if character == '\n' {
                    *line += 1;
                }
                index += 1;
            }
        }
    }
    chars.len()
}

/// 生文字列リテラル (`r#"..."#`) の本体を読み飛ばす。
///
/// # Args
///
/// - `start`: 開き引用符の次の位置。
/// - `hashes`: 開き引用符の前にある `#` の数。
fn skip_raw_string(chars: &[char], start: usize, hashes: usize, line: &mut usize) -> usize {
    let mut index = start;
    while index < chars.len() {
        if chars[index] == '\n' {
            *line += 1;
        }
        if chars[index] == '"' && (1..=hashes).all(|offset| chars.get(index + offset) == Some(&'#'))
        {
            return index + 1 + hashes;
        }
        index += 1;
    }
    chars.len()
}

/// `'` から始まる要素を読み飛ばす。文字リテラルなら終端まで、ライフタイムなら `'` だけを読み飛ばす。
fn skip_quote(chars: &[char], start: usize) -> usize {
    if chars.get(start + 1) == Some(&'\\') {
        let mut index = start + 3;
        while index < chars.len() && chars[index] != '\'' {
            index += 1;
        }
        return (index + 1).min(chars.len());
    }
    if chars.get(start + 2) == Some(&'\'') {
        return start + 3;
    }
    start + 1
}

/// ソースを字句に分解する。コメント、文字列リテラル、文字リテラルは含めない。
fn tokenize(source: &str) -> Vec<LocatedToken> {
    let chars: Vec<char> = source.chars().collect();
    let mut tokens = Vec::new();
    let mut line = 1usize;
    let mut index = 0usize;
    while index < chars.len() {
        let current = chars[index];
        let next = chars.get(index + 1).copied();
        if current == '\n' {
            line += 1;
            index += 1;
        } else if current.is_whitespace() {
            index += 1;
        } else if current == '/' && next == Some('/') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
        } else if current == '/' && next == Some('*') {
            let mut depth = 1usize;
            index += 2;
            while index < chars.len() && depth > 0 {
                if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
                    depth += 1;
                    index += 2;
                } else if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                    depth -= 1;
                    index += 2;
                } else {
                    if chars[index] == '\n' {
                        line += 1;
                    }
                    index += 1;
                }
            }
        } else if current == '"' {
            index = skip_string(&chars, index + 1, &mut line);
        } else if current == '\'' {
            index = skip_quote(&chars, index);
        } else if current.is_alphabetic() || current == '_' {
            let start = index;
            while index < chars.len() && (chars[index].is_alphanumeric() || chars[index] == '_') {
                index += 1;
            }
            let name: String = chars[start..index].iter().collect();
            let hashes = chars[index..].iter().take_while(|&&c| c == '#').count();
            if matches!(name.as_str(), "r" | "br" | "cr") && chars.get(index + hashes) == Some(&'"')
            {
                index = skip_raw_string(&chars, index + hashes + 1, hashes, &mut line);
            } else {
                tokens.push((Token::Ident(name), line));
            }
        } else {
            tokens.push((Token::Punct(current), line));
            index += 1;
        }
    }
    tokens
}

/// `unsafe_code` の直前のリントレベルが `allow` または `expect` であるかを判定する。
///
/// # Args
///
/// - `unsafe_code_index`: `tokens` 内の `unsafe_code` の位置。
fn is_relaxed_by_lint_level(tokens: &[LocatedToken], unsafe_code_index: usize) -> bool {
    for (token, _) in tokens[..unsafe_code_index].iter().rev() {
        match token {
            Token::Punct(']' | ';' | '{' | '}') => return false,
            Token::Ident(name) => match name.as_str() {
                "allow" | "expect" => return true,
                "deny" | "forbid" | "warn" => return false,
                _ => {}
            },
            Token::Punct(_) => {}
        }
    }
    false
}

/// `index` の識別子が、`cfg` / `cfg_attr` / `cfg!` の条件の中にあるかを判定する。
///
/// 直前へたどり、`cfg` 系の識別子に先に出会えば `true`。文や項の区切りに先に出会えば `false`。
/// `slice.windows(2)` のような一般のメソッド名を、OS の判別と取り違えないために用いる。
fn is_inside_cfg(tokens: &[LocatedToken], index: usize) -> bool {
    for (token, _) in tokens[..index].iter().rev() {
        match token {
            Token::Punct(']' | ';' | '{' | '}') => return false,
            Token::Ident(name) if matches!(name.as_str(), "cfg" | "cfg_attr") => return true,
            _ => {}
        }
    }
    false
}

/// `index` の識別子 `os` が、`std::os` の経路の一部であるかを判定する。
///
/// 直前が `std::` である場合と、`use std::{..., os::...};` のようなグループ化した `use` の中にある場合を `true` とする。
/// 変数名や関数名としての `os` は `false`。
fn is_std_os_path(tokens: &[LocatedToken], index: usize) -> bool {
    let is_ident = |position: usize, expected: &str| matches!(&tokens[position].0, Token::Ident(name) if name == expected);
    let is_colon = |position: usize| tokens[position].0 == Token::Punct(':');
    if index >= 3 && is_colon(index - 1) && is_colon(index - 2) && is_ident(index - 3, "std") {
        return true;
    }
    for position in (0..index).rev() {
        if tokens[position].0 == Token::Punct(';') {
            return false;
        }
        if is_ident(position, "use") {
            return position + 1 < index && is_ident(position + 1, "std");
        }
    }
    false
}

/// ソースの中から、禁止された記述を探す。
///
/// # Returns
///
/// 見つかった記述ごとの `(行番号, 理由, 行の内容)`。行番号は 1 から数える。
fn find_violations(source: &str) -> Vec<(usize, &'static str, String)> {
    let tokens = tokenize(source);
    let lines: Vec<&str> = source.lines().collect();
    let mut violations = Vec::new();
    for (index, (token, line)) in tokens.iter().enumerate() {
        let Token::Ident(name) = token else {
            continue;
        };
        let reason = match name.as_str() {
            "unix" | "windows" if is_inside_cfg(&tokens, index) => REASON_OS_CFG,
            name if TARGET_CFG_NAMES.contains(&name) => REASON_OS_CFG,
            "libc" => REASON_LIBC,
            "os" if is_std_os_path(&tokens, index) => REASON_STD_OS,
            "unsafe" => REASON_UNSAFE,
            "unsafe_code" if is_relaxed_by_lint_level(&tokens, index) => REASON_ALLOW_UNSAFE,
            _ => continue,
        };
        let content = lines
            .get(line - 1)
            .map(|text| text.trim().to_string())
            .unwrap_or_default();
        violations.push((*line, reason, content));
    }
    violations
}

/// 違反の理由のうち、`unsafe` に関するものか。
fn is_unsafe_reason(reason: &str) -> bool {
    reason == REASON_UNSAFE || reason == REASON_ALLOW_UNSAFE
}

/// ディレクトリを再帰的にたどり、`excluded_dir` を除く `.rs` ファイルを集める。
fn collect_sources(
    dir: &Path,
    excluded_dir: Option<&Path>,
    found: &mut Vec<PathBuf>,
) -> TestResult {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if Some(path.as_path()) == excluded_dir {
                continue;
            }
            collect_sources(&path, excluded_dir, found)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
    Ok(())
}

/// このクレートの `src/` ディレクトリを返す。
fn source_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

#[test]
fn test_sources_outside_sys_have_no_os_dependent_code() -> TestResult {
    let source_dir = source_dir();
    let mut sources = Vec::new();
    collect_sources(&source_dir, Some(&source_dir.join("sys")), &mut sources)?;
    for root in ["lib.rs", "main.rs"] {
        assert!(
            sources.iter().any(|path| path.ends_with(root)),
            "検査対象に {root} が含まれていないため失敗しました: {sources:?}"
        );
    }

    let mut messages = Vec::new();
    for path in &sources {
        let source = std::fs::read_to_string(path)?;
        for (line, reason, content) in find_violations(&source) {
            messages.push(format!("{}:{line}: {reason}: {content}", path.display()));
        }
    }
    assert!(
        messages.is_empty(),
        "sys の外に OS 依存の記述があるため失敗しました。\n{}",
        messages.join("\n")
    );
    Ok(())
}

#[test]
fn test_sys_modules_outside_allowlist_do_not_use_unsafe() -> TestResult {
    let sys_dir = source_dir().join("sys");
    let mut sources = Vec::new();
    collect_sources(&sys_dir, None, &mut sources)?;

    let mut allowed_found = 0usize;
    let mut messages = Vec::new();
    for path in &sources {
        let relative = path
            .strip_prefix(&sys_dir)?
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if UNSAFE_ALLOWED_FILES.contains(&relative.as_str()) {
            allowed_found += 1;
            continue;
        }
        let source = std::fs::read_to_string(path)?;
        for (line, reason, content) in find_violations(&source) {
            if is_unsafe_reason(reason) {
                messages.push(format!("{}:{line}: {reason}: {content}", path.display()));
            }
        }
    }
    assert_eq!(
        allowed_found,
        UNSAFE_ALLOWED_FILES.len(),
        "unsafe を許すモジュールが sys に存在しないため失敗しました: {UNSAFE_ALLOWED_FILES:?}"
    );
    assert!(
        messages.is_empty(),
        "unsafe を許していない sys のモジュールに unsafe があるため失敗しました。\n{}",
        messages.join("\n")
    );
    Ok(())
}

#[test]
fn test_crate_roots_deny_unsafe_code() -> TestResult {
    for root in ["lib.rs", "main.rs"] {
        let source = std::fs::read_to_string(source_dir().join(root))?;
        let has_deny = source
            .lines()
            .any(|line| line.split_whitespace().collect::<String>() == "#![deny(unsafe_code)]");
        assert!(
            has_deny,
            "{root} に #![deny(unsafe_code)] が無いため失敗しました。"
        );
    }
    Ok(())
}

#[test]
fn test_sys_has_four_boundaries_declared_in_mod() -> TestResult {
    let sys_dir = source_dir().join("sys");
    let mod_source = std::fs::read_to_string(sys_dir.join("mod.rs"))?;
    for name in ["process", "storage", "tty", "clipboard"] {
        let path = sys_dir.join(format!("{name}.rs"));
        assert!(
            path.is_file(),
            "境界のモジュールが存在しないため失敗しました: {}",
            path.display()
        );
        assert!(
            mod_source
                .lines()
                .any(|line| line.trim() == format!("pub mod {name};")),
            "sys/mod.rs に `pub mod {name};` が無いため失敗しました。"
        );
    }
    Ok(())
}

#[test]
fn test_find_violations_detects_bypass_forms() {
    let cases: &[(&str, &str)] = &[
        ("#[cfg(unix)]", REASON_OS_CFG),
        ("#[cfg(not(unix))]", REASON_OS_CFG),
        ("#[cfg(windows)]", REASON_OS_CFG),
        ("#[cfg( unix )]", REASON_OS_CFG),
        ("#[cfg(all(unix, feature = \"x\"))]", REASON_OS_CFG),
        ("#[cfg(any(windows, test))]", REASON_OS_CFG),
        ("#[cfg(target_os = \"linux\")]", REASON_OS_CFG),
        ("#[cfg(target_family = \"unix\")]", REASON_OS_CFG),
        ("#[cfg(target_vendor = \"apple\")]", REASON_OS_CFG),
        ("#[cfg(target_env = \"musl\")]", REASON_OS_CFG),
        ("#[cfg_attr(unix, derive(Debug))]", REASON_OS_CFG),
        ("if cfg!(unix) {}", REASON_OS_CFG),
        ("if cfg!(windows) {}", REASON_OS_CFG),
        ("#[cfg(\n    unix\n)]", REASON_OS_CFG),
        (
            "#[cfg_attr(\n    target_os = \"linux\",\n    derive(Debug)\n)]",
            REASON_OS_CFG,
        ),
        ("let _ = libc::getpid();", REASON_LIBC),
        ("use libc;", REASON_LIBC),
        ("use std::os::unix::fs::PermissionsExt;", REASON_STD_OS),
        ("use std::os;", REASON_STD_OS),
        (
            "use std::{os::unix::fs::PermissionsExt, path::Path};",
            REASON_STD_OS,
        ),
        (
            "use std::{\n    path::Path,\n    os::fd::AsRawFd,\n};",
            REASON_STD_OS,
        ),
        ("unsafe { f() }", REASON_UNSAFE),
        ("unsafe{ f() }", REASON_UNSAFE),
        ("unsafe fn f() {}", REASON_UNSAFE),
        ("unsafe impl Send for T {}", REASON_UNSAFE),
        ("let c = '\"'; unsafe { f() }", REASON_UNSAFE),
        ("fn f<'a>(x: &'a str) { unsafe { g(x) } }", REASON_UNSAFE),
        ("let s = \"\\\"\"; unsafe { f() }", REASON_UNSAFE),
        ("#![allow(unsafe_code)]", REASON_ALLOW_UNSAFE),
        ("#![allow(clippy::all, unsafe_code)]", REASON_ALLOW_UNSAFE),
        ("#[expect(unsafe_code)]", REASON_ALLOW_UNSAFE),
        ("#[cfg_attr(test, allow(unsafe_code))]", REASON_ALLOW_UNSAFE),
        ("#![allow(\n    unsafe_code\n)]", REASON_ALLOW_UNSAFE),
    ];
    for (source, expected_reason) in cases {
        let violations = find_violations(source);
        assert!(
            violations
                .iter()
                .any(|(_, reason, _)| reason == expected_reason),
            "禁止された記述 `{source}` の検出に失敗。"
        );
    }
}

#[test]
fn test_find_violations_reports_line_of_multiline_token() {
    let source = "fn sample() {}\n#[cfg(\n    unix\n)]\nfn other() {}\n";
    let violations = find_violations(source);
    assert!(
        violations
            .iter()
            .any(|(line, reason, _)| *line == 3 && *reason == REASON_OS_CFG),
        "行をまたぐ cfg の行番号の報告に失敗: {violations:?}"
    );
}

#[test]
fn test_find_violations_accepts_portable_code() {
    let cases: &[&str] = &[
        "use std::process::ExitCode;",
        "#![deny(unsafe_code)]",
        "#![forbid(unsafe_code)]",
        "#![allow(dead_code)]\n#![deny(unsafe_code)]",
        "#[cfg(test)]",
        "#[cfg(feature = \"x\")]",
        "#[cfg_attr(doc, aquamarine::aquamarine)]",
        "if cfg!(debug_assertions) {}",
        "let value = std::env::var_os(\"HOME\");",
        "// libc と unsafe と cfg(unix) はコメントなら許可する。",
        "    /// target_os の説明を doc コメントに書く。",
        "let x = 1; // unsafe libc::getpid unix",
        "/* cfg(unix) unsafe { } */ let x = 1;",
        "/* 入れ子 /* unsafe */ libc */ let x = 1;",
        "let text = \"unsafe libc::getpid cfg(unix) std::os\";",
        "let text = r#\"unsafe \"libc\" unix\"#;",
        "let text = \"複数行\nunsafe libc\n\";",
        "fn f<'a>(x: &'a str) -> &'a str { x }",
        "let target_path = 1;",
        "fn target_dir() {}",
        "fn os_version() {}",
        "let os = 1;",
        "fn describe(os: &str) -> &str { os }",
        "let pairs = values.windows(2);",
        "let unix = 1;",
        "use std::io;\nlet os = 1;",
        "use other::os::Thing;",
        "#[cfg(test)]\nfn f() { let _ = x.windows(2); }",
        "fn run() -> ExitCode { ExitCode::SUCCESS }",
    ];
    for source in cases {
        let violations = find_violations(source);
        assert!(
            violations.is_empty(),
            "OS に依存しない記述 `{source}` を違反と判定したため失敗しました: {violations:?}"
        );
    }
}
