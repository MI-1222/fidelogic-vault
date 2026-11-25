//! # 対話モードのコマンドの解析 (`repl_command`)
//!
//! `unlock` が標準入力から読んだ 1 行を、コマンドに分ける。入出力を持たず、OS に依存しない。
//!
//! ## 書式
//!
//! | 行 | 内容 |
//! | :-- | :-- |
//! | `list` | 一覧を表示する |
//! | `get <ENTRY> [--field <項目> \| --clip <項目>]` | 表示、値の出力、コピー。指定はタイトルの前後のどちらにも置ける |
//! | `set <ENTRY>` | 追加または更新する |
//! | `delete <ENTRY>` | 削除する |
//! | `help` | 使えるコマンドを表示する |
//! | `lock`, `exit` | 施錠して終了する |
//!
//! タイトルは、引用符を使わずに、空白を含めてそのまま書く。行の前後の空白は除く。
//! `-` で始まるタイトルと、`--` で始まる語を含むタイトルは、`--` の後に書く。`--` の後は、行末までがタイトルになる。

use core::fmt;

use crate::entry_ops::{EntryField, GetAction};

/// 解析したコマンド。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplCommand<'a> {
    /// 空の行。何もしない。
    Empty,
    /// 使えるコマンドを表示する。
    Help,
    /// 施錠して終了する。
    Quit,
    /// 一覧を表示する。
    List,
    /// エントリを表示、出力、コピーする。
    Get {
        /// 対象のタイトル。
        title: &'a str,
        /// 出力の方法。
        action: GetAction,
    },
    /// エントリを追加または更新する。
    Set {
        /// 対象のタイトル。
        title: &'a str,
    },
    /// エントリを削除する。
    Delete {
        /// 対象のタイトル。
        title: &'a str,
    },
}

/// コマンドの解析の失敗。入力した内容は含まない。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplParseError {
    /// 知らないコマンドである。
    UnknownCommand,
    /// 引数を取らないコマンドに、引数がある。
    UnexpectedArgument,
    /// 対象のエントリの指定が無い。
    MissingEntry,
    /// 知らない指定がある。
    UnknownOption,
    /// `--field` または `--clip` の項目が無いか、知らない項目である。
    InvalidField,
    /// `--field` と `--clip` を合わせて 2 回以上指定した。
    ConflictingOptions,
}

impl fmt::Display for ReplParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCommand => {
                formatter.write_str("知らないコマンドです。`help` で一覧を表示します。")
            }
            Self::UnexpectedArgument => formatter.write_str("このコマンドは引数を取りません。"),
            Self::MissingEntry => formatter.write_str("対象のエントリを指定してください。"),
            Self::UnknownOption => formatter
                .write_str("知らない指定です。`-` で始まるタイトルは `--` の後に書いてください。"),
            Self::InvalidField => formatter.write_str(
                "項目は username, password, url, totp, notes のいずれかを指定してください。",
            ),
            Self::ConflictingOptions => {
                formatter.write_str("`--field` と `--clip` は、どちらかを 1 回だけ指定できます。")
            }
        }
    }
}

/// 1 行をコマンドに分ける。
///
/// # Args
///
/// - `line`: 行の終端を含まない 1 行。
///
/// # Errors
///
/// 書式に合わない場合は [`ReplParseError`]。
pub(crate) fn parse_command(line: &str) -> Result<ReplCommand<'_>, ReplParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(ReplCommand::Empty);
    }
    let (command, rest) = split_word(line);
    let without_arguments = |parsed| {
        if rest.is_empty() {
            Ok(parsed)
        } else {
            Err(ReplParseError::UnexpectedArgument)
        }
    };
    match command {
        "help" => without_arguments(ReplCommand::Help),
        "lock" | "exit" => without_arguments(ReplCommand::Quit),
        "list" => without_arguments(ReplCommand::List),
        "get" => {
            let (title, action) = parse_entry(rest, true)?;
            Ok(ReplCommand::Get {
                title,
                action: action.unwrap_or(GetAction::Summary),
            })
        }
        "set" => parse_entry(rest, false).map(|(title, _)| ReplCommand::Set { title }),
        "delete" => parse_entry(rest, false).map(|(title, _)| ReplCommand::Delete { title }),
        _ => Err(ReplParseError::UnknownCommand),
    }
}

/// 先頭の語と、空白を除いた残りに分ける。
fn split_word(text: &str) -> (&str, &str) {
    match text.split_once(char::is_whitespace) {
        Some((word, rest)) => (word, rest.trim_start()),
        None => (text, ""),
    }
}

/// タイトルと、その前後の指定を解析する。
///
/// # Args
///
/// - `rest`: コマンドより後の、前後の空白を除いた文字列。
/// - `accepts_action`: `--field` と `--clip` を受け付けるか。
///
/// # Returns
///
/// タイトルと、指定された出力の方法。
fn parse_entry(
    mut rest: &str,
    accepts_action: bool,
) -> Result<(&str, Option<GetAction>), ReplParseError> {
    let mut action = None;
    // タイトルより前の指定。
    while rest.starts_with('-') {
        let (word, tail) = split_word(rest);
        if word == "--" {
            return require_title(tail).map(|title| (title, action));
        }
        rest = parse_action(word, tail, accepts_action, &mut action)?;
    }
    // タイトルは、`--` で始まる語の手前までとする。
    let end = option_start(rest).unwrap_or(rest.len());
    let (title, mut options) = rest.split_at(end);
    while !options.is_empty() {
        let (word, tail) = split_word(options);
        options = parse_action(word, tail, accepts_action, &mut action)?;
    }
    require_title(title.trim_end()).map(|title| (title, action))
}

/// 空でないタイトルを返す。
fn require_title(title: &str) -> Result<&str, ReplParseError> {
    if title.is_empty() {
        Err(ReplParseError::MissingEntry)
    } else {
        Ok(title)
    }
}

/// 空白の直後にある、`--` で始まる最初の語の位置を返す。
fn option_start(text: &str) -> Option<usize> {
    let mut after_space = false;
    for (position, character) in text.char_indices() {
        if after_space
            && text
                .get(position..)
                .is_some_and(|tail| tail.starts_with("--"))
        {
            return Some(position);
        }
        after_space = character.is_whitespace();
    }
    None
}

/// 指定 1 つを解析して `action` に記録し、残りの文字列を返す。
fn parse_action<'a>(
    word: &str,
    tail: &'a str,
    accepts_action: bool,
    action: &mut Option<GetAction>,
) -> Result<&'a str, ReplParseError> {
    let (name, joined) = match word.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (word, None),
    };
    let build: fn(EntryField) -> GetAction = match name {
        "--field" if accepts_action => GetAction::Print,
        "--clip" if accepts_action => GetAction::Copy,
        _ => return Err(ReplParseError::UnknownOption),
    };
    let (value, rest) = match joined {
        Some(value) => (value, tail),
        None => split_word(tail),
    };
    let field = value.parse().map_err(|_| ReplParseError::InvalidField)?;
    if action.replace(build(field)).is_some() {
        return Err(ReplParseError::ConflictingOptions);
    }
    Ok(rest)
}

#[cfg(test)]
mod tests {
    use super::{ReplCommand, ReplParseError, parse_command};
    use crate::entry_ops::{EntryField, GetAction};

    fn get(title: &str, action: GetAction) -> ReplCommand<'_> {
        ReplCommand::Get { title, action }
    }

    #[test]
    fn test_commands_without_arguments() {
        let cases = [
            ("", ReplCommand::Empty),
            ("   \t ", ReplCommand::Empty),
            ("help", ReplCommand::Help),
            ("lock", ReplCommand::Quit),
            ("exit", ReplCommand::Quit),
            ("list", ReplCommand::List),
            ("  list  ", ReplCommand::List),
        ];
        for (line, expected) in cases {
            assert_eq!(parse_command(line), Ok(expected), "{line:?} の解析に失敗。");
        }
    }

    #[test]
    fn test_entry_commands_take_the_rest_of_the_line() {
        let cases = [
            ("get github", get("github", GetAction::Summary)),
            (
                "get  my bank  account ",
                get("my bank  account", GetAction::Summary),
            ),
            ("get 銀行　口座", get("銀行　口座", GetAction::Summary)),
            ("get a-b -c", get("a-b -c", GetAction::Summary)),
            ("get -- -dash", get("-dash", GetAction::Summary)),
            (
                "get -- --clip password",
                get("--clip password", GetAction::Summary),
            ),
            ("set my site", ReplCommand::Set { title: "my site" }),
            ("set -- -x", ReplCommand::Set { title: "-x" }),
            (
                "delete old entry",
                ReplCommand::Delete { title: "old entry" },
            ),
            ("delete\tgithub", ReplCommand::Delete { title: "github" }),
        ];
        for (line, expected) in cases {
            assert_eq!(parse_command(line), Ok(expected), "{line:?} の解析に失敗。");
        }
    }

    #[test]
    fn test_get_options_before_or_after_the_title() {
        let print = GetAction::Print(EntryField::Password);
        let copy = GetAction::Copy(EntryField::Totp);
        let cases = [
            ("get --field password github", get("github", print)),
            ("get github --field password", get("github", print)),
            ("get --field=password github", get("github", print)),
            ("get my site --field=password", get("my site", print)),
            ("get --clip totp my site", get("my site", copy)),
            ("get my site   --clip   totp", get("my site", copy)),
            ("get --clip totp -- -dash", get("-dash", copy)),
        ];
        for (line, expected) in cases {
            assert_eq!(parse_command(line), Ok(expected), "{line:?} の解析に失敗。");
        }
    }

    #[test]
    fn test_invalid_lines_are_rejected() {
        use ReplParseError::{
            ConflictingOptions, InvalidField, MissingEntry, UnexpectedArgument, UnknownCommand,
            UnknownOption,
        };
        let cases = [
            ("open", UnknownCommand),
            ("LIST", UnknownCommand),
            ("getgithub", UnknownCommand),
            ("--help", UnknownCommand),
            ("list all", UnexpectedArgument),
            ("help me", UnexpectedArgument),
            ("lock now", UnexpectedArgument),
            ("exit 1", UnexpectedArgument),
            ("get", MissingEntry),
            ("set", MissingEntry),
            ("delete", MissingEntry),
            ("get --", MissingEntry),
            ("set --   ", MissingEntry),
            ("get --field password", MissingEntry),
            ("get -x", UnknownOption),
            ("get --show github", UnknownOption),
            ("get github --show", UnknownOption),
            ("get --fields password github", UnknownOption),
            ("set --notes-file a github", UnknownOption),
            ("delete github --yes", UnknownOption),
            ("delete --yes github", UnknownOption),
            ("get github --field", InvalidField),
            ("get --field title github", InvalidField),
            ("get --field= github", InvalidField),
            ("get github --clip all", InvalidField),
            (
                "get --field password --clip totp github",
                ConflictingOptions,
            ),
            (
                "get --field password github --field password",
                ConflictingOptions,
            ),
            ("get github --clip totp --clip totp", ConflictingOptions),
            ("get github --clip totp extra", UnknownOption),
        ];
        for (line, expected) in cases {
            assert_eq!(
                parse_command(line),
                Err(expected),
                "{line:?} の拒否に失敗。"
            );
        }
    }

    #[test]
    fn test_error_messages_end_with_japanese_period() {
        for error in [
            ReplParseError::UnknownCommand,
            ReplParseError::UnexpectedArgument,
            ReplParseError::MissingEntry,
            ReplParseError::UnknownOption,
            ReplParseError::InvalidField,
            ReplParseError::ConflictingOptions,
        ] {
            assert!(
                error.to_string().ends_with('。'),
                "{error:?} の文末の確認に失敗。"
            );
        }
    }
}
