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
//! | `init` | `--kit-html <PATH>` (任意) | Vault を作成し、リカバリーキットを表示する |
//! | `unlock` | `--idle-timeout <SECS>` (任意、既定 300) | Vault を解錠し、対話モードに入る |
//! | `list` | | エントリの一覧を表示する (秘密のフィールドは表示しない) |
//! | `get` | `<ENTRY>`、`--field <FIELD>` または `--clip <FIELD>` (任意) | エントリを表示、出力、コピーする |
//! | `set` | `<ENTRY>`、`--notes-file <PATH>` または `--notes-stdin` (任意) | エントリを追加・更新する |
//! | `delete` | `<ENTRY>`、`--yes` (任意) | エントリを削除する |
//! | `rotate-key` | `--kek-only` (既定) `[--new-recovery-code]` または `--full-dek [--drop-prf-slot]`、`--kit-html <PATH>` (任意) | 鍵を更新する |
//! | `export` | `--output <PATH>` または `--stdout` (必須)、`--confirm-plaintext` (任意) | 全エントリを平文の JSON で書き出す |
//! | `recover` | `--keep-recovery-code` (任意)、`--kit-html <PATH>` (任意) | リカバリーコードで解錠し、マスターパスワードを再設定する |
//!
//! このほかに、ヘルプに表示しない内部用のサブコマンド `__clipboard-worker` がある。
//! クリップボードへコピーする処理が自分自身を起動するためのもので、利用者が直接使うものではない。
//! 詳細は [`crate::sys::clipboard`] を参照する。
//!
//! すべてのサブコマンドが `--vault <PATH>` と、パスワードの入力元の指定を受け付ける。
//! 指定はサブコマンド名の後に置く。
//! (`fidelogic-cli get --vault ./my.vault github`)。省略したときの既定のパスは、Vault を読み書きする処理で決める。
//! 実行できるすべてのサブコマンドが、省略を認めない。
//!
//! `--kit-html` は、リカバリーコードを発行する場合 (`init`、`--keep-recovery-code` の無い `recover`、
//! `--new-recovery-code` または `--full-dek` の `rotate-key`) だけ受け付ける。
//!
//! ## パスワードの入力元
//!
//! | 指定 | 入力元 |
//! | :-- | :-- |
//! | (指定なし) | 制御端末 |
//! | `--password-stdin` | 標準入力 |
//! | `--password-file <PATH>` | ファイル (グループと他者の権限が無いこと) |
//! | `--password-fd <FD>` | 引き継いだファイル記述子 |
//!
//! `rotate-key` の指定は現在のパスワードの入力元で、新しいパスワードは端末で入力する。
//! `recover` の指定は新しいパスワードの入力元で、リカバリーコードは端末で入力する。
//!
//! 3 つの指定は同時に使えない。`unlock` は標準入力をコマンドの入力に使うため、
//! `--password-stdin` と `--password-fd 0` を拒否する。`set` は、`--notes-stdin` との併用で同じ指定を拒否する。
//! 読み込みは [`crate::secret_input`] が行う。
//!
//! ## 非対話の実行の同意
//!
//! パスワードの入力元を指定した実行は、非対話とみなす。この場合、`delete` は `--yes` を、
//! `export` は `--confirm-plaintext` を必須とする。指定が無ければ、引数の誤りにする。
//! 端末からパスワードを読み込む場合は、指定が無ければ実行の途中で同意を求める。
//!
//! ## 秘密を引数と環境変数で受け取らない
//!
//! パスワード、リカバリーコード、エントリの秘密のフィールドを値として受け取る引数は設けない。
//! 引数はプロセス一覧 (`ps`) やシェルの履歴から、環境変数は `/proc/<pid>/environ` や子プロセスへの継承から漏れるためである。
//! `bpaf` の、環境変数から既定値を読む機能 (`NamedArg` の `env`) も使わない。
//! 秘密は、端末か、上の指定が示す入力元から読み込む。引数で指定するのは入力元だけである。

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use bpaf::parsers::NamedArg;
use bpaf::{Args, OptionParser, ParseFailure, Parser, construct, long, positional, pure, short};
use fidelogic_core::active_profile;

use crate::entry_ops::{EntryField, GetAction};
use crate::export::ExportTarget;
use crate::failpoint::{self, FailPoint};
use crate::secret_input::PasswordSource;
use crate::set::NotesSource;
use crate::sys::clipboard::{
    EXCLUDE_FROM_HISTORY_FLAG, HISTORY_WARNING, HistoryPolicy, WORKER_SUBCOMMAND,
};
use crate::unlock::{DEFAULT_IDLE_TIMEOUT_SECONDS, MAX_IDLE_TIMEOUT_SECONDS};

/// 解析に成功した引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    /// `--vault` で指定された Vault ファイルのパス。省略時は `None`。
    pub vault: Option<PathBuf>,
    /// マスターパスワードの入力元。指定が無ければ制御端末。
    pub password_source: PasswordSource,
    /// 実行するサブコマンド。
    pub subcommand: Subcommand,
}

/// 実行するサブコマンドと、その固有の引数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subcommand {
    /// `init`: Vault を作成する。
    Init {
        /// `--kit-html`: リカバリーキットを、画面の表示に加えて HTML ファイルにも書き出す場合の出力先。
        kit_html: Option<PathBuf>,
    },
    /// `unlock`: Vault を解錠し、対話モードに入る。
    Unlock {
        /// `--idle-timeout`: 無操作の時間の上限 (秒)。
        idle_timeout_seconds: u64,
    },
    /// `list`: エントリの一覧を表示する。
    List,
    /// `get <ENTRY>`: エントリを表示する。
    Get {
        /// 対象のエントリ。
        entry: String,
        /// `--field`, `--clip`: 出力の方法。指定が無ければ、秘密を伏せた表示。
        action: GetAction,
    },
    /// `set <ENTRY>`: エントリを追加・更新する。
    Set {
        /// 対象のエントリ。
        entry: String,
        /// `--notes-file`, `--notes-stdin`: メモの入力元。指定が無ければ制御端末。
        notes: NotesSource,
    },
    /// `delete <ENTRY>`: エントリを削除する。
    Delete {
        /// 対象のエントリ。
        entry: String,
        /// `--yes`: 同意を求めずに削除する。
        assume_yes: bool,
    },
    /// `rotate-key`: 鍵を更新する。
    RotateKey {
        /// 更新の方式。
        mode: RotateMode,
        /// `--kit-html`: 再発行するリカバリーキットを、画面の表示に加えて HTML ファイルにも書き出す場合の出力先。
        kit_html: Option<PathBuf>,
    },
    /// `export`: Vault の内容を書き出す。
    Export {
        /// `--output`, `--stdout`: 出力先。
        target: ExportTarget,
        /// `--confirm-plaintext`: 同意を求めずに平文を書き出す。
        confirmed: bool,
    },
    /// `recover`: リカバリーコードで解錠し、マスターパスワードを再設定する。
    Recover {
        /// `--keep-recovery-code`: リカバリーコードを再発行せず、使ったコードを残す。
        keep_recovery_code: bool,
        /// `--kit-html`: 再発行するリカバリーキットを、画面の表示に加えて HTML ファイルにも書き出す場合の出力先。
        kit_html: Option<PathBuf>,
    },
    /// `__clipboard-worker`: クリップボードへコピーし、一定時間の後に消去する内部用のワーカー。
    ///
    /// ヘルプに表示しない。`--vault` とパスワードの入力元の指定は受け付けない。
    ClipboardWorker {
        /// クリップボードの履歴からの除外の扱い。`--exclude-from-history` で除外する。
        policy: HistoryPolicy,
    },
}

impl Subcommand {
    /// コマンドラインで指定するサブコマンド名を返す。
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Init { .. } => "init",
            Self::Unlock { .. } => "unlock",
            Self::List => "list",
            Self::Get { .. } => "get",
            Self::Set { .. } => "set",
            Self::Delete { .. } => "delete",
            Self::RotateKey { .. } => "rotate-key",
            Self::Export { .. } => "export",
            Self::Recover { .. } => "recover",
            Self::ClipboardWorker { .. } => WORKER_SUBCOMMAND,
        }
    }
}

/// `rotate-key` の更新の方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotateMode {
    /// `--kek-only` (既定): DEK を変えずに、スロットの KEK だけを更新する。
    KekOnly {
        /// `--new-recovery-code`: リカバリーコード (Slot 2) も再発行する。
        new_recovery_code: bool,
    },
    /// `--full-dek`: 新しい DEK で全エントリを再暗号化する。
    FullDek {
        /// `--drop-prf-slot`: WebAuthn PRF のスロット (Slot 1) を、確認せずに破棄する。
        drop_prf_slot: bool,
    },
}

impl RotateMode {
    /// リカバリーコードを再発行する方式かを返す。`--full-dek` は常に再発行する。
    #[must_use]
    pub const fn issues_recovery_code(self) -> bool {
        match self {
            Self::KekOnly { new_recovery_code } => new_recovery_code,
            Self::FullDek { .. } => true,
        }
    }
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
    // 起動直後の保護が解析より前に適用されていることを、テストがこの位置で確かめる。
    failpoint::hit(FailPoint::BeforeArgs);
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
        // `--vault` の解析は全サブコマンドで共通のため、`Usage` の行は省略できる形になる。説明で必須を示す。
        "Vault を作成し、リカバリーキットを表示する (--vault の指定が必須)",
        kit_html_option().map(|kit_html| Subcommand::Init { kit_html }),
    );
    let unlock = subcommand_with_footer(
        "unlock",
        "Vault を解錠し、対話モードに入る (--vault の指定が必須)",
        idle_timeout_option().map(|idle_timeout_seconds| Subcommand::Unlock {
            idle_timeout_seconds,
        }),
        Some(HISTORY_WARNING),
    );
    let list = subcommand(
        "list",
        "エントリの一覧を表示する。秘密のフィールドは表示しない (--vault の指定が必須)",
        pure(Subcommand::List),
    );
    let get = subcommand_with_footer(
        "get",
        "エントリを表示する。パスワード、TOTP、メモは伏せる (--vault の指定が必須)",
        get_arguments(),
        Some(HISTORY_WARNING),
    );
    let set = subcommand(
        "set",
        "エントリを追加・更新する。値は端末で入力する (--vault の指定が必須)",
        set_arguments(),
    );
    let delete = subcommand(
        "delete",
        "エントリを削除する (--vault の指定が必須)",
        delete_arguments(),
    );
    let rotate_key = subcommand(
        "rotate-key",
        "鍵を更新する (--vault の指定が必須。--password-* は現在のパスワードの入力元)",
        rotate_key_arguments(),
    );
    let export = subcommand(
        "export",
        "全エントリを平文の JSON で書き出す (--vault の指定が必須)",
        export_arguments(),
    );
    let recover = subcommand(
        "recover",
        "リカバリーコードで解錠し、マスターパスワードを再設定する (--vault の指定が必須。--password-* は新しいパスワードの入力元)",
        recover_arguments(),
    );

    let clipboard_worker = clipboard_worker();

    let version = format!(
        "{} (fidelogic-core: {})",
        env!("CARGO_PKG_VERSION"),
        active_profile()
    );
    construct!([
        init,
        unlock,
        list,
        get,
        set,
        delete,
        rotate_key,
        export,
        recover,
        clipboard_worker
    ])
    .to_options()
    .descr("Fidelogic Vault のネイティブ CLI")
    .version(version.as_str())
    .help_parser(help_flag())
    .version_parser(short('V').long("version").help("バージョンを表示する"))
}

/// 標準入力をコマンドの入力に使うサブコマンドが、パスワードの入力元に標準入力を指定していないかを判定する。
///
/// `unlock` は、対話モードのコマンドを標準入力から読み込む。
fn does_not_share_standard_input(command_line: &CommandLine) -> bool {
    !(matches!(command_line.subcommand, Subcommand::Unlock { .. })
        && command_line.password_source.reads_standard_input())
}

/// メモとパスワードの両方を、標準入力から読み込む指定でないかを判定する。
fn does_not_read_standard_input_twice(command_line: &CommandLine) -> bool {
    !(matches!(
        command_line.subcommand,
        Subcommand::Set {
            notes: NotesSource::StandardInput,
            ..
        }
    ) && command_line.password_source.reads_standard_input())
}

/// 非対話の実行の `delete` が、同意の指定を持つかを判定する。
///
/// パスワードの入力元を指定した実行は、非対話とみなす。
fn has_deletion_consent(command_line: &CommandLine) -> bool {
    command_line.password_source == PasswordSource::Terminal
        || !matches!(
            command_line.subcommand,
            Subcommand::Delete {
                assume_yes: false,
                ..
            }
        )
}

/// 非対話の実行の `export` が、同意の指定を持つかを判定する。
fn has_plaintext_consent(command_line: &CommandLine) -> bool {
    command_line.password_source == PasswordSource::Terminal
        || !matches!(
            command_line.subcommand,
            Subcommand::Export {
                confirmed: false,
                ..
            }
        )
}

/// サブコマンドの解析器を組み立てる。すべてのサブコマンドに、`--vault` とパスワードの入力元の指定を付ける。
fn subcommand(
    name: &'static str,
    description: &'static str,
    arguments: impl Parser<Subcommand> + 'static,
) -> impl Parser<CommandLine> {
    subcommand_with_footer(name, description, arguments, None)
}

/// [`subcommand`] と同じ解析器を、ヘルプの末尾の説明を付けて組み立てる。
fn subcommand_with_footer(
    name: &'static str,
    description: &'static str,
    arguments: impl Parser<Subcommand> + 'static,
    footer: Option<&'static str>,
) -> impl Parser<CommandLine> {
    let vault = vault_option();
    let password_source = password_source_options();
    let subcommand = arguments;
    let parser = construct!(CommandLine {
        vault,
        password_source,
        subcommand
    })
    .guard(
        does_not_share_standard_input,
        "`unlock` は標準入力をコマンドの入力に使うため、パスワードの入力元に標準入力を指定できません。",
    )
    .guard(
        does_not_read_standard_input_twice,
        "メモとパスワードの両方を、標準入力から読み込むことはできません。",
    )
    .guard(
        has_deletion_consent,
        "`--password-*` を指定した `delete` は非対話の実行とみなすため、`--yes` を指定してください。",
    )
    .guard(
        has_plaintext_consent,
        "`--password-*` を指定した `export` は非対話の実行とみなすため、`--confirm-plaintext` を指定してください。",
    )
    .to_options()
    .descr(description)
    .help_parser(help_flag());
    let parser = match footer {
        Some(footer) => parser.footer(footer),
        None => parser,
    };
    parser.command(name).help(description)
}

/// 内部用のサブコマンド `__clipboard-worker` の解析器を組み立てる。ヘルプには表示しない。
///
/// Vault を扱わないため、`--vault` とパスワードの入力元の指定を付けない。
/// [`CommandLine`] の該当するフィールドは、`None` と制御端末 (未使用) になる。
fn clipboard_worker() -> impl Parser<CommandLine> {
    let vault = pure(None);
    let password_source = pure(PasswordSource::Terminal);
    let subcommand = long(EXCLUDE_FROM_HISTORY_FLAG)
        .help("クリップボードの履歴からの除外を指定する")
        .switch()
        .map(|exclude| Subcommand::ClipboardWorker {
            policy: if exclude {
                HistoryPolicy::Exclude
            } else {
                HistoryPolicy::Allow
            },
        });
    construct!(CommandLine {
        vault,
        password_source,
        subcommand
    })
    .to_options()
    .descr("クリップボードへコピーし、一定時間の後に消去する (内部用)")
    .help_parser(help_flag())
    .command(WORKER_SUBCOMMAND)
    .hide()
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

/// マスターパスワードの入力元の指定。
///
/// `--password-stdin`, `--password-file`, `--password-fd` は同時に指定できない。
/// どれも無い場合は、制御端末から読み込む。
fn password_source_options() -> impl Parser<PasswordSource> {
    let standard_input = long("password-stdin")
        .help("マスターパスワードを標準入力から読み込む")
        .req_flag(PasswordSource::StandardInput);
    let file = long("password-file")
        .help("マスターパスワードをファイル (権限 0600) から読み込む")
        .argument::<PathBuf>("PATH")
        .map(PasswordSource::File);
    let descriptor = long("password-fd")
        .help("マスターパスワードを、引き継いだファイル記述子から読み込む")
        .argument::<i32>("FD")
        .guard(
            |descriptor| *descriptor >= 0,
            "ファイル記述子は 0 以上の整数で指定してください。",
        )
        .map(PasswordSource::Descriptor);
    construct!([standard_input, file, descriptor]).fallback(PasswordSource::Terminal)
}

/// `--kit-html <PATH>` の定義。`init` と、リカバリーコードを再発行するサブコマンドで使う。
fn kit_html_option() -> impl Parser<Option<PathBuf>> {
    long("kit-html")
        .help("リカバリーキットを HTML ファイル (権限 0600) にも書き出す。既存のファイルは上書きしない")
        .argument::<PathBuf>("PATH")
        .optional()
}

/// `recover` の指定。`--kit-html` は、リカバリーコードを再発行する場合だけ受け付ける。
fn recover_arguments() -> impl Parser<Subcommand> {
    let keep_recovery_code = long("keep-recovery-code")
        .help("リカバリーコードを再発行せず、使ったコードを残す")
        .switch();
    let kit_html = kit_html_option();
    construct!(keep_recovery_code, kit_html)
        .guard(
            |(keep_recovery_code, kit_html)| !*keep_recovery_code || kit_html.is_none(),
            "`--kit-html` はリカバリーコードを再発行する場合だけ指定できます。`--keep-recovery-code` と同時に指定しないでください。",
        )
        .map(|(keep_recovery_code, kit_html)| Subcommand::Recover {
            keep_recovery_code,
            kit_html,
        })
}

/// `rotate-key` の指定。`--kit-html` は、リカバリーコードを再発行する場合だけ受け付ける。
fn rotate_key_arguments() -> impl Parser<Subcommand> {
    let mode = rotate_mode();
    let kit_html = kit_html_option();
    construct!(mode, kit_html)
        .guard(
            |(mode, kit_html)| mode.issues_recovery_code() || kit_html.is_none(),
            "`--kit-html` はリカバリーコードを再発行する場合 (`--new-recovery-code` または `--full-dek`) だけ指定できます。",
        )
        .map(|(mode, kit_html)| Subcommand::RotateKey { mode, kit_html })
}

/// `get` / `set` / `delete` が受け取る対象のエントリ。
fn entry_argument() -> impl Parser<String> {
    positional::<String>("ENTRY").help("対象のエントリのタイトル (完全一致)")
}

/// `get` の指定。`--field` と `--clip` は同時に指定できない。
fn get_arguments() -> impl Parser<Subcommand> {
    let print = long("field")
        .help("指定した項目の値だけを標準出力に書く (username, password, url, totp, notes)")
        .argument::<EntryField>("FIELD")
        .map(GetAction::Print);
    let copy = long("clip")
        .help("指定した項目の値をクリップボードへコピーする (username, password, url, totp, notes)")
        .argument::<EntryField>("FIELD")
        .map(GetAction::Copy);
    let action = construct!([print, copy]).fallback(GetAction::Summary);
    let entry = entry_argument();
    construct!(action, entry).map(|(action, entry)| Subcommand::Get { entry, action })
}

/// `set` の指定。`--notes-file` と `--notes-stdin` は同時に指定できない。
fn set_arguments() -> impl Parser<Subcommand> {
    let file = long("notes-file")
        .help("メモをファイルから読み込む")
        .argument::<PathBuf>("PATH")
        .map(NotesSource::File);
    let standard_input = long("notes-stdin")
        .help("メモを標準入力から読み込む")
        .req_flag(NotesSource::StandardInput);
    let notes = construct!([file, standard_input]).fallback(NotesSource::Prompt);
    let entry = entry_argument();
    construct!(notes, entry).map(|(notes, entry)| Subcommand::Set { entry, notes })
}

/// `delete` の指定。
fn delete_arguments() -> impl Parser<Subcommand> {
    let assume_yes = long("yes")
        .help("同意を求めずに削除する (--password-* と併用する場合は必須)")
        .switch();
    let entry = entry_argument();
    construct!(assume_yes, entry)
        .map(|(assume_yes, entry)| Subcommand::Delete { entry, assume_yes })
}

/// `export` の指定。`--output` と `--stdout` のどちらか一方が必要である。
fn export_arguments() -> impl Parser<Subcommand> {
    let file = long("output")
        .help("権限 0600 の新しいファイルに書き出す。既存のファイルは上書きしない")
        .argument::<PathBuf>("PATH")
        .map(ExportTarget::File);
    let standard_output = long("stdout")
        .help("標準出力に書き出す")
        .req_flag(ExportTarget::StandardOutput);
    let target = construct!([file, standard_output]);
    let confirmed = long("confirm-plaintext")
        .help("同意を求めずに平文を書き出す (--password-* と併用する場合は必須)")
        .switch();
    construct!(target, confirmed)
        .map(|(target, confirmed)| Subcommand::Export { target, confirmed })
}

/// `unlock` の `--idle-timeout <SECS>` の定義。
fn idle_timeout_option() -> impl Parser<u64> {
    long("idle-timeout")
        .help("無操作の時間がこの秒数に達したら施錠する (1 から 86400)")
        .argument::<u64>("SECS")
        .guard(
            |seconds| (1..=MAX_IDLE_TIMEOUT_SECONDS).contains(seconds),
            "`--idle-timeout` は 1 から 86400 の秒数で指定してください。",
        )
        .fallback(DEFAULT_IDLE_TIMEOUT_SECONDS)
        .display_fallback()
}

/// `rotate-key` の方式の指定。
///
/// `--kek-only` と `--full-dek` は同時に指定できない。どちらも無い場合は `--kek-only` として扱う。
/// `--drop-prf-slot` は `--full-dek` と組み合わせたときだけ受け付ける。
/// `--new-recovery-code` は `--kek-only` (省略を含む) でだけ受け付ける。`--full-dek` は常に再発行する。
fn rotate_mode() -> impl Parser<RotateMode> {
    let kek_only_flag = long("kek-only")
        .help("DEK を変えずに、スロットの KEK だけを更新する (既定)")
        .req_flag(())
        .optional();
    let new_recovery_code = long("new-recovery-code")
        .help("--kek-only と併用し、リカバリーコードも再発行する")
        .switch();
    let kek_only = construct!(kek_only_flag, new_recovery_code)
        .map(|(_, new_recovery_code)| RotateMode::KekOnly { new_recovery_code });
    let full_dek_flag = long("full-dek")
        .help("新しい DEK で全エントリを再暗号化し、リカバリーコードを再発行する")
        .req_flag(());
    let drop_prf_slot = long("drop-prf-slot")
        .help("--full-dek と併用し、WebAuthn PRF のスロットを確認せずに破棄する")
        .switch();
    let full_dek = construct!(full_dek_flag, drop_prf_slot)
        .map(|((), drop_prf_slot)| RotateMode::FullDek { drop_prf_slot });
    // `--kek-only` の側は、指定が何も無くても成功するため、`--full-dek` の側を先に置く。
    construct!([full_dek, kek_only])
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{CommandLine, ParseExit, RotateMode, Subcommand, parse};
    use crate::entry_ops::{EntryField, GetAction};
    use crate::export::ExportTarget;
    use crate::secret_input::PasswordSource;
    use crate::set::NotesSource;
    use crate::sys::clipboard::{HISTORY_WARNING, HistoryPolicy};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// すべてのサブコマンド名と、`--vault` 以外の必須の引数を付けた最小の引数列。
    const MINIMAL_INVOCATIONS: [&[&str]; 9] = [
        &["init"],
        &["unlock"],
        &["list"],
        &["get", "github"],
        &["set", "github"],
        // パスワードの入力元を指定する実行は非対話とみなすため、同意の指定を付けておく。
        &["delete", "github", "--yes"],
        &["rotate-key"],
        &["export", "--stdout", "--confirm-plaintext"],
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
    fn test_init_kit_html_option() -> TestResult {
        assert_eq!(
            parse_strs(&["init"])?.subcommand,
            Subcommand::Init { kit_html: None }
        );
        for args in [
            &["init", "--kit-html", "./kit.html"][..],
            &["init", "--kit-html=./kit.html"],
            &["init", "--vault", "v", "--kit-html", "./kit.html"],
        ] {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Init {
                    kit_html: Some(PathBuf::from("./kit.html"))
                },
                "{args:?} の解析に失敗。"
            );
        }
        Ok(())
    }

    /// `Usage` の行は `--vault` を省略できる形になるため、`init` の説明で必須を示すこと。
    #[test]
    fn test_init_help_states_that_vault_is_required() -> TestResult {
        for args in [&["init", "--help"][..], &["--help"]] {
            let help = match parse_strs(args) {
                Err(ParseExit::Help(text)) => text,
                other => return Err(format!("{args:?} の解析に失敗: {other:?}").into()),
            };
            assert!(
                help.contains("--vault の指定が必須"),
                "{args:?} の必須の案内の確認に失敗: {help}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_kit_html_option_is_rejected_when_invalid() -> TestResult {
        expect_invalid(&["init", "--kit-html"])?;
        expect_invalid(&["init", "--kit-html", "a", "--kit-html", "b"])?;
        expect_invalid(&["--kit-html", "a", "init"])?;
        for invocation in MINIMAL_INVOCATIONS {
            if invocation != ["init"] && invocation != ["recover"] {
                let args: Vec<&str> = invocation
                    .iter()
                    .chain(&["--kit-html", "a"])
                    .copied()
                    .collect();
                expect_invalid(&args)?;
            }
        }
        Ok(())
    }

    #[test]
    fn test_entry_subcommands_capture_entry() -> TestResult {
        assert_eq!(
            parse_strs(&["get", "github"])?.subcommand,
            Subcommand::Get {
                entry: "github".to_owned(),
                action: GetAction::Summary,
            }
        );
        assert_eq!(
            parse_strs(&["set", "mail"])?.subcommand,
            Subcommand::Set {
                entry: "mail".to_owned(),
                notes: NotesSource::Prompt,
            }
        );
        assert_eq!(
            parse_strs(&["delete", "bank"])?.subcommand,
            Subcommand::Delete {
                entry: "bank".to_owned(),
                assume_yes: false,
            }
        );
        Ok(())
    }

    #[test]
    fn test_get_output_options() -> TestResult {
        let cases: [(&[&str], GetAction); 6] = [
            (&["get", "x"], GetAction::Summary),
            (
                &["get", "x", "--field", "password"],
                GetAction::Print(EntryField::Password),
            ),
            (
                &["get", "--field=username", "x"],
                GetAction::Print(EntryField::Username),
            ),
            (
                &["get", "x", "--clip", "totp"],
                GetAction::Copy(EntryField::Totp),
            ),
            (
                &["get", "--clip=url", "x"],
                GetAction::Copy(EntryField::Url),
            ),
            (
                &["get", "--field", "notes", "--", "x"],
                GetAction::Print(EntryField::Notes),
            ),
        ];
        for (args, expected) in cases {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Get {
                    entry: "x".to_owned(),
                    action: expected,
                },
                "{args:?} の解析に失敗。"
            );
        }
        for args in [
            &["get", "x", "--field"][..],
            &["get", "x", "--clip"],
            &["get", "x", "--field", "title"],
            &["get", "x", "--clip", "Password"],
            &["get", "x", "--field", "password", "--clip", "totp"],
            &["get", "x", "--field", "password", "--field", "totp"],
            &["get", "x", "--clip", "totp", "--clip", "totp"],
            &["get", "x", "--yes"],
        ] {
            expect_invalid(args)?;
        }
        let message = expect_invalid(&["get", "x", "--field", "title"])?;
        assert!(
            message.contains("username, password, url, totp, notes"),
            "項目の一覧の表示の確認に失敗: {message}"
        );
        Ok(())
    }

    /// クリップボードへコピーできるサブコマンドのヘルプに、履歴による漏洩の警告を表示すること。
    #[test]
    fn test_help_of_copying_subcommands_shows_history_warning() -> TestResult {
        // ヘルプは端末の幅で折り返すため、空白と改行を除いて比較する。
        let compact = |text: &str| text.split_whitespace().collect::<String>();
        for name in ["get", "unlock"] {
            let help = match parse_strs(&[name, "--help"]) {
                Err(ParseExit::Help(text)) => text,
                other => return Err(format!("{name} --help の解析に失敗: {other:?}").into()),
            };
            assert!(
                compact(&help).contains(&compact(HISTORY_WARNING)),
                "{name} のヘルプの警告の確認に失敗: {help}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_set_notes_sources() -> TestResult {
        for (args, expected) in [
            (
                &["set", "x", "--notes-file", "./key"][..],
                NotesSource::File(PathBuf::from("./key")),
            ),
            (&["set", "--notes-stdin", "x"], NotesSource::StandardInput),
            (
                &["set", "x", "--notes-stdin", "--password-file", "p"],
                NotesSource::StandardInput,
            ),
            (
                &["set", "x", "--notes-stdin", "--password-fd", "3"],
                NotesSource::StandardInput,
            ),
        ] {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Set {
                    entry: "x".to_owned(),
                    notes: expected,
                },
                "{args:?} の解析に失敗。"
            );
        }
        parse_strs(&["set", "x", "--notes-file", "n", "--password-stdin"])?;
        for args in [
            &["set", "x", "--notes-file"][..],
            &["set", "x", "--notes-file", "a", "--notes-stdin"],
            &["set", "x", "--notes-file", "a", "--notes-file", "b"],
            &["set", "x", "--notes-stdin", "--notes-stdin"],
            &["set", "x", "--notes", "secret"],
        ] {
            expect_invalid(args)?;
        }
        for source in [&["--password-stdin"][..], &["--password-fd", "0"]] {
            let args: Vec<&str> = ["set", "x", "--notes-stdin"]
                .iter()
                .chain(source)
                .copied()
                .collect();
            let message = expect_invalid(&args)?;
            assert!(
                message.contains("標準入力"),
                "{args:?} の理由の表示の確認に失敗: {message}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_delete_requires_yes_for_non_interactive_password() -> TestResult {
        for (args, assume_yes) in [
            (&["delete", "x"][..], false),
            (&["delete", "x", "--yes"], true),
            (&["delete", "--yes", "--password-stdin", "x"], true),
        ] {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Delete {
                    entry: "x".to_owned(),
                    assume_yes,
                },
                "{args:?} の解析に失敗。"
            );
        }
        for source in [
            &["--password-stdin"][..],
            &["--password-file", "p"],
            &["--password-fd", "3"],
        ] {
            let args: Vec<&str> = ["delete", "x"].iter().chain(source).copied().collect();
            let message = expect_invalid(&args)?;
            assert!(
                message.contains("--yes"),
                "{args:?} の理由の表示の確認に失敗: {message}"
            );
        }
        expect_invalid(&["delete", "x", "--yes", "--yes"])?;
        expect_invalid(&["delete", "x", "-y"])?;
        Ok(())
    }

    #[test]
    fn test_export_targets_and_confirmation() -> TestResult {
        let file = ExportTarget::File(PathBuf::from("dump.json"));
        for (args, target, confirmed) in [
            (
                &["export", "--stdout"][..],
                ExportTarget::StandardOutput,
                false,
            ),
            (&["export", "--output", "dump.json"], file.clone(), false),
            (
                &["export", "--output=dump.json", "--confirm-plaintext"],
                file.clone(),
                true,
            ),
            (
                &[
                    "export",
                    "--confirm-plaintext",
                    "--stdout",
                    "--password-stdin",
                ],
                ExportTarget::StandardOutput,
                true,
            ),
        ] {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Export { target, confirmed },
                "{args:?} の解析に失敗。"
            );
        }
        for args in [
            &["export"][..],
            &["export", "--confirm-plaintext"],
            &["export", "--output"],
            &["export", "--stdout", "--output", "a"],
            &["export", "--stdout", "--stdout"],
            &["export", "--output", "a", "--output", "b"],
            &["export", "dump.json"],
        ] {
            expect_invalid(args)?;
        }
        for source in [
            &["--password-stdin"][..],
            &["--password-file", "p"],
            &["--password-fd", "3"],
        ] {
            let args: Vec<&str> = ["export", "--stdout"]
                .iter()
                .chain(source)
                .copied()
                .collect();
            let message = expect_invalid(&args)?;
            assert!(
                message.contains("--confirm-plaintext"),
                "{args:?} の理由の表示の確認に失敗: {message}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_unlock_idle_timeout() -> TestResult {
        for (args, expected) in [
            (&["unlock"][..], 300),
            (&["unlock", "--idle-timeout", "1"], 1),
            (&["unlock", "--idle-timeout=86400"], 86_400),
        ] {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Unlock {
                    idle_timeout_seconds: expected
                },
                "{args:?} の解析に失敗。"
            );
        }
        for value in ["0", "86401", "-1", "1.5", "abc", "", "18446744073709551616"] {
            expect_invalid(&["unlock", &format!("--idle-timeout={value}")])?;
        }
        expect_invalid(&["unlock", "--idle-timeout"])?;
        expect_invalid(&["unlock", "--idle-timeout", "1", "--idle-timeout", "2"])?;
        expect_invalid(&["list", "--idle-timeout", "1"])?;
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
                entry: "-foo".to_owned(),
                action: GetAction::Summary,
            }
        );
        Ok(())
    }

    /// `--new-recovery-code` を指定しない `--kek-only`。
    const KEK_ONLY: RotateMode = RotateMode::KekOnly {
        new_recovery_code: false,
    };

    #[test]
    fn test_rotate_key_modes() -> TestResult {
        let cases: [(&[&str], RotateMode); 8] = [
            (&["rotate-key"], KEK_ONLY),
            (&["rotate-key", "--kek-only"], KEK_ONLY),
            (
                &["rotate-key", "--new-recovery-code"],
                RotateMode::KekOnly {
                    new_recovery_code: true,
                },
            ),
            (
                &["rotate-key", "--kek-only", "--new-recovery-code"],
                RotateMode::KekOnly {
                    new_recovery_code: true,
                },
            ),
            (
                &["rotate-key", "--new-recovery-code", "--kek-only"],
                RotateMode::KekOnly {
                    new_recovery_code: true,
                },
            ),
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
                Subcommand::RotateKey {
                    mode: expected,
                    kit_html: None
                },
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
        expect_invalid(&["rotate-key", "--full-dek", "--new-recovery-code"])?;
        expect_invalid(&["rotate-key", "--new-recovery-code", "--full-dek"])?;
        expect_invalid(&["rotate-key", "--new-recovery-code", "--drop-prf-slot"])?;
        expect_invalid(&["rotate-key", "--new-recovery-code", "--new-recovery-code"])?;
        expect_invalid(&["rotate-key", "--keep-recovery-code"])?;
        Ok(())
    }

    #[test]
    fn test_recovery_code_is_issued_by_new_code_and_full_dek() {
        let cases = [
            (KEK_ONLY, false),
            (
                RotateMode::KekOnly {
                    new_recovery_code: true,
                },
                true,
            ),
            (
                RotateMode::FullDek {
                    drop_prf_slot: false,
                },
                true,
            ),
            (
                RotateMode::FullDek {
                    drop_prf_slot: true,
                },
                true,
            ),
        ];
        for (mode, expected) in cases {
            assert_eq!(
                mode.issues_recovery_code(),
                expected,
                "{mode:?} の判定に失敗。"
            );
        }
    }

    #[test]
    fn test_rotate_key_kit_html_requires_new_recovery_code() -> TestResult {
        for args in [
            &["rotate-key", "--new-recovery-code", "--kit-html", "kit"][..],
            &["rotate-key", "--kit-html=kit", "--full-dek"],
            &[
                "rotate-key",
                "--full-dek",
                "--drop-prf-slot",
                "--kit-html",
                "kit",
            ],
        ] {
            let Subcommand::RotateKey { kit_html, .. } = parse_strs(args)?.subcommand else {
                return Err(format!("{args:?} の解析に失敗。").into());
            };
            assert_eq!(
                kit_html,
                Some(PathBuf::from("kit")),
                "{args:?} の出力先の解析に失敗。"
            );
        }
        for args in [
            &["rotate-key", "--kit-html", "kit"][..],
            &["rotate-key", "--kek-only", "--kit-html", "kit"],
        ] {
            let message = expect_invalid(args)?;
            assert!(
                message.contains("--kit-html"),
                "{args:?} の理由の表示の確認に失敗: {message}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_recover_options() -> TestResult {
        let cases: [(&[&str], bool, Option<&str>); 4] = [
            (&["recover"], false, None),
            (&["recover", "--keep-recovery-code"], true, None),
            (&["recover", "--kit-html", "kit"], false, Some("kit")),
            (
                &["recover", "--vault", "v", "--kit-html=kit"],
                false,
                Some("kit"),
            ),
        ];
        for (args, keep, kit) in cases {
            assert_eq!(
                parse_strs(args)?.subcommand,
                Subcommand::Recover {
                    keep_recovery_code: keep,
                    kit_html: kit.map(PathBuf::from),
                },
                "{args:?} の解析に失敗。"
            );
        }
        let message = expect_invalid(&["recover", "--keep-recovery-code", "--kit-html", "kit"])?;
        assert!(
            message.contains("--kit-html"),
            "理由の表示の確認に失敗: {message}"
        );
        for args in [
            &["recover", "--keep-recovery-code", "--keep-recovery-code"][..],
            &["recover", "--keep-recovery-code=value"],
            &["recover", "--kit-html"],
            &["recover", "--kit-html", "a", "--kit-html", "b"],
            &["recover", "--new-recovery-code"],
            &["recover", "--full-dek"],
        ] {
            expect_invalid(args)?;
        }
        Ok(())
    }

    /// ヘルプで、必須の指定と、パスワードの入力元の意味を示すこと。
    #[test]
    fn test_rekey_help_states_requirements() -> TestResult {
        let cases = [
            (
                "recover",
                "新しいパスワードの入力元",
                "--keep-recovery-code",
            ),
            (
                "rotate-key",
                "現在のパスワードの入力元",
                "--new-recovery-code",
            ),
        ];
        for (name, source, option) in cases {
            let help = match parse_strs(&[name, "--help"]) {
                Err(ParseExit::Help(text)) => text,
                other => return Err(format!("{name} --help の解析に失敗: {other:?}").into()),
            };
            // 説明は端末の幅で折り返すため、空白と改行を除いて比較する。
            let compact = |text: &str| text.split_whitespace().collect::<String>();
            for text in ["--vault の指定が必須", source, option, "--kit-html"] {
                assert!(
                    compact(&help).contains(&compact(text)),
                    "{name} のヘルプの {text} の確認に失敗: {help}"
                );
            }
        }
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

    /// 入力元の指定と、解析結果の組。
    fn password_source_cases() -> [(&'static [&'static str], PasswordSource); 6] {
        [
            (&["--password-stdin"], PasswordSource::StandardInput),
            (
                &["--password-file", "./password.txt"],
                PasswordSource::File(PathBuf::from("./password.txt")),
            ),
            (
                &["--password-file=./password.txt"],
                PasswordSource::File(PathBuf::from("./password.txt")),
            ),
            (&["--password-fd", "3"], PasswordSource::Descriptor(3)),
            (&["--password-fd=0"], PasswordSource::Descriptor(0)),
            (&["--password-fd", "1023"], PasswordSource::Descriptor(1023)),
        ]
    }

    #[test]
    fn test_password_source_defaults_to_terminal() -> TestResult {
        for args in MINIMAL_INVOCATIONS {
            assert_eq!(
                parse_strs(args)?.password_source,
                PasswordSource::Terminal,
                "{args:?} の既定の入力元の確認に失敗。"
            );
        }
        Ok(())
    }

    #[test]
    fn test_password_source_options_are_accepted() -> TestResult {
        for invocation in MINIMAL_INVOCATIONS {
            for (option, expected) in password_source_cases() {
                let args: Vec<&str> = invocation.iter().chain(option.iter()).copied().collect();
                // `unlock` は標準入力をコマンドの入力に使うため、標準入力からの指定を別に検査する。
                if invocation == ["unlock"] && expected.reads_standard_input() {
                    continue;
                }
                let command_line =
                    parse_strs(&args).map_err(|exit| format!("{args:?}: {exit:?}"))?;
                assert_eq!(
                    command_line.password_source, expected,
                    "{args:?} の入力元の解析に失敗。"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn test_unlock_rejects_password_from_standard_input() -> TestResult {
        for option in [
            &["--password-stdin"][..],
            &["--password-fd", "0"],
            &["--password-fd=0"],
        ] {
            let args: Vec<&str> = ["unlock"].iter().chain(option.iter()).copied().collect();
            let message = expect_invalid(&args)?;
            assert!(
                message.contains("標準入力"),
                "{args:?} の理由の表示の確認に失敗: {message}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_password_source_options_are_exclusive() -> TestResult {
        let conflicts: [&[&str]; 6] = [
            &["list", "--password-stdin", "--password-file", "a"],
            &["list", "--password-stdin", "--password-fd", "3"],
            &["list", "--password-file", "a", "--password-fd", "3"],
            &["list", "--password-stdin", "--password-stdin"],
            &["list", "--password-file", "a", "--password-file", "b"],
            &["list", "--password-fd", "3", "--password-fd", "4"],
        ];
        for args in conflicts {
            expect_invalid(args)?;
        }
        Ok(())
    }

    #[test]
    fn test_invalid_password_source_values_are_rejected() -> TestResult {
        // 値の誤りは、既定の入力元 (端末) に置き換えずに拒否する。
        let invalid: [&[&str]; 8] = [
            &["list", "--password-file"],
            &["list", "--password-fd"],
            &["list", "--password-fd", "abc"],
            &["list", "--password-fd="],
            &["list", "--password-fd=-1"],
            &["list", "--password-fd", "2147483648"],
            &["list", "--password-stdin=value"],
            &["--password-stdin", "list"],
        ];
        for args in invalid {
            expect_invalid(args)?;
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
        for option in ["--password-stdin", "--password-file", "--password-fd"] {
            assert!(
                subcommand_help.contains(option),
                "ヘルプに {option} が無い: {subcommand_help}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_clipboard_worker_parses_history_policy() -> TestResult {
        let plain = parse_strs(&["__clipboard-worker"])?;
        assert_eq!(
            plain.subcommand,
            Subcommand::ClipboardWorker {
                policy: HistoryPolicy::Allow
            }
        );
        assert_eq!(plain.subcommand.name(), "__clipboard-worker");
        assert_eq!(plain.vault, None);
        assert_eq!(plain.password_source, PasswordSource::Terminal);

        let concealed = parse_strs(&["__clipboard-worker", "--exclude-from-history"])?;
        assert_eq!(
            concealed.subcommand,
            Subcommand::ClipboardWorker {
                policy: HistoryPolicy::Exclude
            }
        );
        Ok(())
    }

    #[test]
    fn test_clipboard_worker_rejects_vault_and_secret_options() -> TestResult {
        let rejected: [&[&str]; 8] = [
            &["--vault", "./my.vault"],
            &["--password-stdin"],
            &["--password-file", "./password.txt"],
            &["--password-fd", "3"],
            &["--password", "hunter2"],
            &["-p", "hunter2"],
            &["--exclude-from-history", "--exclude-from-history"],
            &["github"],
        ];
        for option in rejected {
            let args: Vec<&str> = ["__clipboard-worker"]
                .iter()
                .chain(option.iter())
                .copied()
                .collect();
            expect_invalid(&args)?;
        }
        Ok(())
    }

    #[test]
    fn test_clipboard_worker_is_hidden_from_help() -> TestResult {
        let help = match parse_strs(&["--help"]) {
            Err(ParseExit::Help(text)) => text,
            other => return Err(format!("--help の解析に失敗: {other:?}").into()),
        };
        assert!(
            !help.contains("__clipboard-worker"),
            "内部用のサブコマンドを非表示にすることの確認に失敗: {help}"
        );
        Ok(())
    }
}
