//! # リカバリーキット (`recovery_kit`)
//!
//! リカバリーコードを利用者に控えてもらうための、端末の画面と HTML の内容を組み立てる。
//! このモジュールは OS に依存しない。端末の制御は、サブコマンドが共有する非公開のモジュール `interaction` が行う。
//!
//! ## 警告
//!
//! リカバリーコードは、単独で Vault 全体を復号できる。画面と HTML の両方に [`SINGLE_FACTOR_WARNING`] を表示する。
//! マスターパスワードの記入欄は設けない。同じ紙に両方が書かれることを避けるためである。
//!
//! ## 秘密の扱い
//!
//! コードを、固定の文言と連結した文字列を作らない。画面は [`screen_parts`] の要素を順に書き、
//! HTML は [`write_html`] が固定の文言とコードを別々に書き込む。
//! 書き込み先には、内部にバッファを持たないもの ([`std::fs::File`] など) を渡す。

use std::io::{self, Write};

/// 画面と HTML に必ず表示する警告。
pub const SINGLE_FACTOR_WARNING: &str = "このコードは、単独で Vault 全体を復号できます。";

/// 画面の、コードより前の部分。
const SCREEN_HEADING: &str = "== Fidelogic Vault リカバリーキット ==\n\n    ";

/// 画面の、コードより後の部分。警告の行には [`SINGLE_FACTOR_WARNING`] を書く。
const SCREEN_GUIDANCE: &str = concat!(
    "\n\n",
    "警告: このコードは、単独で Vault 全体を復号できます。\n",
    "マスターパスワードを忘れた場合の復旧に使います。\n",
    "\n",
    "- 紙などに書き写し、安全な場所に保管してください\n",
    "- 画面の撮影や、クラウドへの保存は避けてください\n",
    "- この画面を閉じると、同じコードは表示できません\n",
    "\n",
    "控えを確認します。コードの末尾 5 文字を入力してください。\n",
);

/// HTML の、コードより前の部分。
const HTML_HEAD: &str = r#"<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>Fidelogic Vault リカバリーキット</title>
<style>
body { font-family: sans-serif; max-width: 40em; margin: 2em auto; padding: 0 1em; line-height: 1.7; }
.code { font-family: monospace; font-size: 1.4em; border: 2px solid; padding: 0.8em; text-align: center; overflow-wrap: anywhere; }
.warning { font-weight: bold; border-left: 0.4em solid; padding-left: 0.8em; }
</style>
</head>
<body>
<h1>Fidelogic Vault リカバリーキット</h1>
<p class="code">"#;

/// HTML の、コードより後の部分。警告の段落には [`SINGLE_FACTOR_WARNING`] を書く。
const HTML_TAIL: &str = r#"</p>
<p class="warning">警告: このコードは、単独で Vault 全体を復号できます。</p>
<p>マスターパスワードを忘れた場合の復旧に使います。</p>
<ul>
<li>このファイルを印刷し、紙を金庫などの安全な場所に保管してください。</li>
<li>マスターパスワードは、この紙に書かないでください。</li>
<li>印刷した後は、このファイルを削除してください。ごみ箱に移した場合は、ごみ箱も空にしてください。</li>
<li>クラウドストレージやメールに、保存または送信しないでください。</li>
</ul>
</body>
</html>
"#;

/// 端末に表示するキットを、書き込む順に分けた形で返す。2 番目の要素が `grouped_code` である。
///
/// 改行は `\n` とする。端末の出力処理が改行を変換する前提である。
///
/// # Args
///
/// - `grouped_code`: 表示用の、区切りを含むリカバリーコード。
#[must_use]
pub fn screen_parts(grouped_code: &str) -> [&str; 3] {
    [SCREEN_HEADING, grouped_code, SCREEN_GUIDANCE]
}

/// 印刷して保管するための、自己完結の HTML を書き込む。
///
/// 外部のリソースを参照せず、スクリプトと入力欄を持たない。
///
/// # Args
///
/// - `writer`: 書き込み先。
/// - `grouped_code`: 表示用の、区切りを含むリカバリーコード。文字は Crockford Base32 と `-` だけで、
///   HTML のエスケープを必要としない。
///
/// # Errors
///
/// 書き込みに失敗した場合は、その [`io::Error`]。
pub fn write_html(writer: &mut impl Write, grouped_code: &str) -> io::Result<()> {
    writer.write_all(HTML_HEAD.as_bytes())?;
    writer.write_all(grouped_code.as_bytes())?;
    writer.write_all(HTML_TAIL.as_bytes())?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::{SINGLE_FACTOR_WARNING, screen_parts, write_html};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// テスト用の表示形のコード。
    const CODE: &str = "FL000-G40R4-0M30E-20918-5GR38-E1X9Q";

    /// 画面の全体を連結する。テストのコードは秘密ではない。
    fn screen() -> String {
        screen_parts(CODE).concat()
    }

    fn html() -> Result<String, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        write_html(&mut output, CODE)?;
        Ok(String::from_utf8(output)?)
    }

    /// 端末での表示幅。ASCII は 1 桁、その他は 2 桁とする。
    fn display_width(line: &str) -> usize {
        line.chars()
            .map(|character| if character.is_ascii() { 1 } else { 2 })
            .sum()
    }

    #[test]
    fn test_screen_contains_code_once_and_warning() {
        let [before, code, after] = screen_parts(CODE);
        assert_eq!(code, CODE);
        assert!(!before.contains(CODE) && !after.contains(CODE));
        assert_eq!(screen().matches(CODE).count(), 1);
        assert!(
            screen().contains(SINGLE_FACTOR_WARNING),
            "画面の警告の表示に失敗。"
        );
        assert!(screen().contains("末尾 5 文字"), "確認の方法の表示に失敗。");
    }

    /// 24 行 80 桁の端末で、再入力の案内の 2 行を足しても、コードが画面の外に流れないこと。
    #[test]
    fn test_screen_fits_in_small_terminal() {
        let screen = screen();
        assert!(screen.ends_with('\n'), "画面の末尾の改行の確認に失敗。");
        assert!(
            screen.lines().count() <= 20,
            "画面の行数の確認に失敗: {}",
            screen.lines().count()
        );
        for line in screen.lines() {
            assert!(
                display_width(line) <= 79,
                "画面の行の幅の確認に失敗: {line}"
            );
        }
    }

    #[test]
    fn test_html_contains_code_once_and_warning() -> TestResult {
        let html = html()?;
        assert!(html.starts_with("<!DOCTYPE html>\n"));
        assert!(html.ends_with("</html>\n"));
        assert_eq!(html.matches(CODE).count(), 1);
        assert!(html.contains(SINGLE_FACTOR_WARNING), "警告の記載に失敗。");
        assert!(html.contains("<meta charset=\"utf-8\">"));
        assert!(
            html.contains("削除してください"),
            "削除の案内の記載に失敗。"
        );
        Ok(())
    }

    #[test]
    fn test_html_is_self_contained_without_script_or_input() -> TestResult {
        let html = html()?.to_ascii_lowercase();
        assert!(
            html.contains("default-src 'none'"),
            "外部の読み込みを禁止する指定の記載に失敗。"
        );
        for forbidden in [
            "<script",
            "<link",
            "<img",
            "<iframe",
            "<input",
            "<textarea",
            "<form",
            "http://",
            "https://",
            "src=",
            "href=",
            "url(",
            "@import",
            "____",
        ] {
            assert!(
                !html.contains(forbidden),
                "`{forbidden}` が無いことの確認に失敗。"
            );
        }
        Ok(())
    }

    /// 使う要素と属性を、列挙したものに限ること。読み込みや実行を行う要素と属性が混ざらないようにする。
    #[test]
    fn test_html_uses_only_listed_elements_and_attributes() -> TestResult {
        const ELEMENTS: [&str; 10] = [
            "html", "head", "meta", "title", "style", "body", "h1", "p", "ul", "li",
        ];
        const ATTRIBUTES: [&str; 6] = ["lang", "charset", "http-equiv", "content", "name", "class"];

        let html = html()?;
        let mut tags = 0;
        for fragment in html.split('<').skip(1) {
            let (tag, _) = fragment
                .split_once('>')
                .ok_or("閉じていないタグがあります。")?;
            if tag == "!DOCTYPE html" {
                continue;
            }
            // 引用符の外側だけを調べる。属性の値は含めない。
            let mut words = tag
                .trim_start_matches('/')
                .split('"')
                .step_by(2)
                .flat_map(str::split_whitespace);
            let element = words.next().ok_or("要素名がありません。")?;
            assert!(
                ELEMENTS.contains(&element),
                "列挙していない要素の混入により失敗しました: {element}"
            );
            for word in words {
                let attribute = word.strip_suffix('=').unwrap_or(word);
                assert!(
                    ATTRIBUTES.contains(&attribute),
                    "列挙していない属性の混入により失敗しました: {attribute}"
                );
            }
            tags += 1;
        }
        assert!(tags > ELEMENTS.len(), "タグの走査の確認に失敗: {tags}");
        // `http-equiv` は、読み込みを禁止する指定だけに使う (画面の転送の指定などを混ぜない)。
        assert_eq!(html.matches("http-equiv=").count(), 1);
        assert!(html.contains("<meta http-equiv=\"Content-Security-Policy\" "));
        Ok(())
    }

    /// 書き込みの呼び出しごとの内容を記録する出力先。
    #[derive(Default)]
    struct Chunks(Vec<Vec<u8>>);

    impl Write for Chunks {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.0.push(buffer.to_vec());
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// コードを他の文言と連結せずに書き込むこと。連結すると、消去されないバッファにコードが残る。
    #[test]
    fn test_html_writes_code_without_concatenation() -> TestResult {
        let mut chunks = Chunks::default();
        write_html(&mut chunks, CODE)?;
        let holding_code: Vec<&Vec<u8>> = chunks
            .0
            .iter()
            .filter(|chunk| {
                chunk
                    .windows(CODE.len())
                    .any(|window| window == CODE.as_bytes())
            })
            .collect();
        assert_eq!(holding_code, [&CODE.as_bytes().to_vec()]);
        Ok(())
    }

    /// 指定した回数だけ書き込みに成功し、その後は失敗する出力先。
    struct FailingAfter(usize);

    impl Write for FailingAfter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            match self.0.checked_sub(1) {
                Some(rest) => {
                    self.0 = rest;
                    Ok(buffer.len())
                }
                None => Err(io::Error::from(io::ErrorKind::StorageFull)),
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_html_reports_every_write_failure() {
        for successes in 0..3 {
            let result = write_html(&mut FailingAfter(successes), CODE);
            assert_eq!(
                result.map_err(|error| error.kind()),
                Err(io::ErrorKind::StorageFull),
                "{successes} 回の成功の後の失敗の報告に失敗。"
            );
        }
    }
}
