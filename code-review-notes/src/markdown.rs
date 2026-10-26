//! Markdown escaping, so scanner output and other untrusted text stays inert in
//! hovers and reports.

/// Backslash-escapes Markdown control characters
pub fn md_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '(' | ')' | '<' | '>' | '#' | '|' | '!' | '~'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn longest_backtick_run(s: &str) -> usize {
    s.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// Inline code span that survives backticks in the text
pub fn inline_code(s: &str) -> String {
    let ticks = "`".repeat(longest_backtick_run(s) + 1);
    let pad = if s.starts_with('`') || s.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{ticks}{pad}{s}{pad}{ticks}")
}

/// Fence is one backtick longer than the longest run inside
pub fn fenced(code: &str) -> String {
    let ticks = "`".repeat(longest_backtick_run(code).max(2) + 1);
    format!("{ticks}\n{}\n{ticks}\n", code.trim_end_matches('\n'))
}

/// Reverses [`md_escape`]-style escapes for plain-text display
pub fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match chars.peek() {
            Some(&next) if c == '\\' && next.is_ascii_punctuation() => {
                out.push(next);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

/// How far (bytes) we look for a link's text or destination. Stops a note full
/// of `[` from making hovers slow.
const MAX_LINK_BYTES: usize = 2000;
/// link-in-link-text nesting past this is just escaped
const MAX_LINK_DEPTH: usize = 4;

/// Turns every link in `md` into plain text, for hovers. Zed opens a clicked
/// link in a hover without asking, and note text comes from the repo.
///
/// `[text](url)`, images and reference links become `text (url)`; autolinks
/// and bare urls become just the url. Urls go in code spans, which never link.
/// Link definitions are shown rather than used, other `[` and HTML tags get
/// escaped, code spans and fenced code are left alone.
pub fn defuse_links(md: &str) -> String {
    let defs = definitions(md);
    let mut out = String::with_capacity(md.len());
    let mut para = String::new();
    let mut fence: Option<(char, usize)> = None;
    let flush = |para: &mut String, out: &mut String| {
        out.push_str(&inline(para, &defs, 0));
        para.clear();
    };
    for line in md.split_inclusive('\n') {
        let t = line.trim_start_matches(' ');
        let indent = line.len() - t.len();
        let marker = t.chars().next().filter(|c| matches!(c, '`' | '~'));
        let run = marker.map_or(0, |c| t.chars().take_while(|&x| x == c).count());
        if indent <= 3 && run >= 3 {
            let c = marker.unwrap_or_default();
            match fence {
                None => {
                    flush(&mut para, &mut out);
                    fence = Some((c, run));
                }
                Some((fc, n)) if fc == c && run >= n && t[run..].trim().is_empty() => fence = None,
                Some(_) => {}
            }
            out.push_str(line);
        } else if fence.is_some() {
            out.push_str(line);
        } else if let Some((label, url)) = definition(line) {
            flush(&mut para, &mut out);
            out.push_str(&format!("\\[{}\\]: {}", md_escape(label), inline_code(url)));
            if line.ends_with('\n') {
                out.push('\n');
            }
        } else {
            para.push_str(line);
        }
    }
    flush(&mut para, &mut out);
    out
}

/// `[label]: url "title"` -> (label, url)
fn definition(line: &str) -> Option<(&str, &str)> {
    let t = line
        .strip_prefix("   ")
        .or_else(|| line.strip_prefix("  "))
        .or_else(|| line.strip_prefix(' '))
        .unwrap_or(line);
    let rest = t.strip_prefix('[')?;
    let close = rest.find("]:")?;
    let label = &rest[..close];
    if label.trim().is_empty() || label.contains(['[', ']']) {
        return None;
    }
    let url = rest[close + 2..].split_whitespace().next()?;
    let url = url
        .strip_prefix('<')
        .and_then(|u| u.strip_suffix('>'))
        .unwrap_or(url);
    Some((label, url))
}

/// case-insensitive, whitespace runs collapse to one space
fn label_key(label: &str) -> String {
    label
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn definitions(md: &str) -> std::collections::HashMap<String, String> {
    let mut defs = std::collections::HashMap::new();
    for line in md.lines() {
        if let Some((label, url)) = definition(line) {
            defs.entry(label_key(label))
                .or_insert_with(|| url.to_string());
        }
    }
    defs
}

/// End of the code span opened by the backtick run at `i`, if it closes
fn code_span_end(s: &str, i: usize) -> Option<usize> {
    let run = s[i..].bytes().take_while(|&b| b == b'`').count();
    let mut j = i + run;
    while let Some(k) = s[j..].find('`') {
        let at = j + k;
        let n = s[at..].bytes().take_while(|&b| b == b'`').count();
        if n == run {
            return Some(at + n);
        }
        j = at + n;
    }
    None
}

/// Matching `]` for the `[` at `i` (nesting included), if within reach
fn closing_bracket(s: &str, i: usize) -> Option<usize> {
    let b = s.as_bytes();
    let end = (i + MAX_LINK_BYTES).min(b.len());
    let mut depth = 0;
    let mut j = i;
    while j < end {
        match b[j] {
            b'\\' => j += 1,
            b'`' => {
                let n = s[j..].bytes().take_while(|&b| b == b'`').count();
                j = code_span_end(s, j).filter(|&e| e <= end).unwrap_or(j + n) - 1;
            }
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    return Some(j);
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// `(dest "title")` at `i` -> destination and end of the parens
fn destination(s: &str, i: usize) -> Option<(&str, usize)> {
    let b = s.as_bytes();
    let end = (i + MAX_LINK_BYTES).min(b.len());
    let mut depth = 0;
    let mut j = i;
    while j < end {
        match b[j] {
            b'\\' => j += 1,
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    let inner = s[i + 1..j].trim();
                    let dest = match inner.strip_prefix('<') {
                        Some(r) => &r[..r.find('>')?],
                        None => inner.split_whitespace().next().unwrap_or(""),
                    };
                    return Some((dest, j + 1));
                }
            }
            _ => {}
        }
        j = (j + 1).min(b.len());
    }
    None
}

/// Link starting with `[` at `i` -> text, url, end
fn link_at<'a>(
    s: &'a str,
    i: usize,
    defs: &'a std::collections::HashMap<String, String>,
) -> Option<(&'a str, &'a str, usize)> {
    let close = closing_bracket(s, i)?;
    let text = &s[i + 1..close];
    let after = &s[close + 1..];
    if after.starts_with('(') {
        let (url, end) = destination(s, close + 1)?;
        return Some((text, url, end));
    }
    if let Some(rest) = after.strip_prefix('[') {
        let r = rest.find(']').filter(|&r| r < MAX_LINK_BYTES)?;
        let label = if rest[..r].trim().is_empty() {
            text
        } else {
            &rest[..r]
        };
        let url = defs.get(&label_key(label))?;
        return Some((text, url, close + 2 + r + 1));
    }
    defs.get(&label_key(text))
        .map(|url| (text, url.as_str(), close + 1))
}

/// Autolink at `i` (`<scheme:...>` or `<user@host>`) -> url, end
fn autolink(s: &str, i: usize) -> Option<(&str, usize)> {
    let rest = &s[i + 1..];
    let close = rest.find(['>', '<', ' ', '\n', '\t'])?;
    if !rest[close..].starts_with('>') {
        return None;
    }
    let url = &rest[..close];
    let scheme = url.find(':').is_some_and(|c| {
        (2..=32).contains(&c)
            && url.starts_with(|c: char| c.is_ascii_alphabetic())
            && url[..c]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    });
    let email = url.contains('@') && !url.starts_with('@') && !url.ends_with('@');
    (scheme || email).then_some((url, i + 1 + close + 1))
}

/// Bare url at `i`, linked the way GFM would
fn bare_url(s: &str, i: usize) -> Option<usize> {
    let rest = &s[i..];
    let starts = ["http://", "https://", "ftp://", "mailto:", "www."]
        .iter()
        .any(|p| {
            rest.get(..p.len())
                .is_some_and(|h| h.eq_ignore_ascii_case(p))
        });
    if !starts
        || s[..i]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric())
    {
        return None;
    }
    let len = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '`' | '"' | '\'' | ')' | ']'))
        .unwrap_or(rest.len());
    let url = rest[..len].trim_end_matches(['.', ',', ':', ';', '!', '?', '*', '_', '~']);
    (!url.is_empty()).then_some(i + url.len())
}

fn inline(s: &str, defs: &std::collections::HashMap<String, String>, depth: usize) -> String {
    if depth > MAX_LINK_DEPTH {
        return md_escape(s);
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' if b.get(i + 1).is_some_and(u8::is_ascii_punctuation) => {
                out.push_str(&s[i..i + 2]);
                i += 2;
                continue;
            }
            b'`' => {
                let n = s[i..].bytes().take_while(|&b| b == b'`').count();
                let end = code_span_end(s, i).unwrap_or(i + n);
                out.push_str(&s[i..end]);
                i = end;
                continue;
            }
            b'[' | b'!' => {
                let at = if b[i] == b'!' { i + 1 } else { i };
                if b.get(at) == Some(&b'[')
                    && let Some((text, url, end)) = link_at(s, at, defs)
                {
                    out.push_str(&inline(text, defs, depth + 1));
                    out.push_str(&format!(" ({})", inline_code(url)));
                    i = end;
                    continue;
                }
                // Escape any leftover `[` (e.g. its `]` was out of reach) so it
                // can't start a link. `\[` renders the same.
                if b[i] == b'[' {
                    out.push_str("\\[");
                    i += 1;
                    continue;
                }
            }
            b'<' => {
                if let Some((url, end)) = autolink(s, i) {
                    out.push_str(&inline_code(url));
                    i = end;
                    continue;
                }
                if b.get(i + 1)
                    .is_some_and(|c| c.is_ascii_alphabetic() || matches!(c, b'/' | b'!' | b'?'))
                {
                    out.push_str("\\<");
                    i += 1;
                    continue;
                }
            }
            _ => {
                if let Some(end) = bare_url(s, i) {
                    out.push_str(&inline_code(&s[i..end]));
                    i = end;
                    continue;
                }
            }
        }
        let c = s[i..].chars().next().expect("i is on a char boundary");
        out.push(c);
        i += c.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping() {
        assert_eq!(md_escape("a](http://evil)"), r"a\]\(http://evil\)");
        assert_eq!(inline_code("a`b"), "``a`b``");
        assert_eq!(fenced("x\n````\ny"), "`````\nx\n````\ny\n`````\n");
    }

    #[test]
    fn unescape_reverses_escape() {
        let s = r"eval() on `x_y` \ C:\path [a](b)";
        assert_eq!(unescape(&md_escape(s)), s);
    }

    #[test]
    fn links_become_text() {
        for (md, want) in [
            ("see [docs](http://evil)", "see docs (`http://evil`)"),
            (
                r#"[a](<http://x y> "t") [b](http://y 'u')"#,
                "a (`http://x y`) b (`http://y`)",
            ),
            ("![pixel](http://evil/p.png)", "pixel (`http://evil/p.png`)"),
            ("[a [b] c](http://e)", r"a \[b] c (`http://e`)"),
            ("[[x](http://a)](http://b)", "x (`http://a`) (`http://b`)"),
            (
                "[![img](http://i)](http://l)",
                "img (`http://i`) (`http://l`)",
            ),
            ("[p](http://e/a_(b))", "p (`http://e/a_(b)`)"),
            ("<http://evil> <me@evil.com>", "`http://evil` `me@evil.com`"),
            ("go to http://evil.com.", "go to `http://evil.com`."),
            ("(www.evil.com)", "(`www.evil.com`)"),
            ("<a href=\"x\">y</a>", "\\<a href=\"x\">y\\</a>"),
            // not links
            (r"\[a\](b) [plain] a < b", r"\[a\](b) \[plain] a < b"),
            ("[open](http://e", r"\[open](`http://e`"),
            ("é [ü](http://e) é", "é ü (`http://e`) é"),
        ] {
            assert_eq!(defuse_links(md), want, "{md}");
        }
    }

    #[test]
    fn reference_links() {
        let md = "[click][1], [Here][] and [here] or [none][2]\n\n[1]: http://evil/1 \"t\"\n  [HERE]: <http://evil/h>\n";
        assert_eq!(
            defuse_links(md),
            "click (`http://evil/1`), Here (`http://evil/h`) and here (`http://evil/h`) or \\[none]\\[2]\n\n\
             \\[1\\]: `http://evil/1`\n\\[HERE\\]: `http://evil/h`\n"
        );
    }

    #[test]
    fn code_is_untouched() {
        let md = "a `[x](http://e)` b ``<http://e> ` `` c\n\n```md\n[x](http://e) <http://e>\n```\n~~~~\n```\n[y](http://e)\n~~~~\nafter [z](http://e)";
        assert_eq!(
            defuse_links(md),
            "a `[x](http://e)` b ``<http://e> ` `` c\n\n```md\n[x](http://e) <http://e>\n```\n~~~~\n```\n[y](http://e)\n~~~~\nafter z (`http://e`)"
        );
        assert_eq!(defuse_links("[`]`](http://e)"), "`]` (`http://e`)");
    }

    #[test]
    fn never_panics() {
        let alphabet = [
            '[', ']', '(', ')', '<', '>', '`', '\\', '!', 'h', 'é', ' ', '\n', ':', '@',
        ];
        let n = alphabet.len();
        for mut i in 0..n.pow(5) {
            let mut text = String::new();
            for _ in 0..5 {
                text.push(alphabet[i % n]);
                i /= n;
            }
            defuse_links(&text);
        }
        assert_eq!(defuse_links("[x]: "), r"\[x]: ");
    }

    #[test]
    fn hostile_notes_stay_fast() {
        let start = std::time::Instant::now();
        for unit in ["[", "[a](", "`a", "``a", "![", "<a", "[x][", "http://"] {
            defuse_links(&unit.repeat(64 * 1024 / unit.len()));
        }
        let deep = format!("{}x{}", "[".repeat(5000), "](http://e)".repeat(5000));
        // out of reach, so not a link; leftover brackets get escaped
        let out = defuse_links(&deep);
        assert!(!out.replace("\\[", "").contains('['), "{}", &out[..200]);
        assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
    }
}
