//! Escaping text for Markdown, so scanner output and other untrusted text
//! stays inert in hovers and reports.

/// Backslash-escape Markdown control characters so scanner text stays inert.
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

/// Inline code span that survives backticks inside the text.
pub fn inline_code(s: &str) -> String {
    let ticks = "`".repeat(longest_backtick_run(s) + 1);
    let pad = if s.starts_with('`') || s.ends_with('`') {
        " "
    } else {
        ""
    };
    format!("{ticks}{pad}{s}{pad}{ticks}")
}

/// Fenced block whose fence is one backtick longer than any run inside it.
pub fn fenced(code: &str) -> String {
    let ticks = "`".repeat(longest_backtick_run(code).max(2) + 1);
    format!("{ticks}\n{}\n{ticks}\n", code.trim_end_matches('\n'))
}

/// Undo [`md_escape`]-style backslash escapes, for places that show plain text.
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
}
