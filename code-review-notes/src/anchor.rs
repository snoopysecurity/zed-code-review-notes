//! Keeping notes attached to their code as the file changes.
//!
//! A note stores the snippet it was made on. When the file is edited, we look
//! for that snippet again, comparing lines with surrounding whitespace removed
//! and blank lines ignored, so re-indenting does not break a note.

use crate::safety::MAX_SNIPPET_LINES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// The snippet is still at the stored lines.
    Exact { start: u32, end: u32 },
    /// The snippet was found at different lines (1-based, inclusive).
    Moved { start: u32, end: u32 },
    /// The snippet is gone; the stored lines are kept for display.
    Stale { start: u32, end: u32 },
}

impl Anchor {
    pub fn range(self) -> (u32, u32) {
        match self {
            Anchor::Exact { start, end }
            | Anchor::Moved { start, end }
            | Anchor::Stale { start, end } => (start, end),
        }
    }

    pub fn is_stale(self) -> bool {
        matches!(self, Anchor::Stale { .. })
    }
}

fn normalized(lines: &[&str]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.trim_start_matches('\u{feff}').trim())
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

/// Normalized form of a snippet, used for fingerprints.
pub fn normalize(snippet: &str) -> String {
    normalized(&snippet.lines().collect::<Vec<_>>()).join("\n")
}

/// Lines `start..=end` (1-based) of `text`, clamped to the file and to the
/// snippet line limit, with a trailing newline.
pub fn extract(text: &str, start: u32, end: u32) -> String {
    let start = start.max(1) as usize;
    let end = (end as usize).min(start + MAX_SNIPPET_LINES - 1);
    let mut out: String = text
        .lines()
        .skip(start - 1)
        .take((end + 1).saturating_sub(start))
        .collect::<Vec<_>>()
        .join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

pub fn locate(snippet: &str, start: u32, end: u32, text: &str) -> Anchor {
    let wanted = normalized(&snippet.lines().collect::<Vec<_>>());
    if wanted.is_empty() {
        return Anchor::Exact { start, end };
    }
    let s = (start as usize).saturating_sub(1);
    // The common case, code still in place, only reads up to the note's end.
    let here: Vec<&str> = text
        .lines()
        .skip(s)
        .take((end as usize).saturating_sub(s))
        .collect();
    if !here.is_empty() && normalized(&here) == wanted {
        return Anchor::Exact { start, end };
    }

    let lines: Vec<&str> = text.lines().collect();
    let matches: Vec<(usize, usize)> = (0..lines.len())
        .filter_map(|i| match_at(&lines, i, &wanted).map(|j| (i, j)))
        .collect();
    // Several identical snippets: take the one nearest to where the note was.
    match matches.iter().min_by_key(|(i, _)| i.abs_diff(s)) {
        Some(&(i, j)) => Anchor::Moved {
            start: i as u32 + 1,
            end: j as u32 + 1,
        },
        None => Anchor::Stale { start, end },
    }
}

/// If the snippet starts at line `i`, return the index of its last line.
fn match_at(lines: &[&str], i: usize, wanted: &[String]) -> Option<usize> {
    if lines[i].trim() != wanted[0] {
        return None;
    }
    let mut k = 1;
    let mut j = i;
    while k < wanted.len() {
        j += 1;
        let line = lines.get(j)?.trim();
        if line.is_empty() {
            continue;
        }
        if line != wanted[k] {
            return None;
        }
        k += 1;
    }
    Some(j)
}

/// Identity of an imported finding, so importing the same report twice is a no-op.
/// `occurrence` tells apart the same rule firing on identical code more than
/// once in a file (0 for the first, in line order); 0 hashes as it always has.
pub fn fingerprint(file: &str, rule: &str, snippet: &str, occurrence: usize) -> String {
    let mut h = blake3::Hasher::new();
    h.update(file.as_bytes());
    h.update(b"\0");
    h.update(rule.as_bytes());
    h.update(b"\0");
    h.update(normalize(snippet).as_bytes());
    if occurrence > 0 {
        h.update(format!("\0{occurrence}").as_bytes());
    }
    h.finalize().to_hex()[..32].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "class A\n  def show\n    User.find_by_sql(q)\n  end\nend\n";

    #[test]
    fn exact_when_unchanged() {
        let snip = extract(FILE, 2, 4);
        assert_eq!(
            locate(&snip, 2, 4, FILE),
            Anchor::Exact { start: 2, end: 4 }
        );
    }

    #[test]
    fn follows_code_moved_by_40_lines() {
        let snip = extract(FILE, 2, 4);
        let moved = format!("{}{FILE}", "# pad\n".repeat(40));
        assert_eq!(
            locate(&snip, 2, 4, &moved),
            Anchor::Moved { start: 42, end: 44 }
        );
    }

    #[test]
    fn survives_reindent_and_blank_lines() {
        let snip = extract(FILE, 2, 4);
        let edited = "module M\nclass A\n\n      def show\n\n        User.find_by_sql(q)\n      end\nend\nend\n";
        assert_eq!(
            locate(&snip, 2, 4, edited),
            Anchor::Moved { start: 4, end: 7 }
        );
    }

    #[test]
    fn stale_when_deleted() {
        let snip = extract(FILE, 2, 4);
        assert_eq!(
            locate(&snip, 2, 4, "class A\nend\n"),
            Anchor::Stale { start: 2, end: 4 }
        );
    }

    #[test]
    fn nearest_of_duplicates() {
        let text = "x()\nfoo\n\n\n\n\n\nx()\n";
        assert_eq!(
            locate("x()", 7, 7, text),
            Anchor::Moved { start: 8, end: 8 }
        );
        assert_eq!(
            locate("x()", 2, 2, text),
            Anchor::Moved { start: 1, end: 1 }
        );
    }

    #[test]
    fn fingerprint_ignores_indentation() {
        assert_eq!(
            fingerprint("a.rb", "r", "  foo\n    bar\n", 0),
            fingerprint("a.rb", "r", "foo\nbar", 0)
        );
        assert_ne!(
            fingerprint("a.rb", "r", "foo", 0),
            fingerprint("b.rb", "r", "foo", 0)
        );
    }
}
