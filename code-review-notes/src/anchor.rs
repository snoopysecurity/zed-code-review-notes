//! Keeps notes attached to their code as the file changes. Whitespace and blank
//! lines are ignored when matching; if the exact snippet is gone we try a near match.

use std::collections::HashMap;

use crate::safety::MAX_SNIPPET_LINES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// Still at the stored lines
    Exact { start: u32, end: u32 },
    /// Found at different lines (1-based, inclusive)
    Moved { start: u32, end: u32 },
    /// Edited code close enough to the snippet. The note keeps its original
    /// snippet so the change stays visible
    Changed { start: u32, end: u32 },
    /// Snippet gone. Stored lines are kept for display
    Stale { start: u32, end: u32 },
}

impl Anchor {
    pub fn range(self) -> (u32, u32) {
        match self {
            Anchor::Exact { start, end }
            | Anchor::Moved { start, end }
            | Anchor::Changed { start, end }
            | Anchor::Stale { start, end } => (start, end),
        }
    }

    pub fn is_stale(self) -> bool {
        matches!(self, Anchor::Stale { .. })
    }

    pub fn is_changed(self) -> bool {
        matches!(self, Anchor::Changed { .. })
    }
}

fn normalized<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<String> {
    lines
        .map(|l| l.trim_start_matches('\u{feff}').trim())
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn normalize(snippet: &str) -> String {
    normalized(snippet.lines()).join("\n")
}

/// Lines `start..=end` (1-based), clamped to the file and MAX_SNIPPET_LINES,
/// newline-terminated
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

/// Nearest non-blank line on either side of the note, trimmed. Lets us tell
/// edited code from a look-alike next to it, and find code that was moved
/// *and* edited.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Context<'a> {
    pub before: Option<&'a str>,
    pub after: Option<&'a str>,
}

pub fn context(text: &str, start: u32, end: u32) -> (Option<String>, Option<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let s = (start as usize).saturating_sub(1).min(lines.len());
    let e = (end as usize).min(lines.len());
    let trimmed = |l: &&str| l.trim_start_matches('\u{feff}').trim().to_string();
    (
        lines[..s].iter().rev().map(trimmed).find(|l| !l.is_empty()),
        lines[e..].iter().map(trimmed).find(|l| !l.is_empty()),
    )
}

#[derive(Clone, Debug, PartialEq)]
pub struct Code {
    pub snippet: String,
    /// Where the snippet ends (it gets cut at the line limit)
    pub end_line: u32,
    pub context_before: Option<String>,
    pub context_after: Option<String>,
}

/// `None` if `start` is past EOF
pub fn code_at(text: &str, start: u32, end: u32) -> Option<Code> {
    let snippet = extract(text, start, end);
    if snippet.is_empty() {
        return None;
    }
    let end_line = start.max(1) + snippet.lines().count().max(1) as u32 - 1;
    let (context_before, context_after) = context(text, start, end_line);
    Some(Code {
        snippet,
        end_line,
        context_before,
        context_after,
    })
}

pub fn locate(snippet: &str, start: u32, end: u32, text: &str) -> Anchor {
    locate_in(snippet, Context::default(), start, end, text)
}

pub fn locate_in(snippet: &str, ctx: Context, start: u32, end: u32, text: &str) -> Anchor {
    let wanted = normalized(snippet.lines());
    if wanted.is_empty() {
        return Anchor::Exact { start, end };
    }
    let s = (start as usize).saturating_sub(1);
    // fast path: still in place, only scan up to the note's end
    let here: Vec<&str> = text
        .lines()
        .skip(s)
        .take((end as usize).saturating_sub(s))
        .collect();
    if !here.is_empty() && normalized(here.iter().copied()) == wanted {
        return Anchor::Exact { start, end };
    }

    let lines: Vec<&str> = text.lines().collect();
    let matches: Vec<(usize, usize)> = (0..lines.len())
        .filter_map(|i| match_at(&lines, i, &wanted).map(|j| (i, j)))
        .collect();
    // several identical copies, nearest to the old position wins
    let moved = matches.iter().min_by_key(|(i, _)| i.abs_diff(s)).copied();
    // Without context there's no telling edited code from a look-alike beside
    // it, so only notes with context get the fuzzy search. Also skipped when an
    // exact copy is about as close as an edit could be
    let slack = (wanted.len() / 4).max(2);
    let has_context = ctx.before.is_some() || ctx.after.is_some();
    let edited = (has_context && moved.is_none_or(|(i, _)| i.abs_diff(s) > slack))
        .then(|| near_match(&wanted, ctx, &lines, s))
        .flatten();
    // edited in place beats an untouched copy further away
    match (moved, edited) {
        (Some((i, _)), Some((e, f))) if e.abs_diff(s) < i.abs_diff(s) => Anchor::Changed {
            start: e as u32 + 1,
            end: f as u32 + 1,
        },
        (Some((i, j)), _) => Anchor::Moved {
            start: i as u32 + 1,
            end: j as u32 + 1,
        },
        (None, Some((e, f))) => Anchor::Changed {
            start: e as u32 + 1,
            end: f as u32 + 1,
        },
        (None, None) => Anchor::Stale { start, end },
    }
}

/// Share of the snippet (token-weighted) that has to survive for code to
/// count as an edit of it
const MIN_SIMILARITY: f64 = 0.8;
/// Below this two lines don't pair at all
const MIN_LINE_SIMILARITY: f64 = 0.5;
/// Past this many lines only identical lines pair. Keeps each keystroke cheap
const MAX_TOKEN_COMPARED_LINES: usize = 40;

/// identifier runs plus single punctuation chars
fn tokens(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut word: Option<usize> = None;
    for (i, c) in line.char_indices() {
        if c.is_alphanumeric() || c == '_' {
            word.get_or_insert(i);
            continue;
        }
        if let Some(w) = word.take() {
            out.push(&line[w..i]);
        }
        if !c.is_whitespace() {
            out.push(&line[i..i + c.len_utf8()]);
        }
    }
    if let Some(w) = word {
        out.push(&line[w..]);
    }
    out
}

/// Dice coefficient over token multisets
fn token_similarity(a: &[&str], b: &[&str]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<&str, i32> = HashMap::new();
    for t in a {
        *counts.entry(t).or_default() += 1;
    }
    let mut common = 0;
    for t in b {
        if let Some(n) = counts.get_mut(t)
            && *n > 0
        {
            *n -= 1;
            common += 1;
        }
    }
    2.0 * common as f64 / (a.len() + b.len()) as f64
}

/// Context lines this alike still count as the same line, roughly one token
/// in ten changed. `fn a() {` vs `fn b() {` is only 0.8.
const MIN_CONTEXT_SIMILARITY: f64 = 0.9;
/// Context lines with fewer tokens (`}`, `end`) are too common to search the
/// whole file by
const MIN_DISTINCTIVE_TOKENS: usize = 3;
/// Max far-away positions to try
const MAX_FAR_CANDIDATES: usize = 16;

fn code_lines<'a>(lines: &[&'a str]) -> Vec<(usize, &'a str)> {
    lines
        .iter()
        .enumerate()
        .map(|(i, l)| (i, l.trim_start_matches('\u{feff}').trim()))
        .filter(|(_, l)| !l.is_empty())
        .collect()
}

/// Look for an edited copy of `wanted` (normalized lines) and return 0-based
/// inclusive line indices. Tries around line `near` first, then wherever the
/// note's context points.
///
/// Token similarity alone can't tell similar code from the same code:
/// `if (!authorized)` scores 0.93 against `if (authorized)`. A match also needs
/// the note's context lines (when recorded) on either side, give or take a
/// couple of lines. Away from the original position a wrong match is easier,
/// which is why the context line there must be distinctive and match exactly.
fn near_match(
    wanted: &[String],
    ctx: Context,
    lines: &[&str],
    near: usize,
) -> Option<(usize, usize)> {
    let code = code_lines(lines);
    let k = wanted.len();
    let slack = (k / 4).max(2); // as in `locate_in`
    let origin = code.partition_point(|&(i, _)| i < near);
    let aligner = Aligner::new(wanted, ctx);
    let found = |center: usize| aligner.align(&code, center, slack);
    let to_lines = |(_, first, last): (f64, usize, usize)| (code[first].0, code[last].0);

    if let Some(m) = found(origin) {
        return Some(to_lines(m));
    }

    // Not near the old spot. Try wherever a distinctive context line ended up
    let distinctive =
        |c: Option<&str>| c.is_some_and(|c| tokens(c).len() >= MIN_DISTINCTIVE_TOKENS);
    if !(distinctive(ctx.before) || distinctive(ctx.after)) {
        return None;
    }
    let mut centers: Vec<usize> = Vec::new();
    for (p, (_, l)) in code.iter().enumerate() {
        if ctx.before == Some(*l) {
            centers.push(p + 1);
        }
        if ctx.after == Some(*l) {
            centers.push(p.saturating_sub(k));
        }
    }
    centers.sort_by_key(|&c| (c.abs_diff(origin), c));
    let mut tried: Vec<usize> = Vec::new();
    let mut best: Option<(f64, usize, usize)> = None;
    for c in centers {
        if tried.len() >= MAX_FAR_CANDIDATES {
            break;
        }
        if c.abs_diff(origin) <= slack || tried.iter().any(|t| t.abs_diff(c) <= slack) {
            continue;
        }
        tried.push(c);
        // nearest first; later candidates have to strictly beat it
        if let Some(m) = found(c)
            && best.is_none_or(|(s, _, _)| m.0 > s + 1e-9)
        {
            best = Some(m);
        }
    }
    best.map(to_lines)
}

#[derive(Clone, Copy, PartialEq)]
enum Row {
    Context,
    Snippet,
}

/// Aligns the snippet plus its context rows against a window of non-blank
/// lines. Each pair scores similarity times the row's token count, which makes
/// a changed `}` cost less than a changed call. Context rows only pair with
/// near-identical lines and all of them must pair (code has to sit between its
/// neighbours).
struct Aligner<'a> {
    rows: Vec<(Row, &'a str, Vec<&'a str>, f64)>,
    snippet_lines: usize,
    snippet_weight: f64,
}

impl<'a> Aligner<'a> {
    fn new(wanted: &'a [String], ctx: Context<'a>) -> Self {
        let row = |kind, text: &'a str| {
            let t = tokens(text);
            let w = t.len().max(1) as f64;
            (kind, text, t, w)
        };
        let rows: Vec<_> = ctx
            .before
            .map(|b| row(Row::Context, b))
            .into_iter()
            .chain(wanted.iter().map(|w| row(Row::Snippet, w.as_str())))
            .chain(ctx.after.map(|a| row(Row::Context, a)))
            .collect();
        let snippet_weight = rows
            .iter()
            .filter(|r| r.0 == Row::Snippet)
            .map(|r| r.3)
            .sum();
        Aligner {
            rows,
            snippet_lines: wanted.len(),
            snippet_weight,
        }
    }

    /// Best alignment around non-blank line `center`, where the snippet should
    /// start. Gives (score, first, last) as indices into `code`. None unless every
    /// context row pairs and the score reaches [`MIN_SIMILARITY`].
    fn align(
        &self,
        code: &[(usize, &str)],
        center: usize,
        slack: usize,
    ) -> Option<(f64, usize, usize)> {
        let k = self.rows.len();
        let contexts = k - self.snippet_lines;
        let lo = center.saturating_sub(slack + contexts);
        let hi = (center + self.snippet_lines + slack + contexts).min(code.len());
        if lo >= hi {
            return None;
        }
        let window = &code[lo..hi];
        let compare_tokens = self.snippet_lines <= MAX_TOKEN_COMPARED_LINES;
        let window_tokens: Vec<Vec<&str>> = window.iter().map(|(_, l)| tokens(l)).collect();
        let similarity = |j: usize, q: usize| -> f64 {
            let (kind, text, toks, _) = &self.rows[j];
            if *text == window[q].1 {
                return 1.0;
            }
            let (compare, min) = match kind {
                Row::Context => (true, MIN_CONTEXT_SIMILARITY),
                Row::Snippet => (compare_tokens, MIN_LINE_SIMILARITY),
            };
            if !compare {
                return 0.0;
            }
            let s = token_similarity(toks, &window_tokens[q]);
            if s >= min { s } else { 0.0 }
        };

        // dp[j][q]: best score aligning rows[..j] with window[..q].
        let m = window.len();
        let mut dp = vec![vec![0.0f64; m + 1]; k + 1];
        for j in 1..=k {
            for q in 1..=m {
                let mut v = dp[j - 1][q].max(dp[j][q - 1]);
                let sim = similarity(j - 1, q - 1);
                if sim > 0.0 {
                    v = v.max(dp[j - 1][q - 1] + self.rows[j - 1].3 * sim);
                }
                dp[j][q] = v;
            }
        }
        // walk back; only snippet rows count toward the score
        let (mut j, mut q) = (k, m);
        let (mut first, mut last) = (None, None);
        let mut score = 0.0;
        let mut contexts_paired = 0;
        while j > 0 && q > 0 {
            if dp[j][q] == dp[j - 1][q] {
                j -= 1;
            } else if dp[j][q] == dp[j][q - 1] {
                q -= 1;
            } else {
                let (kind, _, _, weight) = self.rows[j - 1];
                match kind {
                    Row::Context => contexts_paired += 1,
                    Row::Snippet => {
                        score += weight * similarity(j - 1, q - 1);
                        last.get_or_insert(lo + q - 1);
                        first = Some(lo + q - 1);
                    }
                }
                j -= 1;
                q -= 1;
            }
        }
        let score = score / self.snippet_weight;
        (contexts_paired == contexts && score >= MIN_SIMILARITY).then_some((score, first?, last?))
    }
}

/// Exact trimmed match starting at line `i`. Returns the index of the last line
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

/// Stable id for an imported finding, makes re-importing a report a no-op.
/// `occurrence` separates the same rule firing on identical code twice in one
/// file (0 = first, by line). 0 hashes the same as before it existed.
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
    fn follows_an_edited_line() {
        let edited = "class A\n  def show\n    User.find_by_sql(query)\n  end\nend\n";
        assert_eq!(
            relocate(FILE, 3, 3, edited),
            Anchor::Changed { start: 3, end: 3 }
        );
        // plus a line or two added above
        let shifted = format!("# a\n# b\n{edited}");
        assert_eq!(
            relocate(FILE, 3, 3, &shifted),
            Anchor::Changed { start: 5, end: 5 }
        );
        // moved far and edited, neighbours too plain to search by
        // (`def show`, `end`)
        let moved = format!("{}{edited}", "# pad\n".repeat(30));
        assert!(relocate(FILE, 3, 3, &moved).is_stale());
        // no recorded neighbours -> never treated as edited
        assert!(locate(&extract(FILE, 3, 3), 3, 3, edited).is_stale());
    }

    #[test]
    fn edited_in_place_beats_a_distant_copy() {
        let line = "    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n";
        let text = format!("a()\n{line}{}{line}", "pad()\n".repeat(300));
        let edited = text.replacen("{user_id}", "{uid}", 1);
        assert_eq!(
            relocate(&text, 2, 2, &edited),
            Anchor::Changed { start: 2, end: 2 }
        );
        // ...but a closer exact copy means it moved
        assert_eq!(
            relocate(&text, 2, 2, &text.replacen(line, "", 1)),
            Anchor::Moved {
                start: 302,
                end: 302
            }
        );
    }

    #[test]
    fn deleted_check_does_not_jump_to_its_opposite() {
        let text = "fn a() {\n  if (!authorized) return;\n  run();\n}\n\nfn b() {\n  log();\n  if (authorized) return;\n}\n";
        let gone = text.replace("  if (!authorized) return;\n", "");
        assert!(relocate(text, 2, 2, &gone).is_stale());
    }

    #[test]
    fn follows_an_edited_block() {
        let text = "import db\n\ndef show(user_id):\n    cursor = db.cursor()\n    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n    return cursor.fetchone()\n\nmain()\n";
        let edited = "import db\nimport x\n\ndef show(uid):\n    cursor = db.cursor()\n    log(uid)\n    cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")\n    return cursor.fetchone()\n\nmain()\n";
        assert_eq!(
            relocate(text, 3, 6, edited),
            Anchor::Changed { start: 4, end: 8 }
        );
    }

    #[test]
    fn rewritten_code_is_stale() {
        let edited = "class A\n  def show\n    User.where(id: params[:id]).first\n  end\nend\n";
        assert!(relocate(FILE, 3, 3, edited).is_stale());
    }

    #[test]
    fn deleted_line_does_not_jump_to_its_fixed_twin() {
        let snip = "    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n";
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/demo-app/app/users.py"
        ))
        .unwrap();
        assert_eq!(
            locate(snip, 9, 9, &text),
            Anchor::Exact { start: 9, end: 9 }
        );
        let gone = text.replace(snip, "");
        assert!(locate(snip, 9, 9, &gone).is_stale());
    }

    fn users_py() -> String {
        std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../fixtures/demo-app/app/users.py"
        ))
        .unwrap()
    }

    fn relocate(text: &str, start: u32, end: u32, now: &str) -> Anchor {
        let (before, after) = context(text, start, end);
        let ctx = Context {
            before: before.as_deref(),
            after: after.as_deref(),
        };
        locate_in(&extract(text, start, end), ctx, start, end, now)
    }

    #[test]
    fn context_lines() {
        let text = "a\n\n  b\nc\n\n d \n";
        assert_eq!(context(text, 3, 4), (Some("a".into()), Some("d".into())));
        assert_eq!(context(text, 1, 1), (None, Some("b".into())));
        assert_eq!(context(text, 6, 6), (Some("c".into()), None));
    }

    #[test]
    fn deleted_line_does_not_jump_to_the_adjacent_twin() {
        let text = "  check();\n  if (!authorized) return;\n  if (authorized) return;\n  run();\n";
        let gone = text.replace("  if (!authorized) return;\n", "");
        assert!(relocate(text, 2, 2, &gone).is_stale());
        let edited = text.replace("(!authorized)", "(!is_authorized)");
        assert_eq!(
            relocate(text, 2, 2, &edited),
            Anchor::Changed { start: 2, end: 2 }
        );
    }

    #[test]
    fn follows_code_moved_and_edited() {
        let text = users_py();
        let moved = format!("{}{text}", "# pad\n".repeat(30)).replace("{user_id}", "{uid}");
        assert_eq!(
            relocate(&text, 9, 9, &moved),
            Anchor::Changed { start: 39, end: 39 }
        );
        // no context, no match
        assert!(locate(&extract(&text, 9, 9), 9, 9, &moved).is_stale());
    }

    #[test]
    fn moved_and_deleted_does_not_find_its_fixed_twin() {
        // safe_show has the same neighbours around a parameterised query
        let text = users_py();
        let moved = format!("{}{text}", "# pad\n".repeat(30)).replace(
            "    cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n",
            "",
        );
        assert!(relocate(&text, 9, 9, &moved).is_stale());
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
