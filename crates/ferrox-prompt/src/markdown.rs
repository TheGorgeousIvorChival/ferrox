//! The grammar of `prompts.md`, and the types the rest of the crate works on.
//!
//! # Parsing is the contract
//!
//! The Markdown is the only place prompt prose lives, which means the parse is
//! the whole interface: a field spelled the wrong way is a prompt that renders
//! with a hole in it, and a silently ignored field is a contributor who edits
//! it for weeks. So this parser is deliberately unforgiving about the shape and
//! deliberately quiet about the prose:
//!
//! - Every structural problem is a [`Diagnostic`] with a line number, and the
//!   parser collects them all rather than stopping at the first. Fixing a
//!   library one message per run is how a library stops being maintained.
//! - An unrecognised field is a warning, never silence, so a typo like
//!   `**Levrage:** 4` is reported instead of quietly reading as 1.
//! - A section that looks like a prompt but does not parse as one is a warning
//!   too. `## Prompt 3` is a heading these two projects' Markdown libraries
//!   accept, and it means nothing here; importing one of those libraries
//!   without converting it should produce a message, not a smaller roadmap.
//! - Prose inside a body is never inspected. The tool has no opinion about what
//!   a prompt should say, only about whether it could be said at all.
//!
//! # What is deliberately not flexible
//!
//! A prompt section holds exactly one fenced block. The two prompt renderers
//! this replaces each picked one of two blocks in that situation — "first" and
//! "last" — which means for those libraries the same file could render two
//! different prompts depending on which tool rendered it. Guessing is how a
//! roadmap ends up executing a prompt nobody read. A second block is an error
//! with a line number; add-ons are the extension mechanism.

use std::fmt;
use std::path::{Path, PathBuf};

/// How much a diagnostic should stop you.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Renders and advises anyway.
    Warning,
    /// Blocks rendering, and `check` exits non-zero.
    Error,
}

/// One thing wrong with the library, located in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// `Warning` or `Error`.
    pub severity: Severity,
    /// 1-based line in the library, or 0 when the problem is the file as a whole.
    pub line: usize,
    /// What is wrong, and what to do about it where that is knowable.
    pub message: String,
}

impl Diagnostic {
    /// A problem that blocks rendering.
    pub fn error(line: usize, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Error,
            line,
            message: message.into(),
        }
    }

    /// A problem that is worth reporting but not worth stopping for.
    pub fn warning(line: usize, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "line {}: {}", self.line, self.message)
        }
    }
}

/// Where a prompt is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Open and not started. The only status the advisor picks from.
    Todo,
    /// Open and started. Not picked by ranking, because a half-finished slice
    /// needs finishing before a new one starts, not alongside it.
    Doing,
    /// Finished. Unblocks whatever depends on it.
    Done,
    /// Open and waiting on something that is not a prompt — a decision, an
    /// external dependency, a person.
    Blocked,
}

impl Status {
    /// Every spelling accepted in `**Status:**`, for error messages.
    pub const NAMES: &'static [&'static str] = &["todo", "doing", "done", "blocked"];

    /// Parse a status, or `None` if the spelling is not one of [`Status::NAMES`].
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "todo" => Some(Self::Todo),
            "doing" => Some(Self::Doing),
            "done" => Some(Self::Done),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }

    /// The spelling used in the library.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Todo => "todo",
            Self::Doing => "doing",
            Self::Done => "done",
            Self::Blocked => "blocked",
        }
    }

    /// Whether this prompt still wants attention.
    ///
    /// `Blocked` counts, because a prompt waiting on an external decision is
    /// not finished and listing it as open is the honest description.
    pub fn is_open(self) -> bool {
        !matches!(self, Self::Done)
    }
}

/// How much work a prompt is.
///
/// Ordered smallest-first, because that ordering is the advisor's tie-break: at
/// equal leverage the smaller slice is offered, on the grounds that a finished
/// small slice unblocks more of the roadmap than a started large one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Effort {
    /// Hours.
    Small,
    /// A day or two.
    Medium,
    /// Longer than a sitting, and therefore worth splitting before starting.
    Large,
}

impl Effort {
    /// Every spelling accepted in `**Effort:**`, for error messages.
    pub const NAMES: &'static [&'static str] = &["small", "medium", "large"];

    /// Parse an effort, or `None` if the spelling is not one of [`Effort::NAMES`].
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "small" => Some(Self::Small),
            "medium" => Some(Self::Medium),
            "large" => Some(Self::Large),
            _ => None,
        }
    }

    /// The spelling used in the library.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Small => "small",
            Self::Medium => "medium",
            Self::Large => "large",
        }
    }
}

/// An extra instruction that extends one prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addon {
    /// The name as written in the library.
    pub title: String,
    /// The name as typed on the command line: lowercase, `-` between words.
    pub slug: String,
    /// One line of instruction.
    pub body: String,
}

impl Addon {
    /// `title (body)` for a listing.
    pub fn describe(&self) -> String {
        format!("{}: {}", self.slug, self.body)
    }
}

/// A file a prompt edits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Touch {
    /// A file that must exist. `check` fails when it does not.
    Existing(String),
    /// A file this prompt creates, written `+path`. `check` fails when it
    /// already exists, because a prompt that says it will create a file that is
    /// already there is describing work that is either done or misfiled.
    Created(String),
}

impl Touch {
    /// The path, without the `+`.
    pub fn path(&self) -> &str {
        match self {
            Self::Existing(path) | Self::Created(path) => path,
        }
    }

    /// Whether this prompt claims the file.
    pub fn claims_existing_file(&self) -> bool {
        matches!(self, Self::Existing(_))
    }
}

/// One `{name}` or `{name=default}` in a prompt body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placeholder {
    /// The name given on the command line.
    pub name: String,
    /// The default written in the library, if any. `None` means the value is a
    /// decision this tool refuses to make.
    pub default: Option<String>,
}

/// One prompt: a slice of work, and the conditions under which it is done.
#[derive(Debug, Clone)]
pub struct Prompt {
    /// The number in the heading. Stable, and never renumbered: other prompts
    /// cite it in `**Depends on:**`, so renumbering breaks the graph.
    pub id: u32,
    /// The title after the number.
    pub title: String,
    /// The situation that calls for this prompt.
    pub when_to_use: String,
    /// Where it is in its life.
    pub status: Status,
    /// How much it moves the rest of the roadmap, 1-5.
    pub leverage: u8,
    /// How much work it is.
    pub effort: Effort,
    /// The checks that must pass, printed verbatim.
    pub gates: Vec<String>,
    /// Prompts that must be `done` first.
    pub depends_on: Vec<u32>,
    /// Files it edits.
    pub touches: Vec<Touch>,
    /// Its weight in `--rotate` draws. Zero excludes it.
    pub random_weight: u32,
    /// A rule that applies to this prompt alone, layered under the shared one.
    pub protocol: String,
    /// The prompt itself, placeholders intact.
    pub body: String,
    /// Extra instructions, in library order.
    pub addons: Vec<Addon>,
    /// Placeholders in the body and add-ons, in first-appearance order.
    pub placeholders: Vec<Placeholder>,
    /// Line of the heading, for messages.
    pub line: usize,
}

impl Prompt {
    /// Whether the advisor may offer this prompt.
    pub fn is_open(&self) -> bool {
        self.status.is_open()
    }

    /// The add-on with this slug.
    pub fn addon(&self, slug: &str) -> Option<&Addon> {
        self.addons.iter().find(|addon| addon.slug == slug)
    }

    /// Placeholders with no default: the values only a contributor can supply.
    pub fn required_inputs(&self) -> impl Iterator<Item = &str> {
        self.placeholders
            .iter()
            .filter(|placeholder| placeholder.default.is_none())
            .map(|placeholder| placeholder.name.as_str())
    }

    /// Every prompt that names `id` in its `**Depends on:**`.
    pub fn blocks<'a>(&'a self, library: &'a Library) -> impl Iterator<Item = &'a Prompt> {
        library
            .prompts
            .iter()
            .filter(move |other| other.depends_on.contains(&self.id) && other.is_open())
    }

    /// Existing files this prompt claims.
    pub fn existing_paths(&self) -> impl Iterator<Item = &str> {
        self.touches
            .iter()
            .filter(|touch| touch.claims_existing_file())
            .map(Touch::path)
    }
}

/// The whole library: the shared protocol, the roadmap, and its complaints.
#[derive(Debug)]
pub struct Library {
    /// The file it came from, for every message it prints.
    pub path: PathBuf,
    /// The text it was parsed from, so the tag can name exactly this version.
    pub source: String,
    /// Prepended to every rendered prompt.
    pub shared_protocol: String,
    /// Every prompt, in library order.
    pub prompts: Vec<Prompt>,
    /// Everything wrong with the library, in the order it was found.
    pub diagnostics: Vec<Diagnostic>,
}

impl Library {
    /// Parse a library from Markdown.
    ///
    /// Infallible by design: a malformed field is a [`Diagnostic`] against a
    /// prompt that still exists, because a parser that throws away the library
    /// on the first typo cannot tell you about the second typo.
    pub fn parse(path: &Path, text: &str) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let mut diagnostics = Vec::new();
        let mut shared_protocol = String::new();
        let mut shared_line = None;
        let mut prompts: Vec<Prompt> = Vec::new();

        let mut index = 0;
        while index < lines.len() {
            let Some(heading) = heading_body(lines[index]) else {
                index += 1;
                continue;
            };
            let line = index + 1;
            let end = next_heading(&lines, index + 1);
            let section = &lines[index + 1..end];

            if is_shared_protocol(heading) {
                if shared_line.is_none() {
                    shared_protocol =
                        single_fenced_block(section, line, "shared protocol", &mut diagnostics);
                    shared_line = Some(line);
                } else {
                    diagnostics.push(Diagnostic::error(
                        line,
                        "the shared protocol is declared twice; keep one so the order of what is prepended is unambiguous",
                    ));
                }
            } else if let Some((id, title)) = prompt_id(heading) {
                if let Some(previous) = prompts.iter().find(|prompt| prompt.id == id) {
                    diagnostics.push(Diagnostic::error(
                        line,
                        format!(
                            "P{id} is declared twice (also at line {}); ids are how other prompts \
                             refer to each other, so they must be unique",
                            previous.line
                        ),
                    ));
                }
                prompts.push(parse_prompt(id, title, line, section, &mut diagnostics));
            } else if looks_like_a_prompt(heading) {
                diagnostics.push(Diagnostic::warning(
                    line,
                    format!(
                        "`## {heading}` was not read. A prompt heading is `## P<n> · <title>` — \
                         `## Prompt 3` and `## P three` are accepted by other prompt libraries \
                         and mean nothing here"
                    ),
                ));
            }
            index = end;
        }

        if shared_protocol.is_empty() && shared_line.is_none() {
            diagnostics.push(Diagnostic::error(
                0,
                "no `## Shared protocol` section; every rendered prompt starts with it",
            ));
        }
        if prompts.is_empty() {
            diagnostics.push(Diagnostic::error(0, "no prompts found"));
        }
        if let Some(protocol_line) = placeholders_in(&shared_protocol).first() {
            diagnostics.push(Diagnostic::warning(
                shared_line.unwrap_or(0),
                format!(
                    "the shared protocol holds a placeholder `{{{protocol_line}}}`, and it is \
                     prepended verbatim to every prompt, so no `--set` can reliably reach it"
                ),
            ));
        }

        let mut library = Self {
            path: path.to_path_buf(),
            source: text.to_owned(),
            shared_protocol,
            prompts,
            diagnostics,
        };
        let whole_library = library.check_references();
        library.diagnostics.extend(whole_library);
        library
    }

    /// The prompt with this id.
    pub fn prompt(&self, id: u32) -> Option<&Prompt> {
        self.prompts.iter().find(|prompt| prompt.id == id)
    }

    /// Errors, in library order.
    pub fn errors(&self) -> impl Iterator<Item = &Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Error)
    }

    /// Whether anything blocks rendering.
    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }

    /// A tag naming the exact library text, for the provenance footer.
    pub fn tag(&self) -> String {
        crate::library_tag(&self.source)
    }

    /// Checks that need the whole library rather than one section: dependencies
    /// that name nothing, and dependency cycles.
    ///
    /// Returns rather than appending, because the library is still being built
    /// when these run and a half-built one cannot be mutated in place.
    fn check_references(&self) -> Vec<Diagnostic> {
        let mut findings = Vec::new();
        let ids: Vec<u32> = self.prompts.iter().map(|prompt| prompt.id).collect();
        for prompt in &self.prompts {
            for dependency in &prompt.depends_on {
                if !ids.contains(dependency) {
                    findings.push(Diagnostic::error(
                        prompt.line,
                        format!(
                            "**Depends on:** names P{dependency}, which is not in this library; \
                             a dependency on nothing is a slice that never becomes ready"
                        ),
                    ));
                }
                if *dependency == prompt.id {
                    findings.push(Diagnostic::error(
                        prompt.line,
                        format!(
                            "P{} depends on itself, so it can never become ready",
                            prompt.id
                        ),
                    ));
                }
            }
        }

        // A cycle makes every prompt in it permanently unready, and the advisor
        // would report that as "waiting on P4" forever without saying why. The
        // whole cycle is named, not just the node that closed it, because "P1
        // depends on P1" is not enough to find the edit.
        let mut path = Vec::new();
        let mut done = vec![false; self.prompts.len()];
        let cycle =
            (0..self.prompts.len()).find_map(|start| self.find_cycle(start, &mut path, &mut done));
        if let Some(cycle) = cycle {
            let mut names: Vec<String> = cycle
                .iter()
                .map(|&index| format!("P{}", self.prompts[index].id))
                .collect();
            names.push(names[0].clone());
            findings.push(Diagnostic::error(
                self.prompts[cycle[0]].line,
                format!(
                    "the dependency graph has a cycle ({}), so none of these ever becomes ready",
                    names.join(" -> ")
                ),
            ));
        }
        findings
    }

    /// Depth-first search over prompt indices, carrying the path so a cycle can
    /// be reported as a path. `done` skips nodes already explored, so a wide
    /// diamond of dependencies does not turn the search exponential.
    fn find_cycle(
        &self,
        at: usize,
        path: &mut Vec<usize>,
        done: &mut [bool],
    ) -> Option<Vec<usize>> {
        if done[at] {
            return None;
        }
        if let Some(start) = path.iter().position(|&node| node == at) {
            return Some(path[start..].to_vec());
        }
        path.push(at);
        for dependency in &self.prompts[at].depends_on {
            let Some(next) = self
                .prompts
                .iter()
                .position(|prompt| prompt.id == *dependency)
            else {
                continue;
            };
            if let Some(found) = self.find_cycle(next, path, done) {
                return Some(found);
            }
        }
        path.pop();
        done[at] = true;
        None
    }
}

/// One `## ` heading's text, without the marker.
fn heading_body(line: &str) -> Option<&str> {
    line.strip_prefix("## ").map(str::trim_end)
}

/// Index of the next `## ` heading at or after `from`, or the line count.
fn next_heading(lines: &[&str], from: usize) -> usize {
    (from..lines.len())
        .find(|&index| heading_body(lines[index]).is_some())
        .unwrap_or(lines.len())
}

/// Whether a heading names the shared protocol. Case-insensitive, because the
/// one field name in this grammar that has no id to attach to is the one people
/// will capitalise.
fn is_shared_protocol(heading: &str) -> bool {
    heading.trim().eq_ignore_ascii_case("shared protocol")
}

/// `(id, title)` from `P<n> · <title>`, or `None` if this is not a prompt heading.
///
/// The separator is permissive because `## P2 · Get CI green` and `## P2: Get
/// CI green` are the same heading written two ways, and the tool should not
/// decide which of them is correct. The id is not: `P two` is a prompt with no
/// id, which nothing can refer to.
fn prompt_id(heading: &str) -> Option<(u32, &str)> {
    let rest = heading
        .strip_prefix('P')
        .or_else(|| heading.strip_prefix('p'))?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    let title = rest[digits.len()..].trim_start_matches([' ', '\t', '.', ':', '·', '-', '–', '—']);
    Some((digits.parse().ok()?, title.trim()))
}

/// Whether a heading was probably *meant* to be a prompt.
///
/// Used only to warn, so it can be generous: the cost of a spurious warning is
/// one line of output and the cost of missing a real prompt is a slice nobody
/// is ever offered.
fn looks_like_a_prompt(heading: &str) -> bool {
    let lower = heading.trim().to_ascii_lowercase();
    lower.starts_with('p') || lower.contains("prompt")
}

/// The one fenced block in a section, with a diagnostic for every way there
/// might not be exactly one.
fn single_fenced_block(
    section: &[&str],
    line: usize,
    what: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> String {
    let mut open = None;
    let mut closed = None;
    for (offset, section_line) in section.iter().enumerate() {
        if is_fence(section_line) {
            match open {
                None => open = Some(offset),
                Some(_) if closed.is_none() => closed = Some(offset),
                Some(_) => {
                    diagnostics.push(Diagnostic::error(
                        line + offset + 1,
                        format!(
                            "a second fenced block in the {what} section; exactly one is read, and \
                             which one is not a question this tool answers"
                        ),
                    ));
                    return String::new();
                }
            }
        }
    }
    match (open, closed) {
        (None, _) => {
            diagnostics.push(Diagnostic::error(
                line,
                format!("the {what} section has no fenced block"),
            ));
            String::new()
        }
        (Some(start), None) => {
            diagnostics.push(Diagnostic::error(
                line + start + 1,
                format!("the fenced block in the {what} section is never closed"),
            ));
            String::new()
        }
        (Some(start), Some(end)) => dedent(&section[start + 1..end]),
    }
}

/// Whether a line opens or closes a fenced block.
fn is_fence(line: &str) -> bool {
    line.trim_start().starts_with("```")
}

/// Strip the common leading indentation from a block, and its trailing blank
/// lines.
///
/// Prompts are indented inside fenced blocks in some Markdown styles, and the
/// prompt an agent reads should not carry four spaces on every line.
fn dedent(lines: &[&str]) -> String {
    let common = lines
        .iter()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.len() - line.trim_start().len())
        .min()
        .unwrap_or(0);
    let mut out: Vec<String> = lines
        .iter()
        .map(|line| {
            let trimmed = if line.len() >= common {
                &line[common..]
            } else {
                line.trim_start()
            };
            trimmed.trim_end().to_owned()
        })
        .collect();
    while out.last().is_some_and(String::is_empty) {
        out.pop();
    }
    out.join("\n")
}

/// `**Key:** value`, or `None`.
///
/// Only the first `:**` ends the key, so a value containing `:**` survives.
fn field(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("**")?;
    let end = rest.find(":**")?;
    Some((&rest[..end], rest[end + 3..].trim()))
}

/// `**Add-on — title:** body`, with any of the dashes the two libraries this
/// replaces use between `Add-on` and the title.
fn addon_line(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("**Add-on")?;
    let rest = rest.trim_start();
    let rest = rest
        .strip_prefix(['—', '–', '-', ':'])
        .or_else(|| rest.strip_prefix(' '))?;
    let rest = rest.trim_start();
    let end = rest.find(":**")?;
    let title = rest[..end].trim();
    let body = rest[end + 3..].trim();
    if title.is_empty() || body.is_empty() {
        return None;
    }
    Some((title.to_owned(), body.to_owned()))
}

/// The command-line name for an add-on title.
///
/// ASCII alphanumerics and `-`, which is what a shell passes cleanly and what
/// both libraries this replaces produce. A non-ASCII title therefore has an
/// unusable slug; that is reported by `check` rather than silently mangled,
/// because a mangled slug is one nobody can type.
pub fn slugify(title: &str) -> String {
    let mut slug = String::with_capacity(title.len());
    let mut pending_dash = false;
    for character in title.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_dash && !slug.is_empty() {
                slug.push('-');
            }
            pending_dash = false;
            slug.push(character.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    slug
}

/// Placeholder names in `text`, in first-appearance order.
fn placeholders_in(text: &str) -> Vec<String> {
    scanned_placeholders(text)
        .into_iter()
        .map(|(name, _)| name)
        .collect()
}

/// A placeholder name: word characters only, so `{}` and `{a b}` are literal
/// text rather than two placeholders with empty names.
///
/// Public because [`crate::render`] asks the same question while substituting,
/// and two implementations of "is this a placeholder name" would eventually
/// disagree.
pub fn is_placeholder_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// The value written after the `=` in a placeholder body, if any.
fn placeholder_default(body: &str) -> Option<String> {
    let (name, default) = body.split_once('=')?;
    debug_assert!(is_placeholder_name(name.trim()));
    Some(default.to_owned())
}

/// Parse one `## P<n>` section.
#[allow(clippy::too_many_lines)]
fn parse_prompt(
    id: u32,
    title: &str,
    line: usize,
    section: &[&str],
    diagnostics: &mut Vec<Diagnostic>,
) -> Prompt {
    let mut prompt = Prompt {
        id,
        title: title.to_owned(),
        when_to_use: String::new(),
        status: Status::Todo,
        leverage: 1,
        effort: Effort::Small,
        gates: Vec::new(),
        depends_on: Vec::new(),
        touches: Vec::new(),
        random_weight: 1,
        protocol: String::new(),
        body: String::new(),
        addons: Vec::new(),
        placeholders: Vec::new(),
        line,
    };

    if title.is_empty() {
        diagnostics.push(Diagnostic::error(
            line,
            format!("P{id} has no title; the heading is `## P<n> · <title>`"),
        ));
    }

    let mut in_block = false;
    for (offset, section_line) in section.iter().enumerate() {
        let field_line = line + offset + 1;
        if is_fence(section_line) {
            in_block = !in_block;
            continue;
        }
        if in_block {
            continue;
        }
        if let Some((addon_title, body)) = addon_line(section_line) {
            let slug = slugify(&addon_title);
            if slug.is_empty() {
                diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: the add-on `{addon_title}` has no typeable name. Rename it in \
                         ASCII words, or check will report it every run"
                    ),
                ));
            } else if prompt.addons.iter().any(|addon| addon.slug == slug) {
                diagnostics.push(Diagnostic::error(
                    field_line,
                    format!("P{id}: two add-ons are both called `{slug}`; slugs have to differ"),
                ));
            } else {
                prompt.addons.push(Addon {
                    title: addon_title,
                    slug,
                    body,
                });
            }
            continue;
        }
        let Some((key, value)) = field(section_line) else {
            continue;
        };
        match key {
            "When to use" => value.clone_into(&mut prompt.when_to_use),
            "Status" => match Status::parse(value) {
                Some(status) => prompt.status = status,
                None => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Status:** `{value}` is not one of {}",
                        Status::NAMES.join(", ")
                    ),
                )),
            },
            "Leverage" => match value.parse::<u8>() {
                Ok(leverage @ 1..=5) => prompt.leverage = leverage,
                _ => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!("P{id}: **Leverage:** must be a number from 1 to 5, not `{value}`"),
                )),
            },
            "Effort" => match Effort::parse(value) {
                Some(effort) => prompt.effort = effort,
                None => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Effort:** `{value}` is not one of {}",
                        Effort::NAMES.join(", ")
                    ),
                )),
            },
            "Gates" => {
                prompt.gates = value
                    .split(';')
                    .map(str::trim)
                    .filter(|gate| !gate.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            "Depends on" => {
                for item in value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                {
                    match item.trim_start_matches(['P', 'p']).parse::<u32>() {
                        Ok(dependency) => prompt.depends_on.push(dependency),
                        Err(_) => diagnostics.push(Diagnostic::error(
                            field_line,
                            format!(
                                "P{id}: **Depends on:** `{item}` is not a prompt id; \
                                 write it as P<n> or as the bare number"
                            ),
                        )),
                    }
                }
            }
            "Touches" => {
                prompt.touches = value
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| match item.strip_prefix('+') {
                        Some(path) => Touch::Created(path.trim().to_owned()),
                        None => Touch::Existing(item.to_owned()),
                    })
                    .collect();
            }
            "Random weight" => match value.parse::<u32>() {
                Ok(weight @ 0..=9) => prompt.random_weight = weight,
                _ => diagnostics.push(Diagnostic::error(
                    field_line,
                    format!(
                        "P{id}: **Random weight:** must be a number from 0 to 9, not `{value}`"
                    ),
                )),
            },
            "Prompt protocol" => value.clone_into(&mut prompt.protocol),
            other => diagnostics.push(Diagnostic::warning(
                field_line,
                format!(
                    "P{id}: `**{other}:**` is not a field this tool reads, so it has no effect; \
                     the fields are When to use, Status, Leverage, Effort, Gates, Depends on, \
                     Touches, Random weight and Prompt protocol"
                ),
            )),
        }
    }

    prompt.body = single_fenced_block(section, line, &format!("P{id}"), diagnostics);

    for (name, why) in REQUIRED_FIELDS {
        if !section_has_field(section, name) {
            diagnostics.push(Diagnostic::error(
                line,
                format!("P{id} has no `**{name}:**` line: {why}"),
            ));
        }
    }
    if prompt.when_to_use.is_empty() {
        diagnostics.push(Diagnostic::error(
            line,
            format!(
                "P{id} has no **When to use:** text: {}",
                REQUIRED_FIELDS[0].1
            ),
        ));
    }
    if prompt.gates.is_empty() {
        diagnostics.push(Diagnostic::error(
            line,
            format!(
                "P{id} has no **Gates:**; a slice with no check is a slice nobody can tell is \
                 finished, and this repository does not claim things nothing checks"
            ),
        ));
    }

    collect_placeholders(&mut prompt, diagnostics);
    prompt
}

/// Fields whose absence blocks the slice, and what is lost without each.
///
/// Kept next to the parser so that adding a required field is one line here
/// rather than a rule to remember.
const REQUIRED_FIELDS: &[(&str, &str)] = &[
    (
        "When to use",
        "a prompt nobody can place is a prompt nobody starts",
    ),
    (
        "Status",
        "the advisor picks from statuses, so an unstated prompt is invisible to it",
    ),
    (
        "Leverage",
        "the advisor ranks on it, so an unstated prompt is ranked last by accident",
    ),
    ("Effort", "the advisor breaks ties with it"),
];

/// Whether a field appears at all, as opposed to appearing empty.
fn section_has_field(section: &[&str], key: &str) -> bool {
    let mut in_block = false;
    for line in section {
        if is_fence(line) {
            in_block = !in_block;
        } else if !in_block {
            if let Some((found, _)) = field(line) {
                if found == key {
                    return true;
                }
            }
        }
    }
    false
}

/// Collect the placeholders a prompt needs, from its body and its add-ons.
fn collect_placeholders(prompt: &mut Prompt, diagnostics: &mut Vec<Diagnostic>) {
    let id = prompt.id;
    for source in std::iter::once(prompt.body.clone())
        .chain(prompt.addons.iter().map(|addon| addon.body.clone()))
    {
        for (name, default) in scanned_placeholders(&source) {
            match prompt
                .placeholders
                .iter_mut()
                .find(|slot| slot.name == name)
            {
                Some(slot) => {
                    if slot.default != default && default.is_some() {
                        diagnostics.push(Diagnostic::error(
                            prompt.line,
                            format!(
                                "P{id}: the placeholder {{ {name} }} appears both with and without a \
                                 default; one is always required or always defaulted, because a \
                                 value that is sometimes required and sometimes not is a value \
                                 nobody knows to supply"
                            ),
                        ));
                    }
                }
                None => prompt.placeholders.push(Placeholder { name, default }),
            }
        }
    }
}

/// `(name, default)` for each placeholder occurrence, in order.
///
/// A single scanner, shared with [`placeholders_in`], so "which placeholders does
/// this prompt have" cannot answer differently depending on which caller asked.
fn scanned_placeholders(text: &str) -> Vec<(String, Option<String>)> {
    let mut found = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '{' {
            continue;
        }
        if chars.peek() == Some(&'{') {
            chars.next();
            continue;
        }
        let mut body = String::new();
        let mut closed = false;
        for inner in chars.by_ref() {
            if inner == '}' {
                closed = true;
                break;
            }
            body.push(inner);
        }
        if !closed {
            break;
        }
        let name = body.split('=').next().unwrap_or("").trim();
        if is_placeholder_name(name) {
            found.push((name.to_owned(), placeholder_default(body.trim())));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIBRARY: &str = "\
## Shared protocol

```text
stand up
```

## P1 · First

**When to use:** always
**Status:** done
**Leverage:** 5
**Effort:** small
**Gates:** `cargo test`
**Touches:** crates/ferrox-core/src/lib.rs
**Random weight:** 0

```text
do the first thing with {len=40}
```

**Add-on — Local first:** author here, prove in CI

## P2 · Second

**When to use:** after the first
**Status:** todo
**Leverage:** 3
**Effort:** large
**Gates:** `cargo clippy`; CI: `ci.yml`
**Depends on:** P1
**Touches:** +crates/ferrox-prompt/src/new.rs

```text
do the second thing with {scope}
```

**Add-on — miri-limits:** name what it cannot interpret
";

    fn load(text: &str) -> Library {
        Library::parse(Path::new("prompts.md"), text)
    }

    #[test]
    fn a_library_parses_into_prompts() {
        let library = load(LIBRARY);
        assert!(
            !library.has_errors(),
            "unexpected: {:?}",
            library.diagnostics
        );
        assert_eq!(library.shared_protocol, "stand up");
        assert_eq!(library.prompts.len(), 2);
        let first = library.prompt(1).unwrap();
        assert_eq!(first.title, "First");
        assert_eq!(first.when_to_use, "always");
        assert_eq!(first.status, Status::Done);
        assert_eq!(first.leverage, 5);
        assert_eq!(first.effort, Effort::Small);
        assert_eq!(first.gates, vec!["`cargo test`"]);
        assert_eq!(first.random_weight, 0);
        assert_eq!(first.body, "do the first thing with {len=40}");
        assert_eq!(first.addons.len(), 1);
        assert_eq!(first.addons[0].slug, "local-first");
        assert_eq!(first.placeholders.len(), 1);
        assert_eq!(first.placeholders[0].default.as_deref(), Some("40"));
        assert_eq!(first.touches.len(), 1);
        assert!(first.touches[0].claims_existing_file());
    }

    #[test]
    fn a_prompt_with_no_default_has_a_required_input() {
        let library = load(LIBRARY);
        let second = library.prompt(2).unwrap();
        assert_eq!(second.required_inputs().collect::<Vec<_>>(), vec!["scope"]);
        assert_eq!(second.depends_on, vec![1]);
        assert_eq!(second.effort, Effort::Large);
        assert_eq!(second.gates.len(), 2);
        assert!(!second.touches[0].claims_existing_file());
    }

    #[test]
    fn a_typo_in_a_field_is_a_warning_not_silence() {
        let library = load(&LIBRARY.replace("**Leverage:** 5", "**Levrage:** 5"));
        let typo = library
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.message.contains("Levrage"))
            .expect("a misspelled field must be reported");
        assert_eq!(typo.severity, Severity::Warning);
        assert!(typo.line > 0);
    }

    #[test]
    fn a_second_fenced_block_is_an_error() {
        let text = LIBRARY.replace(
            "**Add-on — Local first:** author here, prove in CI",
            "```text\na second block\n```\n",
        );
        let library = load(&text);
        assert!(
            library
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.message.contains("second fenced block")),
            "a section with two blocks must not be guessed at: {:?}",
            library.diagnostics
        );
    }

    #[test]
    fn an_unclosed_block_is_an_error() {
        let library = load("## Shared protocol\n\n```text\nunterminated\n");
        assert!(library.has_errors());
    }

    #[test]
    fn a_dependency_on_a_prompt_that_does_not_exist_is_an_error() {
        let library = load(&LIBRARY.replace("**Depends on:** P1", "**Depends on:** P9"));
        assert!(library.errors().any(|error| error.message.contains("P9")));
    }

    #[test]
    fn a_cycle_is_reported_with_the_prompts_in_it() {
        let text = "\
## Shared protocol

```text
p
```

## P1 · One

**When to use:** first
**Status:** todo
**Leverage:** 1
**Effort:** small
**Gates:** `cargo test`
**Depends on:** P2

```text
b
```

## P2 · Two

**When to use:** second
**Status:** todo
**Leverage:** 1
**Effort:** small
**Gates:** `cargo test`
**Depends on:** P1

```text
b
```
";
        let library = load(text);
        let cycle = library
            .errors()
            .find(|error| error.message.contains("cycle"))
            .unwrap_or_else(|| {
                panic!(
                    "a cycle must be named, not left to hang: {:?}",
                    library.diagnostics
                )
            });
        assert!(cycle.message.contains("P1"), "{}", cycle.message);
        assert!(cycle.message.contains("P2"), "{}", cycle.message);
    }

    #[test]
    fn a_prompt_depending_on_itself_is_named() {
        let library = load(&LIBRARY.replace("**Depends on:** P1", "**Depends on:** P2"));
        let self_dependency = library
            .errors()
            .find(|error| error.message.contains("depends on itself"))
            .unwrap_or_else(|| {
                panic!(
                    "expected a self-dependency error: {:?}",
                    library.diagnostics
                )
            });
        assert!(self_dependency.message.contains('P'));
    }

    #[test]
    fn a_heading_from_another_library_is_a_warning() {
        let library = load(&LIBRARY.replace("## P2 · Second", "## Prompt 2: Second"));
        let warning = library
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Warning)
            .unwrap_or_else(|| panic!("expected a warning, got {:?}", library.diagnostics));
        assert!(warning.message.contains("## P<n>"), "{}", warning.message);
    }

    #[test]
    fn an_out_of_range_leverage_is_an_error() {
        let library = load(&LIBRARY.replace("**Leverage:** 5", "**Leverage:** 9"));
        assert!(library
            .errors()
            .any(|error| error.message.contains("1 to 5")));
        let word = load(&LIBRARY.replace("**Leverage:** 5", "**Leverage:** high"));
        assert!(word.errors().any(|error| error.message.contains("1 to 5")));
    }

    #[test]
    fn a_prompt_with_no_gates_is_an_error() {
        let library = load(&LIBRARY.replace("**Gates:** `cargo test`\n", ""));
        assert!(library
            .errors()
            .any(|error| error.message.contains("**Gates:**")));
    }

    #[test]
    fn slugs_are_lowercase_and_dashed() {
        assert_eq!(slugify("Local first"), "local-first");
        assert_eq!(slugify("miri  limits!"), "miri-limits");
        assert_eq!(slugify("Isa's ISA matrix"), "isa-s-isa-matrix");
        assert_eq!(slugify("---"), "");
    }

    #[test]
    fn placeholders_may_have_defaults_that_contain_equals() {
        let library = load(&LIBRARY.replace("{len=40}", "{cmd=cargo test --all}"));
        let first = library.prompt(1).unwrap();
        assert_eq!(
            first.placeholders[0].default.as_deref(),
            Some("cargo test --all")
        );
    }

    #[test]
    fn the_live_library_has_no_errors() {
        let text = include_str!("../prompts.md");
        let library = Library::parse(Path::new("prompts.md"), text);
        assert!(
            !library.has_errors(),
            "prompts.md does not parse: {:#?}",
            library.diagnostics
        );
    }
}
