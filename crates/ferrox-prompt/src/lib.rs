//! `ferrox-prompt` — renders the slice a contributor should work on next.
//!
//! # What this is for
//!
//! This repository makes claims that are checked by things that run. Every
//! other part of it is machinery for that; this crate is the part that decides
//! what to work on next, so that "next" is a computed answer rather than
//! whichever of fourteen ideas came to mind most recently.
//!
//! [`Library`] holds the roadmap parsed from `prompts.md`, the single source of
//! truth for both the prompts and the order they are taken in.
//!
//! # How a slice is chosen
//!
//! A prompt is *ready* when its status is `todo` and every prompt in
//! `**Depends on:**` is `done`. Ready prompts are ranked by leverage, and ties
//! are broken towards the smaller effort, because a finished small slice
//! unblocks more of the roadmap than a started large one. The top of that
//! ranking is what [`advisor::handable`] and [`advisor::next_index`] return, and it
//! comes with the reason
//! it beat the others: what it unblocks, what is waiting on it, and which files
//! another open prompt claims as well.
//!
//! That reason is the point. A suggestion with no stated basis gets argued with
//! by whoever has a better idea, which is fair; a suggestion that names its
//! eleven unblocked slices does not.
//!
//! # What this will not do
//!
//! It will not invent a value for a placeholder that has none, and it will not
//! pick a slice whose inputs are unfilled. Both would produce a prompt that
//! looks finished and is not, which is the failure mode every claim in this
//! repository is written to avoid. `next` prints the command to run instead.
//!
//! Nothing here is loaded from a registry, and nothing is compiled from a
//! network. See `prompts.md` for the grammar this parses and
//! `docs/function/prompt-next-slice.md` for the walkthrough.

#![deny(missing_debug_implementations)]

pub mod advisor;
pub mod check;
pub mod clipboard;
pub mod json;
pub mod markdown;
pub mod render;

use std::path::{Path, PathBuf};

pub use markdown::{Addon, Diagnostic, Effort, Library, Prompt, Severity, Status};

/// Where the library lives, relative to the workspace root.
///
/// The tool searches upwards from the working directory for this path so it
/// runs from anywhere inside the repository, which is the same courtesy cargo
/// extends and for the same reason: nobody should have to know which directory a
/// tool has to be started from.
pub const LIBRARY_RELATIVE: &str = "crates/ferrox-prompt/prompts.md";

/// Where the slice ledger lives, relative to the workspace root.
///
/// Runtime state, so it is not in version control: a log of which slices have
/// been handed out is true of one machine and one contributor, and committing
/// it would make every other contributor's ledger wrong.
pub const LEDGER_RELATIVE: &str = ".ferrox/slices.log";

/// The workspace root, found by walking up from `start` looking for
/// [`LIBRARY_RELATIVE`], falling back to the manifest directory of this crate.
///
/// The fallback is what makes a released binary work outside the repository. It
/// names exactly one place the library can be, so if it is missing there too the
/// error can say where it looked rather than "no library found".
pub fn workspace_root(start: &Path) -> PathBuf {
    let mut cursor = Some(start);
    while let Some(dir) = cursor {
        if dir.join(LIBRARY_RELATIVE).is_file() {
            return dir.to_path_buf();
        }
        cursor = dir.parent();
    }
    manifest_root()
}

/// The workspace root this crate was compiled from.
///
/// `CARGO_MANIFEST_DIR` is `<root>/crates/ferrox-prompt`, so the root is two
/// levels up. It is a compile-time constant, which is the point: a binary built
/// here still knows where its library is without being told.
pub fn manifest_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map_or(manifest.clone(), Path::to_path_buf)
}

/// A tag for the exact library text a prompt was rendered from.
///
/// FNV-1a, 64-bit. **Not a checksum**: it is here so an answer can be traced
/// back to the library text that asked the question, and a tag with a
/// collision-prone hash is enough for that. Nothing about correctness depends
/// on it, and it is labelled a tag in the output so nobody mistakes it for an
/// integrity guarantee.
pub fn library_tag(text: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// A library that could not be read at all.
///
/// Distinct from a [`Library`] that parsed and has complaints: this one has no
/// prompts in it, so there is nothing to render and nothing to report a line
/// number against.
#[derive(Debug)]
pub struct Unreadable {
    /// The path that was tried.
    pub path: PathBuf,
    /// What the filesystem said.
    pub message: String,
}

impl std::fmt::Display for Unreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "cannot read prompt library {}: {}",
            self.path.display(),
            self.message
        )
    }
}

impl std::error::Error for Unreadable {}

/// Read and parse the library.
///
/// `--library` wins over the search for [`LIBRARY_RELATIVE`]. The path recorded
/// in the returned library is relative to the workspace root when it is inside
/// it, because a diagnostic that names `crates/ferrox-prompt/prompts.md:42`
/// can be opened, and one that names a temporary directory cannot.
pub fn load_library(explicit: Option<&Path>, cwd: &Path) -> Result<Library, Unreadable> {
    let root = workspace_root(cwd);
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => root.join(LIBRARY_RELATIVE),
    };
    let text = std::fs::read_to_string(&path).map_err(|source| Unreadable {
        path: path.clone(),
        message: source.to_string(),
    })?;
    let display = path
        .strip_prefix(&root)
        .map_or_else(|_| path.clone(), Path::to_path_buf);
    Ok(Library::parse(&display, &text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_is_stable_and_input_sensitive() {
        assert_eq!(library_tag("ferrox"), library_tag("ferrox"));
        assert_ne!(library_tag("ferrox"), library_tag("dovetai"));
        // Length is part of the input, so a trailing newline changes the tag.
        // That is deliberate: the tag names the file, not its gist.
        assert_ne!(library_tag("ferrox\n"), library_tag("ferrox"));
        assert_eq!(library_tag("").len(), 16);
    }

    #[test]
    fn the_manifest_root_is_the_workspace_root() {
        let root = manifest_root();
        assert!(
            root.join(LIBRARY_RELATIVE).is_file(),
            "manifest root {} does not hold the library",
            root.display()
        );
        assert!(root.join("Cargo.toml").is_file());
    }

    #[test]
    fn the_root_is_found_from_a_subdirectory() {
        let root = manifest_root();
        let deep = root.join("crates/ferrox-core/src");
        assert_eq!(workspace_root(&deep), root);
        // And a directory that is not inside the repository at all falls back
        // to the compiled-in root rather than returning nothing.
        assert_eq!(workspace_root(Path::new("/")), manifest_root());
    }
}
