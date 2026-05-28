//! Build script: bake the **upstream** `etzhayyim/kotoba` commit SHA into the
//! binary so `kotoba update-check` can compare apples-to-apples with what's
//! on GitHub's main branch.
//!
//! Resolution order:
//!   1. `KOTOBA_BUILD_COMMIT` env var (CI override).
//!   2. `../../.gitrepo` `commit =` field — tracked by git-subrepo, matches
//!      the upstream tip that this snapshot was synced from.
//!   3. Fall back to `git rev-parse HEAD` (useful when this is a standalone
//!      clone of etzhayyim/kotoba and `.gitrepo` is absent).
//!   4. `"unknown"` if none of the above succeeds.

use std::process::Command;

fn main() {
    // 1. explicit env override
    if let Ok(s) = std::env::var("KOTOBA_BUILD_COMMIT") {
        emit(&s);
        return;
    }

    // 2. .gitrepo upstream pointer (subrepo embedded in a monorepo)
    if let Some(s) = read_gitrepo_commit() {
        emit(&s);
        return;
    }

    // 3. git rev-parse HEAD (standalone clone)
    let sha = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            String::from_utf8(o.stdout).ok().map(|s| s.trim().to_string())
        } else { None })
        .unwrap_or_else(|| "unknown".to_string());
    emit(&sha);
}

fn emit(sha: &str) {
    println!("cargo:rustc-env=KOTOBA_BUILD_COMMIT={sha}");
    println!("cargo:rerun-if-changed=../../.gitrepo");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
}

/// Read the `commit = <sha>` line from `../../.gitrepo` (kotoba project root)
/// and return the first 12 chars.  Returns `None` when the file is absent.
fn read_gitrepo_commit() -> Option<String> {
    let path = std::path::PathBuf::from("..").join("..").join(".gitrepo");
    let raw  = std::fs::read_to_string(&path).ok()?;
    for line in raw.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("commit = ") {
            let sha: String = rest.trim().chars().take(12).collect();
            if !sha.is_empty() && sha.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(sha);
            }
        }
    }
    None
}
