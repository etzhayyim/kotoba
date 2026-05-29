//! Device-local secret storage for `AgentIdentity` material.
//!
//! Per root CLAUDE.md (`Local Secret Storage` rule):
//!   service = `gftd.kotoba`, account = `agent-ed25519` / `agent-x25519` / `agent-did`
//!
//! Backends:
//!   - **macOS**: shells out to `/usr/bin/security` (generic-password items)
//!   - **Linux/other**: read/write `~/.gftd/kotoba.env` with chmod 600
//!
//! All read/write paths are no-ops on missing items, returning `Ok(None)` so
//! the caller can fall through to env vars or ephemeral generation.

use std::path::PathBuf;
use std::process::Command;

const SERVICE: &str = "gftd.kotoba";
const ACCOUNT_ED25519: &str = "agent-ed25519";
const ACCOUNT_X25519: &str = "agent-x25519";
const ACCOUNT_DID: &str = "agent-did";

/// Triple of identity material persisted on the local device.
#[derive(Debug, Clone)]
pub struct StoredIdentity {
    pub ed25519_hex: String, // 64 hex chars (32-byte seed)
    pub x25519_hex: String,  // 64 hex chars (32-byte static secret)
    pub did: String,         // e.g. did:key:z...
}

/// Read the triple if all three items are present.  Returns `None` if any is
/// missing or if no backend is available.
pub fn read_identity() -> Option<StoredIdentity> {
    if cfg!(target_os = "macos") {
        let ed = read_macos(ACCOUNT_ED25519)?;
        let dh = read_macos(ACCOUNT_X25519)?;
        let did = read_macos(ACCOUNT_DID)?;
        Some(StoredIdentity {
            ed25519_hex: ed,
            x25519_hex: dh,
            did,
        })
    } else {
        read_file_backend()
    }
}

/// Persist the triple to the device-local backend.
pub fn write_identity(id: &StoredIdentity) -> anyhow::Result<()> {
    if cfg!(target_os = "macos") {
        write_macos(ACCOUNT_ED25519, &id.ed25519_hex)?;
        write_macos(ACCOUNT_X25519, &id.x25519_hex)?;
        write_macos(ACCOUNT_DID, &id.did)?;
        Ok(())
    } else {
        write_file_backend(id)
    }
}

// ── macOS Keychain backend ────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn read_macos(account: &str) -> Option<String> {
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", SERVICE, "-a", account, "-w"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(not(target_os = "macos"))]
fn read_macos(_account: &str) -> Option<String> {
    None
}

#[cfg(target_os = "macos")]
fn write_macos(account: &str, value: &str) -> anyhow::Result<()> {
    // -U updates existing item if present; -s = service, -a = account, -w = password
    let status = Command::new("/usr/bin/security")
        .args([
            "add-generic-password",
            "-U",
            "-s",
            SERVICE,
            "-a",
            account,
            "-w",
            value,
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("security add-generic-password failed for {account}");
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn write_macos(_account: &str, _value: &str) -> anyhow::Result<()> {
    anyhow::bail!("macOS Keychain backend not available on this OS")
}

// ── Linux/other: ~/.gftd/kotoba.env file backend ──────────────────────────────

fn env_file_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".gftd").join("kotoba.env"))
}

fn read_file_backend() -> Option<StoredIdentity> {
    let path = env_file_path()?;
    let raw = std::fs::read_to_string(&path).ok()?;
    let mut ed: Option<String> = None;
    let mut dh: Option<String> = None;
    let mut did: Option<String> = None;
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("KOTOBA_AGENT_ED25519_HEX=") {
            ed = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("KOTOBA_AGENT_X25519_HEX=") {
            dh = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("KOTOBA_AGENT_DID=") {
            did = Some(rest.trim().to_string());
        }
    }
    Some(StoredIdentity {
        ed25519_hex: ed?,
        x25519_hex: dh?,
        did: did?,
    })
}

fn write_file_backend(id: &StoredIdentity) -> anyhow::Result<()> {
    let path = env_file_path().ok_or_else(|| anyhow::anyhow!("HOME not set"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = format!(
        "KOTOBA_AGENT_ED25519_HEX={}\nKOTOBA_AGENT_X25519_HEX={}\nKOTOBA_AGENT_DID={}\n",
        id.ed25519_hex, id.x25519_hex, id.did
    );
    std::fs::write(&path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_file_path_uses_home() {
        std::env::set_var("HOME", "/tmp/kotoba-keychain-test");
        let path = env_file_path().unwrap();
        assert!(path.ends_with(".gftd/kotoba.env"));
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn file_backend_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        std::env::set_var("HOME", tmp.path());
        let id = StoredIdentity {
            ed25519_hex: "a".repeat(64),
            x25519_hex: "b".repeat(64),
            did: "did:key:zABC".into(),
        };
        write_file_backend(&id).unwrap();
        let got = read_file_backend().unwrap();
        assert_eq!(got.ed25519_hex, id.ed25519_hex);
        assert_eq!(got.x25519_hex, id.x25519_hex);
        assert_eq!(got.did, id.did);
    }
}
