//! Opt-in writer for `~/.aws/config` that inserts or updates a
//! `credential_process`-backed profile stanza.
//!
//! This module never parses the file through an INI library: the AWS
//! config format is close to INI but not identical (comments, blank
//! lines, `=` spacing, and section ordering all carry meaning to
//! humans and to some third-party tools), and round-tripping through
//! `rust-ini` destroys all of it. Instead the file is treated as plain
//! text and only the block belonging to the target profile is
//! replaced. Everything else is preserved byte-for-byte.
//!
//! Managed blocks are demarcated by a pair of comment markers:
//!
//! ```text
//! # managed-by: entraws (do not edit; run `entraws --configure-profile` to update)
//! [profile entraws-secg]
//! credential_process = /path/to/entraws credentials --cache-key <hex> --source keychain
//! region = ap-northeast-1
//! # end: entraws
//! ```
//!
//! Updates replace the range from the `managed-by` marker through the
//! matching `end:` line, so adjacent profiles, comments, and blank
//! lines survive unchanged. A profile that exists without the
//! `managed-by` marker is treated as user-authored and is never
//! overwritten unless `force` is set — the assumption is that the
//! operator configured it deliberately and entraws should not clobber
//! it silently.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Markers that bracket an entraws-managed profile stanza. The exact
/// text is part of the file contract: changing these strings breaks
/// recognition of stanzas written by older versions of the binary.
const MANAGED_START: &str =
    "# managed-by: entraws (do not edit; run `entraws --configure-profile` to update)";
const MANAGED_END: &str = "# end: entraws";

/// Outcome of a single `configure_profile` call. Surfaced on stderr so
/// the operator knows whether the file was changed.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigureOutcome {
    /// File already contained the requested stanza byte-for-byte; no
    /// write occurred.
    NoOp,
    /// A brand-new stanza was appended to the end of the file.
    Added,
    /// An existing managed stanza was replaced with the new contents.
    Updated,
    /// A dry-run was requested; the diff was printed but nothing was
    /// written.
    DryRun,
}

/// Input the `aws_config` writer needs. The caller owns profile naming
/// and the stanza contents; this module only knows how to place them
/// safely.
pub struct ConfigureRequest<'a> {
    pub path: &'a Path,
    pub profile: &'a str,
    pub cache_key: &'a str,
    pub source: &'a str,
    pub region: &'a str,
    pub binary_path: &'a str,
    pub force: bool,
    pub dry_run: bool,
}

/// Insert or update an entraws-managed profile stanza in
/// `~/.aws/config`. See the module-level documentation for the
/// surrounding design decisions.
pub fn configure_profile(req: &ConfigureRequest<'_>) -> Result<ConfigureOutcome> {
    // Refuse to follow symlinks. Mirrors the hardening in
    // `credential::file::write_ini_credentials`: the intent is to stop
    // an attacker-controlled symlink from redirecting our write to a
    // privileged location. Evaluate this before touching the file so a
    // dangling symlink does not even trigger a read.
    if let Ok(metadata) = fs::symlink_metadata(req.path) {
        if metadata.file_type().is_symlink() {
            return Err(Error::SymlinkRejected(PathBuf::from(req.path)));
        }
    }

    // Ensure the parent directory exists. We intentionally do NOT set a
    // specific mode on `~/.aws/`: the directory is typically created by
    // `aws configure` as 0o755 and other tools rely on that; forcing a
    // stricter mode here would break them.
    if let Some(parent) = req.path.parent() {
        fs::create_dir_all(parent).map_err(|source| Error::WriteCredentials {
            path: PathBuf::from(parent),
            source,
        })?;
    }

    let existing = if req.path.exists() {
        fs::read_to_string(req.path).map_err(|source| Error::WriteCredentials {
            path: PathBuf::from(req.path),
            source,
        })?
    } else {
        String::new()
    };

    let new_stanza = build_stanza(req);

    let (updated, outcome) = match locate_profile(&existing, req.profile) {
        Some(FoundBlock {
            start,
            end,
            managed: true,
        }) => {
            // Idempotent: if the current managed block matches the new
            // stanza byte-for-byte there is no reason to touch the
            // file. Saves us from bumping mtime on repeated logins.
            let current = &existing[start..end];
            if current == new_stanza.as_str() {
                return Ok(ConfigureOutcome::NoOp);
            }
            let mut out = String::with_capacity(existing.len());
            out.push_str(&existing[..start]);
            out.push_str(&new_stanza);
            out.push_str(&existing[end..]);
            (out, ConfigureOutcome::Updated)
        }
        Some(FoundBlock {
            start,
            end,
            managed: false,
        }) => {
            if !req.force {
                // A profile with the same name exists but is not
                // bracketed by our markers. Refuse to overwrite by
                // default: the operator likely authored it by hand.
                return Err(Error::ProfileExists {
                    profile: req.profile.to_string(),
                    path: PathBuf::from(req.path),
                });
            }
            let mut out = String::with_capacity(existing.len());
            out.push_str(&existing[..start]);
            out.push_str(&new_stanza);
            out.push_str(&existing[end..]);
            (out, ConfigureOutcome::Updated)
        }
        None => {
            // Append, adding a blank line separator when the file is
            // non-empty so previous sections keep a breathing room.
            let mut out = String::with_capacity(existing.len() + new_stanza.len() + 1);
            out.push_str(&existing);
            if !existing.is_empty() && !existing.ends_with("\n\n") {
                if !existing.ends_with('\n') {
                    out.push('\n');
                }
                out.push('\n');
            }
            out.push_str(&new_stanza);
            (out, ConfigureOutcome::Added)
        }
    };

    if req.dry_run {
        print_diff(&existing, &updated);
        return Ok(ConfigureOutcome::DryRun);
    }

    // One-shot backup. Only created the first time we touch a
    // non-empty file so repeated configure runs do not overwrite the
    // user's pre-entraws state.
    let bak_path = bak_path(req.path);
    if !bak_path.exists() && !existing.is_empty() {
        fs::copy(req.path, &bak_path).map_err(|source| Error::WriteCredentials {
            path: bak_path.clone(),
            source,
        })?;
    }

    atomic_write(req.path, &updated)?;
    Ok(outcome)
}

/// Produce the full text of the managed stanza including the marker
/// comments. Always ends with a newline so concatenation with the rest
/// of the file keeps line structure clean.
fn build_stanza(req: &ConfigureRequest<'_>) -> String {
    format!(
        "{start}\n\
         [profile {profile}]\n\
         credential_process = {bin} credentials --cache-key {key} --source {source}\n\
         region = {region}\n\
         {end}\n",
        start = MANAGED_START,
        profile = req.profile,
        bin = req.binary_path,
        key = req.cache_key,
        source = req.source,
        region = req.region,
        end = MANAGED_END,
    )
}

/// Byte offsets that delimit a profile block within the original file.
/// `managed` says whether the block was fenced by our markers (and is
/// therefore safe to overwrite without `--force`).
struct FoundBlock {
    start: usize,
    end: usize,
    managed: bool,
}

/// Walk the file looking for `[profile <name>]`. When a match is
/// found, expand the range to include:
///
/// * the preceding `MANAGED_START` marker, if present (so updates
///   replace the marker too)
/// * the trailing `MANAGED_END` marker, or the start of the next
///   section header, whichever comes first
///
/// The returned range is half-open (`[start, end)`) and ends on a
/// newline boundary so splicing new content into the gap does not
/// create `\n\n` run-ons or eat a trailing newline.
fn locate_profile(text: &str, profile: &str) -> Option<FoundBlock> {
    let header = format!("[profile {profile}]");
    // Indexing by byte offsets requires us to walk lines manually
    // (String::lines strips the terminator).
    let mut offset = 0usize;
    let mut header_offset: Option<usize> = None;
    let mut prev_is_managed_start = false;
    let mut managed_start_offset: Option<usize> = None;

    while offset < text.len() {
        let line_end = text[offset..]
            .find('\n')
            .map(|rel| offset + rel + 1)
            .unwrap_or(text.len());
        let line = &text[offset..line_end].trim_end_matches(&['\n', '\r'][..]);

        if *line == MANAGED_START {
            prev_is_managed_start = true;
            managed_start_offset = Some(offset);
        } else if *line == header {
            header_offset = Some(offset);
            break;
        } else {
            prev_is_managed_start = false;
            managed_start_offset = None;
        }
        offset = line_end;
    }

    let header_start = header_offset?;
    let mut block_start = header_start;
    let mut managed = false;

    if prev_is_managed_start {
        if let Some(ms) = managed_start_offset {
            block_start = ms;
            managed = true;
        }
    }

    // Find where the block ends. Scan forward from the header for
    // either MANAGED_END (managed block) or the next `[`-prefixed line
    // (unmanaged block; boundary is the start of the next section).
    let mut cursor = text[header_start..]
        .find('\n')
        .map(|rel| header_start + rel + 1)
        .unwrap_or(text.len());
    let mut block_end = cursor;
    while cursor < text.len() {
        let line_end = text[cursor..]
            .find('\n')
            .map(|rel| cursor + rel + 1)
            .unwrap_or(text.len());
        let line = &text[cursor..line_end].trim_end_matches(&['\n', '\r'][..]);

        if managed && *line == MANAGED_END {
            // Include the `MANAGED_END` line in the replaced range.
            block_end = line_end;
            break;
        }
        if !managed && line.starts_with('[') {
            // Next section header: stop just before it.
            block_end = cursor;
            break;
        }
        cursor = line_end;
        block_end = cursor;
    }

    Some(FoundBlock {
        start: block_start,
        end: block_end,
        managed,
    })
}

/// Append `.entraws.bak` to the filename without losing any of the
/// original extension (`config` → `config.entraws.bak`).
fn bak_path(path: &Path) -> PathBuf {
    let mut bak = path.as_os_str().to_os_string();
    bak.push(".entraws.bak");
    PathBuf::from(bak)
}

/// Atomically replace `path` with `content`, preserving the existing
/// file's permission mode when one is present and defaulting to 0o600
/// for newly-created files. Write goes through a same-directory
/// temporary file so `rename(2)` swaps the inode in one shot.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let tmp = tempfile::Builder::new()
        .prefix(".")
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|source| Error::WriteCredentials {
            path: PathBuf::from(parent),
            source,
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.exists() {
            fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0o600)
        } else {
            0o600
        };
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode)).map_err(|source| {
            Error::WriteCredentials {
                path: tmp.path().to_path_buf(),
                source,
            }
        })?;
    }

    {
        let mut handle = tmp.as_file();
        handle
            .write_all(content.as_bytes())
            .map_err(|source| Error::WriteCredentials {
                path: tmp.path().to_path_buf(),
                source,
            })?;
        handle
            .sync_all()
            .map_err(|source| Error::WriteCredentials {
                path: tmp.path().to_path_buf(),
                source,
            })?;
    }

    tmp.persist(path).map_err(|e| Error::WriteCredentials {
        path: PathBuf::from(path),
        source: e.error,
    })?;
    Ok(())
}

/// Minimal diff printer for `--dry-run`. Shows removed lines with `-`
/// and added lines with `+`, which is enough for humans to spot what
/// will change without pulling in a diffing crate.
fn print_diff(before: &str, after: &str) {
    eprintln!("--- current");
    eprintln!("+++ proposed");
    let before_lines: Vec<&str> = before.lines().collect();
    let after_lines: Vec<&str> = after.lines().collect();
    // Naive diff: print every line with a +/- prefix. Good enough for a
    // one-off visualisation; a full LCS diff would be overkill here.
    for line in &before_lines {
        if !after_lines.contains(line) {
            eprintln!("-{line}");
        }
    }
    for line in &after_lines {
        if !before_lines.contains(line) {
            eprintln!("+{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn req_with<'a>(path: &'a Path, profile: &'a str) -> ConfigureRequest<'a> {
        ConfigureRequest {
            path,
            profile,
            cache_key: "abc123",
            source: "keychain",
            region: "ap-northeast-1",
            binary_path: "/usr/local/bin/entraws",
            force: false,
            dry_run: false,
        }
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn adds_stanza_to_empty_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        let r = req_with(&path, "entraws-secg");

        assert_eq!(configure_profile(&r).unwrap(), ConfigureOutcome::Added);

        let content = read(&path);
        assert!(content.contains("[profile entraws-secg]"));
        assert!(content.contains("credential_process = /usr/local/bin/entraws"));
        assert!(content.contains(MANAGED_START));
        assert!(content.contains(MANAGED_END));
    }

    #[test]
    fn preserves_existing_sections_and_comments() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        let original = "\
# My personal setup
[profile default]
region = us-east-1
# dev tenant
sso_start_url = https://dev.example.com/

[profile work]
region = us-west-2
";
        fs::write(&path, original).unwrap();

        configure_profile(&req_with(&path, "entraws-secg")).unwrap();

        let content = read(&path);
        // Original lines survive verbatim.
        assert!(content.starts_with("# My personal setup\n[profile default]\n"));
        assert!(content.contains("# dev tenant\nsso_start_url = https://dev.example.com/\n"));
        assert!(content.contains("[profile work]\nregion = us-west-2\n"));
        // New stanza appended.
        assert!(content.contains("[profile entraws-secg]"));
    }

    #[test]
    fn is_idempotent_for_identical_managed_stanza() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        let r = req_with(&path, "entraws-secg");
        configure_profile(&r).unwrap();
        let before = read(&path);

        assert_eq!(configure_profile(&r).unwrap(), ConfigureOutcome::NoOp);

        let after = read(&path);
        assert_eq!(before, after);
    }

    #[test]
    fn updates_managed_stanza_when_cache_key_changes() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        configure_profile(&req_with(&path, "entraws-secg")).unwrap();

        let new_req = ConfigureRequest {
            cache_key: "def456",
            ..req_with(&path, "entraws-secg")
        };
        assert_eq!(
            configure_profile(&new_req).unwrap(),
            ConfigureOutcome::Updated
        );

        let content = read(&path);
        assert!(content.contains("--cache-key def456"));
        assert!(!content.contains("--cache-key abc123"));
    }

    #[test]
    fn refuses_to_overwrite_unmanaged_profile_without_force() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        let original = "\
[profile entraws-secg]
region = us-east-1
aws_access_key_id = AKIA_HANDWRITTEN
";
        fs::write(&path, original).unwrap();

        let err = configure_profile(&req_with(&path, "entraws-secg")).unwrap_err();
        match err {
            Error::ProfileExists { profile, .. } => {
                assert_eq!(profile, "entraws-secg");
            }
            other => panic!("expected ProfileExists, got {other:?}"),
        }
        // File unchanged.
        assert_eq!(read(&path), original);
    }

    #[test]
    fn force_overwrites_unmanaged_profile() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        let original = "\
[profile entraws-secg]
region = us-east-1
aws_access_key_id = AKIA_HANDWRITTEN

[profile other]
region = eu-west-1
";
        fs::write(&path, original).unwrap();

        let r = ConfigureRequest {
            force: true,
            ..req_with(&path, "entraws-secg")
        };
        assert_eq!(configure_profile(&r).unwrap(), ConfigureOutcome::Updated);

        let content = read(&path);
        // Unmanaged body replaced with managed stanza.
        assert!(!content.contains("AKIA_HANDWRITTEN"));
        assert!(content.contains(MANAGED_START));
        // Adjacent section still present.
        assert!(content.contains("[profile other]\nregion = eu-west-1\n"));
    }

    #[test]
    fn dry_run_does_not_write() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        let r = ConfigureRequest {
            dry_run: true,
            ..req_with(&path, "entraws-secg")
        };

        assert_eq!(configure_profile(&r).unwrap(), ConfigureOutcome::DryRun);
        assert!(!path.exists(), "dry-run must not create the file");
    }

    #[test]
    fn backup_created_once() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, "[profile existing]\nregion = us-east-1\n").unwrap();

        configure_profile(&req_with(&path, "entraws-secg")).unwrap();
        let bak = bak_path(&path);
        assert!(bak.exists(), "backup should be created on first touch");

        // Overwrite the backup with a sentinel; a second configure run
        // must not clobber it.
        fs::write(&bak, "SENTINEL").unwrap();
        configure_profile(&ConfigureRequest {
            cache_key: "new-key",
            ..req_with(&path, "entraws-secg")
        })
        .unwrap();
        assert_eq!(read(&bak), "SENTINEL", "backup must be one-shot");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_targets() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("real_config");
        fs::write(&target, "").unwrap();
        let link = dir.path().join("config_link");
        symlink(&target, &link).unwrap();

        let err = configure_profile(&req_with(&link, "entraws-secg")).unwrap_err();
        match err {
            Error::SymlinkRejected(p) => assert_eq!(p, link),
            other => panic!("expected SymlinkRejected, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn preserves_existing_file_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");
        fs::write(&path, "[profile default]\nregion = us-east-1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        configure_profile(&req_with(&path, "entraws-secg")).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o640,
            "existing mode must be preserved across updates"
        );
    }

    #[cfg(unix)]
    #[test]
    fn defaults_to_0600_for_new_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("config");

        configure_profile(&req_with(&path, "entraws-secg")).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
