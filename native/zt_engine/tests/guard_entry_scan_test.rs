//! C2 static-scan guard test: every destructive **device-level** entry point
//! in `execute.rs` must reach the shared guard chain (in `crate::guard`),
//! and every historic guard-named wrapper must delegate to `crate::guard`.
//!
//! This is a source-level reachability check — it fails if someone adds a
//! new destructive entry point (or reroutes an existing one) without going
//! through boot-disk protection / exclusive-access recheck / partition
//! validation / identity pinning.

/// The whole execution module, scanned as text.
const EXECUTE_SRC: &str = include_str!("../src/execute.rs");

/// Guard-chain functions (as called from `execute.rs`, direct or via
/// wrapper name).
const GUARD_ENTRIES: &[&str] = &[
    "check_boot_disk_protection",
    "check_boot_disk_protection_ctx",
    "verify_exclusive_access_and_recheck",
    "get_guard_identity",
    "recheck_protection_by_dev_t",
    "validate_partition_target",
    "verify_confirmation",
];

/// Device-level destructive entry points (take a device path). The low-level
/// `execute_writer_overwrite*` loop is deliberately excluded: it receives an
/// already-guard-opened writer, and every current call site is guarded (the
/// functions below).
const DEVICE_ENTRY_POINTS: &[&str] = &[
    "nvme_sanitize",
    "ata_secure_erase",
    "ata_sanitize",
    "opal_revert",
    "emmc_sanitize",
    "discard_erase",
    "discard_erase_ctx",
    "discard_erase_partition",
    "discard_erase_partition_ctx",
    "software_overwrite",
    "software_overwrite_partition",
    "software_overwrite_partition_ctx",
];

/// Historic wrapper name → the `crate::guard` function it must delegate to.
const WRAPPER_DELEGATIONS: &[(&str, &str)] = &[
    (
        "check_boot_disk_protection_ctx",
        "crate::guard::check_boot_disk_protection",
    ),
    (
        "verify_exclusive_access_and_recheck",
        "crate::guard::verify_exclusive_access_and_recheck",
    ),
    ("get_guard_identity", "crate::guard::get_guard_identity"),
    (
        "recheck_protection_by_dev_t",
        "crate::guard::recheck_protection_by_dev_t",
    ),
    ("verify_confirmation", "crate::guard::verify_confirmation"),
    (
        "compute_partition_table_fingerprint",
        "crate::guard::compute_partition_table_fingerprint",
    ),
    ("is_mbr_extended_partition", "crate::guard::is_mbr_extended_partition"),
    (
        "unmount_target_partition_and_holders",
        "crate::guard::unmount_target_partition_and_holders",
    ),
    ("resolve_parent_disk", "crate::guard::resolve_parent_disk"),
    ("resolve_parent_serial", "crate::guard::resolve_parent_serial"),
    (
        "validate_partition_target",
        "crate::guard::validate_partition_target",
    ),
];

/// Extract each `fn <name>` block (rustfmt style: closing brace at column 0).
fn fn_blocks(src: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = src.split('\n').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        let is_fn = line.starts_with("pub fn ")
            || line.starts_with("fn ")
            || line.starts_with("pub async fn ")
            || line.starts_with("async fn ")
            || line.starts_with("pub(crate) fn ");
        if is_fn {
            let name = line
                .split("fn ")
                .nth(1)
                .unwrap_or("")
                .split('(')
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            // Body: from the fn line to the next `}` at column 0.
            let mut end = i + 1;
            while end < lines.len() && lines[end] != "}" {
                end += 1;
            }
            let body = lines[i..=end].join("\n");
            out.push((name, body));
            i = end + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// All identifiers immediately followed by `(` in a body.
fn called_fns(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    for word in body
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
    {
        // A call is `name(`; the split removed the `(` itself, so detect via
        // the original text instead — simple approach: check `word(` in body.
        if word.is_empty() {
            continue;
        }
        let pat = format!("{}(", word);
        if body.contains(&pat) {
            out.push(word.to_string());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// BFS from an entry point through the call graph; true if any reachable
/// body directly calls a guard entry.
fn reaches_guard(blocks: &[(String, String)], entry: &str) -> bool {
    let mut visited = std::collections::HashSet::new();
    let mut queue = vec![entry.to_string()];
    while let Some(name) = queue.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        if let Some((_, body)) = blocks.iter().find(|(n, _)| *n == name) {
            for marker in GUARD_ENTRIES {
                // Direct call (own name or crate::guard-prefixed).
                let pat = format!("{}(", marker);
                if body.contains(&pat) {
                    return true;
                }
            }
            for callee in called_fns(body) {
                if blocks.iter().any(|(n, _)| *n == callee) {
                    queue.push(callee);
                }
            }
        }
    }
    false
}

#[test]
fn every_device_entry_point_reaches_the_shared_guard_chain() {
    let blocks = fn_blocks(EXECUTE_SRC);
    // The scan itself must have parsed the entries — guard against silent
    // no-ops if function signatures ever change shape.
    for entry in DEVICE_ENTRY_POINTS {
        assert!(
            blocks.iter().any(|(n, _)| n == entry),
            "entry point `{}` not found by the static scan — update the test",
            entry
        );
    }
    for entry in DEVICE_ENTRY_POINTS {
        assert!(
            reaches_guard(&blocks, entry),
            "destructive entry point `{}` does not reach the shared guard chain",
            entry
        );
    }
}

#[test]
fn historic_guard_wrappers_delegate_to_crate_guard() {
    for (wrapper, delegation) in WRAPPER_DELEGATIONS {
        let (_, body) = blocks_find(EXECUTE_SRC, wrapper)
            .unwrap_or_else(|| panic!("wrapper `{}` not found", wrapper));
        assert!(
            body.contains(delegation),
            "wrapper `{}` must delegate to `{}` (shared chain lives in crate::guard)",
            wrapper,
            delegation
        );
    }
}

fn blocks_find(src: &str, name: &str) -> Option<(String, String)> {
    fn_blocks(src).into_iter().find(|(n, _)| n == name)
}
