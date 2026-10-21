//! C0: characterization goldens — the refactor-proof baseline.
//!
//! These tests pin the engine's observable JSON protocol outputs BEFORE the
//! BlockBackend refactor (Phase C). They must keep passing byte-for-byte
//! through every later phase:
//!
//! 1. `partitions` protocol payload for a deterministic Windows-typical GPT
//!    disk fixture (B1/B2 classification included).
//! 2. A representative dry-run `ExecutionReport` from the partition-scope
//!    discard path (guard chain + plan, no I/O).
//!
//! Regenerate (ONLY when an intentional, reviewed protocol change happens):
//!
//! ```sh
//! ZT_UPDATE_GOLDEN=1 cargo test --test golden_fixtures
//! ```
//!
//! Never regenerate to "fix" a refactor regression — the diff IS the signal.

use std::fs;
use std::path::PathBuf;

use tempfile::TempDir;
use tokio::sync::mpsc;
use zt_engine::execute::{
    compute_partition_table_fingerprint, discard_erase_partition_ctx, FsContext,
    PartitionTargetParams,
};
use zt_engine::partitions::enumerate_partitions_ctx;

// ---------------------------------------------------------------------------
// Deterministic fixture: internal Windows-typical GPT disk (/dev/sda)
// ---------------------------------------------------------------------------

fn guid_bytes(canonical: &str) -> [u8; 16] {
    let parts: Vec<&str> = canonical.split('-').collect();
    assert_eq!(parts.len(), 5, "bad GUID: {}", canonical);
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&u32::from_str_radix(parts[0], 16).unwrap().to_le_bytes());
    out[4..6].copy_from_slice(&u16::from_str_radix(parts[1], 16).unwrap().to_le_bytes());
    out[6..8].copy_from_slice(&u16::from_str_radix(parts[2], 16).unwrap().to_le_bytes());
    let hex = format!("{}{}", parts[3], parts[4]);
    for i in 0..8 {
        out[8 + i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn put_utf16(dst: &mut [u8], s: &str) {
    for (i, unit) in s.encode_utf16().enumerate() {
        dst[i * 2..i * 2 + 2].copy_from_slice(&unit.to_le_bytes());
    }
}

/// 8 MiB GPT image: EFI System, MSR, Basic Data (NTFS), Windows Recovery,
/// LUKS — the B1/B2 classification surface.
fn build_windows_gpt_image() -> Vec<u8> {
    let mut img = vec![0u8; 8 * 1024 * 1024];
    img[510] = 0x55;
    img[511] = 0xAA;
    img[512..520].copy_from_slice(b"EFI PART");
    img[524..528].copy_from_slice(&92u32.to_le_bytes());
    img[584..592].copy_from_slice(&2u64.to_le_bytes());
    img[592..596].copy_from_slice(&128u32.to_le_bytes());
    img[596..600].copy_from_slice(&128u32.to_le_bytes());
    let entries: [(&str, u64, u64, &str); 5] = [
        ("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", 2048, 6143, "EFI system partition"),
        ("e3c9e316-0b5c-4db8-817d-f92df00215ae", 6144, 8191, ""),
        ("ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", 8192, 10239, "Data"),
        ("de94bba4-06d1-4d40-a16a-bfd50179d6ac", 10240, 12287, "Recovery"),
        ("ca7d7ccb-63ed-4c53-861c-1742536059cc", 12288, 14335, ""),
    ];
    for (i, (guid, first, last, name)) in entries.iter().enumerate() {
        let off = 1024 + i * 128;
        img[off..off + 16].copy_from_slice(&guid_bytes(guid));
        img[off + 32..off + 40].copy_from_slice(&first.to_le_bytes());
        img[off + 40..off + 48].copy_from_slice(&last.to_le_bytes());
        put_utf16(&mut img[off + 56..off + 128], name);
    }
    let ntfs = 8192 * 512;
    img[ntfs] = 0xEB;
    img[ntfs + 3..ntfs + 11].copy_from_slice(b"NTFS    ");
    img[ntfs + 510] = 0x55;
    img[ntfs + 511] = 0xAA;
    let luks = 12288 * 512;
    img[luks..luks + 6].copy_from_slice(b"LUKS\xba\xbe");
    img
}

struct GoldenFixture {
    _tmp: TempDir,
    ctx: FsContext,
}

fn write(path: &PathBuf, content: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, content).unwrap();
}

fn build_golden_fixture() -> GoldenFixture {
    let tmp = tempfile::tempdir().unwrap();
    let sys = tmp.path().join("sys");
    let proc = tmp.path().join("proc");
    let dev = tmp.path().join("dev");
    fs::create_dir_all(&dev).unwrap();
    fs::write(dev.join("sda"), build_windows_gpt_image()).unwrap();
    write(&sys.join("class/block/sda/removable"), "0\n");
    write(&sys.join("class/block/sda/dev"), "8:0\n");
    let parts: [(u32, u64, u64); 5] = [
        (1, 2048, 4096),   // EFI System
        (2, 6144, 2048),   // MSR
        (3, 8192, 2048),   // Basic Data (NTFS)
        (4, 10240, 2048),  // Windows Recovery
        (5, 12288, 2048),  // LUKS
    ];
    for (n, start, size) in parts {
        let base = sys.join(format!("class/block/sda/sda{}", n));
        write(&base.join("partition"), &format!("{}\n", n));
        write(&base.join("size"), &format!("{}\n", size));
        write(&base.join("start"), &format!("{}\n", start));
        write(&base.join("dev"), &format!("8:{}\n", n));
        // Guard-chain view: partitions also appear as top-level class/block
        // entries with a sys/block/<disk>/<part> parent node (real sysfs has
        // class/block/sdaN as a symlink; plain dirs satisfy both readers).
        let top = sys.join(format!("class/block/sda{}", n));
        write(&top.join("partition"), &format!("{}\n", n));
        write(&top.join("size"), &format!("{}\n", size));
        write(&top.join("start"), &format!("{}\n", start));
        write(&top.join("dev"), &format!("8:{}\n", n));
        write(&sys.join(format!("block/sda/sda{}", n)), "");
    }
    // Boot from a live USB (sdb, 8:16); sda is the internal target disk —
    // the same situation the golden protocol captures in production.
    write(
        &proc.join("self/mountinfo"),
        "25 30 8:16 / / rw,relatime shared:1 - ext4 /dev/sdb rw\n",
    );
    write(
        &proc.join("swaps"),
        "Filename\t\t\t\tType\t\tSize\tUsed\tPriority\n",
    );
    GoldenFixture {
        _tmp: tmp,
        ctx: FsContext { proc_root: proc, sys_root: sys, dev_root: dev },
    }
}

// ---------------------------------------------------------------------------
// Golden comparison helper
// ---------------------------------------------------------------------------

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/golden")
        .join(name)
}

/// Compare `actual` against the committed golden; with ZT_UPDATE_GOLDEN=1 the
/// golden is (re)written instead.
fn assert_matches_golden(name: &str, actual: &str) {
    let path = golden_path(name);
    if std::env::var("ZT_UPDATE_GOLDEN").ok().as_deref() == Some("1") {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing golden {}: {} (run ZT_UPDATE_GOLDEN=1 once)", name, e));
    assert_eq!(
        expected, actual,
        "protocol output changed — this is a behavior change unless explicitly intended and reviewed"
    );
}

/// Replace the ephemeral tempdir root so goldens are machine-independent.
fn normalize(s: &str, f: &GoldenFixture) -> String {
    s.replace(f._tmp.path().to_str().unwrap(), "<FIXTURE_ROOT>")
}

// ---------------------------------------------------------------------------
// Golden 1: partitions protocol payload
// ---------------------------------------------------------------------------

#[test]
fn golden_partitions_report_json() {
    let f = build_golden_fixture();
    let report = enumerate_partitions_ctx("/dev/sda", &f.ctx).expect("enumerate");
    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    assert_matches_golden("partitions_report.json", &normalize(&json, &f));
}

// ---------------------------------------------------------------------------
// Golden 2: representative dry-run ExecutionReport (partition discard path)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn golden_dry_run_execution_report_json() {
    let f = build_golden_fixture();
    let fp = compute_partition_table_fingerprint("sda", &f.ctx).unwrap();
    let params = PartitionTargetParams {
        expected_partition_num: 3,
        expected_start_sector: 8192,
        expected_size_sectors: 2048,
        expected_partuuid: None,
        expected_table_fingerprint: fp,
    };
    let (tx, _rx) = mpsc::channel(64);
    let report =
        discard_erase_partition_ctx("/dev/sda3", "GOLDEN-SERIAL", "GOLDEN-SERIAL", &params, true, tx, &f.ctx)
            .await
            .expect("dry-run partition discard should succeed");
    let json = serde_json::to_string_pretty(&report).unwrap() + "\n";
    assert_matches_golden("dry_run_execution_report.json", &normalize(&json, &f));
}
