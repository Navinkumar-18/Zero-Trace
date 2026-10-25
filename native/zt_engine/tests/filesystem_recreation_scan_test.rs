//! Phase F static scan: formatter tools may only appear in a function that
//! takes a guard-minted `ValidatedTarget`.

use std::path::{Path, PathBuf};

const FORMATTERS: &[&str] = &["mkfs.vfat", "mkfs.exfat", "mkfs.ntfs", "mkfs.ext4"];

fn collect_rs(dir: PathBuf, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(&dir).expect("read src") {
        let path = entry.expect("entry").path();
        if path.is_dir() {
            collect_rs(path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn enclosing_signature(lines: &[&str], idx: usize) -> String {
    for i in (0..=idx).rev() {
        let t = lines[i].trim_start();
        if t.starts_with("fn ")
            || t.starts_with("pub fn ")
            || t.starts_with("pub(crate) fn ")
            || t.starts_with("pub async fn ")
            || t.starts_with("async fn ")
        {
            let mut sig = String::new();
            let mut j = i;
            loop {
                sig.push_str(lines[j]);
                sig.push('\n');
                if lines[j].contains('{') || j == idx {
                    break;
                }
                j += 1;
            }
            return sig;
        }
    }
    String::new()
}

#[test]
fn formatter_tools_only_appear_in_a_validated_target_function() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    collect_rs(src, &mut files);
    assert!(
        files.len() >= 6,
        "static scan did not see the crate sources"
    );

    let mut violations = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("read source");
        let lines: Vec<&str> = text.split('\n').collect();
        let mut in_tests = false;
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed == "mod tests {" {
                in_tests = true;
                continue;
            }
            if in_tests {
                if *line == "}" {
                    in_tests = false;
                }
                continue;
            }
            if FORMATTERS.iter().any(|tool| line.contains(tool)) {
                let sig = enclosing_signature(&lines, idx);
                if !sig.contains("ValidatedTarget") {
                    violations.push(format!(
                        "{}:{}: formatter tool outside a ValidatedTarget function ({})",
                        file.display(),
                        idx + 1,
                        sig.lines().next().unwrap_or("<no function>")
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "formatter tools must take a guard-minted target:\n{}",
        violations.join("\n")
    );
}
