use ignore::WalkBuilder;
use promptfirewall::{PiiFinding, PiiType, ScanConfig};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub struct WalkerConfig {
    pub paths: Vec<String>,
    pub include: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LocatedPiiFinding {
    pub entity_type: PiiType,
    pub line: usize,
    pub col_start: usize,
    pub col_end: usize,
    pub text: String,
    pub confidence: f32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileResult {
    pub path: String,
    pub pii_findings: Vec<LocatedPiiFinding>,
    pub pii_count: usize,
    pub injection_detected: bool,
    pub injection_score: f32,
    pub injection_labels: Vec<String>,
    pub latency_us: u64,
}

impl FileResult {
    pub fn has_findings(&self) -> bool {
        self.pii_count > 0 || self.injection_detected
    }
}

const DEFAULT_EXTENSIONS: &[&str] = &[
    "py", "ts", "tsx", "js", "jsx", "yaml", "yml", "json", "toml", "env", "cfg", "ini", "conf",
    "txt", "md", "rst", "go", "rs", "java", "kt", "rb", "php", "sh", "bash", "zsh", "sql",
    "graphql", "proto", "tf", "hcl", "dockerfile",
];

pub fn walk_and_scan(walker_config: &WalkerConfig, scan_config: &ScanConfig) -> Vec<FileResult> {
    let mut results = Vec::new();

    for scan_path in &walker_config.paths {
        let path = Path::new(scan_path);
        if path.is_file() {
            if let Some(r) = scan_file(path, scan_config) {
                results.push(r);
            }
            continue;
        }

        let mut builder = WalkBuilder::new(path);
        builder.hidden(true).git_ignore(true).git_global(false);

        for entry in builder.build().flatten() {
            let entry_path = entry.path();
            if !entry_path.is_file() {
                continue;
            }

            if !should_include(entry_path, walker_config) {
                continue;
            }

            if let Some(r) = scan_file(entry_path, scan_config) {
                results.push(r);
            }
        }
    }

    results
}

fn should_include(path: &Path, config: &WalkerConfig) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Check exclude patterns first
    if let Some(excludes) = &config.exclude {
        for pattern in excludes {
            if matches_pattern(name, &ext, pattern) {
                return false;
            }
        }
    }

    // Check include patterns
    if let Some(includes) = &config.include {
        for pattern in includes {
            if matches_pattern(name, &ext, pattern) {
                return true;
            }
        }
        return false;
    }

    // Default: scan common text file extensions
    DEFAULT_EXTENSIONS.contains(&ext.as_str()) || name.starts_with('.')
}

fn matches_pattern(name: &str, ext: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if let Some(stripped) = pattern.strip_prefix("*.") {
        ext == stripped
    } else {
        glob::Pattern::new(pattern)
            .map(|p| p.matches(name))
            .unwrap_or(false)
    }
}

fn scan_file(path: &Path, config: &ScanConfig) -> Option<FileResult> {
    let content = std::fs::read_to_string(path).ok()?;
    if content.is_empty() {
        return None;
    }

    let scan_result = promptfirewall::scan(&content, config);

    let pii_findings: Vec<LocatedPiiFinding> = scan_result
        .pii_findings
        .iter()
        .map(|f| locate_finding(&content, f))
        .collect();

    let pii_count = pii_findings.len();

    Some(FileResult {
        path: path.display().to_string(),
        pii_findings,
        pii_count,
        injection_detected: scan_result.injection_score >= config.injection_threshold,
        injection_score: scan_result.injection_score,
        injection_labels: scan_result.injection_labels,
        latency_us: scan_result.latency_us,
    })
}

fn locate_finding(content: &str, finding: &PiiFinding) -> LocatedPiiFinding {
    let before = &content[..finding.start];
    let line = before.chars().filter(|&c| c == '\n').count() + 1;
    let last_newline = before.rfind('\n').map(|i| i + 1).unwrap_or(0);
    let col_start = finding.start - last_newline + 1;
    let col_end = col_start + (finding.end - finding.start);

    LocatedPiiFinding {
        entity_type: finding.entity_type,
        line,
        col_start,
        col_end,
        text: finding.text.clone(),
        confidence: finding.confidence,
    }
}
