mod sarif;
mod walker;

use clap::Parser;
use std::process;

#[derive(Parser)]
#[command(
    name = "promptfirewall",
    about = "Scan source files for PII leaks and prompt injection patterns",
    version
)]
struct Cli {
    /// Paths to scan (files or directories)
    #[arg(default_value = ".")]
    paths: Vec<String>,

    /// Glob patterns for files to include (e.g. "*.py,*.ts,*.yaml")
    #[arg(short, long, value_delimiter = ',')]
    include: Option<Vec<String>>,

    /// Glob patterns for files to exclude
    #[arg(short, long, value_delimiter = ',')]
    exclude: Option<Vec<String>>,

    /// Disable PII detection
    #[arg(long)]
    no_pii: bool,

    /// Disable injection detection
    #[arg(long)]
    no_injection: bool,

    /// Injection score threshold (0.0-1.0)
    #[arg(long, default_value = "0.7")]
    injection_threshold: f32,

    /// Output format
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// SARIF output file path
    #[arg(long)]
    sarif_file: Option<String>,

    /// Fail with exit code 1 if any findings
    #[arg(long)]
    fail_on_findings: bool,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn main() {
    let cli = Cli::parse();

    let config = promptfirewall::ScanConfig {
        detect_pii: !cli.no_pii,
        detect_injection: !cli.no_injection,
        injection_threshold: cli.injection_threshold,
        redact: false,
        ..Default::default()
    };

    let walker_config = walker::WalkerConfig {
        paths: cli.paths.clone(),
        include: cli.include.clone(),
        exclude: cli.exclude.clone(),
    };

    let file_results = walker::walk_and_scan(&walker_config, &config);

    let total_findings: usize = file_results
        .iter()
        .map(|r| r.pii_count + if r.injection_detected { 1 } else { 0 })
        .sum();

    match cli.format {
        OutputFormat::Text => print_text(&file_results, total_findings),
        OutputFormat::Json => print_json(&file_results),
        OutputFormat::Sarif => print_sarif(&file_results),
    }

    if let Some(path) = &cli.sarif_file {
        let sarif = sarif::to_sarif(&file_results);
        if let Err(e) = std::fs::write(path, sarif) {
            eprintln!("Error writing SARIF file: {e}");
            process::exit(2);
        }
        eprintln!("SARIF report written to {path}");
    }

    if cli.fail_on_findings && total_findings > 0 {
        process::exit(1);
    }
}

fn print_text(results: &[walker::FileResult], total: usize) {
    let files_scanned = results.len();
    let files_with_findings = results.iter().filter(|r| r.has_findings()).count();

    for result in results {
        if !result.has_findings() {
            continue;
        }
        println!("--- {} ---", result.path);
        for finding in &result.pii_findings {
            println!(
                "  PII [{:.0}%] {}: line {} col {}-{} \"{}\"",
                finding.confidence * 100.0,
                finding.entity_type.label(),
                finding.line,
                finding.col_start,
                finding.col_end,
                truncate(&finding.text, 40),
            );
        }
        if result.injection_detected {
            println!(
                "  INJECTION [{:.0}%] score={:.2} labels=[{}]",
                result.injection_score * 100.0,
                result.injection_score,
                result.injection_labels.join(", "),
            );
        }
    }

    println!();
    println!(
        "Scanned {files_scanned} files, {files_with_findings} with findings, {total} total findings"
    );
}

fn print_json(results: &[walker::FileResult]) {
    let json = serde_json::to_string_pretty(results).unwrap_or_default();
    println!("{json}");
}

fn print_sarif(results: &[walker::FileResult]) {
    println!("{}", sarif::to_sarif(results));
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
