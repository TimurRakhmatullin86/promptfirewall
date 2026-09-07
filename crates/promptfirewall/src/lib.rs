mod config;
mod injection;
mod pii;
mod redact;
mod result;

pub use config::{RedactStrategy, ScanConfig};
pub use pii::PiiType;
pub use result::{PiiFinding, ScanResult};

use std::time::Instant;

pub fn scan(text: &str, config: &ScanConfig) -> ScanResult {
    let start = Instant::now();

    let pii_findings = if config.detect_pii {
        pii::scan_pii(text, &config.pii_types)
    } else {
        Vec::new()
    };

    let (injection_score, injection_labels) = if config.detect_injection {
        injection::scan_injection(text, config.injection_threshold)
    } else {
        (0.0, Vec::new())
    };

    let redacted_text = if config.redact && !pii_findings.is_empty() {
        Some(redact::redact_text(
            text,
            &pii_findings,
            &config.redact_with,
        ))
    } else {
        None
    };

    let is_safe = pii_findings.is_empty() && injection_score < config.injection_threshold;
    let latency_us = start.elapsed().as_micros() as u64;

    ScanResult {
        is_safe,
        pii_findings,
        injection_score,
        injection_labels,
        redacted_text,
        latency_us,
    }
}

pub fn is_safe(text: &str) -> bool {
    scan(text, &ScanConfig::default()).is_safe
}
