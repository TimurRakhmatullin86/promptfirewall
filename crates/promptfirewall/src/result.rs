use serde::{Deserialize, Serialize};

use crate::pii::PiiType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiiFinding {
    pub entity_type: PiiType,
    pub start: usize,
    pub end: usize,
    pub text: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub is_safe: bool,
    pub pii_findings: Vec<PiiFinding>,
    pub injection_score: f32,
    pub injection_labels: Vec<String>,
    pub redacted_text: Option<String>,
    pub latency_us: u64,
}
