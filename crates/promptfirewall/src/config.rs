use serde::{Deserialize, Serialize};

use crate::pii::PiiType;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum RedactStrategy {
    #[default]
    Mask,
    Hash,
    Placeholder,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub detect_pii: bool,
    pub detect_injection: bool,
    pub pii_types: Vec<PiiType>,
    pub injection_threshold: f32,
    pub redact: bool,
    pub redact_with: RedactStrategy,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            detect_pii: true,
            detect_injection: true,
            pii_types: PiiType::all(),
            injection_threshold: 0.7,
            redact: false,
            redact_with: RedactStrategy::default(),
        }
    }
}

impl ScanConfig {
    pub fn pii_only() -> Self {
        Self {
            detect_injection: false,
            ..Self::default()
        }
    }

    pub fn injection_only() -> Self {
        Self {
            detect_pii: false,
            ..Self::default()
        }
    }

    pub fn with_redact(mut self, strategy: RedactStrategy) -> Self {
        self.redact = true;
        self.redact_with = strategy;
        self
    }
}
