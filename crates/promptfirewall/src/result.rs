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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreDetail {
    pub points: i32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyScore {
    pub score: u8,
    pub grade: char,
    pub details: Vec<ScoreDetail>,
}

impl SafetyScore {
    pub fn badge_color(&self) -> &'static str {
        match self.grade {
            'A' => "brightgreen",
            'B' => "green",
            'C' => "yellow",
            'D' => "orange",
            _ => "red",
        }
    }
}

fn grade_from_score(score: u8) -> char {
    match score {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    }
}

pub fn compute_safety_score(result: &ScanResult) -> SafetyScore {
    let mut score: i32 = 100;
    let mut details = Vec::new();

    let pii_count = result.pii_findings.len() as i32;
    if pii_count > 0 {
        let pii_penalty = (pii_count * 15).min(45);
        score -= pii_penalty;
        let types: Vec<String> = result
            .pii_findings
            .iter()
            .map(|f| f.entity_type.label().to_string())
            .collect();
        let unique_types: Vec<String> = {
            let mut seen = Vec::new();
            for t in types {
                if !seen.contains(&t) {
                    seen.push(t);
                }
            }
            seen
        };
        details.push(ScoreDetail {
            points: -pii_penalty,
            reason: format!("PII detected ({})", unique_types.join(", ")),
        });
    }

    if result.injection_score > 0.7 {
        score -= 30;
        details.push(ScoreDetail {
            points: -30,
            reason: format!("Injection score {:.2}", result.injection_score),
        });
    } else if result.injection_score > 0.4 {
        score -= 15;
        details.push(ScoreDetail {
            points: -15,
            reason: format!("Injection score {:.2}", result.injection_score),
        });
    }

    let heuristic_count = result.injection_labels.iter()
        .filter(|l| !matches!(l.as_str(), "tfidf_suspicious" | "high_entropy_payload"))
        .count() as i32;
    if heuristic_count > 0 {
        let heuristic_penalty = (heuristic_count * 5).min(20);
        score -= heuristic_penalty;
        details.push(ScoreDetail {
            points: -heuristic_penalty,
            reason: format!("{} heuristic match(es)", heuristic_count),
        });
    }

    if result.injection_labels.contains(&"high_entropy_payload".to_string()) {
        score -= 10;
        details.push(ScoreDetail {
            points: -10,
            reason: "Entropy anomaly".to_string(),
        });
    }

    let final_score = score.clamp(0, 100) as u8;
    let grade = grade_from_score(final_score);

    SafetyScore {
        score: final_score,
        grade,
        details,
    }
}
