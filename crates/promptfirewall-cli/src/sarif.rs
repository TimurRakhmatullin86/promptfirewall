use crate::walker::{FileResult, LocatedPiiFinding};
use serde_json::{json, Value};

pub fn to_sarif(results: &[FileResult]) -> String {
    let sarif = json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "promptfirewall",
                    "informationUri": "https://github.com/TimurRakhmatullin86/promptfirewall",
                    "version": env!("CARGO_PKG_VERSION"),
                    "rules": rules()
                }
            },
            "results": build_results(results)
        }]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_default()
}

fn rules() -> Vec<Value> {
    vec![
        json!({
            "id": "PF001",
            "name": "PiiDetected",
            "shortDescription": { "text": "PII detected in source file" },
            "helpUri": "https://github.com/TimurRakhmatullin86/promptfirewall#pii-detection",
            "defaultConfiguration": { "level": "warning" }
        }),
        json!({
            "id": "PF002",
            "name": "PromptInjection",
            "shortDescription": { "text": "Prompt injection pattern detected" },
            "helpUri": "https://github.com/TimurRakhmatullin86/promptfirewall#injection-detection",
            "defaultConfiguration": { "level": "error" }
        }),
    ]
}

fn build_results(file_results: &[FileResult]) -> Vec<Value> {
    let mut sarif_results = Vec::new();

    for file_result in file_results {
        for pii in &file_result.pii_findings {
            sarif_results.push(pii_to_sarif(pii, &file_result.path));
        }
        if file_result.injection_detected {
            sarif_results.push(injection_to_sarif(file_result));
        }
    }

    sarif_results
}

fn pii_to_sarif(finding: &LocatedPiiFinding, path: &str) -> Value {
    json!({
        "ruleId": "PF001",
        "level": "warning",
        "message": {
            "text": format!(
                "{} detected (confidence: {:.0}%)",
                finding.entity_type.label(),
                finding.confidence * 100.0
            )
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": normalize_path(path)
                },
                "region": {
                    "startLine": finding.line,
                    "startColumn": finding.col_start,
                    "endColumn": finding.col_end
                }
            }
        }]
    })
}

fn injection_to_sarif(result: &FileResult) -> Value {
    json!({
        "ruleId": "PF002",
        "level": "error",
        "message": {
            "text": format!(
                "Prompt injection detected (score: {:.2}, labels: [{}])",
                result.injection_score,
                result.injection_labels.join(", ")
            )
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": normalize_path(&result.path)
                },
                "region": {
                    "startLine": 1,
                    "startColumn": 1
                }
            }
        }]
    })
}

fn normalize_path(path: &str) -> String {
    path.replace('\\', "/")
}
