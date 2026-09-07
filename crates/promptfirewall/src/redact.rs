use crate::config::RedactStrategy;
use crate::result::PiiFinding;

pub fn redact_text(
    text: &str,
    findings: &[PiiFinding],
    strategy: &RedactStrategy,
) -> String {
    if findings.is_empty() {
        return text.to_string();
    }

    // Sort findings by start position in reverse so we can replace from end to start
    let mut sorted: Vec<&PiiFinding> = findings.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.start));

    let mut result = text.to_string();

    for finding in sorted {
        let replacement = match strategy {
            RedactStrategy::Mask => {
                let label = finding.entity_type.label();
                let mask_len = finding.end - finding.start;
                format!("[{}: {}]", label, "*".repeat(mask_len.min(8)))
            }
            RedactStrategy::Hash => {
                let hash = simple_hash(&finding.text);
                format!("[{}:{}]", finding.entity_type.label(), hash)
            }
            RedactStrategy::Placeholder => {
                format!("[{}]", finding.entity_type.label())
            }
        };

        // Bounds check
        if finding.start <= result.len() && finding.end <= result.len() {
            result.replace_range(finding.start..finding.end, &replacement);
        }
    }

    result
}

fn simple_hash(text: &str) -> String {
    // FNV-1a 32-bit for deterministic, fast hashing
    let mut hash: u32 = 2166136261;
    for byte in text.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    format!("{:08x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::PiiType;

    fn make_finding(pii_type: PiiType, start: usize, end: usize, text: &str) -> PiiFinding {
        PiiFinding {
            entity_type: pii_type,
            start,
            end,
            text: text.to_string(),
            confidence: 1.0,
        }
    }

    #[test]
    fn mask_strategy() {
        let text = "SSN is 123-45-6789";
        let findings = vec![make_finding(PiiType::Ssn, 7, 18, "123-45-6789")];
        let result = redact_text(text, &findings, &RedactStrategy::Mask);
        assert!(result.contains("[SSN:"));
        assert!(!result.contains("123-45-6789"));
    }

    #[test]
    fn placeholder_strategy() {
        let text = "email: test@example.com";
        let findings = vec![make_finding(PiiType::Email, 7, 23, "test@example.com")];
        let result = redact_text(text, &findings, &RedactStrategy::Placeholder);
        assert_eq!(result, "email: [EMAIL]");
    }

    #[test]
    fn hash_strategy_deterministic() {
        let text = "card: 4111111111111111";
        let findings = vec![make_finding(PiiType::CreditCard, 6, 22, "4111111111111111")];
        let r1 = redact_text(text, &findings, &RedactStrategy::Hash);
        let r2 = redact_text(text, &findings, &RedactStrategy::Hash);
        assert_eq!(r1, r2);
        assert!(!r1.contains("4111111111111111"));
    }

    #[test]
    fn multiple_findings() {
        let text = "SSN: 123-45-6789 email: test@corp.com";
        let findings = vec![
            make_finding(PiiType::Ssn, 5, 16, "123-45-6789"),
            make_finding(PiiType::Email, 24, 37, "test@corp.com"),
        ];
        let result = redact_text(text, &findings, &RedactStrategy::Placeholder);
        assert_eq!(result, "SSN: [SSN] email: [EMAIL]");
    }

    #[test]
    fn empty_findings() {
        let result = redact_text("hello world", &[], &RedactStrategy::Mask);
        assert_eq!(result, "hello world");
    }
}
