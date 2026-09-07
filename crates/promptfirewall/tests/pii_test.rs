use promptfirewall::{scan, ScanConfig, PiiType, RedactStrategy};

#[test]
fn detects_ssn_in_prompt() {
    let result = scan(
        "My social security number is 123-45-6789",
        &ScanConfig::pii_only(),
    );
    assert!(!result.is_safe);
    assert_eq!(result.pii_findings.len(), 1);
    assert_eq!(result.pii_findings[0].entity_type, PiiType::Ssn);
    assert_eq!(result.pii_findings[0].text, "123-45-6789");
}

#[test]
fn detects_credit_card_luhn_valid() {
    let result = scan(
        "Please charge my card 4111111111111111",
        &ScanConfig::pii_only(),
    );
    assert!(!result.is_safe);
    assert_eq!(result.pii_findings[0].entity_type, PiiType::CreditCard);
}

#[test]
fn rejects_credit_card_luhn_invalid() {
    let result = scan(
        "Not a card: 1234567890123456",
        &ScanConfig::pii_only(),
    );
    let cc_findings: Vec<_> = result
        .pii_findings
        .iter()
        .filter(|f| f.entity_type == PiiType::CreditCard)
        .collect();
    assert!(cc_findings.is_empty());
}

#[test]
fn detects_iban() {
    let result = scan(
        "Wire to DE89370400440532013000 please",
        &ScanConfig::pii_only(),
    );
    assert!(!result.is_safe);
    assert_eq!(result.pii_findings[0].entity_type, PiiType::Iban);
}

#[test]
fn detects_email() {
    let result = scan(
        "Contact me at alice@example.com for details",
        &ScanConfig::pii_only(),
    );
    assert!(!result.is_safe);
    assert_eq!(result.pii_findings[0].entity_type, PiiType::Email);
}

#[test]
fn detects_aws_key() {
    let result = scan(
        "My AWS key is AKIAIOSFODNN7EXAMPLE",
        &ScanConfig::pii_only(),
    );
    assert!(!result.is_safe);
    assert_eq!(result.pii_findings[0].entity_type, PiiType::AwsKey);
}

#[test]
fn safe_text_passes() {
    let result = scan(
        "Hello! The weather is nice today. Let's discuss the project.",
        &ScanConfig::default(),
    );
    assert!(result.is_safe);
    assert!(result.pii_findings.is_empty());
    assert!(result.injection_score < 0.7);
}

#[test]
fn redaction_mask() {
    let config = ScanConfig::pii_only().with_redact(RedactStrategy::Mask);
    let result = scan("SSN: 123-45-6789", &config);
    assert!(result.redacted_text.is_some());
    let redacted = result.redacted_text.unwrap();
    assert!(!redacted.contains("123-45-6789"));
    assert!(redacted.contains("[SSN:"));
}

#[test]
fn redaction_placeholder() {
    let config = ScanConfig::pii_only().with_redact(RedactStrategy::Placeholder);
    let result = scan("email: test@corp.com", &config);
    let redacted = result.redacted_text.unwrap();
    assert_eq!(redacted, "email: [EMAIL]");
}

#[test]
fn multiple_pii_types() {
    let result = scan(
        "SSN: 123-45-6789, card: 4111111111111111, email: user@test.com",
        &ScanConfig::pii_only(),
    );
    assert!(!result.is_safe);
    let types: Vec<PiiType> = result.pii_findings.iter().map(|f| f.entity_type).collect();
    assert!(types.contains(&PiiType::Ssn));
    assert!(types.contains(&PiiType::CreditCard));
    assert!(types.contains(&PiiType::Email));
}

#[test]
fn latency_is_recorded() {
    let result = scan("test text", &ScanConfig::default());
    // Just verify it's populated (will be very small in tests)
    assert!(result.latency_us < 100_000); // should be well under 100ms
}
