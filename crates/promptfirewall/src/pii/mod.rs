mod patterns;
mod luhn;
mod checksum;
mod entities;

pub use entities::PiiType;

use crate::result::PiiFinding;

pub fn scan_pii(text: &str, types: &[PiiType]) -> Vec<PiiFinding> {
    let mut findings = Vec::new();
    for pii_type in types {
        let detector_findings = match pii_type {
            PiiType::Ssn => patterns::detect_ssn(text),
            PiiType::CreditCard => patterns::detect_credit_card(text),
            PiiType::Iban => patterns::detect_iban(text),
            PiiType::Email => patterns::detect_email(text),
            PiiType::Phone => patterns::detect_phone(text),
            PiiType::IpAddress => patterns::detect_ip_address(text),
            PiiType::AwsKey => patterns::detect_aws_key(text),
            PiiType::ApiKey => patterns::detect_api_key(text),
        };
        findings.extend(detector_findings);
    }
    findings.sort_by_key(|f| f.start);
    findings
}
