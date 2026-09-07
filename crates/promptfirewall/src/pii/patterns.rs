use once_cell::sync::Lazy;
use regex::Regex;

use super::checksum;
use super::luhn;
use crate::pii::PiiType;
use crate::result::PiiFinding;

static SSN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(\d{3})-(\d{2})-(\d{4})\b").unwrap());

static CC_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{3,4})\b").unwrap());

static IBAN_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b([A-Z]{2}\d{2}\s?[A-Z0-9]{4}[\sA-Z0-9]{10,30})\b").unwrap());

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b").unwrap());

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b").unwrap()
});

static IP_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap());

static AWS_KEY_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").unwrap());

static API_KEY_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(sk-[a-zA-Z0-9]{20,}|pk_live_[a-zA-Z0-9]{20,}|rk_live_[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|xox[baprs]-[a-zA-Z0-9\-]{10,})\b").unwrap()
});

fn make_finding(pii_type: PiiType, start: usize, end: usize, text: &str) -> PiiFinding {
    PiiFinding {
        entity_type: pii_type,
        start,
        end,
        text: text.to_string(),
        confidence: 1.0,
    }
}

pub fn detect_ssn(text: &str) -> Vec<PiiFinding> {
    SSN_RE
        .captures_iter(text)
        .filter_map(|cap| {
            let m = cap.get(0)?;
            let area: u16 = cap[1].parse().ok()?;
            let group: u16 = cap[2].parse().ok()?;
            let serial: u16 = cap[3].parse().ok()?;
            if !checksum::validate_ssn_area(area) || group == 0 || serial == 0 {
                return None;
            }
            Some(make_finding(PiiType::Ssn, m.start(), m.end(), m.as_str()))
        })
        .collect()
}

pub fn detect_credit_card(text: &str) -> Vec<PiiFinding> {
    CC_RE
        .find_iter(text)
        .filter_map(|m| {
            if luhn::validate(m.as_str()) {
                Some(make_finding(
                    PiiType::CreditCard,
                    m.start(),
                    m.end(),
                    m.as_str(),
                ))
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_iban(text: &str) -> Vec<PiiFinding> {
    IBAN_RE
        .find_iter(text)
        .filter_map(|m| {
            if checksum::validate_iban(m.as_str()) {
                Some(make_finding(PiiType::Iban, m.start(), m.end(), m.as_str()))
            } else {
                None
            }
        })
        .collect()
}

pub fn detect_email(text: &str) -> Vec<PiiFinding> {
    EMAIL_RE
        .find_iter(text)
        .map(|m| make_finding(PiiType::Email, m.start(), m.end(), m.as_str()))
        .collect()
}

pub fn detect_phone(text: &str) -> Vec<PiiFinding> {
    PHONE_RE
        .find_iter(text)
        .map(|m| make_finding(PiiType::Phone, m.start(), m.end(), m.as_str()))
        .collect()
}

pub fn detect_ip_address(text: &str) -> Vec<PiiFinding> {
    IP_RE
        .captures_iter(text)
        .filter_map(|cap| {
            let m = cap.get(0)?;
            let valid = (1..=4).all(|i| cap[i].parse::<u16>().is_ok_and(|v| v <= 255));
            if !valid {
                return None;
            }
            // Skip common non-PII IPs
            let ip = m.as_str();
            if ip == "0.0.0.0" || ip == "127.0.0.1" || ip == "255.255.255.255" {
                return None;
            }
            Some(make_finding(PiiType::IpAddress, m.start(), m.end(), ip))
        })
        .collect()
}

pub fn detect_aws_key(text: &str) -> Vec<PiiFinding> {
    AWS_KEY_RE
        .find_iter(text)
        .map(|m| make_finding(PiiType::AwsKey, m.start(), m.end(), m.as_str()))
        .collect()
}

pub fn detect_api_key(text: &str) -> Vec<PiiFinding> {
    API_KEY_RE
        .find_iter(text)
        .map(|m| make_finding(PiiType::ApiKey, m.start(), m.end(), m.as_str()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_valid_ssn() {
        let findings = detect_ssn("my ssn is 123-45-6789");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "123-45-6789");
        assert_eq!(findings[0].entity_type, PiiType::Ssn);
    }

    #[test]
    fn rejects_invalid_ssn_area_000() {
        assert!(detect_ssn("ssn: 000-12-3456").is_empty());
    }

    #[test]
    fn rejects_invalid_ssn_area_666() {
        assert!(detect_ssn("ssn: 666-12-3456").is_empty());
    }

    #[test]
    fn rejects_invalid_ssn_area_900() {
        assert!(detect_ssn("ssn: 900-12-3456").is_empty());
    }

    #[test]
    fn rejects_ssn_zero_group() {
        assert!(detect_ssn("ssn: 123-00-6789").is_empty());
    }

    #[test]
    fn detects_valid_cc_visa() {
        let findings = detect_credit_card("card: 4111111111111111");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_type, PiiType::CreditCard);
    }

    #[test]
    fn detects_cc_with_spaces() {
        let findings = detect_credit_card("pay with 4111 1111 1111 1111 please");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn rejects_invalid_cc() {
        assert!(detect_credit_card("card: 4111111111111112").is_empty());
    }

    #[test]
    fn detects_valid_iban() {
        let findings = detect_iban("transfer to DE89370400440532013000");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_type, PiiType::Iban);
    }

    #[test]
    fn rejects_invalid_iban() {
        assert!(detect_iban("iban: DE00370400440532013000").is_empty());
    }

    #[test]
    fn detects_email() {
        let findings = detect_email("send to user@example.com today");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "user@example.com");
    }

    #[test]
    fn detects_phone() {
        let findings = detect_phone("call me at +1 555-123-4567");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn detects_ip_address() {
        let findings = detect_ip_address("server at 192.168.1.100");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].text, "192.168.1.100");
    }

    #[test]
    fn skips_loopback_ip() {
        assert!(detect_ip_address("localhost 127.0.0.1").is_empty());
    }

    #[test]
    fn rejects_invalid_ip() {
        assert!(detect_ip_address("bad ip 999.999.999.999").is_empty());
    }

    #[test]
    fn detects_aws_key() {
        let findings = detect_aws_key("key: AKIAIOSFODNN7EXAMPLE");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_type, PiiType::AwsKey);
    }

    #[test]
    fn detects_github_pat() {
        let findings = detect_api_key("token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entity_type, PiiType::ApiKey);
    }

    #[test]
    fn detects_openai_key() {
        let findings = detect_api_key("key: sk-abcdefghijklmnopqrstuvwxyz1234567890");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn no_false_positives_on_normal_text() {
        let text = "Hello, I would like to discuss the project timeline. \
                    The budget is $50,000 and we have 3 developers.";
        assert!(detect_ssn(text).is_empty());
        assert!(detect_credit_card(text).is_empty());
        assert!(detect_iban(text).is_empty());
        assert!(detect_aws_key(text).is_empty());
        assert!(detect_api_key(text).is_empty());
    }

    #[test]
    fn multiple_pii_in_one_text() {
        let text = "SSN: 123-45-6789, email: test@corp.com, card: 4111111111111111";
        let ssns = detect_ssn(text);
        let emails = detect_email(text);
        let cards = detect_credit_card(text);
        assert_eq!(ssns.len(), 1);
        assert_eq!(emails.len(), 1);
        assert_eq!(cards.len(), 1);
    }
}
