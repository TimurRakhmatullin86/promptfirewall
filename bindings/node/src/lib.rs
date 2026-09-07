use napi::bindgen_prelude::*;
use napi_derive::napi;

#[napi(object)]
pub struct JsPiiFinding {
    pub entity_type: String,
    pub start: u32,
    pub end: u32,
    pub text: String,
    pub confidence: f64,
}

#[napi(object)]
pub struct JsScanResult {
    pub is_safe: bool,
    pub pii_findings: Vec<JsPiiFinding>,
    pub injection_score: f64,
    pub injection_labels: Vec<String>,
    pub redacted_text: Option<String>,
    pub latency_us: u32,
}

#[napi(object)]
pub struct JsScanOptions {
    pub detect_pii: Option<bool>,
    pub detect_injection: Option<bool>,
    pub pii_types: Option<Vec<String>>,
    pub injection_threshold: Option<f64>,
    pub redact: Option<bool>,
    pub redact_with: Option<String>,
}

fn parse_redact_strategy(s: &str) -> Result<promptfirewall::RedactStrategy> {
    match s.to_lowercase().as_str() {
        "mask" => Ok(promptfirewall::RedactStrategy::Mask),
        "hash" => Ok(promptfirewall::RedactStrategy::Hash),
        "placeholder" => Ok(promptfirewall::RedactStrategy::Placeholder),
        _ => Err(Error::new(
            Status::InvalidArg,
            format!("Invalid redact strategy '{}'. Use 'mask', 'hash', or 'placeholder'.", s),
        )),
    }
}

fn parse_pii_types(types: &[String]) -> Result<Vec<promptfirewall::PiiType>> {
    types
        .iter()
        .map(|t| match t.to_lowercase().as_str() {
            "ssn" => Ok(promptfirewall::PiiType::Ssn),
            "credit_card" | "creditcard" | "creditCard" => Ok(promptfirewall::PiiType::CreditCard),
            "iban" => Ok(promptfirewall::PiiType::Iban),
            "email" => Ok(promptfirewall::PiiType::Email),
            "phone" => Ok(promptfirewall::PiiType::Phone),
            "ip_address" | "ipaddress" | "ipAddress" | "ip" => {
                Ok(promptfirewall::PiiType::IpAddress)
            }
            "aws_key" | "awskey" | "awsKey" => Ok(promptfirewall::PiiType::AwsKey),
            "api_key" | "apikey" | "apiKey" => Ok(promptfirewall::PiiType::ApiKey),
            _ => Err(Error::new(
                Status::InvalidArg,
                format!(
                    "Unknown PII type '{}'. Valid: ssn, credit_card, iban, email, phone, ip_address, aws_key, api_key",
                    t
                ),
            )),
        })
        .collect()
}

fn convert_result(r: promptfirewall::ScanResult) -> JsScanResult {
    JsScanResult {
        is_safe: r.is_safe,
        pii_findings: r
            .pii_findings
            .into_iter()
            .map(|f| JsPiiFinding {
                entity_type: f.entity_type.label().to_string(),
                start: f.start as u32,
                end: f.end as u32,
                text: f.text,
                confidence: f.confidence as f64,
            })
            .collect(),
        injection_score: r.injection_score as f64,
        injection_labels: r.injection_labels,
        redacted_text: r.redacted_text,
        latency_us: r.latency_us as u32,
    }
}

#[napi]
pub fn scan(text: String, options: Option<JsScanOptions>) -> Result<JsScanResult> {
    let opts = options.unwrap_or(JsScanOptions {
        detect_pii: None,
        detect_injection: None,
        pii_types: None,
        injection_threshold: None,
        redact: None,
        redact_with: None,
    });

    let pii_types = match &opts.pii_types {
        Some(types) => parse_pii_types(types)?,
        None => promptfirewall::PiiType::all(),
    };

    let redact_with = match &opts.redact_with {
        Some(s) => parse_redact_strategy(s)?,
        None => promptfirewall::RedactStrategy::Mask,
    };

    let config = promptfirewall::ScanConfig {
        detect_pii: opts.detect_pii.unwrap_or(true),
        detect_injection: opts.detect_injection.unwrap_or(true),
        pii_types,
        injection_threshold: opts.injection_threshold.unwrap_or(0.7) as f32,
        redact: opts.redact.unwrap_or(false),
        redact_with,
    };

    let result = promptfirewall::scan(&text, &config);
    Ok(convert_result(result))
}

#[napi]
pub fn is_safe(text: String) -> bool {
    promptfirewall::is_safe(&text)
}

#[napi]
pub fn redact(text: String, redact_with: Option<String>) -> Result<String> {
    let strategy = match &redact_with {
        Some(s) => parse_redact_strategy(s)?,
        None => promptfirewall::RedactStrategy::Mask,
    };

    let config = promptfirewall::ScanConfig {
        detect_pii: true,
        detect_injection: false,
        pii_types: promptfirewall::PiiType::all(),
        injection_threshold: 0.7,
        redact: true,
        redact_with: strategy,
    };

    let result = promptfirewall::scan(&text, &config);
    Ok(result.redacted_text.unwrap_or_else(|| text.to_string()))
}

#[napi]
pub fn detect_injection(text: String, threshold: Option<f64>) -> JsScanResult {
    let config = promptfirewall::ScanConfig {
        detect_pii: false,
        detect_injection: true,
        pii_types: Vec::new(),
        injection_threshold: threshold.unwrap_or(0.7) as f32,
        redact: false,
        redact_with: promptfirewall::RedactStrategy::Mask,
    };

    convert_result(promptfirewall::scan(&text, &config))
}

#[napi]
pub fn detect_pii(text: String, pii_types: Option<Vec<String>>) -> Result<JsScanResult> {
    let pii_type_list = match &pii_types {
        Some(types) => parse_pii_types(types)?,
        None => promptfirewall::PiiType::all(),
    };

    let config = promptfirewall::ScanConfig {
        detect_pii: true,
        detect_injection: false,
        pii_types: pii_type_list,
        injection_threshold: 0.7,
        redact: false,
        redact_with: promptfirewall::RedactStrategy::Mask,
    };

    Ok(convert_result(promptfirewall::scan(&text, &config)))
}
