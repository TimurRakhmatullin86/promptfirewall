use pyo3::prelude::*;
use pyo3::types::PyDict;

#[pyclass(frozen)]
#[derive(Clone)]
struct PiiFinding {
    #[pyo3(get)]
    entity_type: String,
    #[pyo3(get)]
    start: usize,
    #[pyo3(get)]
    end: usize,
    #[pyo3(get)]
    text: String,
    #[pyo3(get)]
    confidence: f32,
}

#[pymethods]
impl PiiFinding {
    fn __repr__(&self) -> String {
        format!(
            "PiiFinding(entity_type='{}', start={}, end={}, text='{}', confidence={:.2})",
            self.entity_type, self.start, self.end, self.text, self.confidence
        )
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("entity_type", &self.entity_type)?;
        dict.set_item("start", self.start)?;
        dict.set_item("end", self.end)?;
        dict.set_item("text", &self.text)?;
        dict.set_item("confidence", self.confidence)?;
        Ok(dict)
    }
}

#[pyclass(frozen)]
#[derive(Clone)]
struct ScanResult {
    #[pyo3(get)]
    is_safe: bool,
    #[pyo3(get)]
    pii_findings: Vec<PiiFinding>,
    #[pyo3(get)]
    injection_score: f32,
    #[pyo3(get)]
    injection_labels: Vec<String>,
    #[pyo3(get)]
    redacted_text: Option<String>,
    #[pyo3(get)]
    latency_us: u64,
}

#[pymethods]
impl ScanResult {
    fn __repr__(&self) -> String {
        format!(
            "ScanResult(is_safe={}, pii_count={}, injection_score={:.3}, latency_us={})",
            self.is_safe,
            self.pii_findings.len(),
            self.injection_score,
            self.latency_us
        )
    }

    fn to_dict<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        dict.set_item("is_safe", self.is_safe)?;
        let findings: Vec<_> = self
            .pii_findings
            .iter()
            .map(|f| f.to_dict(py))
            .collect::<PyResult<Vec<_>>>()?;
        dict.set_item("pii_findings", findings)?;
        dict.set_item("injection_score", self.injection_score)?;
        dict.set_item("injection_labels", &self.injection_labels)?;
        dict.set_item("redacted_text", &self.redacted_text)?;
        dict.set_item("latency_us", self.latency_us)?;
        Ok(dict)
    }
}

fn convert_result(r: promptfirewall::ScanResult) -> ScanResult {
    ScanResult {
        is_safe: r.is_safe,
        pii_findings: r
            .pii_findings
            .into_iter()
            .map(|f| PiiFinding {
                entity_type: f.entity_type.label().to_string(),
                start: f.start,
                end: f.end,
                text: f.text,
                confidence: f.confidence,
            })
            .collect(),
        injection_score: r.injection_score,
        injection_labels: r.injection_labels,
        redacted_text: r.redacted_text,
        latency_us: r.latency_us,
    }
}

fn parse_redact_strategy(s: &str) -> PyResult<promptfirewall::RedactStrategy> {
    match s.to_lowercase().as_str() {
        "mask" => Ok(promptfirewall::RedactStrategy::Mask),
        "hash" => Ok(promptfirewall::RedactStrategy::Hash),
        "placeholder" => Ok(promptfirewall::RedactStrategy::Placeholder),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Invalid redact strategy '{}'. Use 'mask', 'hash', or 'placeholder'.",
            s
        ))),
    }
}

fn parse_pii_types(types: Vec<String>) -> PyResult<Vec<promptfirewall::PiiType>> {
    types
        .iter()
        .map(|t| match t.to_lowercase().as_str() {
            "ssn" => Ok(promptfirewall::PiiType::Ssn),
            "credit_card" | "creditcard" => Ok(promptfirewall::PiiType::CreditCard),
            "iban" => Ok(promptfirewall::PiiType::Iban),
            "email" => Ok(promptfirewall::PiiType::Email),
            "phone" => Ok(promptfirewall::PiiType::Phone),
            "ip_address" | "ipaddress" | "ip" => Ok(promptfirewall::PiiType::IpAddress),
            "aws_key" | "awskey" => Ok(promptfirewall::PiiType::AwsKey),
            "api_key" | "apikey" => Ok(promptfirewall::PiiType::ApiKey),
            _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Unknown PII type '{}'. Valid: ssn, credit_card, iban, email, phone, ip_address, aws_key, api_key",
                t
            ))),
        })
        .collect()
}

#[pyfunction]
#[pyo3(signature = (
    text,
    *,
    detect_pii = true,
    detect_injection = true,
    pii_types = None,
    injection_threshold = 0.7,
    redact = false,
    redact_with = "mask"
))]
fn scan(
    text: &str,
    detect_pii: bool,
    detect_injection: bool,
    pii_types: Option<Vec<String>>,
    injection_threshold: f32,
    redact: bool,
    redact_with: &str,
) -> PyResult<ScanResult> {
    let pii_type_list = match pii_types {
        Some(types) => parse_pii_types(types)?,
        None => promptfirewall::PiiType::all(),
    };

    let config = promptfirewall::ScanConfig {
        detect_pii,
        detect_injection,
        pii_types: pii_type_list,
        injection_threshold,
        redact,
        redact_with: parse_redact_strategy(redact_with)?,
    };

    let result = promptfirewall::scan(text, &config);
    Ok(convert_result(result))
}

#[pyfunction]
fn is_safe(text: &str) -> bool {
    promptfirewall::is_safe(text)
}

#[pyfunction]
#[pyo3(signature = (text, *, redact_with = "mask", pii_types = None))]
fn redact(text: &str, redact_with: &str, pii_types: Option<Vec<String>>) -> PyResult<String> {
    let pii_type_list = match pii_types {
        Some(types) => parse_pii_types(types)?,
        None => promptfirewall::PiiType::all(),
    };

    let config = promptfirewall::ScanConfig {
        detect_pii: true,
        detect_injection: false,
        pii_types: pii_type_list,
        injection_threshold: 0.7,
        redact: true,
        redact_with: parse_redact_strategy(redact_with)?,
    };

    let result = promptfirewall::scan(text, &config);
    Ok(result.redacted_text.unwrap_or_else(|| text.to_string()))
}

#[pyfunction]
#[pyo3(signature = (text, *, threshold = 0.7))]
fn detect_injection(text: &str, threshold: f32) -> ScanResult {
    let config = promptfirewall::ScanConfig {
        detect_pii: false,
        detect_injection: true,
        pii_types: Vec::new(),
        injection_threshold: threshold,
        redact: false,
        redact_with: promptfirewall::RedactStrategy::Mask,
    };

    convert_result(promptfirewall::scan(text, &config))
}

#[pyfunction]
#[pyo3(signature = (text, *, pii_types = None))]
fn detect_pii(text: &str, pii_types: Option<Vec<String>>) -> PyResult<ScanResult> {
    let pii_type_list = match pii_types {
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

    Ok(convert_result(promptfirewall::scan(text, &config)))
}

#[pymodule]
fn _internal(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(scan, m)?)?;
    m.add_function(wrap_pyfunction!(is_safe, m)?)?;
    m.add_function(wrap_pyfunction!(redact, m)?)?;
    m.add_function(wrap_pyfunction!(detect_injection, m)?)?;
    m.add_function(wrap_pyfunction!(detect_pii, m)?)?;
    m.add_class::<ScanResult>()?;
    m.add_class::<PiiFinding>()?;
    Ok(())
}
