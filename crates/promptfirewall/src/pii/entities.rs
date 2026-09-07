use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PiiType {
    Ssn,
    CreditCard,
    Iban,
    Email,
    Phone,
    IpAddress,
    AwsKey,
    ApiKey,
}

impl PiiType {
    pub fn all() -> Vec<PiiType> {
        vec![
            Self::Ssn,
            Self::CreditCard,
            Self::Iban,
            Self::Email,
            Self::Phone,
            Self::IpAddress,
            Self::AwsKey,
            Self::ApiKey,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Ssn => "SSN",
            Self::CreditCard => "CREDIT_CARD",
            Self::Iban => "IBAN",
            Self::Email => "EMAIL",
            Self::Phone => "PHONE",
            Self::IpAddress => "IP_ADDRESS",
            Self::AwsKey => "AWS_KEY",
            Self::ApiKey => "API_KEY",
        }
    }
}
