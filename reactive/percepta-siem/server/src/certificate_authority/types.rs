use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration for the Certificate Authority
#[derive(Debug, Clone)]
pub struct CAConfig {
    /// Default certificate validity in days
    pub default_validity_days: u32,
    /// CA certificate and key storage path
    pub ca_storage_path: PathBuf,
    /// Maximum certificates that can be issued
    pub max_certificates: u64,
    /// Organization name for issued certificates
    pub organization: String,
    /// Country code for issued certificates
    pub country: String,
}

impl Default for CAConfig {
    fn default() -> Self {
        Self {
            default_validity_days: 365,
            ca_storage_path: PathBuf::from("certs"),
            max_certificates: 10000,
            organization: String::from("Percepta SIEM"),
            country: String::from("US"),
        }
    }
}

/// Information about an issued certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCertificate {
    pub serial_number: String,
    pub common_name: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub certificate_pem: String,
    pub status: CertificateStatus,
    pub agent_id: Option<String>,
}

/// Information about a revoked certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevokedCertificate {
    pub serial_number: String,
    pub revoked_at: i64,
    pub reason: RevocationReason,
    pub common_name: String,
}

/// Certificate status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CertificateStatus {
    Active,
    Expired,
    Revoked,
    Suspended,
}

/// Reasons for certificate revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
}

/// Certificate signing request with additional metadata
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub common_name: String,
    pub organization: Option<String>,
    pub country: Option<String>,
    pub validity_days: Option<u32>,
    pub agent_id: Option<String>,
    pub dns_names: Vec<String>,
}

/// Response for certificate issuance
#[derive(Debug, Clone)]
pub struct IssuedCertificateWithKey {
    pub certificate: IssuedCertificate,
    pub private_key_pem: String,
}
