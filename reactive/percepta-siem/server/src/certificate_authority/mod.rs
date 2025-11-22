use anyhow::Result;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::BigNum,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{BasicConstraints, KeyUsage},
        X509Builder, X509NameBuilder, X509,
    },
};
use std::{collections::HashMap, fs, sync::atomic::AtomicU64, sync::Arc};
use tokio::sync::RwLock;

mod crl;
mod operations;
mod types;

pub use types::*;

/// Certificate Authority service for Percepta SIEM
#[derive(Debug, Clone)]
pub struct CAService {
    /// CA certificate
    ca_cert: Arc<X509>,
    /// CA private key
    ca_key: Arc<PKey<Private>>,
    /// Certificate serial number counter
    serial_counter: Arc<AtomicU64>,
    /// Issued certificates registry
    issued_certs: Arc<RwLock<HashMap<String, IssuedCertificate>>>,
    /// Certificate Revocation List
    revoked_certs: Arc<RwLock<HashMap<String, RevokedCertificate>>>,
    /// In-memory CRL PEM bytes (generated via openssl ca -gencrl)
    crl_pem: Arc<RwLock<Option<Vec<u8>>>>,
    /// CA configuration
    config: CAConfig,
}

impl CAService {
    /// Create a new CA service instance
    pub async fn new(config: CAConfig) -> Result<Self> {
        fs::create_dir_all(&config.ca_storage_path)?;

        let ca_cert_path = config.ca_storage_path.join("ca.crt");
        let ca_key_path = config.ca_storage_path.join("ca.key");

        let (ca_cert, ca_key) = if ca_cert_path.exists() && ca_key_path.exists() {
            // Load existing CA certificate and key
            let ca_cert_data = fs::read(&ca_cert_path)?;
            let ca_key_data = fs::read(&ca_key_path)?;

            let ca_cert = X509::from_pem(&ca_cert_data)?;
            let ca_key = PKey::private_key_from_pem(&ca_key_data)?;

            (ca_cert, ca_key)
        } else {
            // Generate new CA certificate and key
            let rsa = Rsa::generate(4096)?;
            let key = PKey::from_rsa(rsa)?;

            // Create CA certificate
            let mut name = X509NameBuilder::new()?;
            name.append_entry_by_nid(Nid::COMMONNAME, "Percepta SIEM Root CA")?;
            name.append_entry_by_nid(Nid::ORGANIZATIONNAME, &config.organization)?;
            name.append_entry_by_nid(Nid::COUNTRYNAME, &config.country)?;
            let name = name.build();

            let mut cert = X509Builder::new()?;
            cert.set_version(2)?;

            let serial = BigNum::from_u32(1)?;
            let serial_asn1 = Asn1Integer::from_bn(&serial)?;
            cert.set_serial_number(&serial_asn1)?;

            cert.set_subject_name(&name)?;
            cert.set_issuer_name(&name)?;
            cert.set_pubkey(&key)?;

            let not_before = Asn1Time::days_from_now(0)?;
            let not_after = Asn1Time::days_from_now(3650)?; // 10 years
            cert.set_not_before(&not_before)?;
            cert.set_not_after(&not_after)?;

            let mut constraints = BasicConstraints::new();
            constraints.critical();
            constraints.ca();
            cert.append_extension(constraints.build()?)?;

            let mut usage = KeyUsage::new();
            usage.critical().key_cert_sign().crl_sign();
            cert.append_extension(usage.build()?)?;

            cert.sign(&key, MessageDigest::sha256())?;
            let cert = cert.build();

            // Save CA certificate and key
            fs::write(&ca_cert_path, cert.to_pem()?)?;
            fs::write(&ca_key_path, key.private_key_to_pem_pkcs8()?)?;

            (cert, key)
        };

        Ok(Self {
            ca_cert: Arc::new(ca_cert),
            ca_key: Arc::new(ca_key),
            serial_counter: Arc::new(AtomicU64::new(1)),
            issued_certs: Arc::new(RwLock::new(HashMap::new())),
            revoked_certs: Arc::new(RwLock::new(HashMap::new())),
            crl_pem: Arc::new(RwLock::new(None)),
            config,
        })
    }
}

// Lightweight helper that references the max_certificates config so the field is used
impl CAService {
    /// Return whether we can issue another certificate according to the CAConfig
    pub fn can_issue_more(&self) -> bool {
        // Note: reading AtomicU64 is cheap; we only reference config.max_certificates to exercise the field
        let issued =
            futures::executor::block_on(async { self.issued_certs.read().await.len() }) as u64;
        issued < self.config.max_certificates
    }
}
