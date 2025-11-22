use anyhow::{anyhow, Context, Result};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509Builder, X509NameBuilder};
use std::sync::Arc;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tracing::{debug, info, warn};

use crate::certificate_authority::CAService;
use openssl::x509::X509Crl;

/// Create gRPC server TLS configuration with mTLS
pub async fn create_server_tls_config(ca_service: &Arc<CAService>) -> Result<ServerTlsConfig> {
    // Resolve certs relative to the server crate location to avoid CWD ambiguity
    let cert_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs");

    if !std::path::Path::new(cert_dir).exists() {
        tokio::fs::create_dir_all(cert_dir).await?;
    }

    let server_cert_path = format!("{}/server_cert.pem", cert_dir);
    let server_key_path = format!("{}/server_key.pem", cert_dir);
    let ca_cert_path = format!("{}/ca_cert.pem", cert_dir);

    // Ensure certificates exist, generating them if necessary
    if !std::path::Path::new(&server_cert_path).exists() {
        info!("🔐 Preparing CA and server certificates for gRPC server...");

        let allow_self_signed = std::env::var("PERCEPTA_DEV_SELFSIGNED")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Prefer the CA service for proper issuance
        match ca_service.get_ca_certificate_pem() {
            Ok(ca_cert_pem) => {
                tokio::fs::write(&ca_cert_path, &ca_cert_pem).await?;

                match ca_service.generate_new_server_certificate() {
                    Ok((server_cert, server_key)) => {
                        let server_cert_pem = server_cert.to_pem()?;
                        let server_key_pem = server_key.private_key_to_pem_pkcs8()?;

                        tokio::fs::write(&server_cert_path, &server_cert_pem).await?;
                        tokio::fs::write(&server_key_path, &server_key_pem).await?;
                        info!("✅ Server certificates generated successfully by CAService");
                    }
                    Err(e) => {
                        if allow_self_signed {
                            warn!("CAService failed to generate server certificate: {}. Using DEV self-signed fallback (PERCEPTA_DEV_SELFSIGNED=1)", e);
                            let (cert_pem, key_pem) = generate_self_signed_cert()?;
                            tokio::fs::write(&server_cert_path, &cert_pem).await?;
                            tokio::fs::write(&server_key_path, &key_pem).await?;
                            // For dev fallback, use self-signed as CA root so clients can trust it when explicitly configured
                            tokio::fs::write(&ca_cert_path, &cert_pem).await?;
                        } else {
                            return Err(anyhow!("Failed to generate server certificate via CAService: {}. Set PERCEPTA_DEV_SELFSIGNED=1 to allow a temporary self-signed fallback for development.", e));
                        }
                    }
                }
            }
            Err(e) => {
                if allow_self_signed {
                    warn!("CAService has no CA certificate available ({}). Using DEV self-signed fallback (PERCEPTA_DEV_SELFSIGNED=1)", e);
                    let (cert_pem, key_pem) = generate_self_signed_cert()?;
                    tokio::fs::write(&server_cert_path, &cert_pem).await?;
                    tokio::fs::write(&server_key_path, &key_pem).await?;
                    tokio::fs::write(&ca_cert_path, &cert_pem).await?;
                } else {
                    return Err(anyhow!("CAService has no CA certificate available. Initialize the CA before starting the server, or set PERCEPTA_DEV_SELFSIGNED=1 to allow a temporary self-signed fallback for development."));
                }
            }
        }
    }

    // Load server certificate and private key
    let server_cert = tokio::fs::read(&server_cert_path)
        .await
        .context("Failed to read server certificate")?;
    let server_key = tokio::fs::read(&server_key_path)
        .await
        .context("Failed to read server private key")?;

    // Load CA certificate for client verification
    let ca_cert = tokio::fs::read(&ca_cert_path)
        .await
        .context("Failed to read CA certificate")?;

    // Create server identity
    let server_identity = Identity::from_pem(&server_cert, &server_key);

    // Create CA certificate for client authentication
    let ca_certificate = Certificate::from_pem(&ca_cert);

    // Configure mTLS - require client certificates for security
    let tls_config = ServerTlsConfig::new()
        .identity(server_identity)
        .client_ca_root(ca_certificate);

    // If the CA has an in-memory CRL, write it into the certs directory so
    // it can be used by external systems or for manual inspection.
    // This also serves as a simple integration point for later hot-reload.
    if let Some(crl_bytes) = ca_service.get_crl_pem().await {
        let crl_path = format!("{}/crl.pem", cert_dir);
        if let Err(e) = tokio::fs::write(&crl_path, &crl_bytes).await {
            tracing::warn!("Failed to write CRL to {}: {}", crl_path, e);
        } else {
            info!("📜 CRL written to {}", crl_path);
        }
    }

    info!("🔒 gRPC mTLS configuration prepared - client certificates required");

    Ok(tls_config)
}

/// Reload CRL bytes from the CA service and write to `certs/crl.pem`.
/// This validates the CRL by parsing it with OpenSSL and returns an error on failure.
pub async fn reload_crl_from_ca(ca_service: std::sync::Arc<CAService>) -> Result<()> {
    let cert_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../certs");
    if !std::path::Path::new(cert_dir).exists() {
        tokio::fs::create_dir_all(cert_dir).await?;
    }

    if let Some(crl_bytes) = ca_service.get_crl_pem().await {
        // Validate by parsing
        let _ = X509Crl::from_pem(&crl_bytes).context("Failed to parse CRL PEM")?;

        let crl_path = format!("{}/crl.pem", cert_dir);
        tokio::fs::write(&crl_path, &crl_bytes)
            .await
            .with_context(|| format!("Failed to write CRL to {}", crl_path))?;

        info!("📜 CRL written to {}", crl_path);
    } else {
        info!("No CRL available in CA service to reload");
    }

    Ok(())
}

/// Generate a self-signed certificate for testing and bootstrap purposes
///
/// Creates a 2048-bit RSA key pair and corresponding X.509 certificate
/// valid for 365 days with "Percepta-SIEM" as the common name.
/// Signs the certificate using SHA256 algorithm.
///
/// Returns a tuple of (certificate_pem_bytes, private_key_pem_bytes)
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    info!("🔐 Generating self-signed certificate for Percepta SIEM...");

    // Generate 2048-bit RSA key pair
    let rsa = Rsa::generate(2048).context("Failed to generate RSA key pair")?;

    let private_key = PKey::from_rsa(rsa).context("Failed to create private key from RSA")?;

    debug!("✅ Generated 2048-bit RSA key pair");

    // Create X.509 certificate
    let cert = build_certificate(&private_key).context("Failed to build X.509 certificate")?;

    // Convert to PEM format
    let cert_pem = cert.to_pem()?;

    let key_pem = private_key.private_key_to_pem_pkcs8()?;

    info!("🎉 Self-signed certificate generated successfully");
    debug!("📋 Certificate subject: CN=Percepta-SIEM");
    debug!("📅 Certificate validity: 365 days from now");

    Ok((cert_pem, key_pem))
}

/// Build the X.509 certificate with proper subject and validity period
fn build_certificate(private_key: &PKey<Private>) -> Result<openssl::x509::X509> {
    let mut cert_builder = X509Builder::new()?;

    // Set certificate version (X.509 v3)
    cert_builder.set_version(2)?;

    // Generate random serial number
    let serial_number = generate_serial_number()?;
    use openssl::asn1::Asn1Integer;
    let serial_number = Asn1Integer::from_bn(&serial_number)?;
    cert_builder.set_serial_number(&serial_number)?;

    // Set validity period (365 days from now)
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;

    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    // Set public key
    cert_builder.set_pubkey(private_key)?;

    // Build subject name (CN=Percepta-SIEM)
    let subject_name = build_subject_name()?;
    cert_builder.set_subject_name(&subject_name)?;

    // Set issuer name (same as subject for self-signed)
    cert_builder.set_issuer_name(&subject_name)?;

    // Sign certificate with private key using SHA256
    cert_builder.sign(private_key, MessageDigest::sha256())?;

    let cert = cert_builder.build();
    debug!("✅ Built X.509 certificate with SHA256 signature");

    Ok(cert)
}

/// Build the certificate subject name with CN=Percepta-SIEM
fn build_subject_name() -> Result<openssl::x509::X509Name> {
    let mut name_builder = X509NameBuilder::new()?;

    name_builder.append_entry_by_text("CN", "Percepta-SIEM")?;

    let subject_name = name_builder.build();
    debug!("📝 Built certificate subject: CN=Percepta-SIEM");

    Ok(subject_name)
}

/// Generate a random serial number for the certificate
fn generate_serial_number() -> Result<openssl::bn::BigNum> {
    let mut serial = BigNum::new()?;

    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;

    Ok(serial)
}

/// Save certificate and key to PEM files (utility function for testing)
#[cfg(feature = "dev-utils")]
pub fn save_cert_to_files(
    cert_pem: &[u8],
    key_pem: &[u8],
    cert_path: &str,
    key_path: &str,
) -> Result<()> {
    use std::fs;

    fs::write(cert_path, cert_pem)
        .with_context(|| format!("Failed to write certificate to file: {}", cert_path))?;

    fs::write(key_path, key_pem)
        .with_context(|| format!("Failed to write private key to file: {}", key_path))?;

    info!("💾 Certificate saved to: {}", cert_path);
    info!("🔑 Private key saved to: {}", key_path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::PKey;
    use openssl::x509::X509;

    #[test]
    fn test_generate_self_signed_cert() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());

        let (cert_pem, key_pem) = result.unwrap();

        // Verify certificate can be parsed
        let cert = X509::from_pem(&cert_pem);
        assert!(cert.is_ok());

        // Verify private key can be parsed
        let key = PKey::private_key_from_pem(&key_pem);
        assert!(key.is_ok());

        let cert = cert.unwrap();
        let key = key.unwrap();

        // Verify key matches certificate
        let cert_public_key = cert.public_key().unwrap();
        assert!(key.public_eq(&cert_public_key));
    }

    #[test]
    fn test_certificate_subject() {
        let (cert_pem, _) = generate_self_signed_cert().unwrap();
        let cert = X509::from_pem(&cert_pem).unwrap();

        let subject = cert.subject_name();
        let cn = subject
            .entries()
            .find(|entry| entry.object().to_string() == "commonName");

        assert!(cn.is_some());
    let cn_value = cn.unwrap().data().as_utf8().unwrap();
    let cn_str: &str = cn_value.as_ref();
    assert_eq!(cn_str, "Percepta-SIEM");
    }

    #[test]
    fn test_certificate_validity_period() {
        let (cert_pem, _) = generate_self_signed_cert().unwrap();
        let cert = X509::from_pem(&cert_pem).unwrap();

        let not_before = cert.not_before();
        let not_after = cert.not_after();

        // Certificate should be valid now
        let now = Asn1Time::days_from_now(0).unwrap();
        assert!(not_before <= now);
        assert!(not_after > now);

        // Certificate should be valid for approximately 365 days
        let future = Asn1Time::days_from_now(364).unwrap();
        assert!(not_after > future);

        let too_far_future = Asn1Time::days_from_now(366).unwrap();
        assert!(not_after < too_far_future);
    }

    #[test]
    fn test_build_subject_name() {
        let subject = build_subject_name().unwrap();

        let cn_entry = subject
            .entries()
            .find(|entry| entry.object().to_string() == "commonName");

        assert!(cn_entry.is_some());
    let cn_value = cn_entry.unwrap().data().as_utf8().unwrap();
    let cn_str: &str = cn_value.as_ref();
    assert_eq!(cn_str, "Percepta-SIEM");
    }

    #[test]
    fn test_generate_serial_number() {
        let serial1 = generate_serial_number().unwrap();
        let serial2 = generate_serial_number().unwrap();

        // Serial numbers should be different
        assert_ne!(serial1, serial2);

        // Serial numbers should be positive
        assert!(!serial1.is_negative());
        assert!(!serial2.is_negative());
    }

    #[test]
    fn test_pem_format() {
        let (cert_pem, key_pem) = generate_self_signed_cert().unwrap();

        let cert_str = String::from_utf8(cert_pem).unwrap();
        let key_str = String::from_utf8(key_pem).unwrap();

        // Check PEM headers and footers
        assert!(cert_str.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_str.ends_with("-----END CERTIFICATE-----\n"));

        assert!(key_str.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key_str.ends_with("-----END PRIVATE KEY-----\n"));
    }
}
