use super::{CAService, RevocationReason, RevokedCertificate};
use anyhow::{Context, Result};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::x509::X509Crl;
use openssl_sys as ffi;
use foreign_types_shared::{ForeignType, ForeignTypeRef};
use std::fs;

impl CAService {
    /// Revoke a certificate by serial number, update the in-memory CRL registry,
    /// and regenerate the published CRL.
    pub async fn revoke_certificate(&self, serial: &str) -> Result<()> {
        // Record revocation in-memory; we do not depend on external openssl tooling.
        let issued_common_name = {
            let issued = self.issued_certs.read().await;
            issued
                .get(serial)
                .map(|cert| cert.common_name.clone())
                .unwrap_or_else(|| "Unknown".to_string())
        };

        {
            let mut revoked = self.revoked_certs.write().await;
            revoked.insert(
                serial.to_string(),
                RevokedCertificate {
                    serial_number: serial.to_string(),
                    revoked_at: crate::timestamps::now_seconds(),
                    reason: RevocationReason::Unspecified,
                    common_name: issued_common_name,
                },
            );
        }

        // Regenerate CRL and reload it
        self.generate_crl().await?;
        Ok(())
    }

    /// Generate a Certificate Revocation List (CRL)
    pub async fn generate_crl(&self) -> Result<Vec<u8>> {
        // Get snapshot of revoked certs and CA data before entering blocking section
        let revoked_snapshot = self.revoked_certs.read().await.clone();
        let ca_cert = self.ca_cert.clone();
        let ca_key = self.ca_key.clone();
        
        // Build a CRL using direct FFI calls since openssl-rs doesn't expose builder API
        // Run in spawn_blocking to avoid Send issues with raw pointers
        let crl_pem = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
            unsafe {
                let crl_ptr = ffi::X509_CRL_new();
                if crl_ptr.is_null() {
                    anyhow::bail!("Failed to create X509_CRL");
                }

                // Set version to 1 (v2 CRL)
                if ffi::X509_CRL_set_version(crl_ptr, 1) != 1 {
                    ffi::X509_CRL_free(crl_ptr);
                    anyhow::bail!("Failed to set CRL version");
                }

                // Set issuer name from CA certificate
                let issuer_name = ca_cert.subject_name();
                if ffi::X509_CRL_set_issuer_name(crl_ptr, issuer_name.as_ptr()) != 1 {
                    ffi::X509_CRL_free(crl_ptr);
                    anyhow::bail!("Failed to set CRL issuer name");
                }

                // Set lastUpdate and nextUpdate times
                let last_update = Asn1Time::days_from_now(0)
                    .context("creating last_update time")?;
                let next_update = Asn1Time::days_from_now(7)
                    .context("creating next_update time")?;
                
                if ffi::X509_CRL_set1_lastUpdate(crl_ptr, last_update.as_ptr()) != 1 {
                    ffi::X509_CRL_free(crl_ptr);
                    anyhow::bail!("Failed to set CRL lastUpdate");
                }
                
                if ffi::X509_CRL_set1_nextUpdate(crl_ptr, next_update.as_ptr()) != 1 {
                    ffi::X509_CRL_free(crl_ptr);
                    anyhow::bail!("Failed to set CRL nextUpdate");
                }

                // Add revoked certificates
                for (serial, record) in revoked_snapshot.iter() {
                    let revoked_ptr = ffi::X509_REVOKED_new();
                    if revoked_ptr.is_null() {
                        ffi::X509_CRL_free(crl_ptr);
                        anyhow::bail!("Failed to create X509_REVOKED");
                    }

                    // Set serial number
                    let serial_bn = BigNum::from_dec_str(serial)
                        .or_else(|_| BigNum::from_hex_str(serial))
                        .context("parsing revoked serial number")?;
                    let serial_asn1 = openssl::asn1::Asn1Integer::from_bn(&serial_bn)
                        .context("converting serial to ASN.1")?;
                    
                    if ffi::X509_REVOKED_set_serialNumber(revoked_ptr, serial_asn1.as_ptr()) != 1 {
                        ffi::X509_REVOKED_free(revoked_ptr);
                        ffi::X509_CRL_free(crl_ptr);
                        anyhow::bail!("Failed to set revoked serial number");
                    }

                    // Set revocation date
                    let revoked_at = Asn1Time::from_unix(record.revoked_at)
                        .context("creating revoked timestamp")?;
                    if ffi::X509_REVOKED_set_revocationDate(revoked_ptr, revoked_at.as_ptr()) != 1 {
                        ffi::X509_REVOKED_free(revoked_ptr);
                        ffi::X509_CRL_free(crl_ptr);
                        anyhow::bail!("Failed to set revocation date");
                    }

                    // Add revoked entry to CRL (X509_CRL_add0_revoked takes ownership)
                    if ffi::X509_CRL_add0_revoked(crl_ptr, revoked_ptr) != 1 {
                        ffi::X509_REVOKED_free(revoked_ptr);
                        ffi::X509_CRL_free(crl_ptr);
                        anyhow::bail!("Failed to add revoked certificate to CRL");
                    }
                }

                // Sort the revoked list
                if ffi::X509_CRL_sort(crl_ptr) != 1 {
                    ffi::X509_CRL_free(crl_ptr);
                    anyhow::bail!("Failed to sort CRL");
                }

                // Sign the CRL with CA private key
                let digest = MessageDigest::sha256();
                if ffi::X509_CRL_sign(crl_ptr, ca_key.as_ptr(), digest.as_ptr()) == 0 {
                    ffi::X509_CRL_free(crl_ptr);
                    anyhow::bail!("Failed to sign CRL");
                }

                // Convert to Rust X509Crl object
                let crl = X509Crl::from_ptr(crl_ptr);
                let crl_pem = crl.to_pem().context("serializing CRL to PEM")?;
                
                Ok(crl_pem)
            }
        }).await.context("spawn_blocking failed")??;

        // Store CRL in memory for TLS code to pick up
        {
            let mut guard = self.crl_pem.write().await;
            *guard = Some(crl_pem.clone());
        }

        // Persist CRL to disk alongside other CA artifacts for operational visibility.
        let crl_path = self.config.ca_storage_path.join("crl.pem");
        if let Err(e) = fs::write(&crl_path, &crl_pem) {
            tracing::warn!("Failed to write CRL to {}: {}", crl_path.display(), e);
        }

        Ok(crl_pem)
    }
}

impl CAService {
    /// Return a cloned copy of the in-memory CRL PEM bytes, if available
    pub async fn get_crl_pem(&self) -> Option<Vec<u8>> {
        let guard = self.crl_pem.read().await;
        guard.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CAConfig;
    use anyhow::Result;

    #[tokio::test]
    async fn test_generate_crl_without_openssl_cli() -> Result<()> {
        let temp_dir = tempfile::tempdir().context("creating temp dir")?;
        let mut config = CAConfig::default();
        config.ca_storage_path = temp_dir.path().to_path_buf();
        let ca = CAService::new(config).await.context("creating CAService")?;

        // Attempt to generate the CRL; this now runs entirely in-process without external tools.
        let crl = ca.generate_crl().await.context("generate_crl failed")?;
        // Ensure we got some bytes and they parse
        assert!(!crl.is_empty(), "CRL PEM should not be empty");
    let _parsed = X509Crl::from_pem(&crl).context("parsing returned CRL PEM")?;

        // Ensure the in-memory CRL was stored
        let in_mem = ca.get_crl_pem().await;
        assert!(in_mem.is_some(), "in-memory CRL should be set");

        Ok(())
    }
}
