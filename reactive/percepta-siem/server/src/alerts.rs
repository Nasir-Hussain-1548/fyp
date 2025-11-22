//! Alert Management Module
//! Handles alert generation, deduplication, storage, and notifications

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::percepta::Event;

/// Alert represents a security event that matched a detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: AlertSeverity,
    pub category: String,
    pub message: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u64,
    pub agent_id: String,
    pub agent_hostname: String,
    pub source_events: Vec<String>, // Event hashes
    pub status: AlertStatus,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AlertStatus {
    New,
    Acknowledged,
    Investigating,
    Resolved,
    FalsePositive,
}

/// Alert service for managing alerts
pub struct AlertService {
    alerts: Arc<RwLock<HashMap<String, Alert>>>,
    dedup_window_seconds: i64,
}

impl AlertService {
    pub fn new(dedup_window_seconds: i64) -> Self {
        Self {
            alerts: Arc::new(RwLock::new(HashMap::new())),
            dedup_window_seconds,
        }
    }

    /// Create a new alert or update existing if within dedup window
    pub async fn create_alert(
        &self,
        rule_id: String,
        rule_name: String,
        severity: AlertSeverity,
        category: String,
        message: String,
        event: &Event,
    ) -> Result<Alert> {
        let agent_id = event
            .agent
            .as_ref()
            .map(|a| a.id.clone())
            .unwrap_or_default();

        let agent_hostname = event
            .agent
            .as_ref()
            .map(|a| a.hostname.clone())
            .unwrap_or_default();

        // Create dedup key based on rule_id, agent_id, and message
        let dedup_key = format!("{}:{}:{}", rule_id, agent_id, message);

        let mut alerts = self.alerts.write().await;

        // Check if we have a recent alert matching this pattern
        if let Some(existing) = alerts.get_mut(&dedup_key) {
            let time_diff = Utc::now()
                .signed_duration_since(existing.last_seen)
                .num_seconds();

            if time_diff < self.dedup_window_seconds {
                // Update existing alert
                existing.last_seen = Utc::now();
                existing.count += 1;
                existing.source_events.push(event.hash.clone());

                info!(
                    "Alert deduplicated: {} (count: {}, rule: {})",
                    existing.id, existing.count, rule_id
                );

                return Ok(existing.clone());
            }
        }

        // Create new alert
        let now = Utc::now();
        let alert = Alert {
            id: uuid::Uuid::new_v4().to_string(),
            rule_id,
            rule_name,
            severity,
            category,
            message,
            first_seen: now,
            last_seen: now,
            count: 1,
            agent_id,
            agent_hostname,
            source_events: vec![event.hash.clone()],
            status: AlertStatus::New,
            metadata: HashMap::new(),
        };

        info!(
            "New alert created: {} (severity: {:?}, rule: {})",
            alert.id, alert.severity, alert.rule_id
        );

        alerts.insert(dedup_key, alert.clone());
        Ok(alert)
    }

    /// Get all alerts
    pub async fn get_alerts(&self) -> Vec<Alert> {
        self.alerts.read().await.values().cloned().collect()
    }

    /// Get alerts by severity
    pub async fn get_alerts_by_severity(&self, severity: AlertSeverity) -> Vec<Alert> {
        self.alerts
            .read()
            .await
            .values()
            .filter(|a| a.severity == severity)
            .cloned()
            .collect()
    }

    /// Get alerts by status
    pub async fn get_alerts_by_status(&self, status: AlertStatus) -> Vec<Alert> {
        self.alerts
            .read()
            .await
            .values()
            .filter(|a| a.status == status)
            .cloned()
            .collect()
    }

    /// Update alert status
    pub async fn update_alert_status(&self, alert_id: &str, status: AlertStatus) -> Result<()> {
        let mut alerts = self.alerts.write().await;

        for alert in alerts.values_mut() {
            if alert.id == alert_id {
                alert.status = status.clone();
                info!("Alert {} status updated to {:?}", alert_id, status);
                return Ok(());
            }
        }

        Err(anyhow::anyhow!("Alert not found: {}", alert_id))
    }

    /// Send alert notifications
    pub async fn notify(&self, alert: &Alert) -> Result<()> {
        // Log to file
        self.log_alert(alert).await?;

        // Future: webhook notifications, email, Slack, etc.
        match alert.severity {
            AlertSeverity::Critical | AlertSeverity::High => {
                warn!(
                    "🚨 ALERT [{}]: {} - {}",
                    alert.severity_str(),
                    alert.rule_name,
                    alert.message
                );
            }
            _ => {
                info!(
                    "⚠️ ALERT [{}]: {} - {}",
                    alert.severity_str(),
                    alert.rule_name,
                    alert.message
                );
            }
        }

        Ok(())
    }

    /// Log alert to file
    async fn log_alert(&self, alert: &Alert) -> Result<()> {
        let alert_dir = std::path::Path::new("../data/alerts");
        tokio::fs::create_dir_all(alert_dir).await?;

        let alert_file = alert_dir.join("alerts.json");
        let alert_json = serde_json::to_string(alert).context("Failed to serialize alert")?;
        let alert_line = format!("{}\n", alert_json);

        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&alert_file)
            .await
            .context("Failed to open alerts file")?
            .write_all(alert_line.as_bytes())
            .await
            .context("Failed to write alert to file")?;

        Ok(())
    }

    /// Clean up old resolved/false positive alerts
    pub async fn cleanup_old_alerts(&self, retention_days: i64) {
        let cutoff = Utc::now() - chrono::Duration::days(retention_days);
        let mut alerts = self.alerts.write().await;

        let initial_count = alerts.len();
        alerts.retain(|_, alert| {
            match alert.status {
                AlertStatus::Resolved | AlertStatus::FalsePositive => alert.last_seen > cutoff,
                _ => true, // Keep unresolved alerts regardless of age
            }
        });

        let removed = initial_count - alerts.len();
        if removed > 0 {
            info!("Cleaned up {} old resolved alerts", removed);
        }
    }
}

impl Alert {
    fn severity_str(&self) -> &str {
        match self.severity {
            AlertSeverity::Critical => "CRITICAL",
            AlertSeverity::High => "HIGH",
            AlertSeverity::Medium => "MEDIUM",
            AlertSeverity::Low => "LOW",
            AlertSeverity::Info => "INFO",
        }
    }
}

use tokio::io::AsyncWriteExt;
