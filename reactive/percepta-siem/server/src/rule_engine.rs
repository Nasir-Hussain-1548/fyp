//! Rule Engine Module
//! Evaluates incoming events against detection rules and triggers alerts

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::alerts::{Alert, AlertService, AlertSeverity};
use crate::percepta::Event;

/// Detection rule definition
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub severity: String,
    pub category: String,
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub threshold: Option<Threshold>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Threshold {
    pub count: u64,
    pub window_seconds: i64,
    pub group_by: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Action {
    #[serde(rename = "type")]
    pub action_type: String,
    pub message: String,
}

/// Rule engine for event evaluation
pub struct RuleEngine {
    rules: Vec<Rule>,
    alert_service: Arc<AlertService>,
    threshold_tracker: Arc<RwLock<ThresholdTracker>>,
}

/// Tracks event counts for threshold-based rules
struct ThresholdTracker {
    counts: HashMap<String, Vec<ThresholdEntry>>,
}

struct ThresholdEntry {
    timestamp: DateTime<Utc>,
    group_key: String,
}

impl ThresholdTracker {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
        }
    }

    fn add_event(&mut self, rule_id: &str, group_key: String) {
        let entry = ThresholdEntry {
            timestamp: Utc::now(),
            group_key,
        };

        self.counts
            .entry(rule_id.to_string())
            .or_insert_with(Vec::new)
            .push(entry);
    }

    fn check_threshold(&mut self, rule_id: &str, group_key: &str, threshold: &Threshold) -> bool {
        let now = Utc::now();
        let cutoff = now - chrono::Duration::seconds(threshold.window_seconds);

        // Clean up old entries and count matches
        if let Some(entries) = self.counts.get_mut(rule_id) {
            entries.retain(|e| e.timestamp > cutoff);

            let count = entries.iter().filter(|e| e.group_key == group_key).count() as u64;

            count >= threshold.count
        } else {
            false
        }
    }

    fn cleanup_old(&mut self, retention_seconds: i64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(retention_seconds);

        for entries in self.counts.values_mut() {
            entries.retain(|e| e.timestamp > cutoff);
        }
    }
}

impl RuleEngine {
    pub fn new(alert_service: Arc<AlertService>) -> Self {
        Self {
            rules: Vec::new(),
            alert_service,
            threshold_tracker: Arc::new(RwLock::new(ThresholdTracker::new())),
        }
    }

    /// Load rules from YAML file
    pub async fn load_rules_from_file(&mut self, file_path: &Path) -> Result<()> {
        info!("Loading rules from: {}", file_path.display());

        let content = tokio::fs::read_to_string(file_path)
            .await
            .with_context(|| format!("Failed to read rules file: {}", file_path.display()))?;

        #[derive(Deserialize)]
        struct RulesFile {
            rules: Vec<Rule>,
        }

        let rules_file: RulesFile = serde_yaml::from_str(&content)
            .with_context(|| format!("Failed to parse rules file: {}", file_path.display()))?;

        self.rules = rules_file.rules;

        let enabled_count = self.rules.iter().filter(|r| r.enabled).count();
        info!(
            "Loaded {} rules ({} enabled, {} disabled)",
            self.rules.len(),
            enabled_count,
            self.rules.len() - enabled_count
        );

        Ok(())
    }

    /// Evaluate an event against all enabled rules
    pub async fn evaluate_event(&self, event: &Event) -> Result<Vec<Alert>> {
        let mut alerts = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if let Ok(true) = self.matches_rule(event, rule).await {
                debug!("Event matched rule: {} ({})", rule.name, rule.id);

                // Handle threshold-based rules
                if let Some(threshold) = &rule.threshold {
                    let group_key = self.build_group_key(event, &threshold.group_by);

                    {
                        let mut tracker = self.threshold_tracker.write().await;
                        tracker.add_event(&rule.id, group_key.clone());

                        if !tracker.check_threshold(&rule.id, &group_key, threshold) {
                            debug!(
                                "Rule {} threshold not met yet for group: {}",
                                rule.id, group_key
                            );
                            continue;
                        }
                    }

                    info!(
                        "Rule {} threshold exceeded for group: {}",
                        rule.id, group_key
                    );
                }

                // Create alert
                let severity = self.parse_severity(&rule.severity);
                let message = self.build_alert_message(event, rule);

                match self
                    .alert_service
                    .create_alert(
                        rule.id.clone(),
                        rule.name.clone(),
                        severity,
                        rule.category.clone(),
                        message,
                        event,
                    )
                    .await
                {
                    Ok(alert) => {
                        self.alert_service.notify(&alert).await?;
                        alerts.push(alert);
                    }
                    Err(e) => {
                        warn!("Failed to create alert for rule {}: {}", rule.id, e);
                    }
                }
            }
        }

        Ok(alerts)
    }

    /// Check if event matches all conditions in a rule
    async fn matches_rule(&self, event: &Event, rule: &Rule) -> Result<bool> {
        for condition in &rule.conditions {
            if !self.matches_condition(event, condition)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if event matches a single condition
    fn matches_condition(&self, event: &Event, condition: &Condition) -> Result<bool> {
        let field_value = self.extract_field_value(event, &condition.field)?;

        match condition.operator.as_str() {
            "equals" => {
                let target = condition.value.as_deref().unwrap_or("");
                Ok(field_value == target)
            }
            "contains" => {
                let target = condition.value.as_deref().unwrap_or("");
                Ok(field_value.contains(target))
            }
            "in" => Ok(condition.values.iter().any(|v| field_value.contains(v))),
            "regex" => {
                let pattern = condition.value.as_deref().unwrap_or("");
                let re = Regex::new(pattern)
                    .with_context(|| format!("Invalid regex pattern: {}", pattern))?;
                Ok(re.is_match(&field_value))
            }
            _ => {
                warn!("Unknown operator: {}", condition.operator);
                Ok(false)
            }
        }
    }

    /// Extract field value from event using dot notation
    fn extract_field_value(&self, event: &Event, field_path: &str) -> Result<String> {
        let parts: Vec<&str> = field_path.split('.').collect();

        match parts.as_slice() {
            ["event", "category"] => Ok(format!(
                "{:?}",
                event.event.as_ref().map(|e| e.category).unwrap_or(0)
            )),
            ["event", "outcome"] => Ok(format!(
                "{:?}",
                event.event.as_ref().map(|e| e.outcome).unwrap_or(0)
            )),
            ["event", "action"] => Ok(event
                .event
                .as_ref()
                .map(|e| e.action.as_str())
                .unwrap_or("")
                .to_string()),
            ["user", "name"] => Ok(event
                .user
                .as_ref()
                .map(|u| u.name.as_str())
                .unwrap_or("")
                .to_string()),
            ["user", "id"] => Ok(event
                .user
                .as_ref()
                .map(|u| u.id.as_str())
                .unwrap_or("")
                .to_string()),
            ["process", "name"] => Ok(event
                .process
                .as_ref()
                .map(|p| p.name.as_str())
                .unwrap_or("")
                .to_string()),
            ["process", "command_line"] => Ok(event
                .process
                .as_ref()
                .map(|p| p.command_line.as_str())
                .unwrap_or("")
                .to_string()),
            ["file", "path"] => Ok(event
                .file
                .as_ref()
                .map(|f| f.path.as_str())
                .unwrap_or("")
                .to_string()),
            ["file", "operation"] => Ok(format!(
                "{:?}",
                event.file.as_ref().map(|f| f.operation).unwrap_or(0)
            )),
            ["network", "dst_port"] => Ok(event
                .network
                .as_ref()
                .map(|n| n.dst_port.to_string())
                .unwrap_or_default()),
            ["network", "direction"] => Ok(format!(
                "{:?}",
                event.network.as_ref().map(|n| n.direction).unwrap_or(0)
            )),
            ["network", "dst_ip"] => Ok(event
                .network
                .as_ref()
                .map(|n| n.dst_ip.as_str())
                .unwrap_or("")
                .to_string()),
            ["network", "src_ip"] => Ok(event
                .network
                .as_ref()
                .map(|n| n.src_ip.as_str())
                .unwrap_or("")
                .to_string()),
            ["registry", "path"] => Ok(event
                .registry
                .as_ref()
                .map(|r| r.path.as_str())
                .unwrap_or("")
                .to_string()),
            ["agent", "hostname"] => Ok(event
                .agent
                .as_ref()
                .map(|a| a.hostname.as_str())
                .unwrap_or("")
                .to_string()),
            ["agent", "id"] => Ok(event
                .agent
                .as_ref()
                .map(|a| a.id.as_str())
                .unwrap_or("")
                .to_string()),
            ["host", "ip"] => Ok(event
                .host
                .as_ref()
                .and_then(|h| h.ip.first().map(|s| s.as_str()))
                .unwrap_or("")
                .to_string()),
            _ => Ok(String::new()),
        }
    }

    /// Build group key for threshold tracking
    fn build_group_key(&self, event: &Event, group_by: &[String]) -> String {
        group_by
            .iter()
            .map(|field| self.extract_field_value(event, field).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Build alert message with template substitution
    fn build_alert_message(&self, event: &Event, rule: &Rule) -> String {
        if let Some(action) = rule.actions.first() {
            let mut message = action.message.clone();

            // Simple template substitution
            let replacements = vec![
                (
                    "{{user.name}}",
                    self.extract_field_value(event, "user.name")
                        .unwrap_or_default(),
                ),
                (
                    "{{agent.hostname}}",
                    self.extract_field_value(event, "agent.hostname")
                        .unwrap_or_default(),
                ),
                (
                    "{{process.name}}",
                    self.extract_field_value(event, "process.name")
                        .unwrap_or_default(),
                ),
                (
                    "{{process.command_line}}",
                    self.extract_field_value(event, "process.command_line")
                        .unwrap_or_default(),
                ),
                (
                    "{{file.path}}",
                    self.extract_field_value(event, "file.path")
                        .unwrap_or_default(),
                ),
                (
                    "{{network.dst_ip}}",
                    self.extract_field_value(event, "network.dst_ip")
                        .unwrap_or_default(),
                ),
                (
                    "{{network.dst_port}}",
                    self.extract_field_value(event, "network.dst_port")
                        .unwrap_or_default(),
                ),
                (
                    "{{host.ip}}",
                    self.extract_field_value(event, "host.ip")
                        .unwrap_or_default(),
                ),
            ];

            for (placeholder, value) in replacements {
                message = message.replace(placeholder, &value);
            }

            message
        } else {
            format!("{}: {}", rule.name, rule.description)
        }
    }

    fn parse_severity(&self, severity_str: &str) -> AlertSeverity {
        match severity_str.to_lowercase().as_str() {
            "critical" => AlertSeverity::Critical,
            "high" => AlertSeverity::High,
            "medium" => AlertSeverity::Medium,
            "low" => AlertSeverity::Low,
            _ => AlertSeverity::Info,
        }
    }

    /// Cleanup old threshold tracking data
    pub async fn cleanup_old_thresholds(&self) {
        let mut tracker = self.threshold_tracker.write().await;
        tracker.cleanup_old(3600); // Keep last hour
    }
}
