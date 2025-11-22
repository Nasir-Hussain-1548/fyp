//! Search API Module
//! Provides RESTful endpoints for querying events and alerts with filters

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::enroll::AppState;
use percepta_server::alerts::Alert;

#[derive(Debug, Deserialize)]
pub struct EventSearchQuery {
    #[serde(default)]
    pub from: Option<String>, // ISO 8601 timestamp
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future severity-based filtering
    pub severity: Option<String>,
    #[serde(default)]
    pub q: Option<String>, // Keyword search
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    100
}

#[derive(Debug, Serialize)]
pub struct EventSearchResponse {
    pub events: Vec<serde_json::Value>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
pub struct AlertsResponse {
    pub alerts: Vec<Alert>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub total_events: usize,
    pub total_alerts: usize,
    pub alerts_by_severity: std::collections::HashMap<String, usize>,
    pub events_last_hour: usize,
    pub connected_agents: usize,
}

/// GET /api/events - Search events with filters
pub async fn search_events(
    State(state): State<AppState>,
    Query(query): Query<EventSearchQuery>,
) -> impl IntoResponse {
    info!("Event search request: {:?}", query);

    // Parse time range
    let from = query
        .from
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let to = query
        .to
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    // Get events from storage
    {
        let mut events = state.storage_service.get_recent_events().await;
        // Apply filters
        if let Some(from_time) = from {
            events.retain(|e| {
                e.event_time
                    .as_ref()
                    .map(|t| {
                        DateTime::from_timestamp(t.seconds, 0).unwrap_or_else(Utc::now) >= from_time
                    })
                    .unwrap_or(false)
            });
        }

        events.retain(|e| {
            e.event_time
                .as_ref()
                .map(|t| DateTime::from_timestamp(t.seconds, 0).unwrap_or_else(Utc::now) <= to)
                .unwrap_or(true)
        });

        if let Some(agent_id) = &query.agent_id {
            events.retain(|e| {
                e.agent
                    .as_ref()
                    .map(|a| a.id.contains(agent_id))
                    .unwrap_or(false)
            });
        }

        if let Some(category) = &query.category {
            events.retain(|e| {
                e.event
                    .as_ref()
                    .map(|ev| format!("{:?}", ev.category).contains(category))
                    .unwrap_or(false)
            });
        }

        if let Some(keyword) = &query.q {
            let keyword_lower = keyword.to_lowercase();
            events.retain(|e| {
                // Search in multiple fields
                e.event
                    .as_ref()
                    .map(|ev| {
                        ev.summary.to_lowercase().contains(&keyword_lower)
                            || ev.original_message.to_lowercase().contains(&keyword_lower)
                    })
                    .unwrap_or(false)
                    || e.user
                        .as_ref()
                        .map(|u| u.name.to_lowercase().contains(&keyword_lower))
                        .unwrap_or(false)
                    || e.process
                        .as_ref()
                        .map(|p| {
                            p.name.to_lowercase().contains(&keyword_lower)
                                || p.command_line.to_lowercase().contains(&keyword_lower)
                        })
                        .unwrap_or(false)
            });
        }

        let total = events.len();
        let page = query.offset / query.limit;

        // Apply pagination
        let paginated: Vec<_> = events
            .into_iter()
            .skip(query.offset)
            .take(query.limit)
            .collect();

        let has_more = query.offset + query.limit < total;

        // Convert to JSON
        let events_json: Vec<serde_json::Value> = paginated
            .into_iter()
            .filter_map(|e| serde_json::to_value(&e).ok())
            .collect();

        let response = EventSearchResponse {
            events: events_json,
            total,
            page,
            per_page: query.limit,
            has_more,
        };

        (StatusCode::OK, Json(response))
    }
}

/// GET /api/alerts - Get all alerts
pub async fn get_alerts(State(state): State<AppState>) -> impl IntoResponse {
    let alerts = state.alert_service.get_alerts().await;
    let total = alerts.len();

    Json(AlertsResponse { alerts, total })
}

/// GET /api/stats - Get SIEM statistics
pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    // Get events
    let events = state.storage_service.get_recent_events().await;
    let total_events = events.len();

    // Count events in last hour
    let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
    let events_last_hour = events
        .iter()
        .filter(|e| {
            e.event_time
                .as_ref()
                .and_then(|t| DateTime::from_timestamp(t.seconds, 0))
                .map(|dt| dt > one_hour_ago)
                .unwrap_or(false)
        })
        .count();

    // Get alerts
    let alerts = state.alert_service.get_alerts().await;
    let total_alerts = alerts.len();

    // Count alerts by severity
    let mut alerts_by_severity = std::collections::HashMap::new();
    for alert in &alerts {
        let severity = format!("{:?}", alert.severity);
        *alerts_by_severity.entry(severity).or_insert(0) += 1;
    }

    // Count connected agents (unique agent IDs in recent events)
    let connected_agents = events
        .iter()
        .filter_map(|e| e.agent.as_ref().map(|a| a.id.as_str()))
        .collect::<std::collections::HashSet<_>>()
        .len();

    Json(StatsResponse {
        total_events,
        total_alerts,
        alerts_by_severity,
        events_last_hour,
        connected_agents,
    })
}
