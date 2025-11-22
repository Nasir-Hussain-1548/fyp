//! GUI and API for viewing real-time events.

use crate::enroll::AppState;
use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Json, Response};
use serde::Serialize;
use tracing::warn;

// --- Authentication Middleware ---

/// Axum middleware to protect routes with a secret API key.
pub async fn api_key_auth(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Get the API key from the request header `X-Api-Key`
    let auth_header = req
        .headers()
        .get("X-Api-Key")
        .and_then(|value| value.to_str().ok());

    if let Some(key) = auth_header {
        if key == state.api_key {
            // Key is valid, proceed to the handler
            return Ok(next.run(req).await);
        }
    }

    // Key is missing or invalid
    warn!("Unauthorized API access attempt.");
    Err(StatusCode::UNAUTHORIZED)
}

// --- API Handler ---

/// Axum handler to serve the most recent events as JSON.
#[derive(Serialize)]
pub struct EventsResponse {
    events: Vec<percepta_server::percepta::Event>,
}

pub async fn get_events_api(State(state): State<AppState>) -> impl IntoResponse {
    let events = state.storage_service.get_recent_events().await;
    Json(EventsResponse { events })
}

// --- GUI Page Handler ---

/// Axum handler to serve the main HTML page for the event viewer.
pub async fn serve_gui_page() -> Html<String> {
    Html(get_gui_html())
}

// --- HTML, CSS, and JavaScript Content ---

fn get_gui_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Percepta SIEM - Live Events</title>
    <style>
        :root {
            --bg-color: #1a1a1a;
            --table-bg: #2c2c2c;
            --text-color: #e0e0e0;
            --header-bg: #333;
            --border-color: #444;
            --accent-color: #007bff;
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 1rem;
        }
        h1 { text-align: center; color: var(--accent-color); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }
        th, td {
            border: 1px solid var(--border-color);
            padding: 0.75rem;
            text-align: left;
            white-space: nowrap;
        }
        th {
            background-color: var(--header-bg);
            position: sticky;
            top: 0;
        }
        tbody tr:nth-child(odd) { background-color: var(--table-bg); }
        tbody tr:hover { background-color: #4a4a4a; }
        .auth-overlay {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0,0,0,0.8); display: flex; justify-content: center; align-items: center; z-index: 100;
        }
        .auth-box { background: var(--table-bg); padding: 2rem; border-radius: 8px; text-align: center; }
        .auth-box input { padding: 0.5rem; margin-top: 0.5rem; margin-bottom: 1rem; width: 250px; }
        .auth-box button { padding: 0.5rem 1rem; cursor: pointer; }
    </style>
</head>
<body>
    <div id="auth-overlay" class="auth-overlay">
        <div class="auth-box">
            <h2>API Key Required</h2>
            <p>Please enter the API key to view events.</p>
            <input type="password" id="api-key-input" placeholder="Enter API Key">
            <br>
            <button id="auth-submit">Submit</button>
        </div>
    </div>

    <h1>Percepta SIEM - Live Events</h1>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Agent ID</th>
                <th>Hostname</th>
                <th>Summary</th>
                <th>Provider</th>
            </tr>
        </thead>
        <tbody id="events-table-body"></tbody>
    </table>

    <script>
        const apiKeyInput = document.getElementById('api-key-input');
        const authSubmit = document.getElementById('auth-submit');
        const authOverlay = document.getElementById('auth-overlay');
        const tableBody = document.getElementById('events-table-body');

        let apiKey = sessionStorage.getItem('percepta-api-key');

        function hideAuthOverlay() {
            authOverlay.style.display = 'none';
        }

        function showAuthOverlay() {
            authOverlay.style.display = 'flex';
        }

        async function fetchEvents() {
            if (!apiKey) {
                showAuthOverlay();
                return;
            }

            try {
                const response = await fetch('/api/events', {
                    headers: { 'X-Api-Key': apiKey }
                });

                if (response.status === 401) {
                    sessionStorage.removeItem('percepta-api-key');
                    apiKey = null;
                    showAuthOverlay();
                    return;
                }

                if (!response.ok) {
                    console.error('Failed to fetch events:', response.statusText);
                    return;
                }

                const data = await response.json();
                renderEvents(data.events);
            } catch (error) {
                console.error('Error fetching events:', error);
            }
        }

        function renderEvents(events) {
            // Clear existing rows
            tableBody.innerHTML = '';
            // Sort events by time, newest first
            events.sort((a, b) => b.event_time.seconds - a.event_time.seconds);

            for (const event of events) {
                const row = document.createElement('tr');
                const eventTime = new Date(event.event_time.seconds * 1000).toLocaleString();
                
                row.innerHTML = `
                    <td>${eventTime}</td>
                    <td>${event.agent?.id || 'N/A'}</td>
                    <td>${event.agent?.hostname || 'N/A'}</td>
                    <td style="white-space: normal;">${event.event?.summary || 'N/A'}</td>
                    <td>${event.event?.provider || 'N/A'}</td>
                `;
                tableBody.appendChild(row);
            }
        }

        authSubmit.addEventListener('click', () => {
            const key = apiKeyInput.value;
            if (key) {
                apiKey = key;
                sessionStorage.setItem('percepta-api-key', key);
                hideAuthOverlay();
                fetchEvents();
            }
        });

        // Initial check
        if (apiKey) {
            hideAuthOverlay();
            fetchEvents();
        } else {
            showAuthOverlay();
        }

        // Fetch events every 3 seconds
        setInterval(fetchEvents, 3000);
    </script>
</body>
</html>
"#.to_string()
}
