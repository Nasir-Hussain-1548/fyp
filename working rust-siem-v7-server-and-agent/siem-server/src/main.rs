use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::Path as FsPath,
    sync::Arc,
};
use tokio::net::TcpListener;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tracing::{error, info};
use uuid::Uuid;

const LOG_FILE_PATH: &str = "data/logs.xml";
const ALERT_FILE_PATH: &str = "data/alerts.json";
const SESSION_COOKIE: &str = "siem_session";
const ADMIN_USER: &str = "admin";
const ADMIN_PASS: &str = "admin";

struct AppState {
    sessions: Mutex<HashSet<String>>,
    agents: Mutex<HashMap<Uuid, AgentInfo>>,
    logs: Mutex<Vec<LogEntry>>,
    alerts: Mutex<Vec<AlertDefinition>>,
}

#[derive(Clone, Serialize)]
struct AgentInfo {
    id: Uuid,
    name: String,
    host: String,
    last_seen: DateTime<Utc>,
}

#[derive(Clone, Serialize)]
struct AgentView {
    id: Uuid,
    name: String,
    host: String,
    last_seen: DateTime<Utc>,
    status: String,
}

#[derive(Clone, Serialize)]
struct LogEntry {
    id: Uuid,
    agent_id: Option<Uuid>,
    host: String,
    level: String,
    message: String,
    timestamp: DateTime<Utc>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    agent_name: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct AlertDefinition {
    id: Uuid,
    name: String,
    level: String, // INFO / WARN / ERROR / ANY
    keyword: String,
    #[serde(default)]
    description: String,
    created_at: DateTime<Utc>,
    enabled: bool,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Deserialize, Serialize)]
struct AgentRegisterRequest {
    agent_name: String,
    host: String,
}

#[derive(Serialize)]
struct AgentRegisterResponse {
    agent_id: Uuid,
}

#[derive(Deserialize)]
struct AgentHeartbeatRequest {
    agent_id: Uuid,
}

#[derive(Deserialize)]
struct AgentLogRequest {
    agent_id: Uuid,
    host: String,
    level: String,
    message: String,
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    agent_name: Option<String>,
    #[serde(default)]
    ip: Option<String>,
}

#[derive(Deserialize)]
struct CreateAlertRequest {
    name: String,
    level: String,
    keyword: String,
    description: String,
}

#[derive(Deserialize)]
struct LookupRequest {
    value: String,
}

#[derive(Serialize)]
struct LookupResult {
    ip: String,
    is_malicious: bool,
    reason: String,
    raw: Value,
}

type SharedState = Arc<AppState>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("siem-server=debug,axum=info")
        .init();

    let existing_alerts = load_alerts_from_file(ALERT_FILE_PATH).unwrap_or_default();

    let state = Arc::new(AppState {
        sessions: Mutex::new(HashSet::new()),
        agents: Mutex::new(HashMap::new()),
        logs: Mutex::new(Vec::new()),
        alerts: Mutex::new(existing_alerts),
    });

    let app = Router::new()
        .route("/", get(root))
        .route("/login", get(show_login).post(handle_login))
        .route("/logout", post(handle_logout))
        .route("/dashboard", get(dashboard))
        // logs + agents API
        .route("/api/agents", get(api_agents))
        .route("/api/logs", get(api_logs))
        .route("/api/admin/agents/remove/:id", post(api_admin_remove_agent))
        // alerts API
        .route("/api/alerts", get(api_alerts).post(api_create_alert))
        // lookup API
        .route("/api/lookup/ip", post(api_lookup_ip))
        // agent API
        .route("/api/agent/register", post(api_agent_register))
        .route("/api/agent/heartbeat", post(api_agent_heartbeat))
        .route("/api/agent/logs", post(api_agent_logs))
        // downloads
        .route("/download", get(download_auto))
        .route("/download/agent/windows", get(download_agent_windows))
        .route("/download/agent/linux", get(download_agent_linux))
        .with_state(state)
        .layer(CookieManagerLayer::new());

    let addr = SocketAddr::from(([127, 0, 0, 1], 9200));
    info!("Starting SIEM dashboard on http://{}/", addr);
    let _ = webbrowser::open("http://127.0.0.1:9200/login");

    let listener = TcpListener::bind(addr)
        .await
        .expect("failed to bind TCP listener");

    axum::serve(listener, app)
        .await
        .expect("server failed");
}

// ---------- Auth / UI routing ----------

async fn root(cookies: Cookies, State(state): State<SharedState>) -> Response {
    if is_authenticated(&cookies, &state) {
        Redirect::to("/dashboard").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

async fn show_login(cookies: Cookies, State(state): State<SharedState>) -> Response {
    if is_authenticated(&cookies, &state) {
        Redirect::to("/dashboard").into_response()
    } else {
        Html(login_page_html()).into_response()
    }
}

async fn handle_login(
    cookies: Cookies,
    State(state): State<SharedState>,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    if form.username == ADMIN_USER && form.password == ADMIN_PASS {
        let token = Uuid::new_v4().to_string();
        state.sessions.lock().insert(token.clone());

        let mut cookie = Cookie::new(SESSION_COOKIE.to_string(), token);
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookies.add(cookie);

        Redirect::to("/dashboard").into_response()
    } else {
        Html(login_page_html_with_error("Invalid credentials")).into_response()
    }
}

async fn handle_logout(cookies: Cookies, State(state): State<SharedState>) -> Response {
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        let token = cookie.value().to_string();
        state.sessions.lock().remove(&token);
        let mut remove_cookie = Cookie::new(SESSION_COOKIE.to_string(), "");
        remove_cookie.set_path("/");
        cookies.remove(remove_cookie);
    }
    Redirect::to("/login").into_response()
}

async fn dashboard(cookies: Cookies, State(state): State<SharedState>) -> Response {
    if !is_authenticated(&cookies, &state) {
        Redirect::to("/login").into_response()
    } else {
        Html(dashboard_page_html()).into_response()
    }
}

// ---------- Agents & Logs API ----------

async fn api_agents(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> Response {
    if !is_authenticated(&cookies, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let agents = state.agents.lock();
    let now = Utc::now();
    let vus: Vec<AgentView> = agents
        .values()
        .cloned()
        .map(|a| {
            let delta = now - a.last_seen;
            let status = if delta < Duration::seconds(30) {
                "online".to_string()
            } else {
                "offline".to_string()
            };
            AgentView {
                id: a.id,
                name: a.name,
                host: a.host,
                last_seen: a.last_seen,
                status,
            }
        })
        .collect();

    Json(vus).into_response()
}

/// Return up to last 30 days of logs; frontend does 1/7/30/custom filtering + search
async fn api_logs(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> Response {
    if !is_authenticated(&cookies, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut logs = state.logs.lock().clone();
    let cutoff = Utc::now() - Duration::days(30);
    logs.retain(|l| l.timestamp >= cutoff);
    logs.sort_by_key(|l| l.timestamp);
    Json(logs).into_response()
}

async fn api_admin_remove_agent(
    cookies: Cookies,
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Response {
    if !is_authenticated(&cookies, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let removed = state.agents.lock().remove(&id).is_some();
    if removed {
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

// ---------- Alerts API ----------

async fn api_alerts(
    cookies: Cookies,
    State(state): State<SharedState>,
) -> Response {
    if !is_authenticated(&cookies, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let alerts = state.alerts.lock().clone();
    Json(alerts).into_response()
}

async fn api_create_alert(
    cookies: Cookies,
    State(state): State<SharedState>,
    Json(req): Json<CreateAlertRequest>,
) -> Response {
    if !is_authenticated(&cookies, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let mut alerts = state.alerts.lock();
    let alert = AlertDefinition {
        id: Uuid::new_v4(),
        name: req.name,
        level: req.level.to_uppercase(),
        keyword: req.keyword,
        description: req.description,
        created_at: Utc::now(),
        enabled: true,
    };
    alerts.push(alert.clone());

    if let Err(e) = save_alerts_to_file(ALERT_FILE_PATH, &alerts) {
        error!("Failed to save alerts DB: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Json(alert).into_response()
}

// ---------- IP Lookup API ----------

async fn api_lookup_ip(
    cookies: Cookies,
    State(state): State<SharedState>,
    Json(req): Json<LookupRequest>,
) -> Response {
    if !is_authenticated(&cookies, &state) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match perform_ip_lookup(&req.value).await {
        Ok(result) => {
            if result.is_malicious {
                let mut alerts = state.alerts.lock();
                let alert = AlertDefinition {
                    id: Uuid::new_v4(),
                    name: format!("Auto: Malicious IP {}", result.ip),
                    level: "ERROR".to_string(),
                    keyword: result.ip.clone(),
                    description: format!("Auto-created from IP lookup: {}", result.reason),
                    created_at: Utc::now(),
                    enabled: true,
                };
                alerts.push(alert.clone());
                if let Err(e) = save_alerts_to_file(ALERT_FILE_PATH, &alerts) {
                    error!("Failed to save alerts DB after IP lookup: {}", e);
                }
            }
            Json(result).into_response()
        }
        Err(e) => {
            error!("IP lookup failed: {}", e);
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

async fn perform_ip_lookup(ip: &str) -> Result<LookupResult, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    if let Ok(api_key) = std::env::var("ABUSEIPDB_API_KEY") {
        // Use AbuseIPDB if API key set
        let resp: Value = client
            .get("https://api.abuseipdb.com/api/v2/check")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .header("Key", api_key)
            .header("Accept", "application/json")
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let data = resp.get("data").cloned().unwrap_or(Value::Null);
        let score = data
            .get("abuseConfidenceScore")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let is_malicious = score >= 50;
        let reason = format!("AbuseIPDB abuseConfidenceScore={}", score);
        Ok(LookupResult {
            ip: ip.to_string(),
            is_malicious,
            reason,
            raw: data,
        })
    } else {
        // Fallback: ip-api.com for geo/ISP info; no malicious verdict
        let resp: Value = client
            .get(format!("http://ip-api.com/json/{}", ip))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let country = resp
            .get("country")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");
        let isp = resp.get("isp").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let reason = format!("Geo lookup only (no AbuseIPDB API key). Country={country}, ISP={isp}");
        Ok(LookupResult {
            ip: ip.to_string(),
            is_malicious: false,
            reason,
            raw: resp,
        })
    }
}

// ---------- Agent-facing API ----------

async fn api_agent_register(
    State(state): State<SharedState>,
    Json(req): Json<AgentRegisterRequest>,
) -> Response {
    let id = Uuid::new_v4();
    let info = AgentInfo {
        id,
        name: req.agent_name.clone(),
        host: req.host.clone(),
        last_seen: Utc::now(),
    };
    state.agents.lock().insert(id, info);
    info!("Agent registered: {}", id);
    Json(AgentRegisterResponse { agent_id: id }).into_response()
}

async fn api_agent_heartbeat(
    State(state): State<SharedState>,
    Json(req): Json<AgentHeartbeatRequest>,
) -> Response {
    let mut agents = state.agents.lock();
    if let Some(agent) = agents.get_mut(&req.agent_id) {
        agent.last_seen = Utc::now();
        StatusCode::OK.into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn api_agent_logs(
    State(state): State<SharedState>,
    Json(req): Json<AgentLogRequest>,
) -> Response {
    let mut logs = state.logs.lock();
    let now = Utc::now();
    let ts = req.timestamp.unwrap_or(now);

    let entry = LogEntry {
        id: Uuid::new_v4(),
        agent_id: Some(req.agent_id),
        host: req.host,
        level: req.level,
        message: req.message,
        timestamp: ts,
        source: req.source,
        agent_name: req.agent_name,
        ip: req.ip,
    };
    logs.push(entry);

    // prune >30 days
    let cutoff = now - Duration::days(30);
    logs.retain(|l| l.timestamp >= cutoff);

    if let Err(e) = save_logs_to_xml(LOG_FILE_PATH, &logs) {
        error!("Failed to save XML logs: {}", e);
    }

    StatusCode::OK.into_response()
}

// ---------- Downloads ----------

/// Auto-detect OS via User-Agent and redirect to the right download
async fn download_auto(headers: HeaderMap) -> Response {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if ua.contains("Windows") {
        download_agent_windows().await
    } else if ua.contains("Linux") || ua.contains("X11") {
        download_agent_linux().await
    } else {
        Html(r#"
<!DOCTYPE html>
<html><body style="background:#020617;color:#e5e7eb;font-family:sans-serif;">
<h2>Choose agent</h2>
<p>Could not detect OS from User-Agent. Please choose:</p>
<ul>
  <li><a href="/download/agent/windows">Windows agent</a></li>
  <li><a href="/download/agent/linux">Linux agent</a></li>
</ul>
</body></html>
"#.to_string()).into_response()
    }
}

// NOTE: STILL STUBS – replace with real binaries later
async fn download_agent_windows() -> Response {
    // TODO: read real binary from disk, e.g. ./agents/siem-agent-windows.exe
    let body = b"This is a placeholder for Windows agent binary.\n";
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"siem-agent-windows.txt\"",
            ),
        ],
        body.as_ref(),
    )
        .into_response()
}

async fn download_agent_linux() -> Response {
    // TODO: read real binary from disk, e.g. ./agents/siem-agent-linux
    let body = b"This is a placeholder for Linux agent binary.\n";
    (
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"siem-agent-linux.txt\"",
            ),
        ],
        body.as_ref(),
    )
        .into_response()
}

// ---------- Helpers ----------

fn is_authenticated(cookies: &Cookies, state: &SharedState) -> bool {
    if let Some(cookie) = cookies.get(SESSION_COOKIE) {
        let token = cookie.value().to_string();
        state.sessions.lock().contains(&token)
    } else {
        false
    }
}

fn save_logs_to_xml(path: &str, logs: &[LogEntry]) -> std::io::Result<()> {
    use std::fs;
    use std::io::Write;

    let p = FsPath::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = fs::File::create(p)?;
    writeln!(file, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(file, "<logs>")?;

    for l in logs {
        let msg = escape_xml(&l.message);
        let host = escape_xml(&l.host);
        let level = escape_xml(&l.level);
        let agent_id_str = l
            .agent_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| "none".to_string());
        let source = escape_xml(&l.source.clone().unwrap_or_default());
        let agent_name = escape_xml(&l.agent_name.clone().unwrap_or_default());
        let ip = escape_xml(&l.ip.clone().unwrap_or_default());

        writeln!(
            file,
            r#"  <log id="{id}" agent_id="{agent_id}" timestamp="{ts}" source="{source}" agent_name="{agent_name}" ip="{ip}">"#,
            id = l.id,
            agent_id = agent_id_str,
            ts = l.timestamp.to_rfc3339(),
            source = source,
            agent_name = agent_name,
            ip = ip,
        )?;
        writeln!(file, "    <host>{}</host>", host)?;
        writeln!(file, "    <level>{}</level>", level)?;
        writeln!(file, "    <message>{}</message>", msg)?;
        writeln!(file, "  </log>")?;
    }

    writeln!(file, "</logs>")?;
    Ok(())
}

fn escape_xml(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn save_alerts_to_file(path: &str, alerts: &[AlertDefinition]) -> std::io::Result<()> {
    use std::fs;

    let p = FsPath::new(path);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }

    let file = fs::File::create(p)?;
    serde_json::to_writer_pretty(file, alerts)?;
    Ok(())
}

fn load_alerts_from_file(path: &str) -> std::io::Result<Vec<AlertDefinition>> {
    use std::fs;
    let p = FsPath::new(path);
    if !p.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(p)?;
    let alerts: Vec<AlertDefinition> = serde_json::from_reader(file)?;
    Ok(alerts)
}

// ---------- HTML UI ----------

fn login_page_html() -> String {
    login_page_html_with_error("")
}

fn login_page_html_with_error(error: &str) -> String {
    let error_html = if !error.is_empty() {
        format!(r#"<p style="color:red;">{}</p>"#, error)
    } else {
        "".to_string()
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SIEM Login</title>
<style>
body {{
  font-family: sans-serif;
  background: #111827;
  color: #e5e7eb;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
}}
.card {{
  background: #1f2937;
  padding: 24px 32px;
  border-radius: 12px;
  box-shadow: 0 10px 25px rgba(0,0,0,0.6);
  width: 320px;
}}
input[type="text"], input[type="password"] {{
  width: 100%;
  padding: 8px 10px;
  margin: 8px 0 16px 0;
  border-radius: 6px;
  border: 1px solid #374151;
  background: #111827;
  color: #e5e7eb;
}}
button {{
  width: 100%;
  padding: 10px;
  border-radius: 6px;
  border: none;
  background: #3b82f6;
  color: white;
  font-weight: 600;
  cursor: pointer;
}}
button:hover {{
  background: #2563eb;
}}
</style>
</head>
<body>
<div class="card">
  <h2>SIEM Login</h2>
  {error}
  <form method="post" action="/login">
    <label>Username</label><br>
    <input type="text" name="username" value="admin" />
    <label>Password</label><br>
    <input type="password" name="password" value="admin" />
    <button type="submit">Login</button>
  </form>
</div>
</body>
</html>
"#,
        error = error_html
    )
}

fn dashboard_page_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Rust SIEM Dashboard</title>
<style>
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  margin: 0;
  background: #020617;
  color: #e5e7eb;
}
header {
  padding: 16px 24px;
  background: linear-gradient(90deg, #0f172a, #1f2937);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
header h1 {
  margin: 0;
  font-size: 20px;
}
main {
  padding: 16px 24px;
}
button.logout {
  background: transparent;
  color: #e5e7eb;
  border: 1px solid #64748b;
  border-radius: 999px;
  padding: 6px 10px;
  cursor: pointer;
  font-size: 12px;
}
.nav-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 12px;
}
.tab-btn {
  padding: 6px 12px;
  border-radius: 999px;
  border: 1px solid #334155;
  background: #020617;
  color: #e5e7eb;
  font-size: 12px;
  cursor: pointer;
}
.tab-btn.active {
  background: #3b82f6;
  border-color: #3b82f6;
}
.card {
  background: #020617;
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 16px;
  border: 1px solid #1f2937;
  box-shadow: 0 10px 30px rgba(15,23,42,0.8);
}
.card h2 {
  margin-top: 0;
  font-size: 18px;
}
.small {
  font-size: 11px;
  color: #9ca3af;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}
th, td {
  padding: 6px 8px;
  border-bottom: 1px solid #111827;
}
th {
  text-align: left;
  font-weight: 600;
  background: #020617;
}
.status-online { color: #22c55e; font-weight: 600; }
.status-offline { color: #f97316; font-weight: 600; }
.level-INFO { color: #93c5fd; }
.level-WARN { color: #fde68a; }
.level-ERROR { color: #fecaca; }
.badge {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 999px;
  background: #111827;
  font-size: 11px;
}
input, select, textarea {
  background: #020617;
  border-radius: 6px;
  border: 1px solid #334155;
  color: #e5e7eb;
  padding: 4px 6px;
  font-size: 12px;
}
button.primary {
  border-radius: 6px;
  border: none;
  padding: 6px 10px;
  background: #3b82f6;
  color: white;
  font-size: 12px;
  cursor: pointer;
}
button.primary:hover { background: #2563eb; }
.filter-buttons {
  display: flex;
  gap: 6px;
  margin-bottom: 8px;
  align-items: center;
}
.filter-buttons button {
  padding: 4px 8px;
  font-size: 11px;
  border-radius: 999px;
  border: 1px solid #334155;
  background: #020617;
  color: #e5e7eb;
  cursor: pointer;
}
.filter-buttons button.active {
  background: #3b82f6;
  border-color: #3b82f6;
}
.filter-buttons input[type="datetime-local"] {
  font-size: 11px;
}
.alert-form-inline {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 8px;
  border-top: 1px solid #1f2937;
  padding-top: 8px;
}
.search-bar {
  display:flex;
  align-items:center;
  gap:6px;
  margin-bottom:8px;
}
.search-bar input[type="text"] {
  flex:1;
}
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(15,23,42,0.85);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 50;
}
.modal {
  background: #020617;
  border-radius: 12px;
  border: 1px solid #1f2937;
  box-shadow: 0 20px 60px rgba(15,23,42,0.9);
  max-width: 720px;
  width: 100%;
  max-height: 80vh;
  padding: 16px 20px;
  overflow: auto;
}
.modal h3 {
  margin-top: 0;
  font-size: 18px;
}
.modal pre {
  white-space: pre-wrap;
  word-wrap: break-word;
  font-size: 12px;
  background: #020617;
  border-radius: 8px;
  border: 1px solid #1f2937;
  padding: 8px;
}
.badge-pill {
  display:inline-block;
  padding:2px 8px;
  border-radius:999px;
  border:1px solid #1f2937;
  font-size:11px;
  margin-right:4px;
}
.badge-pill.label {
  border-color:#475569;
  color:#9ca3af;
}
.badge-pill.value {
  border-color:#334155;
}
</style>
</head>
<body>
<header>
  <h1>Rust SIEM Dashboard</h1>
  <form method="post" action="/logout">
    <button type="submit" class="logout">Logout</button>
  </form>
</header>
<main>
  <div class="nav-tabs">
    <button class="tab-btn active" id="tab-logs" onclick="switchTab('logs')">Logs</button>
    <button class="tab-btn" id="tab-agents" onclick="switchTab('agents')">Agents</button>
    <button class="tab-btn" id="tab-alerts" onclick="switchTab('alerts')">Alerts</button>
  </div>

  <!-- Logs view -->
  <div id="view-logs">
    <div class="card">
      <h2>Logs</h2>
      <p class="small">
        Showing up to last 30 days. Use filters for 24h / 7d / 30d / custom. All logs are here.
      </p>

      <div class="filter-buttons">
        <span class="small">Range:</span>
        <button onclick="setLogFilter('1d')" id="btn-filter-1d">Last 24h</button>
        <button onclick="setLogFilter('7d')" id="btn-filter-7d">Last 7 days</button>
        <button onclick="setLogFilter('30d')" id="btn-filter-30d">Last 30 days</button>
        <span class="small" style="margin-left:8px;">Custom:</span>
        <input type="datetime-local" id="custom-from" />
        <input type="datetime-local" id="custom-to" />
        <button onclick="setLogFilter('custom')" id="btn-filter-custom">Apply</button>
      </div>

      <div class="search-bar">
        <span class="small">Search:</span>
        <input id="log-search" type="text" placeholder="e.g. source=Security agent=win001 ip=192.168.100.10 level=ERROR" onkeydown="if(event.key==='Enter'){setSearchQuery();}">
        <button class="primary" onclick="setSearchQuery()">Apply</button>
        <button style="padding:4px 8px;border-radius:6px;border:1px solid #334155;background:transparent;color:#e5e7eb;font-size:11px;cursor:pointer;" onclick="clearSearch()">Clear</button>
      </div>

      <div style="margin: 8px 0;">
        <button class="primary" onclick="openAlertFromSelected()">Create alert from selected logs</button>
        <span class="small" id="selected-count-label" style="margin-left:8px;">0 selected</span>
      </div>

      <table>
        <thead>
          <tr>
            <th><input type="checkbox" id="chk-all" onclick="toggleSelectAll(this)"></th>
            <th>Time (UTC)</th>
            <th>Host</th>
            <th>Level</th>
            <th>Message</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody id="logs-body"></tbody>
      </table>

      <div class="alert-form-inline" id="inline-alert-form" style="display:none;">
        <h3 style="margin:0;font-size:14px;">Create alert from selected logs</h3>
        <label class="small">Name</label>
        <input id="alert-name" placeholder="e.g. Failed login burst" />
        <label class="small">Level</label>
        <select id="alert-level">
          <option value="ANY">ANY</option>
          <option value="INFO">INFO</option>
          <option value="WARN">WARN</option>
          <option value="ERROR">ERROR</option>
        </select>
        <label class="small">Keyword</label>
        <input id="alert-keyword" placeholder="Substring to match in log message" />
        <label class="small">Description</label>
        <textarea id="alert-description" rows="3" placeholder="Describe what this alert means"></textarea>
        <div>
          <button class="primary" onclick="submitAlertFromSelection()">Save alert</button>
          <button style="margin-left:6px;padding:4px 8px;border-radius:6px;border:1px solid #334155;background:transparent;color:#e5e7eb;font-size:11px;cursor:pointer;" onclick="closeInlineAlertForm()">Cancel</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Alerts tab view -->
  <div id="view-alerts" style="display:none;">
    <div class="card">
      <h2>Alerts</h2>
      <p class="small">All defined alerts from <code>data/alerts.json</code>. Automatic alerts from IP lookups are also shown here.</p>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Level</th>
            <th>Keyword</th>
            <th>Description</th>
            <th>Created</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody id="alerts-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Agents view -->
  <div id="view-agents" style="display:none;">
    <div class="card">
      <h2>Agents</h2>
      <p class="small">
        Live agents (based on heartbeat). Use <code>/download</code> to auto-download the right agent binary for this host.
      </p>
      <table>
        <thead>
          <tr>
            <th>Agent ID</th>
            <th>Name</th>
            <th>Host</th>
            <th>Last Seen</th>
            <th>Status</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody id="agents-body"></tbody>
      </table>
    </div>
  </div>
</main>

<!-- Log detail modal -->
<div class="modal-backdrop" id="log-detail-modal">
  <div class="modal">
    <div style="display:flex;justify-content:space-between;align-items:center;">
      <h3>Log details</h3>
      <button style="border:none;background:transparent;color:#9ca3af;font-size:18px;cursor:pointer;" onclick="closeLogDetail()">&times;</button>
    </div>
    <div id="log-detail-body" class="small"></div>
  </div>
</div>

<script>
let logsCache = [];
let currentFilter = '7d'; // default
let selectedLogIds = new Set();
let currentSearchQuery = "";

// ---- tab switching ----
function switchTab(tab) {
  document.getElementById('view-logs').style.display = tab === 'logs' ? '' : 'none';
  document.getElementById('view-agents').style.display = tab === 'agents' ? '' : 'none';
  document.getElementById('view-alerts').style.display = tab === 'alerts' ? '' : 'none';

  document.getElementById('tab-logs').classList.toggle('active', tab === 'logs');
  document.getElementById('tab-agents').classList.toggle('active', tab === 'agents');
  document.getElementById('tab-alerts').classList.toggle('active', tab === 'alerts');
}

// ---- logs filtering ----
function setLogFilter(mode) {
  currentFilter = mode;
  ['1d','7d','30d','custom'].forEach(m => {
    const btn = document.getElementById('btn-filter-' + m);
    if (btn) btn.classList.toggle('active', m === mode);
  });
  renderLogs();
}

function setSearchQuery() {
  currentSearchQuery = document.getElementById('log-search').value.trim();
  renderLogs();
}

function clearSearch() {
  currentSearchQuery = "";
  const input = document.getElementById('log-search');
  if (input) input.value = "";
  renderLogs();
}

function parseSearchQuery(q) {
  if (!q) return [];
  const tokens = q.split(/\s+/).filter(Boolean);
  const filters = [];
  tokens.forEach(tok => {
    const parts = tok.split('=');
    if (parts.length === 2) {
      filters.push({ key: parts[0].toLowerCase(), value: parts[1].toLowerCase() });
    } else {
      filters.push({ key: 'any', value: tok.toLowerCase() });
    }
  });
  return filters;
}

function matchesSearch(log, filters) {
  if (!filters || filters.length === 0) return true;

  const host = (log.host || "").toLowerCase();
  const level = (log.level || "").toLowerCase();
  const message = (log.message || "").toLowerCase();
  const source = (log.source || "").toLowerCase();
  const agentName = (log.agent_name || "").toLowerCase();
  const ip = (log.ip || "").toLowerCase();

  return filters.every(f => {
    const v = f.value;
    switch (f.key) {
      case 'host': return host.includes(v);
      case 'level': return level.includes(v);
      case 'msg':
      case 'message': return message.includes(v);
      case 'source': return source.includes(v);
      case 'agent': return agentName.includes(v);
      case 'ip': return ip.includes(v);
      case 'any':
      default:
        return (
          host.includes(v) ||
          level.includes(v) ||
          message.includes(v) ||
          source.includes(v) ||
          agentName.includes(v) ||
          ip.includes(v)
        );
    }
  });
}

function renderLogs() {
  const tbody = document.getElementById('logs-body');
  tbody.innerHTML = '';

  const now = new Date();
  let fromTime = null;
  let toTime = null;

  if (currentFilter === '1d') {
    fromTime = new Date(now.getTime() - 24*60*60*1000);
  } else if (currentFilter === '7d') {
    fromTime = new Date(now.getTime() - 7*24*60*60*1000);
  } else if (currentFilter === '30d') {
    fromTime = new Date(now.getTime() - 30*24*60*60*1000);
  } else if (currentFilter === 'custom') {
    const fromStr = document.getElementById('custom-from').value;
    const toStr = document.getElementById('custom-to').value;
    if (fromStr) fromTime = new Date(fromStr);
    if (toStr) toTime = new Date(toStr);
  }

  const filters = parseSearchQuery(currentSearchQuery);

  let filtered = logsCache.slice();
  filtered = filtered.filter(l => {
    const t = new Date(l.timestamp);
    if (fromTime && t < fromTime) return false;
    if (toTime && t > toTime) return false;
    return matchesSearch(l, filters);
  });

  filtered.forEach(l => {
    const tr = document.createElement('tr');
    const levelClass = 'level-' + (l.level || 'INFO');
    const checked = selectedLogIds.has(l.id);
    tr.innerHTML = `
      <td><input type="checkbox" data-log-id="${l.id}" ${checked ? 'checked' : ''} onclick="toggleRowSelection(event)"></td>
      <td class="small">${l.timestamp}</td>
      <td>${l.host}</td>
      <td class="${levelClass}"><span class="badge">${l.level}</span></td>
      <td>${l.message}</td>
      <td><button style="font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid #334155;background:transparent;color:#e5e7eb;cursor:pointer;" onclick="showLogDetailById('${l.id}')">View</button></td>
    `;
    tbody.appendChild(tr);
  });

  updateSelectedCount();
}

function toggleRowSelection(ev) {
  const id = ev.target.getAttribute('data-log-id');
  if (!id) return;
  if (ev.target.checked) {
    selectedLogIds.add(id);
  } else {
    selectedLogIds.delete(id);
    const chkAll = document.getElementById('chk-all');
    if (chkAll) chkAll.checked = false;
  }
  updateSelectedCount();
}

function toggleSelectAll(master) {
  selectedLogIds.clear();
  if (master.checked) {
    logsCache.forEach(l => { selectedLogIds.add(l.id); });
  }
  renderLogs();
}

function updateSelectedCount() {
  const lbl = document.getElementById('selected-count-label');
  if (lbl) lbl.textContent = selectedLogIds.size + ' selected';
}

// ---- log detail modal ----
function showLogDetailById(id) {
  const log = logsCache.find(l => l.id === id);
  if (!log) return;
  const body = document.getElementById('log-detail-body');
  const ip = log.ip || "";
  const source = log.source || "";
  const agentName = log.agent_name || "";
  const lines = [];

  lines.push(`<div style="margin-bottom:8px;">`);
  lines.push(`<span class="badge-pill label">Time</span><span class="badge-pill value">${log.timestamp}</span>`);
  lines.push(`<span class="badge-pill label">Host</span><span class="badge-pill value">${log.host}</span>`);
  if (agentName) {
    lines.push(`<span class="badge-pill label">Agent</span><span class="badge-pill value">${agentName}</span>`);
  }
  if (source) {
    lines.push(`<span class="badge-pill label">Source</span><span class="badge-pill value">${source}</span>`);
  }
  if (ip) {
    lines.push(`<span class="badge-pill label">IP</span><span class="badge-pill value">${ip}</span>`);
  }
  lines.push(`</div>`);

  lines.push(`<div style="margin-bottom:8px;">`);
  lines.push(`<span class="badge-pill label">Level</span><span class="badge-pill value">${log.level}</span>`);
  lines.push(`</div>`);

  lines.push(`<div style="margin-bottom:8px;"><span class="badge-pill label">Message</span></div>`);
  lines.push(`<pre>${escapeHtml(log.message || "")}</pre>`);

  if (ip) {
    lines.push(`<div style="margin-top:8px;">`);
    lines.push(`<button class="primary" onclick="lookupIp('${ip}')">Lookup IP reputation</button>`);
    lines.push(`<span class="small" id="lookup-status" style="margin-left:8px;"></span>`);
    lines.push(`</div>`);
  } else {
    lines.push(`<p class="small" style="margin-top:8px;">No IP attached to this log.</p>`);
  }

  body.innerHTML = lines.join("");
  document.getElementById('log-detail-modal').style.display = 'flex';
}

function closeLogDetail() {
  document.getElementById('log-detail-modal').style.display = 'none';
  const st = document.getElementById('lookup-status');
  if (st) st.textContent = "";
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function lookupIp(ip) {
  const status = document.getElementById('lookup-status');
  if (status) {
    status.textContent = "Looking up " + ip + "...";
  }
  try {
    const res = await fetch('/api/lookup/ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value: ip })
    });
    if (!res.ok) {
      if (status) status.textContent = "Lookup failed";
      return;
    }
    const data = await res.json();
    const isBad = data.is_malicious;
    const reason = data.reason || "";
    if (status) {
      status.textContent = (isBad ? "Malicious IP detected! " : "No malicious verdict. ") + reason;
      status.style.color = isBad ? '#f97316' : '#9ca3af';
    }
    // refresh alerts table to include auto-created alert, if any
    fetchAlerts();
  } catch (err) {
    console.error('lookupIp error', err);
    if (status) status.textContent = "Lookup error";
  }
}

// ---- alerts from selected logs ----
function openAlertFromSelected() {
  if (selectedLogIds.size === 0) {
    alert('Select at least one log row first.');
    return;
  }

  const selectedLogs = logsCache.filter(l => selectedLogIds.has(l.id));
  const uniqueKeywords = new Set();
  selectedLogs.forEach(l => {
    (l.message || "").split(/\s+/).forEach(w => {
      if (w.length > 4) uniqueKeywords.add(w.toLowerCase());
    });
  });
  const firstKeyword = Array.from(uniqueKeywords)[0] || '';

  document.getElementById('alert-name').value = '';
  document.getElementById('alert-level').value = 'ANY';
  document.getElementById('alert-keyword').value = firstKeyword;
  document.getElementById('alert-description').value =
    `Created from ${selectedLogs.length} selected logs.`;

  document.getElementById('inline-alert-form').style.display = '';
}

function closeInlineAlertForm() {
  document.getElementById('inline-alert-form').style.display = 'none';
}

async function submitAlertFromSelection() {
  const name = document.getElementById('alert-name').value.trim();
  const level = document.getElementById('alert-level').value;
  const keyword = document.getElementById('alert-keyword').value.trim();
  const description = document.getElementById('alert-description').value.trim();

  if (!name || !keyword) {
    alert('Name and keyword are required.');
    return;
  }

  try {
    const res = await fetch('/api/alerts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, level, keyword, description })
    });
    if (!res.ok) {
      console.error('Failed to create alert', await res.text());
      alert('Failed to create alert');
      return;
    }
    closeInlineAlertForm();
    fetchAlerts();
    switchTab('alerts');
  } catch (err) {
    console.error('submitAlertFromSelection error', err);
  }
}

// ---- fetchers ----
async function fetchAgents() {
  try {
    const res = await fetch('/api/agents');
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById('agents-body');
    tbody.innerHTML = '';
    data.forEach(a => {
      const tr = document.createElement('tr');
      const statusClass = a.status === 'online' ? 'status-online' : 'status-offline';
      tr.innerHTML = `
        <td><span class="small">${a.id}</span></td>
        <td>${a.name}</td>
        <td>${a.host}</td>
        <td class="small">${a.last_seen}</td>
        <td class="${statusClass}">${a.status.toUpperCase()}</td>
        <td>
          <button onclick="removeAgent('${a.id}')" style="font-size:11px;padding:2px 6px;border-radius:999px;border:1px solid #4b5563;background:transparent;color:#e5e7eb;cursor:pointer;">
            Remove
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('fetchAgents error', err);
  }
}

async function removeAgent(id) {
  try {
    const res = await fetch('/api/admin/agents/remove/' + id, { method: 'POST' });
    if (res.ok) {
      fetchAgents();
    }
  } catch (err) {
    console.error('removeAgent error', err);
  }
}

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    if (!res.ok) return;
    logsCache = await res.json();
    renderLogs();
  } catch (err) {
    console.error('fetchLogs error', err);
  }
}

async function fetchAlerts() {
  try {
    const res = await fetch('/api/alerts');
    if (!res.ok) return;
    const data = await res.json();
    const tbody = document.getElementById('alerts-body');
    if (!tbody) return;
    tbody.innerHTML = '';
    data.forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.name}</td>
        <td>${a.level}</td>
        <td>${a.keyword}</td>
        <td class="small">${a.description || ''}</td>
        <td class="small">${a.created_at}</td>
        <td>${a.enabled ? 'YES' : 'NO'}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('fetchAlerts error', err);
  }
}

// initial load
switchTab('logs');
setLogFilter('7d');
fetchLogs();
fetchAlerts();
fetchAgents();
setInterval(fetchLogs, 5000);
setInterval(fetchAlerts, 10000);
setInterval(fetchAgents, 5000);
</script>
</body>
</html>
"#
    .to_string()
}
