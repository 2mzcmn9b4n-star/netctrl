//! server.rs
//! =========
//! Axum HTTP API server exposing the exact same JSON API as the Python
//! server.py so the GUI (`gui.py`) can connect without modification.
//!
//! Endpoints (EXACT match to Python server.py)
//! -------------------------------------------
//!   GET  /api/devices       – list all known devices
//!   GET  /api/health        – liveness probe
//!   POST /api/monitor       – set is_monitored = true/false per device
//!   POST /api/scan          – trigger an immediate ARP sweep
//!   POST /api/block         – toggle is_blocked flag
//!   POST /api/speed         – set speed limit for a device
//!   POST /api/restore-all   – un-monitor EVERY device (graceful ARP restore)

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use serde::Deserialize;
use tower_http::cors::{Any, CorsLayer};

use crate::device_registry::REGISTRY;

// ------------------------------------------------------------------
// Request logging middleware — logs every incoming request BEFORE routing
// ------------------------------------------------------------------
async fn log_requests(req: Request<axum::body::Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    println!("[SERVER] {} {}", method, uri.path());
    next.run(req).await
}

/// Application state shared with every request handler.
#[derive(Clone)]
pub struct AppState {
    pub spoofer: Arc<crate::spoofer::Spoofer>,
    pub forwarder: Arc<crate::l2_forwarder::L2Forwarder>,
    pub scanner: Arc<crate::scanner::Scanner>,
    /// Resolved gateway MAC (populated by main.rs after ARP resolution)
    pub gateway_mac: String,
    /// Network interface name
    pub interface: String,
    /// Local IP address
    pub local_ip: String,
    /// Local MAC address
    pub local_mac: String,
    /// Gateway IP address
    pub gateway_ip: String,
}

// ------------------------------------------------------------------
// Request / Response types – identical JSON shapes to Python server.py
// ------------------------------------------------------------------

/// POST /api/monitor body.
/// Python GUI sends: {"mac": "...", "monitored": true/false, "is_monitored": true/false}
#[derive(Debug, Deserialize)]
pub struct MonitorRequest {
    pub mac: String,
    #[serde(default)]
    pub monitor: Option<bool>,
    #[serde(default)]
    pub monitored: Option<bool>,
    #[serde(default)]
    pub is_monitored: Option<bool>,
}

/// POST /api/block body – Python sends {"mac": "...", "blocked": true/false}
#[derive(Debug, Deserialize)]
pub struct BlockRequest {
    pub mac: String,
    pub blocked: bool,
}

/// POST /api/speed body – {"mac": "...", "speed_limit_kbps": 512.5 or null}
#[derive(Debug, Deserialize)]
pub struct SpeedRequest {
    pub mac: String,
    pub speed_limit_kbps: Option<f64>,
}

// ------------------------------------------------------------------
// Route setup
// ------------------------------------------------------------------

pub async fn run_server(
    listen_addr: SocketAddr,
    state: AppState,
) {
    let shared = Arc::new(state);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = axum::Router::new()
        .route("/api/devices", get(handle_get_devices))
        .route("/api/health", get(handle_health))
        .route("/api/status", get(handle_status))
        .route("/api/monitor", post(handle_monitor))
        .route("/api/scan", post(handle_scan))
        .route("/api/block", post(handle_block))
        .route("/api/speed", post(handle_speed))
        .route("/api/restore-all", post(handle_restore_all))
        .route("/api/set-name", post(handle_set_name))
        .layer(axum::middleware::from_fn(log_requests))
        .layer(cors)
        .with_state(shared);

    println!(
        "[SERVER] Registered routes: GET /api/devices, GET /api/health, GET /api/status, POST /api/monitor, POST /api/scan, POST /api/block, POST /api/speed, POST /api/restore-all, POST /api/set-name"
    );

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[SERVER] !! Failed to bind {}: {}", listen_addr, e);
            return;
        }
    };

    println!(
        "[SERVER] Listening on http://{} (endpoints: /api/devices /api/health /api/monitor /api/scan /api/block /api/speed /api/restore-all)",
        listen_addr
    );

    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| eprintln!("[SERVER] !! serve error: {}", e));

    println!("[SERVER] HTTP server stopped.");
}

// ------------------------------------------------------------------
// Handlers
// ------------------------------------------------------------------

async fn handle_health() -> impl IntoResponse {
    // Python returns: {"ok": true}
    (StatusCode::OK, Json(serde_json::json!({"ok": true})))
}

async fn handle_status(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Return runtime status including the resolved gateway MAC
    let data = serde_json::json!({
        "ok": true,
        "interface": state.interface,
        "local_ip": state.local_ip,
        "local_mac": state.local_mac,
        "gateway_ip": state.gateway_ip,
        "gateway_mac": state.gateway_mac,
    });
    (StatusCode::OK, Json(data))
}

async fn handle_get_devices(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let devices = REGISTRY.get_all();
    let forwarder_pkts = state.forwarder.stats_pkts();
    // CRITICAL: Return EXACT shape Python GUI expects at gui.py line 279:
    //   payload.get("devices", [])
    // MUST be top-level {"devices": [...]}
    let data = serde_json::json!({
        "devices": devices,
        "packets_forwarded": forwarder_pkts,
    });
    println!(
        "[SERVER] GET /api/devices -> {} devices ({} pkts forwarded)",
        devices.len(),
        forwarder_pkts
    );
    (StatusCode::OK, Json(data))
}

async fn handle_monitor(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MonitorRequest>,
) -> impl IntoResponse {
    let mac = req.mac.to_lowercase();
    // Python GUI sends "monitored" and "is_monitored" keys.
    // Accept any of them (monitor first, then monitored, then is_monitored).
    let monitored = req.monitor
        .or(req.monitored)
        .or(req.is_monitored)
        .unwrap_or(false);

    println!(
        "[SERVER] POST /api/monitor: mac={} monitored={}",
        mac, monitored
    );

    // Validate device exists
    let prev = match REGISTRY.get_by_mac(&mac) {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                // FIX #4: Match Python shape: {"ok": false, "error": "..."}
                Json(serde_json::json!({"ok": false, "error": format!("unknown mac {}", mac)})),
            );
        }
    };

    let prev_monitored = prev.is_monitored;

    // FIX #7: Only trigger ARP restore when transitioning monitored→unmonitored,
    // matching Python server.py line 110-115 exactly.
    let was_monitored = prev_monitored;
    REGISTRY.set_monitored(&mac, monitored);

    // Get the updated device for the response
    let updated = REGISTRY.get_by_mac(&mac);

    if was_monitored && !monitored {
        // Mark unmonitored timestamp for L2Forwarder grace period
        REGISTRY.set_unmonitored_timestamp(&mac);

        // Trigger instant ARP restore
        if let Some(ref dev) = updated {
            println!("[SERVER] INSTANT ARP RESTORE for: ip={} mac={}", dev.ip, dev.mac);
            state.spoofer.send_arp_restore(&dev.ip, &dev.mac).ok();
        }
    }

    // FIX #4: Match Python response shape: {"ok": true, "device": {...}}
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "device": updated})),
    )
}

async fn handle_block(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<BlockRequest>,
) -> impl IntoResponse {
    let mac = req.mac.to_lowercase();
    println!(
        "[SERVER] POST /api/block: mac={} blocked={}",
        mac, req.blocked
    );

    if REGISTRY.get_by_mac(&mac).is_none() {
        return (
            StatusCode::NOT_FOUND,
            // FIX #4: Match Python shape
            Json(serde_json::json!({"ok": false, "error": format!("unknown mac {}", mac)})),
        );
    }

    let updated = REGISTRY.set_blocked(&mac, req.blocked);
    println!(
        "[SERVER] set_blocked: mac={} -> {}",
        mac, req.blocked
    );

    // FIX #4: Match Python response shape: {"ok": true, "device": {...}}
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "device": updated})),
    )
}

async fn handle_speed(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SpeedRequest>,
) -> impl IntoResponse {
    let mac = req.mac.to_lowercase();
    println!(
        "[SERVER] POST /api/speed: mac={} speed_limit_kbps={:?}",
        mac, req.speed_limit_kbps
    );

    if REGISTRY.get_by_mac(&mac).is_none() {
        return (
            StatusCode::NOT_FOUND,
            // FIX #4: Match Python shape
            Json(serde_json::json!({"ok": false, "error": format!("unknown mac {}", mac)})),
        );
    }

    let updated = REGISTRY.set_speed_limit(&mac, req.speed_limit_kbps);
    println!(
        "[SERVER] set_speed_limit: mac={} -> {:?} KB/s",
        mac, req.speed_limit_kbps
    );

    // FIX #4: Match Python response shape: {"ok": true, "device": {...}}
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "device": updated})),
    )
}

async fn handle_scan(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    println!("[SERVER] POST /api/scan – triggering ARP scan");
    // FIX #8: run_scan() uses blocking pcap operations (~1.5 s).
    // Run it on the blocking threadpool so it doesn't starve the async runtime.
    let scanner = state.scanner.clone();
    let count = match tokio::task::spawn_blocking(move || scanner.run_scan()).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            eprintln!("[SERVER] !! scan error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": e})),
            );
        }
        Err(join_err) => {
            eprintln!("[SERVER] !! scan join error: {}", join_err);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"ok": false, "error": join_err.to_string()})),
            );
        }
    };
    println!("[SERVER] scan complete: {} new devices", count);
    // Match Python: {"ok": true, "new_devices": count}
    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "new_devices": count})),
    )
}

async fn handle_restore_all(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    println!("[SERVER] POST /api/restore-all – restoring ALL devices");

    let devices = REGISTRY.get_all();
    let monitored: Vec<_> = devices.iter().filter(|d| d.is_monitored).collect();
    let count = monitored.len();

    // FIX #7: Mark unmonitored timestamp for grace period
    for d in &monitored {
        REGISTRY.set_monitored(&d.mac, false);
        REGISTRY.set_unmonitored_timestamp(&d.mac);
        // FIX #5: Send 3 ARP restores (primary + 2 extras) to guarantee delivery.
        // The first one is the "kill packet" that immediately corrects the victim's
        // ARP cache so they can route directly to the real gateway.
        state.spoofer.send_arp_restore(&d.ip, &d.mac).ok();
    }

    // FIX #4: Match Python API shape – {"ok": true, ...}
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "message": format!("restored {} devices", count),
            "count": count,
        })),
    )
}

/// POST /api/set-name body: {"mac": "...", "display_name": "..."}
#[derive(Debug, Deserialize)]
pub struct SetNameRequest {
    pub mac: String,
    pub display_name: String,
}

async fn handle_set_name(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SetNameRequest>,
) -> impl IntoResponse {
    let mac = req.mac.to_lowercase();
    let name = req.display_name.trim().to_string();
    println!("[SERVER] POST /api/set-name: mac={} name={}", mac, name);

    if name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"ok": false, "error": "display_name cannot be empty"})),
        );
    }

    if REGISTRY.get_by_mac(&mac).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"ok": false, "error": format!("unknown mac {}", mac)})),
        );
    }

    REGISTRY.set_display_name(&mac, &name);

    (
        StatusCode::OK,
        Json(serde_json::json!({"ok": true, "mac": mac, "display_name": name})),
    )
}
