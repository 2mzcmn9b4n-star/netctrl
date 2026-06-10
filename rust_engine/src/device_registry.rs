//! device_registry.rs
//! ==================
//! Thread-safe state management for discovered LAN devices.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub name: String,
    pub display_name: Option<String>,
    pub dl_bytes: u64,
    pub ul_bytes: u64,
    pub dl_speed: f64,
    pub ul_speed: f64,
    pub total_ul_bytes: u64,
    pub total_dl_bytes: u64,
    pub is_monitored: bool,
    pub is_blocked: bool,
    pub is_local: bool,
    pub speed_limit_kbps: Option<f64>,
    pub first_seen: f64,
    pub last_seen: f64,
}

#[derive(Debug)]
struct DeviceInner {
    ip: String,
    mac: String,
    name: String,
    /// Resolved display name (NetBIOS/mDNS/json). None = not yet resolved.
    display_name: Option<String>,
    dl_bytes: AtomicU64,
    ul_bytes: AtomicU64,
    total_ul_bytes: AtomicU64,
    total_dl_bytes: AtomicU64,
    prev_dl: AtomicU64,
    prev_ul: AtomicU64,
    dl_speed: f64,
    ul_speed: f64,
    is_monitored: bool,
    unmonitored_at: Option<Instant>,
    is_blocked: bool,
    is_local: bool,
    speed_limit: Option<f64>,
    tokens: AtomicU64,
    last_token_update: Instant,
    first_seen: Instant,
    last_seen: Instant,
}

pub struct DeviceRegistry {
    devices: RwLock<HashMap<String, DeviceInner>>,
    last_tick: RwLock<Instant>,
    start_instant: Instant,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self {
            devices: RwLock::new(HashMap::new()),
            last_tick: RwLock::new(Instant::now()),
            start_instant: Instant::now(),
        }
    }

    // ------------------------------------------------------------------
    // Registration / discovery
    // ------------------------------------------------------------------

    pub fn register(&self, ip: &str, mac: &str, name: &str, is_local: bool) -> bool {
        let mac_lower = mac.to_lowercase();
        let now = Instant::now();

        let mut devices = self.devices.write().unwrap();
        if let Some(dev) = devices.get_mut(&mac_lower) {
            dev.ip = ip.to_string();
            dev.last_seen = now;
            return false;
        }

        let dev = DeviceInner {
            ip: ip.to_string(),
            mac: mac_lower.clone(),
            name: if name.is_empty() {
                "Unknown".to_string()
            } else {
                name.to_string()
            },
            dl_bytes: AtomicU64::new(0),
            ul_bytes: AtomicU64::new(0),
            total_ul_bytes: AtomicU64::new(0),
            total_dl_bytes: AtomicU64::new(0),
            prev_dl: AtomicU64::new(0),
            prev_ul: AtomicU64::new(0),
            dl_speed: 0.0,
            ul_speed: 0.0,
            is_monitored: !is_local, // local device is never monitored
            display_name: None,
            unmonitored_at: None,
            is_blocked: false,
            is_local,
            speed_limit: None,
            tokens: AtomicU64::new(f64::MAX.to_bits()),
            last_token_update: now,
            first_seen: now,
            last_seen: now,
        };

        println!(
            "[REGISTRY] NEW device registered: ip={} mac={} name={} monitored={} local={}",
            dev.ip, mac_lower, dev.name, dev.is_monitored, dev.is_local
        );

        devices.insert(mac_lower, dev);
        true
    }

    /// Register the local machine (the one running NetCtrl) as a special entry.
    pub fn register_local(&self, ip: &str, mac: &str, hostname: &str) {
        self.register(ip, mac, hostname, true);
    }

    // ------------------------------------------------------------------
    // Lookups
    // ------------------------------------------------------------------

    pub fn get_by_mac(&self, mac: &str) -> Option<Device> {
        let mac_lower = mac.to_lowercase();
        let devices = self.devices.read().unwrap();
        devices.get(&mac_lower).map(|d| self.to_device_snapshot(d))
    }

    pub fn get_by_ip(&self, ip: &str) -> Option<Device> {
        let devices = self.devices.read().unwrap();
        devices
            .values()
            .find(|d| d.ip == ip)
            .map(|d| self.to_device_snapshot(d))
    }

    /// Returns all devices with the local machine FIRST, then sorted by IP.
    pub fn get_all(&self) -> Vec<Device> {
        let devices = self.devices.read().unwrap();
        let mut all: Vec<Device> = devices.values().map(|d| self.to_device_snapshot(d)).collect();
        // Sort: local devices first (true > false), then by IP
        all.sort_by(|a, b| {
            b.is_local
                .cmp(&a.is_local)
                .then_with(|| a.ip.cmp(&b.ip))
        });
        all
    }

    pub fn get_monitored(&self) -> Vec<Device> {
        let devices = self.devices.read().unwrap();
        devices
            .values()
            .filter(|d| d.is_monitored)
            .map(|d| self.to_device_snapshot(d))
            .collect()
    }

    pub fn is_monitored_by_mac(&self, mac: &str) -> bool {
        let mac_lower = mac.to_lowercase();
        let devices = self.devices.read().unwrap();
        devices.get(&mac_lower).map_or(false, |d| d.is_monitored)
    }

    pub fn is_blocked_mac(&self, mac: &str) -> bool {
        let mac_lower = mac.to_lowercase();
        let devices = self.devices.read().unwrap();
        devices.get(&mac_lower).map_or(false, |d| d.is_blocked)
    }

    pub fn is_in_grace_period(&self, mac: &str, seconds: f64) -> bool {
        let mac_lower = mac.to_lowercase();
        let devices = self.devices.read().unwrap();
        if let Some(d) = devices.get(&mac_lower) {
            if let Some(at) = d.unmonitored_at {
                return at.elapsed().as_secs_f64() < seconds;
            }
        }
        false
    }

    // ------------------------------------------------------------------
    // State toggling
    // ------------------------------------------------------------------

    pub fn set_monitored(&self, mac: &str, monitored: bool) -> Option<Device> {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        let d = devices.get_mut(&mac_lower)?;
        let prev = d.is_monitored;
        d.is_monitored = monitored;
        if monitored {
            d.unmonitored_at = None;
        }
        println!(
            "[REGISTRY] set_monitored: mac={} {} -> {}",
            mac_lower, prev, d.is_monitored
        );
        Some(self.to_device_snapshot(d))
    }

    pub fn set_blocked(&self, mac: &str, blocked: bool) -> Option<Device> {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        let d = devices.get_mut(&mac_lower)?;
        d.is_blocked = blocked;
        println!(
            "[REGISTRY] set_blocked: mac={} -> {}",
            mac_lower, blocked
        );
        Some(self.to_device_snapshot(d))
    }

    pub fn set_speed_limit(&self, mac: &str, speed_limit_kbps: Option<f64>) -> Option<Device> {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        let d = devices.get_mut(&mac_lower)?;
        d.speed_limit = speed_limit_kbps.map(|kbps| kbps * 1024.0);
        let initial_tokens = d.speed_limit.unwrap_or(f64::MAX);
        d.tokens.store(initial_tokens.to_bits(), Ordering::Relaxed);
        d.last_token_update = Instant::now();
        println!(
            "[REGISTRY] set_speed_limit: mac={} -> {:?} bytes/sec",
            mac_lower, d.speed_limit
        );
        Some(self.to_device_snapshot(d))
    }

    pub fn allow_packet(&self, mac: &str, size: u64) -> bool {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        let Some(d) = devices.get_mut(&mac_lower) else {
            return false;
        };

        let limit = match d.speed_limit {
            Some(l) => l,
            None => return true,
        };

        let now = Instant::now();
        let elapsed = d.last_token_update.elapsed().as_secs_f64();
        let current_tokens = f64::from_bits(d.tokens.load(Ordering::Relaxed));
        let mut new_tokens = current_tokens + elapsed * limit;
        d.last_token_update = now;

        let max_tokens = limit * 2.0;
        if new_tokens > max_tokens {
            new_tokens = max_tokens;
        }

        if new_tokens >= size as f64 {
            new_tokens -= size as f64;
            d.tokens.store(new_tokens.to_bits(), Ordering::Relaxed);
            true
        } else {
            d.tokens.store(new_tokens.to_bits(), Ordering::Relaxed);
            false
        }
    }

    /// FIX #2: Refund tokens when forwarder fails to send a packet that was
    /// already counted by allow_packet.  Call this from l2_forwarder on send
    /// error to avoid permanent token drain & phantom byte counting.
    pub fn refund_tokens(&self, mac: &str, size: u64) {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        if let Some(d) = devices.get_mut(&mac_lower) {
            if d.speed_limit.is_some() {
                let current = f64::from_bits(d.tokens.load(Ordering::Relaxed));
                let limit = d.speed_limit.unwrap();
                let max_tokens = limit * 2.0;
                let refunded = (current + size as f64).min(max_tokens);
                d.tokens.store(refunded.to_bits(), Ordering::Relaxed);
            }
        }
    }

    pub fn set_unmonitored_timestamp(&self, mac: &str) {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        if let Some(d) = devices.get_mut(&mac_lower) {
            d.unmonitored_at = Some(Instant::now());
        }
    }

    // ------------------------------------------------------------------
    // Byte accounting
    // ------------------------------------------------------------------

    pub fn add_ul(&self, mac: &str, n: u64) {
        let mac_lower = mac.to_lowercase();
        let devices = self.devices.read().unwrap();
        if let Some(d) = devices.get(&mac_lower) {
            d.ul_bytes.fetch_add(n, Ordering::Relaxed);
            d.total_ul_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    pub fn add_dl(&self, mac: &str, n: u64) {
        let mac_lower = mac.to_lowercase();
        let devices = self.devices.read().unwrap();
        if let Some(d) = devices.get(&mac_lower) {
            d.dl_bytes.fetch_add(n, Ordering::Relaxed);
            d.total_dl_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    // ------------------------------------------------------------------
    // Periodic speed calculation
    // ------------------------------------------------------------------

    pub fn tick_speeds(&self) {
        let dt = {
            let mut last_tick = self.last_tick.write().unwrap();
            let now = Instant::now();
            let dt = now.duration_since(*last_tick).as_secs_f64().max(1e-3);
            *last_tick = now;
            dt
        };

        let macs: Vec<String> = {
            let devices = self.devices.read().unwrap();
            devices.keys().cloned().collect()
        };

        for mac in &macs {
            let mut devices = self.devices.write().unwrap();
            if let Some(d) = devices.get_mut(mac) {
                let dl_bytes = d.dl_bytes.load(Ordering::Relaxed);
                let ul_bytes = d.ul_bytes.load(Ordering::Relaxed);
                let prev_dl = d.prev_dl.load(Ordering::Relaxed);
                let prev_ul = d.prev_ul.load(Ordering::Relaxed);

                d.dl_speed = (dl_bytes.saturating_sub(prev_dl)) as f64 / dt;
                d.ul_speed = (ul_bytes.saturating_sub(prev_ul)) as f64 / dt;
                d.prev_dl.store(dl_bytes, Ordering::Relaxed);
                d.prev_ul.store(ul_bytes, Ordering::Relaxed);
            }
        }
    }

    // ------------------------------------------------------------------
    // Display name resolution (Feature #4)
    // ------------------------------------------------------------------

    /// Set the human-readable display name for a device (e.g. from NetBIOS/mDNS).
    pub fn set_display_name(&self, mac: &str, name: &str) {
        let mac_lower = mac.to_lowercase();
        let mut devices = self.devices.write().unwrap();
        if let Some(d) = devices.get_mut(&mac_lower) {
            d.display_name = Some(name.to_string());
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn to_device_snapshot(&self, d: &DeviceInner) -> Device {
        Device {
            ip: d.ip.clone(),
            mac: d.mac.clone(),
            name: d.name.clone(),
            display_name: d.display_name.clone(),
            dl_bytes: d.dl_bytes.load(Ordering::Relaxed),
            ul_bytes: d.ul_bytes.load(Ordering::Relaxed),
            dl_speed: d.dl_speed,
            ul_speed: d.ul_speed,
            total_ul_bytes: d.total_ul_bytes.load(Ordering::Relaxed),
            total_dl_bytes: d.total_dl_bytes.load(Ordering::Relaxed),
            is_monitored: d.is_monitored,
            is_blocked: d.is_blocked,
            is_local: d.is_local,
            speed_limit_kbps: d.speed_limit.map(|bps| bps / 1024.0),
            first_seen: d.first_seen.duration_since(self.start_instant).as_secs_f64(),
            last_seen: d.last_seen.duration_since(self.start_instant).as_secs_f64(),
        }
    }
}

pub static REGISTRY: once_cell::sync::Lazy<DeviceRegistry> =
    once_cell::sync::Lazy::new(DeviceRegistry::new);