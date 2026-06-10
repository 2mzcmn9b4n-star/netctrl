//! Main entry point for the Rust engine.
//!
//! Startup sequence:
//!   1. Read config (interface name, MAC, IP, gateway) from CLI args or env.
//!   2. Initialize global device registry.
//!   3. Run ARP broadcast scan (/24 subnet) – ~1.5 s.
//!   4. Open pcap handles (capture + send) for L2 forwarding.
//!   5. Launch concurrent tasks:
//!        a) ARP poison loop  (tokio blocking task – pcap is blocking)
//!        b) L2 forward loop  (tokio blocking task – pcap is blocking)
//!        c) HTTP API server  (axum, tokio async task)
//!   6. Wait for Ctrl+C, then gracefully restore every monitored host and exit.

use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;

mod device_registry;
mod l2_forwarder;
mod scanner;
mod server;
mod spoofer;

// ------------------------------------------------------------------
// Gateway MAC auto-resolution (mirrors Python detect_context)
// ------------------------------------------------------------------

/// Resolve the Gateway MAC address by sending a targeted ARP who-has request.
/// Returns the MAC string if resolution succeeds, or an error string.
fn resolve_gateway_mac(
    iface: &str,
    local_mac: &str,
    local_ip: &str,
    gateway_ip: &str,
) -> Result<String, String> {
    use pcap::Capture;
    use pcap::Device as PcapDevice;
    use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet_packet::Packet;
    use pnet::util::MacAddr;

    println!("[MAIN] Resolving gateway MAC for {} via ARP...", gateway_ip);

    let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
    let dev = devices
        .into_iter()
        .find(|d| d.name == iface)
        .ok_or_else(|| format!("interface '{}' not found", iface))?;

    let mut cap = Capture::from_device(dev.clone())
        .map_err(|e| format!("pcap open for ARP: {}", e))?
        .promisc(true)
        .snaplen(65535)
        .timeout(100)
        .immediate_mode(true)
        .open()
        .map_err(|e| format!("pcap open capture: {}", e))?;

    cap.filter("arp", true)
        .map_err(|e| format!("pcap arp filter: {}", e))?;

    let local_mac_bytes = l2_forwarder::parse_mac_to_bytes(local_mac)?;
    let local_ip_bytes = parse_ip_bytes(local_ip);
    let gateway_ip_bytes = parse_ip_bytes(gateway_ip);

    // Build ARP who-has for gateway IP
    let mut buf = vec![0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        eth.set_source(MacAddr(
            local_mac_bytes[0], local_mac_bytes[1], local_mac_bytes[2],
            local_mac_bytes[3], local_mac_bytes[4], local_mac_bytes[5],
        ));
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..]).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(MacAddr(
            local_mac_bytes[0], local_mac_bytes[1], local_mac_bytes[2],
            local_mac_bytes[3], local_mac_bytes[4], local_mac_bytes[5],
        ));
        arp.set_sender_proto_addr(
            std::net::Ipv4Addr::new(
                local_ip_bytes[0], local_ip_bytes[1],
                local_ip_bytes[2], local_ip_bytes[3],
            )
            .into(),
        );
        arp.set_target_hw_addr(MacAddr(0, 0, 0, 0, 0, 0));
        arp.set_target_proto_addr(
            std::net::Ipv4Addr::new(
                gateway_ip_bytes[0], gateway_ip_bytes[1],
                gateway_ip_bytes[2], gateway_ip_bytes[3],
            )
            .into(),
        );
    }
    // Pad to 60 bytes minimum Ethernet frame
    if buf.len() < 60 { buf.resize(60, 0u8); }

    // Retry up to 3 times
    for attempt in 1..=3 {
        // Need a clone each time because sendpacket takes ownership
        let arp_pkt = buf.clone();
        cap.sendpacket(arp_pkt)
            .map_err(|e| format!("sendpacket ARP who-has: {}", e))?;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            match cap.next_packet() {
                Ok(pkt) => {
                    use pnet_packet::ethernet::EthernetPacket;
                    if let Some(eth) = EthernetPacket::new(pkt.data) {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply {
                                let sender_ip = arp.get_sender_proto_addr();
                                let gw_ip = format!("{}", sender_ip);
                                if gw_ip == gateway_ip {
                                    let smac = arp.get_sender_hw_addr();
                                    let gw_mac = format!(
                                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        smac.0, smac.1, smac.2, smac.3, smac.4, smac.5,
                                    );
                                    println!("[MAIN] Gateway MAC resolved: {}", gw_mac);
                                    return Ok(gw_mac);
                                }
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => break,
            }
        }
        println!("[MAIN] ARP attempt {}/3 timed out, retrying...", attempt);
    }

    Err(format!(
        "Could not resolve gateway MAC for {}. Is the gateway reachable? Are you running as admin?",
        gateway_ip
    ))
}

fn parse_ip_bytes(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    let mut out = [0u8; 4];
    let n = parts.len().min(4);
    out[..n].copy_from_slice(&parts[..n]);
    out
}

// ------------------------------------------------------------------
// CLI arguments (mirrors Python main.py settings)
// ------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "rust_engine",
    about = "High-performance Layer-2 network management engine",
    version = env!("CARGO_PKG_VERSION")
)]
struct Args {
    /// Network interface to bind (e.g. "Ethernet" or "eth0")
    #[arg(short, long, default_value = "Ethernet")]
    interface: String,

    /// Local IP address (host machine)
    #[arg(long, default_value = "192.168.0.100")]
    ip: String,

    /// Local MAC address
    #[arg(long, default_value = "aa:bb:cc:dd:ee:ff")]
    mac: String,

    /// Gateway IP address
    #[arg(short, long, default_value = "192.168.1.1")]
    gateway_ip: String,

    /// Gateway MAC address. If omitted, auto-resolved via ARP who-has.
    #[arg(long, default_value = "")]
    gateway_mac: String,

    /// HTTP API listen address
    #[arg(short, long, default_value = "127.0.0.1:8765")]
    listen: String,

    /// Subnet prefix (first three octets) for ARP scan
    #[arg(long, default_value = "192.168.1")]
    subnet: String,

    /// ARP poison interval in milliseconds
    #[arg(long, default_value = "2000")]
    arp_interval: u64,
}

// ------------------------------------------------------------------
// Main
// ------------------------------------------------------------------

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args = Args::parse();

    // ---- Interface selection (Feature #5) ----
    // 1. Try the --interface argument directly as a pcap device name.
    // 2. If that fails or is the default "Ethernet", fall back to
    //    auto-detecting by matching the configured local IP against
    //    each device's address list.

    println!("[DEBUG] Enumerating pcap devices...");
    let all_devices =
        pcap::Device::list().expect("FATAL: pcap::Device::list() failed");

    for dev in &all_devices {
        let ips: Vec<String> = dev
            .addresses
            .iter()
            .map(|a| a.addr.to_string())
            .collect();
        println!(
            "[DEBUG]   name: {}  desc: {:?}  ips: {:?}",
            dev.name, dev.desc, ips
        );
    }

    // Try explicit --interface first
    let mut actual_iface: Option<String> = None;
    if !args.interface.is_empty() && args.interface != "Ethernet" {
        if all_devices.iter().any(|d| d.name == args.interface) {
            actual_iface = Some(args.interface.clone());
            println!(
                "[MAIN] Using explicitly provided interface: {}",
                actual_iface.as_ref().unwrap()
            );
        } else {
            eprintln!(
                "[MAIN] !! --interface '{}' not found in pcap device list; falling back to IP auto-detection",
                args.interface
            );
        }
    }

    // Fallback: auto-detect by IP
    if actual_iface.is_none() {
        for dev in &all_devices {
            let ips: Vec<String> = dev
                .addresses
                .iter()
                .map(|a| a.addr.to_string())
                .collect();
            if ips.iter().any(|ip_str| ip_str == &args.ip) {
                actual_iface = Some(dev.name.clone());
            }
        }
    }

    let actual_iface = actual_iface.unwrap_or_else(|| {
        panic!(
            "Could not find any pcap device matching interface '{}' or IP {}! \
             Check that the interface is up and the IP is correct.",
            args.interface, args.ip
        );
    });

    println!(
        "[MAIN] Selected interface: {}  (IP: {})",
        actual_iface, args.ip
    );

    // ---- Gateway MAC resolution ----
    // BUG FIX #1: Validate that provided gateway_mac is a real MAC address.
    // main.py may pass "??:??:??:??:??:??" when ARP cache lookup fails,
    // which would cause us to skip ARP resolution and break DL/UL counting.
    let gateway_mac_provided = !args.gateway_mac.is_empty()
        && !args.gateway_mac.contains('?')
        && l2_forwarder::parse_mac_to_bytes(&args.gateway_mac).is_ok();

    let gateway_mac = if gateway_mac_provided {
        println!("[MAIN] Using provided gateway MAC: {}", args.gateway_mac);
        args.gateway_mac.clone()
    } else if !args.gateway_mac.is_empty() {
        println!(
            "[MAIN] Gateway MAC '{}' looks invalid — falling back to ARP resolution",
            args.gateway_mac
        );
        match resolve_gateway_mac(&actual_iface, &args.mac, &args.ip, &args.gateway_ip) {
            Ok(gw_mac) => gw_mac,
            Err(e) => {
                eprintln!("[MAIN] !! Gateway MAC resolution failed: {}", e);
                eprintln!("[MAIN]    Please provide --gateway-mac manually or ensure gateway is reachable.");
                return;
            }
        }
    } else {
        match resolve_gateway_mac(&actual_iface, &args.mac, &args.ip, &args.gateway_ip) {
            Ok(gw_mac) => gw_mac,
            Err(e) => {
                eprintln!("[MAIN] !! Gateway MAC resolution failed: {}", e);
                eprintln!("[MAIN]    Please provide --gateway-mac manually or ensure gateway is reachable.");
                return;
            }
        }
    };

    println!("╔══════════════════════════════════════════════╗");
    println!("║  Rust Engine v{}                         ║", env!("CARGO_PKG_VERSION"));
    println!("║  Interface : {:<31} ║", actual_iface);
    println!("║  IP        : {:<31} ║", args.ip);
    println!("║  MAC       : {:<31} ║", args.mac);
    println!("║  Gateway   : {:<31} ║", args.gateway_ip);
    println!("║  GW MAC    : {:<31} ║", gateway_mac);
    println!("║  HTTP API  : {:<31} ║", args.listen);
    println!("╚══════════════════════════════════════════════╝");

    // ---- 1. ARP Scan ----
    let scanner = scanner::Scanner::new(
        &actual_iface,
        &args.mac,
        &args.ip,
        &args.subnet,
        &args.gateway_ip,
    );
    match scanner.run_scan() {
        Ok(n) => println!("[MAIN] Scanner discovered {} host(s)", n),
        Err(e) => eprintln!("[MAIN] !! Scanner error: {}", e),
    }

    // Register the local machine as a special device (Feature #3)
    {
        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "This Device".to_string());
        device_registry::REGISTRY.register_local(&args.ip, &args.mac, &hostname);
        println!("[MAIN] Registered local device: ip={} mac={} hostname={}", args.ip, args.mac, hostname);
    }

    // ---- 2. Build engine components ----
    let forwarder = std::sync::Arc::new(l2_forwarder::L2Forwarder::new(
        &actual_iface,
        &args.ip,
        &args.mac,
        &gateway_mac,
    ));

    let spoofer = std::sync::Arc::new(spoofer::Spoofer::new(
        &actual_iface,
        &args.mac,
        &args.gateway_ip,
        &gateway_mac,
        args.arp_interval,
    ));

    // ---- 3. Open pcap handles ----
    if let Err(e) = forwarder.open_capture() {
        eprintln!("[MAIN] !! Failed to open L2 capture: {}", e);
        return;
    }

    if let Err(e) = forwarder.open_send() {
        eprintln!("[MAIN] !! Failed to open L2 send handle: {}", e);
        return;
    }

    // ---- 4. Launch background tasks ----

    // 4a) ARP poison loop (blocking)
    let spoofer_clone = spoofer.clone();
    let poison_handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = spoofer_clone.run_poison_loop() {
            eprintln!("[MAIN] !! Spoofer stopped: {}", e);
        }
    });

    // 4b) L2 forwarder (blocking)
    let forwarder_clone = forwarder.clone();
    let forward_handle = tokio::task::spawn_blocking(move || {
        if let Err(e) = forwarder_clone.run_forwarding_loop() {
            eprintln!("[MAIN] !! Forwarder stopped: {}", e);
        }
    });

    // 4c) Speed ticker – runs once per second to compute dl_speed/ul_speed
    let _tick_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            device_registry::REGISTRY.tick_speeds();
        }
    });

    // 4d) HTTP API server (async)
    let listen_addr: SocketAddr = args.listen.parse().expect("invalid listen address");
    let scanner_arc = Arc::new(scanner);
    let server_state = server::AppState {
        spoofer: spoofer.clone(),
        forwarder: forwarder.clone(),
        scanner: scanner_arc,
        gateway_mac: gateway_mac.clone(),
        interface: actual_iface.clone(),
        local_ip: args.ip.clone(),
        local_mac: args.mac.clone(),
        gateway_ip: args.gateway_ip.clone(),
    };
    let server_handle = tokio::spawn(async move {
        server::run_server(listen_addr, server_state).await;
    });

    // ---- 6. Wait for Ctrl+C ----
    println!("[MAIN] Engine running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await.ok();
    println!("\n[MAIN] Ctrl+C received. Initiating graceful shutdown...");

    // Signal spoofer to stop
    spoofer.stop();

    // Close the capture handle to unblock the forwarder
    forwarder.close_capture();

    // Wait for tasks to finish (with timeout)
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        async {
            let _ = poison_handle.await;
            let _ = server_handle.await;
        },
    )
    .await;

    // Best-effort wait for forwarder
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        forward_handle,
    )
    .await;

    // ---- 6. Graceful ARP restore for all monitored devices ----
    let devices = device_registry::REGISTRY.get_all();
    for dev in &devices {
        if dev.is_monitored {
            println!(
                "[MAIN] Restoring ARP for {} ({})...",
                dev.ip, dev.mac
            );
            if let Err(e) = spoofer.send_arp_restore(&dev.ip, &dev.mac) {
                eprintln!("[MAIN] !! Restore failed for {}: {}", dev.ip, e);
            }
        }
    }

    println!("[MAIN] Shutdown complete. Goodbye.");
}