//! scanner.rs
//! ==========
//! Fast ARP broadcast scanner that discovers all devices in the /24 subnet
//! within 1-2 seconds on engine startup.
//!
//! Newly discovered devices are initially set to `is_monitored = true` so the
//! forwarding engine and ARP poisoner pick them up immediately.

use std::collections::HashMap;
use std::time::Instant;

use pcap::Capture;
use pcap::Device as PcapDevice;
use pnet_packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet_packet::Packet;
use pnet::util::MacAddr;

use crate::device_registry::REGISTRY;
use crate::l2_forwarder::parse_mac_to_bytes;

pub struct Scanner {
    iface: String,
    local_mac: String,
    subnet_prefix: String,
    local_ip: String,
    gateway_ip: String,
}

impl Scanner {
    pub fn new(iface: &str, local_mac: &str, local_ip: &str, subnet_prefix: &str, gateway_ip: &str) -> Self {
        Self {
            iface: iface.to_string(),
            local_mac: local_mac.to_lowercase(),
            subnet_prefix: subnet_prefix.to_string(),
            local_ip: local_ip.to_string(),
            gateway_ip: gateway_ip.to_string(),
        }
    }

    pub fn run_scan(&self) -> Result<usize, String> {
        println!(
            "[SCANNER] Starting ARP broadcast scan on {}/24 via interface '{}'",
            self.subnet_prefix, self.iface
        );

        let devices = PcapDevice::list().map_err(|e| format!("pcap device list: {}", e))?;
        let dev = devices
            .into_iter()
            .find(|d| d.name == self.iface)
            .ok_or_else(|| format!("interface '{}' not found", self.iface))?;

        let mut cap = Capture::from_device(dev.clone())
            .map_err(|e| format!("pcap open: {}", e))?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .immediate_mode(true)
            .open()
            .map_err(|e| format!("pcap open capture: {}", e))?;

        cap.filter("arp", true)
            .map_err(|e| format!("pcap arp filter: {}", e))?;

        let local_mac_bytes = parse_mac_to_bytes(&self.local_mac)?;

        // Send ARP requests for all 254 hosts
        for host in 1..=254u8 {
            let target_ip = format!("{}.{}", self.subnet_prefix, host);
            let pkt = build_arp_request(&local_mac_bytes, &self.local_ip, &target_ip);
            if let Err(e) = cap.sendpacket(pkt) {
                eprintln!("[SCANNER] !! sendpacket error for {}: {}", target_ip, e);
            }
        }

        println!("[SCANNER] Sent 254 ARP requests – listening for replies...");

        let deadline = Instant::now() + std::time::Duration::from_millis(1500);
        let mut discovered: HashMap<String, String> = HashMap::new(); // ip -> mac

        while Instant::now() < deadline {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Some((ip, mac)) = parse_arp_reply(packet.data) {
                        if ip != self.gateway_ip {
                            discovered.entry(ip).or_insert(mac);
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(_) => break,
            }
        }

        // Register discovered devices
        let mut count = 0;
        for (ip, mac) in &discovered {
            let hostname = "Unknown".to_string();
            println!("[SCANNER] Discovered: ip={} mac={} hostname={}", ip, mac, hostname);
            REGISTRY.register(ip, mac, &hostname, false);
            count += 1;
        }

        println!("[SCANNER] Scan complete – {} device(s) found", count);
        Ok(count)
    }
}

fn build_arp_request(local_mac: &[u8; 6], local_ip: &str, target_ip: &str) -> Vec<u8> {
    let target_ip_bytes = parse_ip_to_bytes(target_ip);
    let source_ip_bytes = parse_ip_to_bytes(local_ip);

    let mut buf = vec![0u8; 42];

    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(MacAddr(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        eth.set_source(MacAddr(
            local_mac[0], local_mac[1], local_mac[2],
            local_mac[3], local_mac[4], local_mac[5],
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
            local_mac[0], local_mac[1], local_mac[2],
            local_mac[3], local_mac[4], local_mac[5],
        ));
        arp.set_sender_proto_addr(
            std::net::Ipv4Addr::new(
                source_ip_bytes[0],
                source_ip_bytes[1],
                source_ip_bytes[2],
                source_ip_bytes[3],
            )
            .into(),
        );
        arp.set_target_hw_addr(MacAddr(0, 0, 0, 0, 0, 0));
        arp.set_target_proto_addr(
            std::net::Ipv4Addr::new(
                target_ip_bytes[0],
                target_ip_bytes[1],
                target_ip_bytes[2],
                target_ip_bytes[3],
            )
            .into(),
        );
    }

    // Pad to 60 bytes (minimum Ethernet frame) to avoid Windows Npcap error 31.
    const MIN_ETH_FRAME: usize = 60;
    if buf.len() < MIN_ETH_FRAME {
        buf.resize(MIN_ETH_FRAME, 0u8);
    }
    buf
}

fn parse_arp_reply(data: &[u8]) -> Option<(String, String)> {
    use pnet_packet::ethernet::EthernetPacket;

    let eth = EthernetPacket::new(data)?;
    let arp = ArpPacket::new(eth.payload())?;

    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }

    let sender_ip = arp.get_sender_proto_addr();
    let ip = format!("{}", sender_ip);

    let sender_mac = arp.get_sender_hw_addr();
    let mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        sender_mac.0, sender_mac.1, sender_mac.2,
        sender_mac.3, sender_mac.4, sender_mac.5,
    );

    Some((ip, mac))
}

fn parse_ip_to_bytes(ip: &str) -> [u8; 4] {
    let parts: Vec<u8> = ip.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    let mut out = [0u8; 4];
    let n = parts.len().min(4);
    out[..n].copy_from_slice(&parts[..n]);
    out
}