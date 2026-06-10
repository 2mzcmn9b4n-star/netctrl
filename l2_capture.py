"""
l2_capture.py
=============
Layer-2 packet relay using scapy's AsyncSniffer.

Per Blueprint 3.A we do NOT enable Layer-3 IP forwarding. Instead we sniff
frames, rewrite ONLY the Ethernet header, and re-inject with sendp().

Per Blueprint 3.B we install a strict BPF filter that excludes any frame
sourced by our own MAC; otherwise we would sniff our own injected frames
and loop forever, melting the NIC.

Forwarding rules
----------------
Outbound  (Ether.src == any_monitored_victim_mac):
    Ether.dst <- gateway_mac
    Ether.src <- local_mac
    -> sendp()
    UL bytes credited to that victim.

Inbound   (Ether.src == gateway_mac AND IP.dst belongs to a monitored victim):
    Ether.dst <- victim_mac
    Ether.src <- local_mac
    -> sendp()
    DL bytes credited to that victim.

Everything else is silently dropped (not our concern).
"""

import threading
from scapy.all import AsyncSniffer, Ether, IP, sendp

from device_registry import REGISTRY


class L2Forwarder:
    def __init__(self,
                 iface: str,
                 local_ip: str,
                 local_mac: str,
                 gateway_mac: str):
        self.iface       = iface
        self.local_ip    = local_ip
        self.local_mac   = local_mac.lower()
        self.gateway_mac = gateway_mac.lower()

        # CRITICAL anti-loop BPF (Blueprint 3.B – do not modify lightly)
        self.bpf = (
            f"ip and not host {local_ip} "
            f"and not ether src {local_mac}"
        )
        print(f"[L2FWD] BPF filter -> {self.bpf!r}")

        self._sniffer: AsyncSniffer | None = None
        self._send_lock = threading.Lock()   # serialize sendp() across threads
        self._stats_pkts = 0

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._sniffer:
            return
        print(f"[L2FWD] starting AsyncSniffer on iface={self.iface}")
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf,
            prn=self._on_packet,
            store=False,
        )
        self._sniffer.start()
        print("[L2FWD] AsyncSniffer running")

    def stop(self) -> None:
        if self._sniffer:
            print("[L2FWD] stopping AsyncSniffer ...")
            try:
                self._sniffer.stop()
            except Exception as e:
                print(f"[L2FWD] !! sniffer stop error: {e}")
            self._sniffer = None

    # ------------------------------------------------------------------
    # Per-packet callback (HOT PATH – keep it short!)
    # ------------------------------------------------------------------
    def _on_packet(self, pkt) -> None:
        # We installed a BPF that already constrains to IP+non-self.
        # Still, defensively gate on Ether/IP layers.
        if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
            return

        eth = pkt[Ether]
        ip  = pkt[IP]
        src_mac = eth.src.lower()
        size = len(pkt)

        # ---------- OUTBOUND: victim -> internet ----------
        # Check if device is monitored OR in the grace period after unmonitoring
        if REGISTRY.is_monitored_mac(src_mac) or REGISTRY.is_in_grace_period(src_mac):
            if REGISTRY.is_blocked_mac(src_mac):
                return
            
            # Use the precise Token Bucket logic
            if not REGISTRY.allow_packet(src_mac, size):
                return  # Drop if over speed limit
            
            new_pkt = pkt.copy()
            new_pkt[Ether].dst = self.gateway_mac
            new_pkt[Ether].src = self.local_mac
            self._send(new_pkt)
            REGISTRY.add_ul(src_mac, size)
            self._stats_pkts += 1
            return

        # ---------- INBOUND: gateway -> (some victim) ----------
        if src_mac == self.gateway_mac:
            victim = REGISTRY.get_by_ip(ip.dst)
            if victim and (victim["is_monitored"] or REGISTRY.is_in_grace_period(victim["mac"])):
                if victim["is_blocked"]:
                    return
                
                # Use the precise Token Bucket logic
                if not REGISTRY.allow_packet(victim["mac"], size):
                    return  # Drop if over speed limit
                
                new_pkt = pkt.copy()
                new_pkt[Ether].dst = victim["mac"]
                new_pkt[Ether].src = self.local_mac
                self._send(new_pkt)
                REGISTRY.add_dl(victim["mac"], size)
                self._stats_pkts += 1
            return

        # else: not our problem – drop.

    # ------------------------------------------------------------------
    def _send(self, pkt) -> None:
        try:
            with self._send_lock:
                sendp(pkt, iface=self.iface, verbose=False)
        except Exception as e:
            # Forwarder errors must be loud – they are the #1 source of bugs
            print(f"[L2FWD] !! sendp error: {e}")
