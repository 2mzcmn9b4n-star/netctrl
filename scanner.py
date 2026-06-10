"""
scanner.py
==========
Background LAN discovery using a broadcast ARP "who-has" sweep.

Why ARP scan (and not ping)?
 - Layer-2 visibility regardless of firewall rules on victims.
 - Cheap: one broadcast, every host on the /24 replies.
 - Identical to the technique NetCut/SelfishNet use.

On every reply we register the device in the global REGISTRY.
Because REGISTRY.register() auto-sets is_monitored=True, the moment
a device is discovered the Spoofer's poison loop will pick it up on
its next sweep – satisfying Blueprint 3.C ("Auto-Start").
"""

import ipaddress
import socket
import threading
import time

from scapy.all import ARP, Ether, srp

from device_registry import REGISTRY


SCAN_INTERVAL = 15.0   # seconds between full re-scans


class Scanner:
    def __init__(self,
                 iface: str,
                 local_ip: str,
                 netmask: str,
                 local_mac: str,
                 gateway_ip: str):
        self.iface      = iface
        self.local_ip   = local_ip
        self.local_mac  = local_mac.lower()
        self.gateway_ip = gateway_ip
        # Compute the CIDR network from ip + netmask
        try:
            net = ipaddress.IPv4Network(
                f"{local_ip}/{netmask}", strict=False)
            self.cidr = str(net)
        except Exception:
            # Fallback to /24 if netmask cannot be parsed
            self.cidr = f"{local_ip.rsplit('.', 1)[0]}.0/24"
        print(f"[SCANNER] sweep range -> {self.cidr}")

        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run, name="ScannerLoop", daemon=True)
        self._thread.start()
        print("[SCANNER] thread started")

    def stop(self) -> None:
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=3)

    # ------------------------------------------------------------------
    def scan_once(self) -> int:
        """Run a single ARP sweep, register any new devices.
        Returns the number of *new* devices added."""
        print(f"[SCANNER] sweep starting on {self.cidr} (fast mode) ...")
        
        # Highly optimized ARP Broadcast method
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.cidr)
        try:
            # timeout=2 and retry=1 for rapid responses as requested
            ans, _ = srp(pkt, iface=self.iface, timeout=2,
                         verbose=False, retry=1)
        except Exception as e:
            print(f"[SCANNER] !! fast srp failed: {e}")
            return 0

        new_count = 0
        for _, reply in ans:
            ip  = reply.psrc
            mac = reply.hwsrc.lower()

            # Skip ourselves and the gateway
            if ip == self.local_ip or mac == self.local_mac:
                continue
            
            # Skip the gateway as a victim
            if ip == self.gateway_ip:
                continue

            # Automatically add discovered devices to the registry
            # Note: REGISTRY.register already sets is_monitored=True by default
            name = self._hostname_guess(ip)
            if REGISTRY.register(ip, mac, name):
                new_count += 1

        print(f"[SCANNER] fast sweep done – {len(ans)} replies, "
              f"{new_count} new devices found in ~2s")
        return new_count

    # ------------------------------------------------------------------
    def _run(self) -> None:
        # Do a fast initial scan, then settle into the longer interval.
        try:
            self.scan_once()
        except Exception as e:
            print(f"[SCANNER] !! initial scan failed: {e}")

        while not self._stop_evt.is_set():
            self._stop_evt.wait(SCAN_INTERVAL)
            if self._stop_evt.is_set():
                break
            try:
                self.scan_once()
            except Exception as e:
                print(f"[SCANNER] !! scan error: {e}")

    # ------------------------------------------------------------------
    @staticmethod
    def _hostname_guess(ip: str) -> str:
        """Best-effort reverse DNS – returns short name or empty string."""
        try:
            socket.setdefaulttimeout(0.4)
            host = socket.gethostbyaddr(ip)[0]
            return host.split('.')[0]
        except Exception:
            return ""


def speed_ticker_thread() -> threading.Thread:
    """Spawn a 1-Hz thread that refreshes per-device DL/UL speeds."""
    def _tick():
        while True:
            time.sleep(1.0)
            try:
                REGISTRY.tick_speeds()
            except Exception as e:
                print(f"[TICKER] !! tick_speeds error: {e}")

    t = threading.Thread(target=_tick, name="SpeedTicker", daemon=True)
    t.start()
    print("[TICKER] 1Hz speed ticker started")
    return t
