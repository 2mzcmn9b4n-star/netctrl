import ctypes, sys

def _require_admin():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(f'"{a}"' for a in sys.argv),
            None, 1
        )
        sys.exit(0)

_require_admin()

"""
main.py
======
Entry point for NetCtrl – a LAN bandwidth controller using ARP spoofing.

+---------------------+           +-----------------------+
|       main.py       |           |                       |
|  (launcher +        |  HTTP     | Rust engine           |
|   GUI)              |<--------->| (rust_engine.exe)     |
|                     | REST API  |                       |
+---------------------+           +-----------------------+

Two back-ends are available:
  • Rust   – the default when frozen (PyInstaller) or when --rust is given.
  • Python – fallback used when the Rust binary is missing or when --py is given.

Network interface selection:
  - On first run, shows a dialog letting the user pick the network interface.
  - The selection is saved to netctrl_config.json for subsequent runs.
"""

import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

# ---- Pull gui module from the same directory ----
from gui import run_gui

# ---- Conditionally import the Python-native engine components ----
# (They are NOT needed when the Rust binary handles everything.)
try:
    from device_registry import REGISTRY
    from l2_capture import L2Forwarder, speed_ticker_thread
    from scanner import Scanner
    from server import api_server
    from spoofer import Spoofer
    PYTHON_ENGINE_AVAILABLE = True
except ImportError as e:
    REGISTRY = None
    L2Forwarder = None
    Scanner = None
    api_server = None
    Spoofer = None
    PYTHON_ENGINE_AVAILABLE = False
    print(f"[MAIN] Python engine components not available: {e}")


# ----------------------------------------------------------------------
# Config file helpers (Feature #5)
# ----------------------------------------------------------------------
CONFIG_FILENAME = "netctrl_config.json"


def _get_base_path() -> str:
    """Return the directory containing the executable or script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


def _config_path() -> str:
    return os.path.join(_get_base_path(), CONFIG_FILENAME)


def load_interface_config() -> Optional[str]:
    """Load saved interface name from netctrl_config.json, if it exists."""
    path = _config_path()
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        iface = data.get("interface", "").strip()
        if iface:
            return iface
    except Exception:
        pass
    return None


def save_interface_config(iface: str) -> None:
    """Save the selected interface name to netctrl_config.json."""
    path = _config_path()
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"interface": iface}, fh, indent=2)
    except Exception as e:
        print(f"[MAIN] Warning: could not save config to {path}: {e}")


# ----------------------------------------------------------------------
# Context detection
# ----------------------------------------------------------------------
def _get_local_mac(ip: str) -> str:
    """Return the MAC address of *this* machine's interface holding the
    given IPv4 address, or '??:??:??:??:??:??' if unavailable.
    """
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        for ifname, snics in addrs.items():
            for snic in snics:
                if snic.family == socket.AF_INET:
                    if snic.address == ip:
                        # scan same interface for the AF_LINK / MAC
                        for s2 in snics:
                            if s2.family.value == 17:  # AF_LINK on macOS / Linux
                                mac = s2.address.replace("-", ":").lower()
                                if mac and mac != "00:00:00:00:00:00":
                                    return mac
                            elif s2.family.name == "AF_LINK":
                                mac = s2.address.replace("-", ":").lower()
                                if mac and mac != "00:00:00:00:00:00":
                                    return mac
                        # Windows fallback: AF_PACKET not exposed by psutil;
                        # use getmac.get_mac_address()
                        try:
                            from getmac import get_mac_address
                            m = get_mac_address(ip=ip, network_request=False)
                            if m:
                                return m.replace("-", ":").lower()
                        except ImportError:
                            # try win32 APIs directly
                            try:
                                import os as _os
                                output = _os.popen(f"arp -a {ip}").read()
                                # very rough parse – last resort
                            except Exception:
                                pass
    except ImportError:
        pass
    return "??:??:??:??:??:??"


def detect_context() -> dict:
    """Auto-detect the local IP, local MAC, gateway IP, gateway MAC,
    and network interface name using the system's route table and
    ARP cache.

    Returns a dictionary with keys: iface, local_ip, local_mac,
    gateway_ip, gateway_mac, netmask.
    """
    import netifaces  # cross-platform route/gateway info

    gw = netifaces.gateways()
    default = gw.get("default", {})
    iface = None
    local_ip = None
    gateway_ip = None
    netmask = "255.255.255.0"

    if netifaces.AF_INET in default:
        (_gateway_ip, iface) = default[netifaces.AF_INET]
        gateway_ip = _gateway_ip
        try:
            addrs = netifaces.ifaddresses(iface)
            ipv4 = addrs[netifaces.AF_INET][0]
            local_ip = ipv4.get("addr", "127.0.0.1")
            netmask = ipv4.get("netmask", "255.255.255.0")
        except Exception:
            local_ip = "127.0.0.1"

    if gateway_ip is None:
        # fallback — scan netiface data
        for gateways in gw.values():
            for proto, entries in gateways.items():
                if entries:
                    if isinstance(entries, list):
                        e = entries[0]
                    elif isinstance(entries, dict):
                        e = entries
                    else:
                        continue
                    gateway_ip = e

    if local_ip is None:
        local_ip = socket.gethostbyname(socket.gethostname())

    gateway_mac = "??:??:??:??:??:??"
    if gateway_ip:
        try:
            from getmac import get_mac_address
            gm = get_mac_address(ip=gateway_ip, network_request=False)
            if gm:
                gateway_mac = gm.replace("-", ":").lower()
        except Exception:
            pass

    local_mac = _get_local_mac(local_ip)

    return {
        "iface": iface,
        "local_ip": local_ip,
        "local_mac": local_mac,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "netmask": netmask,
    }


# ----------------------------------------------------------------------
# Feature #5: Interface selector dialog on first run
# ----------------------------------------------------------------------
def select_interface_first_run() -> Optional[str]:
    """
    Check for saved config; if missing, show a Tkinter dialog listing
    UP IPv4 non-loopback interfaces. Returns the selected interface name
    or None if user cancelled.
    """
    # 1. Check if config exists and has a valid interface
    saved = load_interface_config()
    if saved:
        print(f"[MAIN] Using saved interface from config: {saved}")
        return saved

    # 2. Enumerate interfaces using psutil
    try:
        import psutil
    except ImportError:
        print("[MAIN] psutil not available, cannot show interface selector")
        return None

    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    candidates: list[dict] = []
    for ifname, snics in addrs.items():
        # Must be UP
        if ifname not in stats or not stats[ifname].isup:
            continue
        # Skip loopback
        if ifname.lower().startswith("lo"):
            continue
        ipv4 = None
        mac = None
        for snic in snics:
            if snic.family == socket.AF_INET:
                ipv4 = snic.address
            # Get MAC from AF_LINK or similar
            if hasattr(snic, "family"):
                family_val = snic.family.value if hasattr(snic.family, "value") else snic.family
                if family_val == 17 or str(snic.family).find("AF_LINK") >= 0 or str(snic.family).find("AF_PACKET") >= 0:
                    mac = snic.address
        # Must have an IPv4 address
        if ipv4:
            candidates.append({
                "name": ifname,
                "ip": ipv4,
                "mac": mac or "N/A",
            })

    if not candidates:
        print("[MAIN] No suitable network interfaces found")
        return None

    # 3. Show Tkinter dialog
    selected = {"iface": None}

    root = tk.Tk()
    root.title("NetCtrl – Select Network Interface")
    root.geometry("550x350")
    root.configure(bg="#1e1e22")
    root.resizable(False, False)

    # Make it a transient dialog on top
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass

    # Header
    header = tk.Label(
        root,
        text="Select Network Interface",
        font=("Segoe UI", 14, "bold"),
        fg="#ffffff",
        bg="#1e1e22",
        pady=12,
    )
    header.pack()

    subtext = tk.Label(
        root,
        text="Choose the interface connected to your LAN (e.g. Ethernet or Wi-Fi)",
        font=("Segoe UI", 9),
        fg="#9aa0a6",
        bg="#1e1e22",
    )
    subtext.pack()

    # Frame for the listbox
    list_frame = tk.Frame(root, bg="#1e1e22")
    list_frame.pack(fill="both", expand=True, padx=20, pady=10)

    # Scrollbar + Listbox
    scrollbar = tk.Scrollbar(list_frame)
    scrollbar.pack(side="right", fill="y")

    listbox = tk.Listbox(
        list_frame,
        yscrollcommand=scrollbar.set,
        bg="#2a2a30",
        fg="#e6e6e6",
        selectbackground="#4a90e2",
        selectforeground="#ffffff",
        font=("Consolas", 10),
        height=10,
        borderwidth=0,
        highlightthickness=0,
    )
    listbox.pack(side="left", fill="both", expand=True)
    scrollbar.config(command=listbox.yview)

    # Populate list
    for i, c in enumerate(candidates):
        label = f"{c['name']:20s}  {c['ip']:16s}  MAC: {c['mac']}"
        listbox.insert(tk.END, label)
        # Store candidate index as item data
        listbox.itemconfig(i, {"fg": "#e6e6e6"})

    # Select first by default
    if candidates:
        listbox.selection_set(0)

    def on_confirm():
        sel = listbox.curselection()
        if sel:
            idx = sel[0]
            selected["iface"] = candidates[idx]["name"]
            root.destroy()
        else:
            # No selection, pick first
            if candidates:
                selected["iface"] = candidates[0]["name"]
            root.destroy()

    def on_cancel():
        selected["iface"] = None
        root.destroy()

    # Buttons
    btn_frame = tk.Frame(root, bg="#1e1e22")
    btn_frame.pack(pady=(0, 15))

    confirm_btn = tk.Button(
        btn_frame,
        text="Confirm",
        command=on_confirm,
        bg="#4a90e2",
        fg="white",
        activebackground="#2f6fbd",
        activeforeground="white",
        relief="flat",
        padx=20,
        pady=6,
        font=("Segoe UI", 10, "bold"),
    )
    confirm_btn.pack(side="left", padx=5)

    cancel_btn = tk.Button(
        btn_frame,
        text="Cancel",
        command=on_cancel,
        bg="#3a3a44",
        fg="#e6e6e6",
        activebackground="#2a2a30",
        activeforeground="white",
        relief="flat",
        padx=20,
        pady=6,
        font=("Segoe UI", 10),
    )
    cancel_btn.pack(side="left", padx=5)

    root.mainloop()

    result = selected["iface"]
    if result:
        save_interface_config(result)
        print(f"[MAIN] Interface selected and saved: {result}")
    else:
        print("[MAIN] Interface selection cancelled by user")

    return result


def get_rust_engine_path():
    # When running as PyInstaller bundle
    if getattr(sys, 'frozen', False):
        base = sys._MEIPASS
        bundled = os.path.join(base, 'rust_engine.exe')
        # Extract to a writable temp location
        tmp_dir = os.path.join(tempfile.gettempdir(), 'netctrl')
        os.makedirs(tmp_dir, exist_ok=True)
        dest = os.path.join(tmp_dir, 'rust_engine.exe')
        shutil.copy2(bundled, dest)
        return dest
    else:
        # Running as plain Python script
        return os.path.join(os.path.dirname(__file__), 'rust_engine.exe')


# ----------------------------------------------------------------------
def main():
    # ---- Dynamic engine selection ----
    use_rust = getattr(sys, "frozen", False) or "--rust" in sys.argv
    backend_label = "(Rust Backend)" if use_rust else "(Python Backend)"

    print("=" * 60)
    print(f" NetCtrl  –  Layer-2 LAN Management Tool  {backend_label}")
    print("=" * 60)

    # ---- Feature #5: Interface selection ----
    # On first run, show a dialog to select the network interface.
    # The selection is saved and reused on subsequent runs.
    selected_iface = select_interface_first_run()
    if not selected_iface:
        print("[MAIN] No interface selected, falling back to auto-detection")
        # Fall back to auto-detection
        ctx = detect_context()
        selected_iface = ctx.get("iface")
        if not selected_iface:
            print("[MAIN] FATAL: Could not determine network interface. Exiting.")
            sys.exit(1)
    else:
        # Use the selected interface but still detect other context info
        ctx = detect_context()
        ctx["iface"] = selected_iface

    spoofer = None
    forwarder = None
    scanner = None

    rust_process = None  # declare in outer scope
    _stop_health_check = threading.Event()
    health_queue = queue.Queue()

    if use_rust:
        # Rust engine mode: auto-launch rust_engine.exe silently.
        # We look for it next to this executable.

        base_path = _get_base_path()

        rust_exe = get_rust_engine_path()
        if os.path.isfile(rust_exe):
            print(f"[MAIN] Launching Rust engine: {rust_exe}")
            # CREATE_NO_WINDOW = 0x08000000 on Windows, so no console flashes.
            creationflags = 0x08000000 if sys.platform == "win32" else 0
            rust_process = subprocess.Popen(
                [
                    rust_exe,
                    "--interface", ctx["iface"],
                    "--ip", ctx["local_ip"],
                    "--mac", ctx["local_mac"],
                    "--gateway-ip", ctx["gateway_ip"],
                    "--gateway-mac", ctx["gateway_mac"],
                    "--listen", "127.0.0.1:8765",
                ],
                creationflags=creationflags,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            print(f"[MAIN] Rust engine PID: {rust_process.pid}")

            # ---- Health check daemon ----
            def _health_check():
                nonlocal rust_process
                restart_count = 0
                while not _stop_health_check.is_set():
                    _stop_health_check.wait(5.0)
                    if _stop_health_check.is_set():
                        break
                    # poll() returns None if still running
                    ret = rust_process.poll()
                    if ret is not None:
                        ts = time.strftime("%Y-%m-%d %H:%M:%S")
                        print(f"[MAIN] !! Rust engine crashed (exit code {ret}) at {ts}")
                        # Attempt restart up to 3 times
                        while restart_count < 3:
                            restart_count += 1
                            print(f"[MAIN] Restart attempt {restart_count}/3...")
                            time.sleep(3)
                            if _stop_health_check.is_set():
                                break
                            try:
                                rust_process_new = subprocess.Popen(
                                    [
                                        rust_exe,
                                        "--interface", ctx["iface"],
                                        "--ip", ctx["local_ip"],
                                        "--mac", ctx["local_mac"],
                                        "--gateway-ip", ctx["gateway_ip"],
                                        "--gateway-mac", ctx["gateway_mac"],
                                        "--listen", "127.0.0.1:8765",
                                    ],
                                    creationflags=0x08000000 if sys.platform == "win32" else 0,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL,
                                )
                                # Update the outer rust_process reference
                                rust_process = rust_process_new
                                print(f"[MAIN] Rust engine restarted, new PID: {rust_process.pid}")
                                restart_count = 0
                                break
                            except Exception as e:
                                print(f"[MAIN] !! Restart attempt {restart_count}/3 failed: {e}")
                        if restart_count >= 3:
                            msg = f"[FATAL] Rust engine crashed and all 3 restart attempts failed. Please restart NetCtrl manually."
                            print(f"[MAIN] {msg}")
                            health_queue.put(msg)
                            break
            threading.Thread(target=_health_check, daemon=True).start()
        else:
            print(f"[MAIN] WARNING: rust_engine.exe not found at {rust_exe}")
            print("[MAIN] Please run the Rust engine separately on http://127.0.0.1:8765")
            rust_process = None

        # Wait for the API to come up before handing off to the GUI
        waited = 0
        while rust_process is not None and waited < 10:
            try:
                import urllib.request
                req = urllib.request.Request("http://127.0.0.1:8765/api/devices", method="GET")
                with urllib.request.urlopen(req, timeout=1.0) as r:
                    r.read()
                print(f"[MAIN] Rust API responded after {waited}s")
                break
            except Exception:
                time.sleep(1)
                waited += 1
        if waited >= 10:
            print("[MAIN] !! Rust API did not respond within 10s, continuing anyway.")
    else:
        # ---- Build core components (Python engine) ----
        spoofer = Spoofer(
            iface       = ctx["iface"],
            local_ip    = ctx["local_ip"],
            local_mac   = ctx["local_mac"],
            gateway_ip  = ctx["gateway_ip"],
            gateway_mac = ctx["gateway_mac"],
        )
        forwarder = L2Forwarder(
            iface       = ctx["iface"],
            local_ip    = ctx["local_ip"],
            local_mac   = ctx["local_mac"],
            gateway_mac = ctx["gateway_mac"],
        )
        scanner = Scanner(
            iface       = ctx["iface"],
            local_ip    = ctx["local_ip"],
            netmask     = ctx["netmask"],
            local_mac   = ctx["local_mac"],
            gateway_ip  = ctx["gateway_ip"],
        )

        # ---- Wire the API server to the live engine instances ----
        api_server.SPOOFER = spoofer
        api_server.SCANNER = scanner

        # ---- Start everything ----
        forwarder.start()           # sniffer with anti-loop BPF must be up FIRST
        spoofer.start()             # poison loop
        scanner.start()             # ARP sweeps every 15 s
        speed_ticker_thread()       # 1 Hz speed calc
        api_server.run_server_in_thread(host="127.0.0.1", port=8765)

        # tiny grace period so the API socket is bound before the GUI polls it
        time.sleep(0.4)

    print("[MAIN] all subsystems up – launching GUI")

    try:
        run_gui(
            local_ip    = ctx["local_ip"],
            local_mac   = ctx["local_mac"],
            gateway_ip  = ctx["gateway_ip"],
            gateway_mac = ctx["gateway_mac"],
            backend_label = backend_label,
            rust_process = rust_process,
            health_queue = health_queue,
        )
    except KeyboardInterrupt:
        print("[MAIN] Ctrl-C received")
    finally:
        # Signal health check thread to stop, then wait briefly
        _stop_health_check.set()
        # Cleanup is what keeps the LAN healthy after we exit.
        print("[MAIN] shutting down ...")
        if spoofer is not None:
            try:
                spoofer.stop()        # also bursts ARP restore for every device
            except Exception as e:
                print(f"[MAIN] spoofer.stop error: {e}")
        if forwarder is not None:
            try:
                forwarder.stop()
            except Exception as e:
                print(f"[MAIN] forwarder.stop error: {e}")
        if scanner is not None:
            try:
                scanner.stop()
            except Exception as e:
                print(f"[MAIN] scanner.stop error: {e}")
        print("[MAIN] bye.")


if __name__ == "__main__":
    main()