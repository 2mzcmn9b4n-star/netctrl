"""
server.py
=========
Local aiohttp HTTP API used as the IPC channel between the GUI and the
networking engine.

Endpoints
---------
GET  /api/devices          – snapshot of every known device (JSON list)
POST /api/monitor          – body: {"mac": "...", "monitored": true|false}
POST /api/scan             – trigger an immediate ARP sweep
GET  /api/health           – liveness probe

CRITICAL (Blueprint 3.E):
    Do NOT use `await request.json()`.
    If the client forgets `Content-Type: application/json` it blows up
    with a silent HTTP 400. We always parse manually:

        raw = await request.text()
        data = json.loads(raw)
"""

import asyncio
import json
import threading
from typing import Optional

from aiohttp import web

from device_registry import REGISTRY


# Filled in by main.py before start() is called.
SPOOFER = None      # type: Optional[object]    (spoofer.Spoofer)
SCANNER = None      # type: Optional[object]    (scanner.Scanner)


# ----------------------------------------------------------------------
# Handlers
# ----------------------------------------------------------------------
async def health(_request: web.Request) -> web.Response:
    return web.json_response({"ok": True})


async def list_devices(_request: web.Request) -> web.Response:
    devices = REGISTRY.get_all()
    # Strip private "_prev_*" keys – not interesting to the GUI.
    public = []
    for d in devices:
        speed_limit_kbps = (d["speed_limit"] / 1024) if d["speed_limit"] else None
        public.append({
            "ip":           d["ip"],
            "mac":          d["mac"],
            "name":         d["name"],
            "dl_bytes":     d["dl_bytes"],
            "ul_bytes":     d["ul_bytes"],
            "dl_speed":     round(d["dl_speed"], 1),
            "ul_speed":     round(d["ul_speed"], 1),
            "is_monitored": d["is_monitored"],
            "is_blocked":   d["is_blocked"],
            "speed_limit_kbps": round(speed_limit_kbps, 1) if speed_limit_kbps else None,
            "first_seen":   d["first_seen"],
            "last_seen":    d["last_seen"],
        })
    return web.json_response({"devices": public})


async def toggle_monitor(request: web.Request) -> web.Response:
    """
    Toggle the is_monitored flag for a device.

    Body (JSON, parsed MANUALLY per Blueprint 3.E):
        {"mac": "aa:bb:cc:dd:ee:ff", "monitored": true|false}
    """
    # ---- Manual JSON parsing as requested to avoid strict aiohttp errors ----
    try:
        raw = await request.text()
        print(f"[API] [TOGGLE] /api/monitor received: {raw!r}")
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        print(f"[API] !! /api/monitor JSON decode error: {e}")
        return web.json_response(
            {"ok": False, "error": f"invalid JSON: {e}"}, status=400)

    mac = (data.get("mac") or "").lower().strip()
    # Handle both "monitored" and "is_monitored" keys just in case
    monitored = bool(data.get("monitored") if "monitored" in data else data.get("is_monitored"))
    
    if not mac:
        return web.json_response(
            {"ok": False, "error": "missing 'mac'"}, status=400)

    # Capture previous state
    prev = REGISTRY.get_by_mac(mac)
    if prev is None:
        print(f"[API] !! Toggle failed: Unknown MAC {mac}")
        return web.json_response(
            {"ok": False, "error": f"unknown mac {mac}"}, status=404)
    
    prev_monitored = prev["is_monitored"]
    print(f"[API] [TOGGLE] mac={mac} | {prev_monitored} -> {monitored}")

    # Update Registry
    updated = REGISTRY.set_monitored(mac, monitored)
    if updated is None:
        return web.json_response(
            {"ok": False, "error": "registry update failed"}, status=500)

    # CRITICAL: If transitioning from monitored -> unmonitored, trigger ARP RESTORE
    if prev_monitored and not monitored:
        # Mark unmonitored timestamp for L2Forwarder grace period
        REGISTRY.set_unmonitored_timestamp(mac)
        
        if SPOOFER is not None:
            print(f"[API] [RESTORE] Triggering instant ARP restore for {updated['ip']} ...")
            # Run in thread to not block the API response
            def _restore_worker():
                try:
                    SPOOFER.restore_arp(updated["ip"], updated["mac"])
                except Exception as e:
                    print(f"[API] !! [RESTORE] Worker failed for {mac}: {e}")
            
            threading.Thread(target=_restore_worker, name=f"Restore-{mac}", daemon=True).start()
        else:
            print("[API] !! [RESTORE] Warning: SPOOFER instance is None, cannot restore ARP!")

    return web.json_response({"ok": True, "device": updated})


async def trigger_scan(_request: web.Request) -> web.Response:
    if SCANNER is None:
        return web.json_response(
            {"ok": False, "error": "scanner not ready"}, status=503)
    # Off-load the actual sniff to a worker thread.
    loop = asyncio.get_running_loop()
    new_count = await loop.run_in_executor(None, SCANNER.scan_once)
    return web.json_response({"ok": True, "new_devices": new_count})


async def toggle_block(request: web.Request) -> web.Response:
    """
    Toggle the is_blocked flag for a device.

    Body (JSON, parsed MANUALLY per Blueprint 3.E):
        {"mac": "aa:bb:cc:dd:ee:ff", "blocked": true|false}
    """
    try:
        raw = await request.text()
        print(f"[API] /api/block raw body: {raw!r}")
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        print(f"[API] /api/block JSON decode error: {e}")
        return web.json_response(
            {"ok": False, "error": f"invalid JSON: {e}"}, status=400)

    mac = (data.get("mac") or "").lower().strip()
    blocked = bool(data.get("blocked"))
    if not mac:
        return web.json_response(
            {"ok": False, "error": "missing 'mac'"}, status=400)

    print(f"[API] /api/block mac={mac} -> blocked={blocked}")

    updated = REGISTRY.set_blocked(mac, blocked)
    if updated is None:
        return web.json_response(
            {"ok": False, "error": f"unknown mac {mac}"}, status=404)

    return web.json_response({"ok": True, "device": updated})


async def set_speed_limit(request: web.Request) -> web.Response:
    """
    Set speed limit for a device.

    Body (JSON, parsed MANUALLY per Blueprint 3.E):
        {"mac": "aa:bb:cc:dd:ee:ff", "speed_limit_kbps": 512.5 or null}
        speed_limit_kbps: speed limit in KB/s, or null for unlimited
    """
    try:
        raw = await request.text()
        print(f"[API] /api/speed raw body: {raw!r}")
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError as e:
        print(f"[API] /api/speed JSON decode error: {e}")
        return web.json_response(
            {"ok": False, "error": f"invalid JSON: {e}"}, status=400)

    mac = (data.get("mac") or "").lower().strip()
    speed_limit_kbps = data.get("speed_limit_kbps")
    
    if not mac:
        return web.json_response(
            {"ok": False, "error": "missing 'mac'"}, status=400)

    # Convert KB/s to bytes/s, or None if unlimited
    if speed_limit_kbps is None:
        speed_limit_bps = None
    else:
        try:
            speed_limit_bps = float(speed_limit_kbps) * 1024.0
            if speed_limit_bps <= 0:
                return web.json_response(
                    {"ok": False, "error": "speed_limit_kbps must be positive or null"}, status=400)
        except (TypeError, ValueError):
            return web.json_response(
                {"ok": False, "error": "speed_limit_kbps must be a number or null"}, status=400)

    print(f"[API] /api/speed mac={mac} -> speed_limit={speed_limit_bps} bytes/sec")

    updated = REGISTRY.set_speed_limit(mac, speed_limit_bps)
    if updated is None:
        return web.json_response(
            {"ok": False, "error": f"unknown mac {mac}"}, status=404)

    return web.json_response({"ok": True, "device": updated})


# ----------------------------------------------------------------------
# Server bootstrap
# ----------------------------------------------------------------------
def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get ("/api/health",  health)
    app.router.add_get ("/api/devices", list_devices)
    app.router.add_post("/api/monitor", toggle_monitor)
    app.router.add_post("/api/scan",    trigger_scan)
    app.router.add_post("/api/block",   toggle_block)
    app.router.add_post("/api/speed",   set_speed_limit)
    return app


def run_server_in_thread(host: str = "127.0.0.1", port: int = 8765) -> threading.Thread:
    """
    Spin up the aiohttp server in its own thread with its own asyncio loop,
    so we can keep the main thread free for the Tk GUI.
    """
    def _serve():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        app = build_app()
        runner = web.AppRunner(app)
        loop.run_until_complete(runner.setup())
        site = web.TCPSite(runner, host, port)
        loop.run_until_complete(site.start())
        print(f"[SERVER] aiohttp listening on http://{host}:{port}")
        try:
            loop.run_forever()
        finally:
            loop.run_until_complete(runner.cleanup())
            loop.close()

    t = threading.Thread(target=_serve, name="APIServer", daemon=True)
    t.start()
    return t
