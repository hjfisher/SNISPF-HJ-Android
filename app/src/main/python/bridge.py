# bridge.py — Chaquopy bridge for SNISPF-HJ Android
import threading
import asyncio
import json
import sys
import io
import logging
import traceback
import time

# ── State ─────────────────────────────────────────────────────────────────────
_proxy_thread = None
_stop_event   = threading.Event()
_loop         = None
_conn_manager  = None
_ip_discovery  = None
_sni_discovery = None

_log_buffer   = []
_log_lock     = threading.Lock()
_status       = "stopped"

_stats = {
    "active_connections":   0,
    "total_connections":    0,
    "pool_active_slots":    0,
    "pool_draining":        0,   # pairs draining (still serving old conns)
    "probed_stable":        0,
    "probed_weak":          0,
    "probed_dead":          0,
    "probed_total":         0,
    "pairs_total":          0,
    "pairs_probed":         0,
    "pairs_unprobed":       0,
    "discovery_done":       0,
    "static_ips_count":     0,
    "dynamic_ips_found":    0,
    "dynamic_ip_discovery": 0,
    "static_snis_count":    0,
    "dynamic_snis_found":   0,
    "dynamic_sni_discovery": 0,
    "quarantine_size":      0,
    "sni_quarantine_size":  0,
    "uptime_seconds":       0,
}
_stats_lock = threading.Lock()
_start_time = None


# ── Logging ───────────────────────────────────────────────────────────────────
def _ts():
    return time.strftime("%H:%M:%S")

def _log(msg):
    with _log_lock:
        _log_buffer.append(f"[{_ts()}] {msg}")
        if len(_log_buffer) > 1000:
            _log_buffer.pop(0)

class _Capture(io.TextIOBase):
    def write(self, text):
        s = text.strip()
        if s:
            _log(s)
        return len(text)
    def flush(self): pass

class _LogHandler(logging.Handler):
    def emit(self, record):
        try:
            _log(self.format(record))
        except Exception:
            pass

def _install_log_capture():
    sys.stdout = _Capture()
    sys.stderr = _Capture()
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    h = _LogHandler()
    h.setFormatter(logging.Formatter("%(name)s: %(message)s"))
    root.handlers.clear()
    root.addHandler(h)


# ── Stats snapshot ────────────────────────────────────────────────────────────
def _snapshot():
    global _conn_manager, _ip_discovery, _sni_discovery
    cm = _conn_manager
    if cm is None:
        return
    try:
        ex   = cm.explorer
        pool = cm.pool

        all_pairs   = list(ex.stats.values())
        pairs_total = len(all_pairs)

        probed = [p for p in all_pairs if p.probed]
        stable = [p for p in probed if p.alive and p.combined_loss_rate < ex.loss_threshold]
        weak   = [p for p in probed if p.alive and p.combined_loss_rate >= ex.loss_threshold]
        dead   = [p for p in probed if not p.alive]

        # active_connections = _pool + _draining (draining pairs still serve live conns)
        active_pool   = pool._pool     if hasattr(pool, "_pool")     else []
        draining_pool = pool._draining if hasattr(pool, "_draining") else []
        serving_pairs = active_pool + draining_pool
        active_conns  = sum(p.active_connections for p in serving_pairs)
        total_conns   = sum(p.total_connections  for p in all_pairs)

        pairs_probed   = len(probed)
        pairs_unprobed = pairs_total - pairs_probed

        # Count unique static/dynamic IPs and SNIs directly from pool truth
        # (origin is stamped on every PairStats — more reliable than the
        # discovery threads' own internal counters).
        static_ips:   set = set()
        dynamic_ips:  set = set()
        static_snis:  set = set()
        dynamic_snis: set = set()
        for ps in all_pairs:
            (dynamic_ips if ps.ip_origin == "dynamic" else static_ips).add(ps.ip)
            (dynamic_snis if ps.sni_origin == "dynamic" else static_snis).add(ps.sni)

        ip_quarantine  = len(getattr(ex, "_ip_quarantine", {}))
        sni_quarantine = len(getattr(ex, "_sni_quarantine", {}))

        with _stats_lock:
            _stats["pool_active_slots"]   = len(active_pool)
            _stats["pool_draining"]       = len(draining_pool)
            _stats["active_connections"]  = active_conns
            _stats["total_connections"]   = total_conns
            _stats["probed_stable"]       = len(stable)
            _stats["probed_weak"]         = len(weak)
            _stats["probed_dead"]         = len(dead)
            _stats["probed_total"]        = pairs_probed
            _stats["pairs_total"]         = pairs_total
            _stats["pairs_probed"]        = pairs_probed
            _stats["pairs_unprobed"]      = pairs_unprobed
            _stats["discovery_done"]      = 1 if pairs_unprobed == 0 else 0
            _stats["static_ips_count"]    = len(static_ips)
            _stats["dynamic_ips_found"]   = len(dynamic_ips)
            _stats["static_snis_count"]   = len(static_snis)
            _stats["dynamic_snis_found"]  = len(dynamic_snis)
            _stats["quarantine_size"]     = ip_quarantine
            _stats["sni_quarantine_size"] = sni_quarantine

    except Exception as e:
        _log(f"[stats] error: {e}")


# ── Proxy thread ──────────────────────────────────────────────────────────────
def _run_proxy(config_json, use_root_int):  # use_root_int kept for API compat, unused
    global _status, _loop, _start_time, _conn_manager, _ip_discovery

    use_root    = (use_root_int == 1)
    old_out     = sys.stdout
    old_err     = sys.stderr
    old_handlers = logging.getLogger().handlers[:]

    try:
        _status = "starting"
        _log("Starting SNISPF-HJ...")

        _install_log_capture()

        config = json.loads(config_json)

        from sni_spoofing.cli           import build_strategy
        from sni_spoofing.forwarder     import start_server
        from sni_spoofing.pool          import build_connection_manager
        from sni_spoofing.ip_discovery  import build_ip_discovery
        from sni_spoofing.sni_discovery import build_sni_discovery
        from sni_spoofing.utils         import get_default_interface_ipv4, resolve_host
        _log("Imports OK")

        # Resolve IP/SNI
        ips  = config.get("CONNECT_IPS", [])
        snis = config.get("FAKE_SNIS",   [])
        config.setdefault("CONNECT_IP", resolve_host(ips[0] if ips else "104.18.38.202"))
        config.setdefault("FAKE_SNI",   snis[0] if snis else "cdnjs.cloudflare.com")

        # Build pool
        _conn_manager = build_connection_manager(config)
        if _conn_manager is not None:
            total  = len(_conn_manager.explorer.stats)
            n_ips  = len(ips)
            n_snis = len(snis)
            _log(f"Pool built: {n_ips} IPs × {n_snis} SNIs = {total} pairs")
            with _stats_lock:
                _stats["pairs_total"]    = total
                _stats["pairs_unprobed"] = total
            _conn_manager.start_health_loop()

            # Start IP discovery if enabled in config
            _ip_discovery = build_ip_discovery(_conn_manager, config)
            if _ip_discovery is not None:
                _ip_discovery.start()
                _log(f"Dynamic IP discovery enabled — will scan Cloudflare CIDRs every {int(config.get('DISCOVERY_INTERVAL', 120))}s")
                with _stats_lock:
                    _stats["dynamic_ip_discovery"] = 1
            else:
                _log("Dynamic IP discovery disabled (set DYNAMIC_IP_DISCOVERY=true to enable)")

            # Start SNI discovery if enabled in config (mirrors IP discovery)
            _sni_discovery = build_sni_discovery(_conn_manager, config)
            if _sni_discovery is not None:
                _sni_discovery.start()
                _log(f"Dynamic SNI discovery enabled — will sample Tranco/Umbrella/Majestic every {int(config.get('SNI_DISCOVERY_INTERVAL', 120))}s")
                with _stats_lock:
                    _stats["dynamic_sni_discovery"] = 1
            else:
                _log("Dynamic SNI discovery disabled (set DYNAMIC_SNI_DISCOVERY=true to enable)")
        else:
            _log("Single-endpoint mode (no pool)")

        interface_ip = get_default_interface_ipv4(config["CONNECT_IP"])

        # Raw injector (root) is not supported on Android — Chaquopy sandbox
        # cannot obtain CAP_NET_RAW, so we always use userspace fragmentation.
        raw_injector = None
        strategy     = build_strategy(config, raw_injector=raw_injector)
        listen_host  = config.get("LISTEN_HOST",  "0.0.0.0")
        listen_port  = int(config.get("LISTEN_PORT",  40443))
        connect_port = int(config.get("CONNECT_PORT", 443))

        _status     = "running"
        _start_time = time.monotonic()
        _log(f"Proxy listening {listen_host}:{listen_port} -> {config['CONNECT_IP']}:{connect_port} SNI={config['FAKE_SNI']}")

        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)

        async def _ticker():
            tick = 0
            while not _stop_event.is_set():
                # Always update uptime (lightweight)
                if _start_time:
                    with _stats_lock:
                        _stats["uptime_seconds"] = int(time.monotonic() - _start_time)
                # Full snapshot every 5 ticks (10s) — reduces CPU in background
                if tick % 5 == 0:
                    _snapshot()
                tick += 1
                await asyncio.sleep(2)

        async def _serve():
            srv  = asyncio.create_task(start_server(
                listen_host     = listen_host,
                listen_port     = listen_port,
                connect_ip      = config["CONNECT_IP"],
                connect_port    = connect_port,
                fake_sni        = config["FAKE_SNI"],
                bypass_strategy = strategy,
                interface_ip    = interface_ip,
                raw_injector    = raw_injector,
                conn_manager    = _conn_manager,
            ))
            tick = asyncio.create_task(_ticker())
            while not _stop_event.is_set():
                await asyncio.sleep(0.5)
            tick.cancel()
            srv.cancel()
            for t in (tick, srv):
                try:    await t
                except: pass

        _loop.run_until_complete(_serve())

    except Exception:
        _status = "error"
        _log(f"ERROR: {traceback.format_exc()}")
    finally:
        _status = "stopped"
        _log("Proxy stopped.")
        sys.stdout = old_out
        sys.stderr = old_err
        root = logging.getLogger()
        root.handlers.clear()
        for h in old_handlers:
            root.addHandler(h)
        if _loop and not _loop.is_closed():
            _loop.close()
        _loop          = None
        _conn_manager  = None
        _ip_discovery  = None
        _sni_discovery = None


# ── Public API ────────────────────────────────────────────────────────────────
def start(config_json, use_root_int):
    global _proxy_thread, _stop_event, _status

    if _proxy_thread and _proxy_thread.is_alive():
        return "already_running"

    try:
        json.loads(config_json)
    except Exception as e:
        return f"invalid_config: {e}"

    _stop_event = threading.Event()
    with _log_lock:
        _log_buffer.clear()
    with _stats_lock:
        for k in _stats:
            _stats[k] = 0

    _proxy_thread = threading.Thread(
        target=_run_proxy, args=(config_json, int(use_root_int)),
        daemon=True, name="snispf-proxy"
    )
    _proxy_thread.start()
    return "ok"

def stop():
    global _status
    if _stop_event:
        _stop_event.set()
    _status = "stopping"
    _log("Stop signal sent...")
    return "ok"

def get_status():
    global _proxy_thread, _status
    if _proxy_thread and not _proxy_thread.is_alive():
        _status = "stopped"
    return _status

def get_logs():
    with _log_lock:
        return "\n".join(_log_buffer)

def get_stats():
    with _stats_lock:
        return "\n".join(f"{k}={v}" for k, v in _stats.items())

def clear_logs():
    with _log_lock:
        _log_buffer.clear()
    return "ok"
