"""Dynamic Cloudflare IP discovery — feeds fresh IPs into the connection pool.

Inspired by https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner
(and its predecessor CloudflareScanner by Ptechgithub).

How it works
------------
Cloudflare publishes their IP ranges at https://www.cloudflare.com/ips-v4.
All IPs in those subnets are valid Cloudflare edge nodes.  We exploit that
by randomly sampling addresses from the official CIDR blocks, probing them
with a plain TCP connect, and handing the survivors to the connection pool.

This runs in a daemon thread alongside the pool's own health loop.  It does
NOT replace the static CONNECT_IPS list — it *augments* it.  Newly found
IPs are injected into the CombinationExplorer so the ActivePool can start
using them immediately (on the next pool refresh cycle).

Integration
-----------
Call ``start_discovery_loop()`` after creating the ConnectionManager::

    from sni_spoofing.ip_discovery import IPDiscovery
    discovery = IPDiscovery(manager=conn_manager, snis=config["FAKE_SNIS"])
    discovery.start()

or let ``build_connection_manager`` / ``cli.py`` do it automatically when
``DYNAMIC_IP_DISCOVERY`` is set to ``true`` in the config.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import threading
import time
from typing import List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .pool import ConnectionManager, PairStats

logger = logging.getLogger("snispf.discovery")

# ---------------------------------------------------------------------------
# Official Cloudflare IPv4 CIDR ranges (source: cloudflare.com/ips-v4)
# These rarely change; update when Cloudflare publishes new allocations.
# ---------------------------------------------------------------------------
CLOUDFLARE_CIDRS: List[str] = [
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "108.162.192.0/18",
    "131.0.72.0/22",
    "141.101.64.0/18",
    "162.158.0.0/15",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
]


# ---------------------------------------------------------------------------
# IP sampler — mirrors the Go logic from CloudflareScanner/task/ip.go
# ---------------------------------------------------------------------------

def _sample_random_ips(cidr: str, count: int) -> List[str]:
    """Return ``count`` random IPs drawn uniformly from a CIDR block.

    For a /22 (1022 hosts) we can draw many unique addresses.
    For a /13 (524286 hosts) the sample is tiny relative to the range —
    that's fine; the scanner sweeps multiple rounds over time.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError:
        logger.warning("Invalid CIDR %r — skipping.", cidr)
        return []

    hosts = list(network.hosts())
    if not hosts:
        return []

    k = min(count, len(hosts))
    return [str(ip) for ip in random.sample(hosts, k)]


def sample_cloudflare_ips(total: int, cidrs: Optional[List[str]] = None) -> List[str]:
    """Sample ``total`` random IPs spread across all Cloudflare CIDR ranges.

    IPs are drawn proportionally: subnets with more hosts contribute more
    candidates, which mirrors the distribution of real Cloudflare traffic.

    Args:
        total: How many IPs to sample overall.
        cidrs: Override the built-in CIDR list (useful for testing).

    Returns:
        A shuffled list of IPv4 strings, length ≤ ``total``.
    """
    cidrs = cidrs or CLOUDFLARE_CIDRS
    if not cidrs:
        return []

    # Count total host capacity so we can weight proportionally.
    weights: List[int] = []
    for cidr in cidrs:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            weights.append(net.num_addresses - 2)  # exclude network + broadcast
        except ValueError:
            weights.append(0)

    total_hosts = sum(weights)
    if total_hosts == 0:
        return []

    result: List[str] = []
    for cidr, w in zip(cidrs, weights):
        if w == 0:
            continue
        # Proportional share, at least 1 per CIDR.
        share = max(1, round(total * w / total_hosts))
        result.extend(_sample_random_ips(cidr, share))

    random.shuffle(result)
    # Trim to exactly ``total`` (proportional rounding may overshoot slightly).
    return result[:total]


# ---------------------------------------------------------------------------
# TLS reachability probe
# ---------------------------------------------------------------------------

def _tls_probe(ip: str, port: int, timeout: float, attempts: int) -> float:
    """Return the fraction of successful TLS handshakes (0.0 – 1.0).

    Unlike a plain TCP connect, this actually completes a TLS handshake
    (ClientHello → ServerHello) which proves the server is genuinely
    accepting and responding to TLS traffic on the given port — not just
    that the TCP port is open.

    SNI is set to ``cloudflare.com`` (a safe, always-valid Cloudflare host)
    so the server can route the handshake correctly.  Certificate validation
    is disabled because we are testing IP reachability, not cert validity.
    """
    import ssl

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    successes = 0
    for _ in range(attempts):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname="cloudflare.com") as tls:
                    # ServerHello received — IP is genuinely serving TLS.
                    _ = tls.version()
                    successes += 1
        except Exception:
            pass
        time.sleep(random.uniform(0.02, 0.08))
    return successes / attempts


# ---------------------------------------------------------------------------
# IPDiscovery — the main scanner class
# ---------------------------------------------------------------------------

class IPDiscovery:
    """Continuously discovers fresh Cloudflare IPs and injects them into the pool.

    Lifecycle
    ~~~~~~~~~
    1. ``start()`` — launches a daemon thread that runs ``_loop()`` forever.
    2. Every ``scan_interval`` seconds the scanner:
       a. Samples ``scan_batch`` random IPs from the Cloudflare CIDR list.
       b. Probes each candidate with ``probe_attempts`` TCP connects.
       c. Accepts IPs whose success rate is ≥ ``min_success_rate``.
       d. For each accepted IP that is **new** (not already in the pool),
          injects (IP × all known SNIs) into the CombinationExplorer.
       e. Caps the dynamic pool at ``max_dynamic_ips`` to avoid unbounded
          memory growth — evicts the oldest discoveries when over limit.

    The ConnectionManager's health loop picks up new pairs on its next
    ``periodic_explore()`` cycle (typically within 30 s).
    """

    def __init__(
        self,
        manager: "ConnectionManager",
        snis: List[str],
        scan_batch: int = 100,
        scan_interval: float = 120.0,
        probe_attempts: int = 3,
        probe_timeout: float = 2.0,
        min_success_rate: float = 0.50,
        max_dynamic_ips: int = 200,
        port: int = 443,
        cidrs: Optional[List[str]] = None,
    ) -> None:
        """Create an IPDiscovery instance.

        Args:
            manager:          The active ConnectionManager to inject IPs into.
            snis:             The SNI list to pair with each discovered IP.
            scan_batch:       How many random IPs to sample each round.
            scan_interval:    Seconds between scan rounds.
            probe_attempts:   TCP connect attempts per candidate.
            probe_timeout:    TCP connect timeout (seconds) per attempt.
            min_success_rate: Fraction of probes that must succeed (0–1).
            max_dynamic_ips:  Cap on how many dynamic IPs we keep in memory.
            port:             Target port for TCP probes (usually 443).
            cidrs:            Override the built-in Cloudflare CIDR list.
        """
        self.manager = manager
        # NOTE: ``snis`` is only used as the *initial* seed list. The actual
        # list used at injection time always reads live from
        # ``manager.explorer._all_snis`` via the ``snis`` property below, so
        # newly discovered dynamic SNIs are automatically included without
        # this object needing to be told about them separately.
        self._initial_snis = list(snis)
        self.scan_batch = scan_batch
        self.scan_interval = scan_interval
        self.probe_attempts = probe_attempts
        self.probe_timeout = probe_timeout
        self.min_success_rate = min_success_rate
        self.max_dynamic_ips = max_dynamic_ips
        self.port = port
        self.cidrs = cidrs or CLOUDFLARE_CIDRS

        # Set of IPs already known to the pool (static + dynamic).
        self._known_ips: Set[str] = {
            ip for (ip, _) in manager.explorer.stats.keys()
        }
        # Ordered list of dynamically discovered IPs (oldest first).
        self._dynamic_ips: List[str] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def _sync_with_explorer(self) -> None:
        """Reconcile our local IP bookkeeping with the explorer's state.

        ``pool.py`` can evict or recycle IPs entirely on its own (via
        ``ActivePool.refresh()`` → ``evict_weakest_ip`` /
        ``recycle_ip_attempt``) without this object ever being told. If we
        don't reconcile, ``_known_ips``/``_dynamic_ips`` drift out of sync
        with reality: evicted IPs stay "known" forever (silently blocking
        re-discovery of that same IP later) and the dynamic-IP count stops
        reflecting how many IPs are actually active — exactly the stale
        "Dynamic IPs found" stat seen in the status dashboard.

        Two different signals matter here, and they're not the same thing:
          - ``explorer._ip_origin_ledger`` records an IP's *origin*
            (static/dynamic) permanently — even while the IP sits in
            quarantine, it's still "dynamic" by origin.
          - ``explorer._all_ips`` records whether the IP is *currently
            active* (i.e. has at least one live pair in ``stats``).
            Quarantined IPs are removed from this list; recycled ones are
            added back.

        ``dynamic_ip_count`` and the eviction cap need to reflect *active*
        dynamic IPs, not just ones we've ever heard of — so we filter on
        membership in ``_all_ips``, using the ledger only to confirm the
        origin is "dynamic" (so we never accidentally drop a static IP
        that happens to share bookkeeping).
        """
        with self._lock:
            ledger = self.manager.explorer._ip_origin_ledger
            active_ips = set(self.manager.explorer._all_ips)
            self._dynamic_ips = [
                ip for ip in self._dynamic_ips
                if ip in active_ips and ledger.get(ip) == "dynamic"
            ]
            # _known_ips should never block an IP from being reconsidered
            # once pool.py has fully forgotten it (i.e. it's no longer
            # active AND no longer in the ledger at all). A dynamic IP
            # that's merely quarantined (active=False, ledger=dynamic)
            # should stay "known" so discovery doesn't re-probe it while
            # pool.py is still tracking it for recycling.
            self._known_ips = {
                ip for ip in self._known_ips
                if ip in active_ips or ip in ledger
            }

    @property
    def snis(self) -> List[str]:
        """Always-current list of SNIs known to the pool's explorer.

        Reading this live (rather than a fixed snapshot taken at __init__)
        means a newly discovered dynamic SNI is automatically included the
        next time an IP is injected — no extra wiring needed between
        IPDiscovery and SNIDiscovery.
        """
        live = self.manager.explorer._all_snis
        return live if live else self._initial_snis

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> threading.Thread:
        """Start the discovery loop in a background daemon thread."""
        self._thread = threading.Thread(
            target=self._loop,
            name="snispf-ip-discovery",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "IP discovery started — batch=%d  interval=%ds  CIDRs=%d",
            self.scan_batch, int(self.scan_interval), len(self.cidrs),
        )
        return self._thread

    @property
    def dynamic_ip_count(self) -> int:
        self._sync_with_explorer()
        with self._lock:
            return len(self._dynamic_ips)

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        """Main discovery loop — runs forever in a daemon thread."""
        # First scan starts after a short delay so the pool's own initial
        # probe can finish first.
        time.sleep(15 + random.uniform(0, 10))

        while True:
            try:
                self._scan_round()
            except Exception:
                import traceback
                logger.debug("Discovery error:\n%s", traceback.format_exc())

            jitter = random.uniform(-15, 15)
            sleep_for = max(30, self.scan_interval + jitter)
            logger.debug("Next IP discovery scan in %.0f s", sleep_for)
            time.sleep(sleep_for)

    def _scan_round(self) -> None:
        """Run one full scan round: sample → probe → inject.

        Skips entirely (no network calls at all) once the dynamic IP cap
        is reached — there is no point spending bandwidth and CPU probing
        random new candidates when there's no room to keep them anyway.
        Discovery resumes automatically the moment a slot frees up (e.g.
        pool.py evicts a weak dynamic IP), since _sync_with_explorer keeps
        the count accurate.
        """
        # Reconcile with pool.py's eviction/recycling before checking the
        # cap — otherwise a stale count could make us skip when a slot is
        # actually free, or scan when we're actually full.
        self._sync_with_explorer()

        with self._lock:
            current_count = len(self._dynamic_ips)
        if current_count >= self.max_dynamic_ips:
            logger.debug(
                "IP discovery: dynamic IP cap reached (%d/%d) — skipping scan round.",
                current_count, self.max_dynamic_ips,
            )
            return

        candidates = sample_cloudflare_ips(self.scan_batch, self.cidrs)

        # Filter out IPs already in the pool.
        with self._lock:
            known = set(self._known_ips)
        candidates = [ip for ip in candidates if ip not in known]

        if not candidates:
            logger.debug("Discovery: all sampled IPs already known — skipping.")
            return

        logger.info(
            "IP discovery: probing %d candidates (batch=%d, %d new) ...",
            len(candidates), self.scan_batch, len(candidates),
        )

        # Probe in parallel threads.
        accepted: List[str] = []
        lock = threading.Lock()

        def _probe_one(ip: str) -> None:
            rate = _tls_probe(
                ip, self.port, self.probe_timeout, self.probe_attempts
            )
            if rate >= self.min_success_rate:
                with lock:
                    accepted.append(ip)

        threads = [
            threading.Thread(target=_probe_one, args=(ip,), daemon=True)
            for ip in candidates
        ]
        # Stagger thread starts to avoid a SYN flood.
        for t in threads:
            t.start()
            time.sleep(random.uniform(0, 0.02))
        for t in threads:
            t.join()

        logger.info(
            "IP discovery: %d / %d candidates accepted (≥%.0f%% success)",
            len(accepted), len(candidates), self.min_success_rate * 100,
        )

        if not accepted:
            return

        # Inject new IPs into the pool.
        injected = 0
        for ip in accepted:
            injected += self._inject_ip(ip)

        logger.info(
            "IP discovery: injected %d new (IP, SNI) pairs into the pool.",
            injected,
        )

        # Trigger an immediate pool refresh so the best new pairs can enter
        # the active set without waiting for the next scheduled health cycle.
        if injected > 0:
            self.manager.pool.refresh()

    def _inject_ip(self, ip: str) -> int:
        """Add one new IP × all known SNIs into the explorer.

        Only pairs with SNIs that are currently active (not quarantined) —
        mirrors the same rule used for SNI discovery: never pair a newly
        found entity with something on the other axis that's been
        quarantined for poor performance.

        Returns the number of pairs added.
        """
        # Reconcile first so the cap check below reflects IPs pool.py may
        # have evicted/recycled on its own since our last sync.
        self._sync_with_explorer()

        with self._lock:
            if ip in self._known_ips:
                return 0

            # Enforce the cap: evict the oldest dynamic IP if over limit.
            if len(self._dynamic_ips) >= self.max_dynamic_ips:
                evicted_ip = self._dynamic_ips.pop(0)
                self._known_ips.discard(evicted_ip)
                explorer = self.manager.explorer
                # Remove evicted pairs from the explorer stats dict.
                # (They won't be in the active pool since they're old/weak.)
                for sni in self.snis:
                    explorer.stats.pop((evicted_ip, sni), None)
                # CRITICAL: also drop it from _all_ips and the origin
                # ledger. Without this, the IP stays "known" to the
                # explorer forever — every time SNIDiscovery injects a
                # *new* SNI, it pairs that SNI with all of self._all_ips,
                # silently resurrecting IPs we just evicted and making
                # the dynamic-IP cap meaningless over time.
                if evicted_ip in explorer._all_ips:
                    explorer._all_ips.remove(evicted_ip)
                explorer._ip_origin_ledger.pop(evicted_ip, None)
                logger.debug("Discovery: evicted old IP %s from pool.", evicted_ip)

            self._known_ips.add(ip)
            self._dynamic_ips.append(ip)
            # Permanently record this IP's origin so later recycle/lookup
            # operations never misclassify it as static, even if it has
            # zero active pairs at the moment of lookup.
            explorer_for_ledger = self.manager.explorer
            explorer_for_ledger._ip_origin_ledger[ip] = "dynamic"

        # Add PairStats entries for ip × all currently-active snis.
        from .pool import PairStats  # local import to avoid circular

        explorer = self.manager.explorer
        added = 0
        for sni in self.snis:
            # Skip SNIs that have since been quarantined — don't pair a
            # fresh IP with something already known to be weak.
            if sni in explorer._sni_quarantine:
                continue
            key = (ip, sni)
            if key not in explorer.stats:
                sni_origin = explorer._lookup_sni_origin(sni)
                ps = PairStats(ip, sni, ip_origin="dynamic", sni_origin=sni_origin)
                explorer.stats[key] = ps
                # Also add to the unexplored queue so it gets probed soon.
                with explorer._lock:
                    explorer._unexplored.append(key)
                    if ip not in explorer._all_ips:
                        explorer._all_ips.append(ip)
                added += 1

        return added


    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def log_status(self) -> None:
        self._sync_with_explorer()
        with self._lock:
            dynamic = len(self._dynamic_ips)
            known = len(self._known_ips)
        logger.info(
            "IP discovery status — dynamic IPs: %d / %d  total known: %d",
            dynamic, self.max_dynamic_ips, known,
        )


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------

def build_ip_discovery(
    manager: "ConnectionManager",
    config: dict,
) -> Optional["IPDiscovery"]:
    """Build an IPDiscovery from config, or return None if disabled.

    Reads the following config keys (all optional):

    ``DYNAMIC_IP_DISCOVERY``   bool   Enable dynamic discovery (default: false)
    ``DISCOVERY_BATCH``        int    IPs sampled per round (default: 100)
    ``DISCOVERY_INTERVAL``     float  Seconds between rounds (default: 120)
    ``DISCOVERY_PROBE_TRIES``  int    TCP probes per candidate (default: 3)
    ``DISCOVERY_TIMEOUT``      float  TCP connect timeout (default: 2.0)
    ``DISCOVERY_MIN_SUCCESS``  float  Min success rate 0–1 (default: 0.50)
    ``DISCOVERY_MAX_IPS``      int    Cap on dynamic IPs (default: 200)
    """
    if not config.get("DYNAMIC_IP_DISCOVERY", False):
        return None

    snis: List[str] = config.get("FAKE_SNIS", [])
    if not snis and config.get("FAKE_SNI"):
        snis = [config["FAKE_SNI"]]
    if not snis:
        logger.warning("IP discovery enabled but no FAKE_SNIS — disabled.")
        return None

    return IPDiscovery(
        manager=manager,
        snis=snis,
        scan_batch=config.get("DISCOVERY_BATCH", 100),
        scan_interval=config.get("DISCOVERY_INTERVAL", 120.0),
        probe_attempts=config.get("DISCOVERY_PROBE_TRIES", 3),
        probe_timeout=config.get("DISCOVERY_TIMEOUT", 2.0),
        min_success_rate=config.get("DISCOVERY_MIN_SUCCESS", 0.50),
        max_dynamic_ips=config.get("DISCOVERY_MAX_IPS", 200),
        port=config.get("CONNECT_PORT", 443),
    )
