"""Dynamic Cloudflare SNI discovery — feeds fresh SNIs into the connection pool.

Mirrors ``ip_discovery.py`` exactly, but on the opposite axis: instead of
sampling random IPs from Cloudflare's CIDR ranges, this samples random
*domain names* from large public domain-ranking lists (Tranco, Cisco
Umbrella, Majestic Million) plus a curated seed list, checks whether each
one resolves to a Cloudflare IP, and — if so — probes it with a real TLS
handshake against one of the pool's currently-active IPs. Domains that pass
are injected into the pool as new SNIs, paired only with IPs that are
**not currently quarantined** (mirroring the same rule IP discovery uses
when pairing a fresh IP with SNIs).

Inspired by https://github.com/hjfisher/cf_sni_scanner
(cf_sni_finder_v2.py / sni_merger.py).

Two independent timers
-----------------------
Downloading the Tranco/Umbrella/Majestic lists is relatively heavy (each is
a multi-megabyte CSV/ZIP) and those lists barely change day to day, so this
module splits the work into two loops with very different cadences:

1. ``_source_refresh_loop`` — runs every ``SNI_SOURCE_REFRESH_INTERVAL``
   seconds (default: 6 hours). Downloads the public domain lists once,
   merges them with the curated seed list, and stores the result in an
   in-memory cache (``self._domain_pool``). No network discovery/probing
   happens here — just refreshing the candidate pool.

2. ``_discovery_loop`` — runs every ``SNI_DISCOVERY_INTERVAL`` seconds
   (default: 120s, same cadence as IP discovery). Samples a batch of
   domains from the in-memory cache, resolves them, filters for
   Cloudflare-hosted ones, probes with a real TLS handshake, and injects
   the survivors into the pool. This loop never touches the network for
   bulk downloads — only individual DNS lookups and TLS probes.

Integration
-----------
Call ``start()`` after creating the ConnectionManager::

    from sni_spoofing.sni_discovery import SNIDiscovery
    discovery = SNIDiscovery(manager=conn_manager)
    discovery.start()

or let ``build_sni_discovery`` / ``cli.py`` do it automatically when
``DYNAMIC_SNI_DISCOVERY`` is set to ``true`` in the config.
"""

from __future__ import annotations

import io
import ipaddress
import logging
import random
import socket
import ssl
import threading
import time
import zipfile
from typing import List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from .pool import ConnectionManager

logger = logging.getLogger("snispf.sni_discovery")

# ---------------------------------------------------------------------------
# Official Cloudflare IPv4 CIDR ranges — reused to check if a resolved
# domain is genuinely Cloudflare-hosted (same list as ip_discovery.py).
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
_CF_NETWORKS = [ipaddress.ip_network(c) for c in CLOUDFLARE_CIDRS]


def _is_cloudflare_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _CF_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Curated high-value seed domains — small, hand-picked, known to often be
# Cloudflare-fronted. Used as a reliable baseline even if the public list
# downloads fail (e.g. no internet access at startup).
# ---------------------------------------------------------------------------
CURATED_SEEDS: List[str] = """
discord.com
discordapp.com
canva.com
notion.so
medium.com
dev.to
hashnode.com
fly.io
cloudflare.com
workers.dev
pages.dev
trycloudflare.com
cdnjs.cloudflare.com
cdnjs.com
cdn.jsdelivr.net
vercel.com
vercel.app
railway.app
render.com
netlify.com
netlify.app
surge.sh
gitbook.io
gitbook.com
readme.io
readme.com
stoplight.io
swagger.io
postman.com
rapidapi.com
replit.com
codesandbox.io
stackblitz.com
glitch.com
codepen.io
jsfiddle.net
jsbin.com
observablehq.com
npmjs.com
npmjs.org
registry.npmjs.org
unpkg.com
skypack.dev
esm.sh
esm.run
jspm.io
hub.docker.com
golang.org
go.dev
rust-lang.org
crates.io
lib.rs
docs.rs
pypi.org
rubygems.org
packagist.org
nuget.org
gradle.org
dart.dev
pub.dev
sourceforge.net
gitlab.com
bitbucket.org
codeberg.org
huggingface.co
arxiv.org
researchgate.net
zenodo.org
biorxiv.org
medrxiv.org
stackoverflow.com
stackexchange.com
superuser.com
serverfault.com
askubuntu.com
reddit.com
substack.com
ghost.org
wordpress.com
squarespace.com
webflow.com
framer.com
bubble.io
airtable.com
coda.io
obsidian.md
logseq.com
linear.app
monday.com
clickup.com
toggl.com
clockify.me
freshdesk.com
crisp.chat
tawk.to
sentry.io
grafana.com
prometheus.io
elastic.co
stripe.com
paddle.com
twilio.com
sendgrid.com
mailchimp.com
mailgun.com
klaviyo.com
hubspot.com
pipedrive.com
auth0.com
okta.com
yarnpkg.com
pnpm.io
bun.sh
deno.land
deno.com
standardnotes.com
philarchive.org
rollbar.com
logrocket.com
""".strip().splitlines()

# Public domain-ranking sources, downloaded once per SNI_SOURCE_REFRESH_INTERVAL.
_EXTRA_SOURCES = {
    "majestic": "https://downloads.majestic.com/majestic_million.csv",
    "umbrella": "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
}


def _clean_domain(d: str) -> str:
    d = d.strip().lower().split("#")[0].strip()
    for p in ("https://", "http://", "ftp://"):
        if d.startswith(p):
            d = d[len(p):]
    return d.split("/")[0].split(":")[0].split("?")[0]


def _fetch_zip_csv(url: str, limit: int, col: int = 1, timeout: float = 90.0) -> List[str]:
    """Download a ZIP containing a CSV and extract up to ``limit`` domains."""
    import urllib.request

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        zf = zipfile.ZipFile(io.BytesIO(data))
        csv_bytes = zf.read(zf.namelist()[0]).decode(errors="ignore")
        domains = []
        for line in csv_bytes.splitlines():
            if len(domains) >= limit:
                break
            parts = line.strip().split(",")
            if len(parts) > col:
                d = _clean_domain(parts[col])
                if d and "." in d:
                    domains.append(d)
        return domains
    except Exception as e:
        logger.debug("Failed to fetch %s: %s", url, e)
        return []


def _fetch_plain_csv(
    url: str, limit: int, col: int = 1, skip_header: bool = True, timeout: float = 60.0
) -> List[str]:
    """Download a plain CSV and extract up to ``limit`` domains."""
    import urllib.request

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode(errors="ignore")
        domains = []
        for i, line in enumerate(text.splitlines()):
            if skip_header and i == 0:
                continue
            if len(domains) >= limit:
                break
            parts = line.strip().split(",")
            if len(parts) > col:
                d = _clean_domain(parts[col])
                if d and "." in d:
                    domains.append(d)
        return domains
    except Exception as e:
        logger.debug("Failed to fetch %s: %s", url, e)
        return []


def fetch_domain_pool(limit_per_source: int = 5000) -> Set[str]:
    """Download and merge domains from all public sources + curated seeds.

    This is the expensive, network-heavy operation — call it rarely (see
    ``SNI_SOURCE_REFRESH_INTERVAL``), never on every discovery cycle.
    """
    domains: Set[str] = {_clean_domain(d) for d in CURATED_SEEDS if d.strip()}
    logger.info("SNI source refresh: %d curated seeds", len(domains))

    for name, url in _EXTRA_SOURCES.items():
        if name == "majestic":
            found = _fetch_plain_csv(url, limit_per_source, col=1, skip_header=True)
        else:
            found = _fetch_zip_csv(url, limit_per_source, col=1)
        domains.update(found)
        logger.info(
            "SNI source refresh: %s → %s",
            name, f"{len(found)} domains" if found else "failed/unreachable",
        )

    # Basic sanity filtering.
    domains = {d for d in domains if d and "." in d and len(d) < 100 and " " not in d}
    logger.info("SNI source refresh: %d unique candidate domains total", len(domains))
    return domains


# ---------------------------------------------------------------------------
# DNS resolve + Cloudflare check + TLS probe
# ---------------------------------------------------------------------------

def _resolve(domain: str, timeout: float = 5.0) -> Optional[str]:
    """Resolve a domain to its first IPv4 address, or None on failure."""
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            info = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        finally:
            socket.setdefaulttimeout(old_timeout)
        if info:
            return info[0][4][0]
    except Exception:
        pass
    return None


def _tls_probe_sni(ip: str, sni: str, port: int, timeout: float, attempts: int) -> float:
    """Return the fraction of successful TLS handshakes for (ip, sni).

    Identical methodology to pool.py's CombinationExplorer._probe_one and
    ip_discovery.py's _tls_probe: a real handshake, not just a TCP connect,
    since a server may accept the TCP connection but reject the TLS layer.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    successes = 0
    for _ in range(attempts):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni):
                    successes += 1
        except Exception:
            pass
        time.sleep(random.uniform(0.02, 0.08))
    return successes / attempts


# ---------------------------------------------------------------------------
# SNIDiscovery — the main scanner class
# ---------------------------------------------------------------------------

class SNIDiscovery:
    """Continuously discovers fresh Cloudflare-hosted SNIs and injects them
    into the pool.

    Lifecycle
    ~~~~~~~~~
    1. ``start()`` — launches two daemon threads:
       a. the source-refresh loop (rare, heavy downloads)
       b. the discovery loop (frequent, lightweight sampling + probing)
    2. Every ``scan_interval`` seconds the discovery loop:
       a. Samples ``scan_batch`` random domains from the in-memory cache.
       b. Resolves each one and checks whether the IP is Cloudflare-owned.
       c. Probes the survivors with a real TLS handshake against one of the
          pool's currently-active IPs.
       d. Accepts domains whose success rate is ≥ ``min_success_rate``.
       e. Injects each accepted SNI, paired with every IP currently known
          to the pool that is **not quarantined** — mirroring the same
          rule IP discovery uses on the SNI side.
       f. Caps the dynamic SNI count at ``max_dynamic_snis``, evicting the
          oldest discovery when over the limit.
    """

    def __init__(
        self,
        manager: "ConnectionManager",
        scan_batch: int = 50,
        scan_interval: float = 120.0,
        source_refresh_interval: float = 21600.0,
        probe_attempts: int = 3,
        probe_timeout: float = 2.0,
        min_success_rate: float = 0.50,
        max_dynamic_snis: int = 100,
        domains_per_source: int = 5000,
        port: int = 443,
    ) -> None:
        """Create a SNIDiscovery instance.

        Args:
            manager:                  The active ConnectionManager.
            scan_batch:                Domains sampled per discovery cycle.
            scan_interval:             Seconds between discovery cycles.
            source_refresh_interval:   Seconds between heavy source downloads.
            probe_attempts:            TLS handshake attempts per candidate.
            probe_timeout:             TLS handshake timeout per attempt.
            min_success_rate:          Fraction of probes that must succeed.
            max_dynamic_snis:          Cap on dynamically discovered SNIs.
            domains_per_source:        Domains pulled from each public list.
            port:                      Target port for TLS probes (usually 443).
        """
        self.manager = manager
        self.scan_batch = scan_batch
        self.scan_interval = scan_interval
        self.source_refresh_interval = source_refresh_interval
        self.probe_attempts = probe_attempts
        self.probe_timeout = probe_timeout
        self.min_success_rate = min_success_rate
        self.max_dynamic_snis = max_dynamic_snis
        self.domains_per_source = domains_per_source
        self.port = port

        # In-memory cache of candidate domains, refreshed rarely.
        self._domain_pool: Set[str] = set(CURATED_SEEDS)
        self._domain_pool_lock = threading.Lock()

        # SNIs already known to the pool (static + dynamic).
        self._known_snis: Set[str] = set(manager.explorer._all_snis)
        # Ordered list of dynamically discovered SNIs (oldest first).
        self._dynamic_snis: List[str] = []
        self._lock = threading.Lock()

        self._source_thread: Optional[threading.Thread] = None
        self._discovery_thread: Optional[threading.Thread] = None

    def _sync_with_explorer(self) -> None:
        """Reconcile our local SNI bookkeeping with the explorer's state.

        Mirrors ``IPDiscovery._sync_with_explorer`` exactly, on the SNI
        axis. ``pool.py`` can evict or recycle SNIs entirely on its own
        (via ``ActivePool.refresh()`` → ``evict_weakest_sni`` /
        ``recycle_sni_attempt``) without this object ever being told.

        Two different signals matter:
          - ``explorer._sni_origin_ledger`` records a SNI's *origin*
            permanently, even while it sits in quarantine.
          - ``explorer._all_snis`` records whether the SNI is *currently
            active* (has at least one live pair in ``stats``).

        ``dynamic_sni_count`` and the eviction cap need to reflect *active*
        dynamic SNIs, so we filter on membership in ``_all_snis``, using
        the ledger only to confirm the origin is "dynamic".
        """
        with self._lock:
            ledger = self.manager.explorer._sni_origin_ledger
            active_snis = set(self.manager.explorer._all_snis)
            self._dynamic_snis = [
                sni for sni in self._dynamic_snis
                if sni in active_snis and ledger.get(sni) == "dynamic"
            ]
            # A dynamic SNI that's merely quarantined (active=False,
            # ledger=dynamic) should stay "known" so discovery doesn't
            # re-probe it while pool.py is still tracking it for recycling.
            self._known_snis = {
                sni for sni in self._known_snis
                if sni in active_snis or sni in ledger
            }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start both background loops (source refresh + discovery)."""
        self._source_thread = threading.Thread(
            target=self._source_refresh_loop,
            name="snispf-sni-source-refresh",
            daemon=True,
        )
        self._source_thread.start()

        self._discovery_thread = threading.Thread(
            target=self._discovery_loop,
            name="snispf-sni-discovery",
            daemon=True,
        )
        self._discovery_thread.start()

        logger.info(
            "SNI discovery started — batch=%d  interval=%ds  source_refresh=%ds",
            self.scan_batch, int(self.scan_interval), int(self.source_refresh_interval),
        )

    @property
    def dynamic_sni_count(self) -> int:
        self._sync_with_explorer()
        with self._lock:
            return len(self._dynamic_snis)

    # ------------------------------------------------------------------
    # Loop 1: source refresh (rare, heavy)
    # ------------------------------------------------------------------

    def _source_refresh_loop(self) -> None:
        """Periodically re-download the public domain lists.

        Runs an initial refresh shortly after startup (the curated seeds
        are usable immediately, so this delay just avoids competing with
        the pool's own initial probing burst), then repeats on
        ``source_refresh_interval``.
        """
        time.sleep(20 + random.uniform(0, 10))

        while True:
            try:
                fresh = fetch_domain_pool(self.domains_per_source)
                with self._domain_pool_lock:
                    self._domain_pool = fresh
                logger.info(
                    "SNI source refresh complete: %d candidate domains cached.",
                    len(fresh),
                )
            except Exception:
                import traceback
                logger.debug("SNI source refresh error:\n%s", traceback.format_exc())

            time.sleep(max(300, self.source_refresh_interval))

    # ------------------------------------------------------------------
    # Loop 2: discovery (frequent, lightweight)
    # ------------------------------------------------------------------

    def _discovery_loop(self) -> None:
        """Main discovery loop — samples, probes, injects. Runs forever."""
        # First scan starts after a short delay so the pool's own initial
        # probe can finish first (mirrors ip_discovery.py's behaviour).
        time.sleep(15 + random.uniform(0, 10))

        while True:
            try:
                self._scan_round()
            except Exception:
                import traceback
                logger.debug("SNI discovery error:\n%s", traceback.format_exc())

            jitter = random.uniform(-15, 15)
            sleep_for = max(30, self.scan_interval + jitter)
            logger.debug("Next SNI discovery scan in %.0f s", sleep_for)
            time.sleep(sleep_for)

    def _scan_round(self) -> None:
        """Run one full scan round: sample → resolve → probe → inject.

        Skips entirely (no DNS lookups, no TLS probes) once the dynamic
        SNI cap is reached — there is no point spending resources finding
        new candidate domains when there's no room to keep them anyway.
        Discovery resumes automatically the moment a slot frees up (e.g.
        pool.py evicts a weak dynamic SNI), since _sync_with_explorer keeps
        the count accurate.
        """
        # Reconcile with pool.py's eviction/recycling before checking the
        # cap — otherwise a stale count could make us skip when a slot is
        # actually free, or scan when we're actually full.
        self._sync_with_explorer()

        with self._lock:
            current_count = len(self._dynamic_snis)
        if current_count >= self.max_dynamic_snis:
            logger.debug(
                "SNI discovery: dynamic SNI cap reached (%d/%d) — skipping scan round.",
                current_count, self.max_dynamic_snis,
            )
            return

        with self._domain_pool_lock:
            pool_snapshot = list(self._domain_pool)

        if not pool_snapshot:
            logger.debug("SNI discovery: domain pool empty — skipping round.")
            return

        with self._lock:
            known = set(self._known_snis)
        candidates_pool = [d for d in pool_snapshot if d not in known]
        if not candidates_pool:
            logger.debug("SNI discovery: all sampled domains already known — skipping.")
            return

        random.shuffle(candidates_pool)
        candidates = candidates_pool[: self.scan_batch]

        logger.info("SNI discovery: checking %d candidate domain(s) ...", len(candidates))

        # Step 1: resolve + Cloudflare filter (parallel threads).
        cf_candidates: List[str] = []
        cf_lock = threading.Lock()

        def _resolve_one(domain: str) -> None:
            ip = _resolve(domain)
            if ip and _is_cloudflare_ip(ip):
                with cf_lock:
                    cf_candidates.append(domain)

        threads = [
            threading.Thread(target=_resolve_one, args=(d,), daemon=True)
            for d in candidates
        ]
        for t in threads:
            t.start()
            time.sleep(random.uniform(0, 0.01))
        for t in threads:
            t.join()

        logger.info(
            "SNI discovery: %d / %d candidates are Cloudflare-hosted",
            len(cf_candidates), len(candidates),
        )

        if not cf_candidates:
            return

        # Step 2: TLS handshake probe against an active pool IP.
        probe_ip = self._pick_probe_ip()
        if probe_ip is None:
            logger.debug("SNI discovery: no active IP available to probe against.")
            return

        accepted: List[str] = []
        accept_lock = threading.Lock()

        def _probe_one(domain: str) -> None:
            rate = _tls_probe_sni(
                probe_ip, domain, self.port, self.probe_timeout, self.probe_attempts
            )
            if rate >= self.min_success_rate:
                with accept_lock:
                    accepted.append(domain)

        threads = [
            threading.Thread(target=_probe_one, args=(d,), daemon=True)
            for d in cf_candidates
        ]
        for t in threads:
            t.start()
            time.sleep(random.uniform(0, 0.02))
        for t in threads:
            t.join()

        logger.info(
            "SNI discovery: %d / %d Cloudflare domains passed TLS probe (≥%.0f%%)",
            len(accepted), len(cf_candidates), self.min_success_rate * 100,
        )

        if not accepted:
            return

        injected = 0
        for sni in accepted:
            injected += self._inject_sni(sni)

        logger.info("SNI discovery: injected %d new (IP, SNI) pairs into the pool.", injected)

        if injected > 0:
            self.manager.pool.refresh()

    def _pick_probe_ip(self) -> Optional[str]:
        """Pick an IP currently known to the pool (not quarantined) to probe with."""
        ips = list(self.manager.explorer._all_ips)
        if not ips:
            return None
        return random.choice(ips)

    def _inject_sni(self, sni: str) -> int:
        """Add one new SNI × all currently-active IPs into the explorer.

        Only pairs with IPs that are currently active (not quarantined) —
        the same rule IP discovery applies on the IP side when pairing a
        fresh IP with SNIs.

        Returns the number of pairs added.
        """
        # Reconcile first so the cap check below reflects SNIs pool.py may
        # have evicted/recycled on its own since our last sync.
        self._sync_with_explorer()

        with self._lock:
            if sni in self._known_snis:
                return 0

            if len(self._dynamic_snis) >= self.max_dynamic_snis:
                evicted_sni = self._dynamic_snis.pop(0)
                self._known_snis.discard(evicted_sni)
                explorer = self.manager.explorer
                for ip in list(explorer._all_ips):
                    explorer.stats.pop((ip, evicted_sni), None)
                # CRITICAL: also drop it from _all_snis and the origin
                # ledger — see the matching fix in ip_discovery.py for why.
                # Without this, IPDiscovery resurrects evicted SNIs every
                # time it injects a new IP.
                if evicted_sni in explorer._all_snis:
                    explorer._all_snis.remove(evicted_sni)
                explorer._sni_origin_ledger.pop(evicted_sni, None)
                logger.debug("SNI discovery: evicted old SNI %s from pool.", evicted_sni)

            self._known_snis.add(sni)
            self._dynamic_snis.append(sni)
            # Permanently record this SNI's origin so later recycle/lookup
            # operations never misclassify it as static, even if it has
            # zero active pairs at the moment of lookup.
            self.manager.explorer._sni_origin_ledger[sni] = "dynamic"

        from .pool import PairStats  # local import to avoid circular

        explorer = self.manager.explorer
        added = 0
        for ip in list(explorer._all_ips):
            # Skip IPs that have since been quarantined.
            if ip in explorer._ip_quarantine:
                continue
            key = (ip, sni)
            if key not in explorer.stats:
                ip_origin = explorer._lookup_ip_origin(ip)
                ps = PairStats(ip, sni, ip_origin=ip_origin, sni_origin="dynamic")
                explorer.stats[key] = ps
                with explorer._lock:
                    explorer._unexplored.append(key)
                    if sni not in explorer._all_snis:
                        explorer._all_snis.append(sni)
                added += 1

        return added

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def log_status(self) -> None:
        self._sync_with_explorer()
        with self._lock:
            dynamic = len(self._dynamic_snis)
            known = len(self._known_snis)
        with self._domain_pool_lock:
            pool_size = len(self._domain_pool)
        logger.info(
            "SNI discovery status — dynamic SNIs: %d / %d  total known: %d  "
            "candidate pool: %d",
            dynamic, self.max_dynamic_snis, known, pool_size,
        )


# ---------------------------------------------------------------------------
# Factory helper
# ---------------------------------------------------------------------------

def build_sni_discovery(
    manager: "ConnectionManager",
    config: dict,
) -> Optional[SNIDiscovery]:
    """Build a SNIDiscovery from config, or return None if disabled.

    Reads the following config keys (all optional):

    ``DYNAMIC_SNI_DISCOVERY``       bool   Enable dynamic SNI discovery (default: false)
    ``SNI_DISCOVERY_BATCH``         int    Domains sampled per round (default: 50)
    ``SNI_DISCOVERY_INTERVAL``      float  Seconds between discovery rounds (default: 120)
    ``SNI_SOURCE_REFRESH_INTERVAL`` float  Seconds between source list downloads
                                           (default: 21600, i.e. 6 hours)
    ``SNI_DISCOVERY_PROBE_TRIES``   int    TLS probes per candidate (default: 3)
    ``SNI_DISCOVERY_TIMEOUT``       float  TLS handshake timeout (default: 2.0)
    ``SNI_DISCOVERY_MIN_SUCCESS``   float  Min success rate 0–1 (default: 0.50)
    ``MAX_DYNAMIC_SNIS``            int    Cap on dynamic SNIs (default: 100)
    ``SNI_DISCOVERY_DOMAINS_PER_SOURCE`` int  Domains pulled per public list
                                           (default: 5000)
    """
    if not config.get("DYNAMIC_SNI_DISCOVERY", False):
        return None

    return SNIDiscovery(
        manager=manager,
        scan_batch=config.get("SNI_DISCOVERY_BATCH", 50),
        scan_interval=config.get("SNI_DISCOVERY_INTERVAL", 120.0),
        source_refresh_interval=config.get("SNI_SOURCE_REFRESH_INTERVAL", 21600.0),
        probe_attempts=config.get("SNI_DISCOVERY_PROBE_TRIES", 3),
        probe_timeout=config.get("SNI_DISCOVERY_TIMEOUT", 2.0),
        min_success_rate=config.get("SNI_DISCOVERY_MIN_SUCCESS", 0.50),
        max_dynamic_snis=config.get("MAX_DYNAMIC_SNIS", 100),
        domains_per_source=config.get("SNI_DISCOVERY_DOMAINS_PER_SOURCE", 5000),
        port=config.get("CONNECT_PORT", 443),
    )
