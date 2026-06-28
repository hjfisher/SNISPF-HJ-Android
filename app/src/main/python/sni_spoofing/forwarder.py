"""Core TCP forwarder with DPI bypass.

This is the main engine that:
1. Listens for incoming TCP connections
2. Reads the first TLS ClientHello from the client
3. Connects to the configured upstream IP
4. Applies the chosen DPI bypass strategy
5. Relays data bidirectionally between client and server

When a raw injector is available (Linux + root), it registers each
outgoing connection so the sniffer can capture the SYN/ACK handshake
and inject the fake ClientHello with an out-of-window seq number.
"""

import asyncio
import logging
import socket
import sys
import time
import traceback
from typing import Optional, TYPE_CHECKING

# `resource` is a POSIX-only module (Linux/macOS/BSD). It does not exist on
# Windows, so we import it defensively and skip the fd-limit tweak there.
try:
    import resource  # type: ignore
except ImportError:  # pragma: no cover -- Windows
    resource = None  # type: ignore

from .bypass.base import BypassStrategy
from .shaping import DISABLED_SHAPER, TrafficShaper
from .tls import ClientHelloBuilder

if TYPE_CHECKING:
    # Avoid a circular import; only needed for type annotations.
    from .pool import ConnectionManager, PairStats

logger = logging.getLogger("snispf")

# Buffer size for socket operations
BUFFER_SIZE = 65535

# How many consecutive failures on a single IP before triggering failover
FAILOVER_THRESHOLD = 3

# Rapid failure window -- if we get FAILOVER_THRESHOLD failures within
# this many seconds, the IP is considered blocked.
FAILOVER_WINDOW = 30.0

# Maximum concurrent connections.  Keeps the process well under the
# OS file-descriptor limit and avoids "Too many open files" crashes
# that macOS users hit with the default 256 fd limit.
MAX_CONCURRENT_CONNECTIONS = 512


def _raise_fd_limit():
    """Try to raise the OS file-descriptor soft limit.

    macOS defaults to 256, which is far too low for a proxy that handles
    many parallel connections (each needs 2 fds: incoming + outgoing).
    We attempt to raise the soft limit to the hard limit, or at least
    to a reasonable value.

    No-op on Windows, where the `resource` module does not exist and
    socket count is governed differently.
    """
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft < 4096:
            target = min(hard, 65536) if hard > soft else 4096
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
                logger.debug("Raised fd limit from %d to %d", soft, target)
            except (ValueError, OSError):
                # On some systems we cannot raise beyond hard limit
                try:
                    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
                except (ValueError, OSError):
                    pass
    except (AttributeError, OSError):
        # resource module not available (unlikely) or unsupported platform
        pass


class ConnectionTracker:
    """Tracks per-IP connection failures to detect blocking."""

    def __init__(self):
        self._failures = {}   # ip -> list of failure timestamps
        self._successes = {}  # ip -> count

    def record_failure(self, ip: str) -> int:
        """Record a failure and return how many occurred within the window."""
        now = time.monotonic()
        if ip not in self._failures:
            self._failures[ip] = []
        self._failures[ip].append(now)
        # Prune old entries
        cutoff = now - FAILOVER_WINDOW
        self._failures[ip] = [t for t in self._failures[ip] if t > cutoff]
        return len(self._failures[ip])

    def record_success(self, ip: str):
        """Record a successful connection (resets the failure counter)."""
        self._failures.pop(ip, None)
        self._successes[ip] = self._successes.get(ip, 0) + 1

    def should_failover(self, ip: str) -> bool:
        count = len(self._failures.get(ip, []))
        return count >= FAILOVER_THRESHOLD

    def clear(self, ip: str):
        self._failures.pop(ip, None)


# Module-level tracker shared across connections
_conn_tracker = ConnectionTracker()


async def handle_connection(
    incoming_sock: socket.socket,
    incoming_addr: tuple,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
    raw_injector=None,
    conn_manager: "Optional[ConnectionManager]" = None,
    shaper: Optional[TrafficShaper] = None,
):
    """Handle a single incoming connection.

    When a ``conn_manager`` (ConnectionManager) is supplied the (IP, SNI)
    pair is chosen dynamically via the pool's weighted-random picker.
    Statistics are recorded so the pool can track real-traffic loss and
    rotate out degraded upstreams without dropping live connections.

    Flow:
    1. Read first data from client (should be TLS ClientHello)
    2. Pick upstream (IP, SNI) — from pool or from static config
    3. Create outgoing socket, optionally register with raw injector
    4. Connect to target server (3-way handshake happens here;
       the raw injector captures SYN and injects after 3rd ACK)
    5. Apply the bypass strategy (sends real data, waits for inject
       confirmation)
    6. Relay data bidirectionally; update pool stats on completion
    """
    loop = asyncio.get_running_loop()
    outgoing_sock = None
    local_port = None
    active_shaper = shaper if shaper is not None else DISABLED_SHAPER

    # ── Pool integration: pick the best (IP, SNI) pair ────────────────
    # If a ConnectionManager is available, override the static config values
    # with the pool's weighted-random selection so degraded upstreams are
    # avoided and the best pairs are favoured.
    pair = None
    if conn_manager is not None:
        pair = conn_manager.pick_pair()
        active_ip = pair.ip
        active_sni = pair.sni
        with pair.lock:
            pair.active_connections += 1
            pair.total_connections += 1
    else:
        active_ip = connect_ip
        active_sni = fake_sni

    def _release_pair(failed: bool = False) -> None:
        """Decrement the active-connection counter and optionally report failure."""
        if pair is None:
            return
        with pair.lock:
            pair.active_connections = max(0, pair.active_connections - 1)
        if failed:
            pair.record_real_packet(lost=True)
            conn_manager.report_failure(pair)

    try:
        # Read the first data from client (should be TLS ClientHello)
        first_data = await asyncio.wait_for(
            loop.sock_recv(incoming_sock, BUFFER_SIZE),
            timeout=30.0,
        )

        if not first_data:
            incoming_sock.close()
            _release_pair(failed=False)
            return

        # Parse to see if it's a TLS ClientHello
        parsed = ClientHelloBuilder.parse_client_hello(first_data)
        client_sni = parsed.get("sni", "unknown")
        logger.info(
            f"[{incoming_addr[0]}:{incoming_addr[1]}] -> "
            f"{active_ip}:{connect_port} | SNI: {client_sni} | "
            f"Fake: {active_sni} | Method: {bypass_strategy.name}"
            + (f" | pool_loss={pair.combined_loss_rate*100:.1f}%" if pair else "")
        )

        # Create outgoing socket
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)

        # Bind to specific interface if configured
        if interface_ip:
            outgoing_sock.bind((interface_ip, 0))

        # Set keepalive
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except (AttributeError, OSError):
            pass  # Not available on all platforms

        # If raw injector is available, register the outgoing port
        # BEFORE connecting so the sniffer can see the SYN.
        if raw_injector is not None:
            # We need to bind first to know the local port
            if not interface_ip:
                outgoing_sock.bind(("", 0))
            local_port = outgoing_sock.getsockname()[1]
            fake_hello = ClientHelloBuilder.build_client_hello(sni=active_sni)
            raw_injector.register_port(local_port, fake_hello)

        # Connect to target server (triggers SYN -> SYN+ACK -> ACK)
        try:
            await asyncio.wait_for(
                loop.sock_connect(outgoing_sock, (active_ip, connect_port)),
                timeout=15.0,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            fail_count = _conn_tracker.record_failure(active_ip)
            logger.debug(
                "[%s:%d] Connect to %s failed (%d/%d): %s",
                incoming_addr[0], incoming_addr[1], active_ip,
                fail_count, FAILOVER_THRESHOLD, exc,
            )
            raise

        # If we didn't know the port before, grab it now
        if local_port is None and raw_injector is not None:
            local_port = outgoing_sock.getsockname()[1]

        # Apply DPI bypass strategy
        # The strategy handles:
        # - Waiting for raw injection confirmation (if available)
        # - Sending the real ClientHello (fragmented or not)
        success = await bypass_strategy.apply(
            client_sock=incoming_sock,
            server_sock=outgoing_sock,
            fake_sni=active_sni,
            first_data=first_data,
            loop=loop,
        )

        if not success:
            logger.warning(
                f"[{incoming_addr[0]}:{incoming_addr[1]}] "
                f"Bypass strategy '{bypass_strategy.name}' failed, "
                f"falling back to direct relay"
            )
            # Fallback: just send the data directly
            await loop.sock_sendall(outgoing_sock, first_data)

        # NOTE: Do NOT mark success yet.  We need to verify the server
        # actually responds with valid data (not a block page or RST).
        # Success is recorded only after the first server response
        # is received in the relay loop below.

        # Bidirectional relay
        done = asyncio.Event()
        server_responded = False

        async def _relay(s_in, s_out, label):
            nonlocal server_responded
            try:
                while True:
                    data = await loop.sock_recv(s_in, BUFFER_SIZE)
                    if not data:
                        break
                    await active_shaper.send(loop, s_out, data, label)
                    # Record success only when we get the first
                    # response from the server (S->C direction).
                    if label == "S->C" and not server_responded:
                        server_responded = True
                        _conn_tracker.record_success(active_ip)
                        if pair is not None:
                            pair.record_real_packet(lost=False)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            except Exception:
                logger.debug(f"Relay error ({label}): {traceback.format_exc()}")
            finally:
                done.set()

        # Watcher: fires when the pool drain-timeout expires for this pair.
        # Closes both sockets so the relay tasks exit cleanly.
        async def _drain_watcher():
            if pair is None:
                return
            ev = pair.force_close_event
            # Poll cheaply; the event is set at most once per pair lifetime.
            while not done.is_set():
                if ev.is_set():
                    logger.debug(
                        "Drain timeout reached for %s — closing connection "
                        "from %s:%s",
                        pair.ip, incoming_addr[0], incoming_addr[1],
                    )
                    try:
                        incoming_sock.close()
                    except Exception:
                        pass
                    try:
                        if outgoing_sock:
                            outgoing_sock.close()
                    except Exception:
                        pass
                    done.set()
                    return
                await asyncio.sleep(0.5)

        c2s_task = loop.create_task(_relay(incoming_sock, outgoing_sock, "C->S"))
        s2c_task = loop.create_task(_relay(outgoing_sock, incoming_sock, "S->C"))
        watcher_task = loop.create_task(_drain_watcher())

        # Wait until one direction closes, then cancel the others.
        await done.wait()
        c2s_task.cancel()
        s2c_task.cancel()
        watcher_task.cancel()
        await asyncio.gather(c2s_task, s2c_task, watcher_task, return_exceptions=True)

        # If the server never responded, record a failure.
        # This catches cases where DPI allows the handshake but
        # blocks or RSTs actual application data.
        if not server_responded:
            _conn_tracker.record_failure(active_ip)
            _release_pair(failed=True)
        else:
            _release_pair(failed=False)

    except asyncio.TimeoutError:
        logger.debug(f"[{incoming_addr[0]}:{incoming_addr[1]}] Connection timeout")
        _release_pair(failed=True)
    except Exception:
        logger.debug(f"Connection handler error: {traceback.format_exc()}")
        _release_pair(failed=True)
    finally:
        try:
            incoming_sock.close()
        except Exception:
            pass
        try:
            if outgoing_sock:
                outgoing_sock.close()
        except Exception:
            pass
        # Clean up raw injector port state
        if raw_injector is not None and local_port is not None:
            raw_injector.cleanup_port(local_port)


async def start_server(
    listen_host: str,
    listen_port: int,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
    raw_injector=None,
    conn_manager: "Optional[ConnectionManager]" = None,
    shaper: Optional[TrafficShaper] = None,
):
    """Start the TCP forwarding server.

    When ``conn_manager`` is supplied, each incoming connection picks its
    upstream (IP, SNI) from the pool instead of using the static
    ``connect_ip`` / ``fake_sni`` values.  The static values are kept as
    fallback defaults so the function signature stays backwards-compatible.

    Creates a listening socket and handles incoming connections,
    applying the DPI bypass strategy to each one.
    """
    # Raise the OS file-descriptor limit before binding
    _raise_fd_limit()

    # Create listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setblocking(False)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((listen_host, listen_port))

    # Set keepalive on the listening socket
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
    except (AttributeError, OSError):
        pass

    server_sock.listen(128)

    loop = asyncio.get_running_loop()

    # Semaphore limits concurrent connections to prevent fd exhaustion.
    # Each proxied connection uses 2 fds (client + server), plus the
    # listening socket itself.  This cap prevents the "Too many open
    # files" crash that happens on macOS (default fd limit 256) and
    # Android/Termux when VPN clients open many connections at once.
    conn_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)

    logger.info(f"Listening on {listen_host}:{listen_port}")
    if conn_manager is not None:
        logger.info("Upstream selection: POOL (multi-IP / multi-SNI)")
    else:
        logger.info(f"Forwarding to {connect_ip}:{connect_port}")
        logger.info(f"Fake SNI: {fake_sni}")
    logger.info(f"Bypass strategy: {bypass_strategy.name}")
    if shaper is not None and shaper.enabled:
        logger.info(
            f"Traffic shaping: ENABLED (direction={shaper.direction}, "
            f"chunk={shaper.min_chunk}-{shaper.max_chunk}B, "
            f"delay={shaper.min_delay_ms}-{shaper.max_delay_ms}ms)"
        )
    else:
        logger.info("Traffic shaping: disabled")
    if raw_injector is not None:
        logger.info("Raw packet injection: ACTIVE (seq_id trick enabled)")
    else:
        logger.info("Raw packet injection: not available (fragmentation only)")
    logger.info(f"Interface IP: {interface_ip or 'auto'}")
    logger.info("=" * 60)
    logger.info("Ready! Configure your application to use:")
    logger.info(f"  Address: 127.0.0.1:{listen_port}")
    logger.info("=" * 60)

    async def _guarded_handle(sock, addr):
        """Wrap handle_connection with the concurrency semaphore."""
        async with conn_semaphore:
            await handle_connection(
                incoming_sock=sock,
                incoming_addr=addr,
                connect_ip=connect_ip,
                connect_port=connect_port,
                fake_sni=fake_sni,
                bypass_strategy=bypass_strategy,
                interface_ip=interface_ip,
                raw_injector=raw_injector,
                conn_manager=conn_manager,
                shaper=shaper,
            )

    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(server_sock)
            incoming_sock.setblocking(False)

            loop.create_task(_guarded_handle(incoming_sock, addr))
    except asyncio.CancelledError:
        pass
    finally:
        server_sock.close()
        logger.info("Server stopped.")
