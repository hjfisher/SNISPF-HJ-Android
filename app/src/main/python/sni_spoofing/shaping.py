"""Traffic shaping layer to defeat flow-based DPI fingerprinting.

Some networks (observed on certain mobile carriers) let the TLS
handshake through fine -- the SNI-fragmentation bypass works -- but
then fingerprint the *post-handshake* data stream itself. Proxy
protocols carried by upstream tools (VLESS/VMess/Trojan/Hysteria,
etc.) produce large, steady, bidirectional bursts that don't look
like normal HTTPS browsing, and get throttled/RST'd once real traffic
starts flowing.

SNISPF-HJ only owns the handshake; everything after that is relayed
byte-for-byte from/to the upstream core. This module sits in that
relay path and reshapes the outgoing byte stream -- smaller, randomly
sized chunks with random delays between them -- so it looks more like
ordinary web traffic instead of a flat, fast proxy tunnel.

Disabled by default (TRAFFIC_SHAPING_ENABLED=false): it adds latency
and is only useful on networks that do this kind of flow analysis.
"""

import asyncio
import random
from typing import Optional


class TrafficShaper:
    """Paces outgoing relay data to obscure proxy-protocol traffic patterns."""

    def __init__(
        self,
        enabled: bool = False,
        min_chunk: int = 200,
        max_chunk: int = 1200,
        min_delay_ms: float = 5.0,
        max_delay_ms: float = 40.0,
        direction: str = "download_only",
    ):
        self.enabled = enabled
        self.min_chunk = max(1, min_chunk)
        self.max_chunk = max(self.min_chunk, max_chunk)
        self.min_delay_ms = max(0.0, min_delay_ms)
        self.max_delay_ms = max(self.min_delay_ms, max_delay_ms)
        # "download_only" -> only shape server->client (S->C) traffic,
        # since that's the direction where bulk/flow detection happens.
        # "both" -> shape both directions.
        self.direction = direction

    def applies_to(self, label: str) -> bool:
        """Whether shaping should be applied to a given relay direction."""
        if not self.enabled:
            return False
        if self.direction == "both":
            return True
        return label == "S->C"

    async def send(self, loop, sock, data: bytes, label: str) -> None:
        """Send ``data`` on ``sock``, shaping it if enabled for ``label``.

        ``label`` is the relay direction tag used by forwarder.py:
        "C->S" (client to server / upload) or "S->C" (server to client
        / download).
        """
        if not self.applies_to(label):
            await loop.sock_sendall(sock, data)
            return

        view = memoryview(data)
        total = len(view)
        offset = 0
        first = True
        while offset < total:
            chunk_size = random.randint(self.min_chunk, self.max_chunk)
            chunk = view[offset : offset + chunk_size]
            if not first:
                delay = random.uniform(self.min_delay_ms, self.max_delay_ms) / 1000.0
                if delay > 0:
                    await asyncio.sleep(delay)
            await loop.sock_sendall(sock, chunk)
            offset += chunk_size
            first = False

    @classmethod
    def from_config(cls, config: dict) -> "TrafficShaper":
        """Build a TrafficShaper from the loaded config.json dict."""
        return cls(
            enabled=bool(config.get("TRAFFIC_SHAPING_ENABLED", False)),
            min_chunk=int(config.get("SHAPING_MIN_CHUNK", 200)),
            max_chunk=int(config.get("SHAPING_MAX_CHUNK", 1200)),
            min_delay_ms=float(config.get("SHAPING_MIN_DELAY_MS", 5.0)),
            max_delay_ms=float(config.get("SHAPING_MAX_DELAY_MS", 40.0)),
            direction=str(config.get("SHAPING_DIRECTION", "download_only")),
        )


# A disabled shaper is a safe default: applies_to() always returns False,
# so send() always falls through to a plain sock_sendall with no overhead.
DISABLED_SHAPER = TrafficShaper(enabled=False)


def get_shaper(config: Optional[dict]) -> TrafficShaper:
    """Convenience helper: build a shaper from config, or return the
    no-op disabled shaper if config is None."""
    if not config:
        return DISABLED_SHAPER
    return TrafficShaper.from_config(config)
