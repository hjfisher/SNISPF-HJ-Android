"""Direct (passthrough) connection strategy.

Forwards the client's TLS ClientHello to the server completely unmodified
— no fragmentation, no fake decoy hello, no SNI substitution. The pool's
multi-IP selection still applies (so the connection benefits from health
tracking, eviction, and dynamic IP discovery), but the SNI the upstream
server actually sees is exactly what the client (e.g. v2ray, xray) sent.

Use this when the upstream server already handles its own censorship
circumvention (e.g. VLESS+Reality, Trojan with a real cert) and SNISPF-HJ
is only being used for its connection pool — picking the healthiest
Cloudflare-fronted IP — not for SNI spoofing. Faking the SNI in that case
is actively harmful: Cloudflare/the upstream may route the connection to
the wrong backend based on the substituted SNI, causing the seemingly
random failures this strategy avoids.
"""

import asyncio
import socket


from .base import BypassStrategy


class DirectBypass(BypassStrategy):
    """Forward the client's data unmodified — no SNI spoofing at all.

    This is the simplest possible strategy: take whatever the client sent
    (``first_data``, normally a TLS ClientHello with the client's *real*
    SNI) and send it straight through to the server, byte for byte. No
    fragmentation, no decoy ClientHello, no substituted SNI.

    Pairs with this strategy still come from the pool, so multi-IP
    health-tracking, eviction, and discovery all keep working — only the
    SNI-faking behaviour is disabled.
    """

    name = "direct"

    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        """Send the client's original data straight to the server.

        ``fake_sni`` is accepted for interface compatibility with other
        strategies but is intentionally ignored — that's the entire point
        of this strategy.
        """
        if loop is None:
            loop = asyncio.get_running_loop()

        try:
            await loop.sock_sendall(server_sock, first_data)
            return True
        except Exception:
            return False
