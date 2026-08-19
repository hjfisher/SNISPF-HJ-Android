"""Fake SNI bypass strategy.

Sends a fake TLS ClientHello with an allowed SNI that DPI will parse
and whitelist, but the real server will ignore.

Two operating modes:
- With raw sockets (Linux + root): Uses the seq_id trick from the
  original tool. Injects a fake ClientHello with an out-of-window
  TCP sequence number. DPI parses it, server drops it.
- Without raw sockets (fallback): Sends the real ClientHello in
  fragments so DPI cannot read the SNI from any single packet.
  The fake_sni prefix method does NOT work without raw sockets
  because sending the fake on the same TCP stream corrupts the
  TLS handshake.
"""

import asyncio
import logging
import socket
from typing import Optional

from .base import BypassStrategy
from ..tls.fragment import fragment_client_hello

logger = logging.getLogger("snispf")

# Delay between TLS fragments when fragmenting the real ClientHello
# after the seq_id fake injection. Matches the value used in the
# combined strategy so behaviour is consistent.
_REAL_FRAGMENT_DELAY = 0.1


class FakeSNIBypass(BypassStrategy):
    """Bypass DPI by injecting a fake TLS ClientHello with spoofed SNI.

    The only reliable way to do this is with raw socket injection
    (out-of-window seq trick). When raw sockets are not available,
    the real ClientHello is fragmented so DPI cannot read the SNI.

    Methods:
    - "raw_inject" - Inject fake ClientHello with wrong seq number
      via AF_PACKET. DPI sees it, server drops it. (Linux + root)
    - "fragment_fallback" - Falls back to fragmenting the real
      ClientHello. No fake is sent on the real stream.
    """

    name = "fake_sni"

    def __init__(self, method: str = "prefix_fake", raw_injector=None,
                 fragment_real: bool = True,
                 fragment_strategy: str = "sni_split"):
        """Initialise the fake_sni strategy.

        Args:
            method: Sub-method name (kept for backwards compatibility).
            raw_injector: Active ``RawInjector`` instance or ``None``.
            fragment_real: When a raw injector is active, also fragment
                the real ClientHello at the SNI boundary after the
                out-of-window fake has been confirmed. This protects
                against DPI that reassembles TCP and matches the SNI
                on the real stream (observed with some xhttp / ws
                configs that carry larger ClientHello records, e.g.
                multi-value ALPN). Defaults to ``True``.
            fragment_strategy: Fragmentation strategy passed through to
                ``fragment_client_hello`` when ``fragment_real`` is on.
        """
        self.method = method
        self.raw_injector = raw_injector
        self.fragment_real = fragment_real
        self.fragment_strategy = fragment_strategy

    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        if loop is None:
            loop = asyncio.get_running_loop()

        # If we have a raw injector running, the fake was already injected
        # during the TCP handshake. Just send the real data and go.
        if self.raw_injector is not None:
            return await self._raw_inject_send(
                server_sock, first_data, loop
            )

        # Without raw sockets, fragment the real ClientHello so DPI can't
        # read the SNI from any single packet.
        return await self._fragment_fallback(
            server_sock, first_data, loop
        )

    async def _raw_inject_send(
        self,
        server_sock: socket.socket,
        first_data: bytes,
        loop,
    ) -> bool:
        """With raw injection, the fake was already sent out-of-window.

        After the server confirms it ignored the fake, send the real
        ClientHello. By default the real ClientHello is also split at
        the SNI boundary; this matches the behaviour of the ``combined``
        strategy and is required for stricter DPI that reassembles the
        TCP stream and matches the SNI on the real handshake (observed
        with xhttp / ws configs that carry larger ClientHellos, e.g.
        multi-value ALPN such as ``h3,h2,http/1.1``).

        Set ``fragment_real=False`` to restore the previous behaviour
        of sending the real ClientHello as a single segment.
        """
        try:
            local_port = server_sock.getsockname()[1]

            # Wait for the sniffer to confirm the server ignored the fake.
            confirmed = await loop.run_in_executor(
                None,
                self.raw_injector.wait_for_confirmation,
                local_port,
                2.0,
            )

            if not confirmed:
                logger.warning(
                    f"port={local_port}: server did not confirm fake was "
                    f"ignored (timeout). Sending real data anyway."
                )

            # Send the real ClientHello. Fragmenting at the SNI boundary
            # in addition to the seq_id trick covers DPI that does TCP
            # reassembly on the real stream (some xhttp / ws configs).
            if self.fragment_real:
                try:
                    server_sock.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                    )
                except OSError:
                    pass

                fragments = fragment_client_hello(
                    first_data, self.fragment_strategy
                )

                for i, fragment in enumerate(fragments):
                    await loop.sock_sendall(server_sock, fragment)
                    if i < len(fragments) - 1 and _REAL_FRAGMENT_DELAY > 0:
                        await asyncio.sleep(_REAL_FRAGMENT_DELAY)

                try:
                    server_sock.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 0
                    )
                except OSError:
                    pass
            else:
                # Legacy path: send the real ClientHello untouched.
                await loop.sock_sendall(server_sock, first_data)

            return True

        except Exception:
            return False

    async def _fragment_fallback(
        self,
        server_sock: socket.socket,
        first_data: bytes,
        loop,
    ) -> bool:
        """Fallback: fragment the real ClientHello at the SNI boundary.

        Without raw sockets we cannot safely send a fake ClientHello
        (it would corrupt the TLS stream). Instead, fragment the real
        ClientHello so DPI cannot read the full SNI from a single packet.
        """
        try:
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            fragments = fragment_client_hello(first_data, "sni_split")

            for i, fragment in enumerate(fragments):
                await loop.sock_sendall(server_sock, fragment)
                if i < len(fragments) - 1:
                    await asyncio.sleep(0.1)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return True

        except Exception:
            return False
