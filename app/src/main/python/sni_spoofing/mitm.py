"""TLS-terminating MITM relay mode (tls-decrypt / tls-repack).

Implements the "new mode" idea from @patterniha's xray config — the tool
builds its own SSL (auto-generated self-signed certificate), terminates the
client's TLS session, and re-encrypts with a fresh, fingerprint-clean TLS
connection to the real upstream.

Flow::

    client app ──TLS──► 127.0.0.1:LISTEN_PORT   (self-signed cert, SHA-256 pinned)
                         │  (decrypt: inner VLESS/Trojan/SS stream is now plaintext)
                         ▼
                    CONNECT_IP:CONNECT_PORT  ──new TLS ClientHello──► real server
                         │  (fake SNI + custom cipherSuites + ALPN + FINALMASK)
                         ▼
                    bidirectional relay

Only TCP is supported.  The inner protocol is never parsed — bytes are relayed
verbatim (like the ``tunnel`` inbound in the reference config).
"""

import asyncio
import logging
import ssl
from typing import List, Optional

from .finalmask import FinalMasker
from .tls.ciphers import to_openssl_cipher_string

logger = logging.getLogger("snispf.mitm")

BUFFER_SIZE = 65535


def _apply_upstream_ciphers(ctx: ssl.SSLContext, cipher_suites: Optional[str]) -> None:
    """Configure ``set_ciphers`` from a xray ``cipherSuites`` string.

    IANA names are translated to OpenSSL spellings; TLS 1.3 suites cannot be
    set via Python's stdlib ``set_ciphers`` and are left to OpenSSL defaults.
    """
    ossl = to_openssl_cipher_string(cipher_suites) if cipher_suites else None
    if not ossl:
        return
    try:
        ctx.set_ciphers(ossl)
    except ssl.SSLError as exc:
        logger.warning(
            "Upstream cipherSuites rejected by OpenSSL (%s) — using defaults",
            exc,
        )


async def handle_mitm_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    cipher_suites: Optional[str],
    alpn: List[str],
    masker_template: Optional[FinalMasker],
    use_client_sni: bool = False,
    conn_manager=None,
) -> None:
    """Handle one client connection in MITM mode.

    The incoming ``(reader, writer)`` pair is the *decrypted* stream (the
    ``asyncio.start_server(..., ssl=...)`` handshake has already terminated
    the client's TLS session).

    When a ``conn_manager`` (ConnectionManager) is supplied, the upstream
    (IP, SNI) pair is picked dynamically from the pool and real-traffic
    success/failure is reported back — exactly like the standard forward
    mode — so degraded upstreams are avoided and evicted.
    """
    loop = asyncio.get_running_loop()
    peer = writer.get_extra_info("peername")

    # ── Pool integration: pick the best (IP, SNI) pair ──────────────────
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
        if pair is None:
            return
        with pair.lock:
            pair.active_connections = max(0, pair.active_connections - 1)
        if failed:
            pair.record_real_packet(lost=True)
            conn_manager.report_failure(pair)

    # ── Capture the client's SNI / ALPN so we can forward them upstream
    #    (mirrors xray's ``fromMitM`` serverName/alpn substitution).
    #    ``SSLSocket.server_hostname`` is empty on the server side on some
    #    platforms, so the SNI comes from the ``sni_callback`` we registered.
    client_sni = None
    client_alpn = None
    try:
        sslobj = writer.get_extra_info("ssl_object")
        if sslobj is not None:
            client_sni = (
                getattr(sslobj, "_snispf_sni", None)
                or getattr(sslobj, "server_hostname", None)
            )
            client_alpn = sslobj.selected_alpn_protocol()
    except Exception:
        pass

    # Feed the client's real SNI back to the pool so IP-only pools can
    # probe the IPs against it (the decoy SNI is never sent upstream).
    if conn_manager is not None:
        conn_manager.note_client_sni(client_sni)

    # ── Upstream TLS context (fresh ClientHello: fake SNI + cipherSuites) ──
    up_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    up_ctx.check_hostname = False
    up_ctx.verify_mode = ssl.CERT_NONE
    _apply_upstream_ciphers(up_ctx, cipher_suites)
    # The upstream ALPN must mirror exactly what the client negotiated.
    # Offering "h2" as well makes Cloudflare pick h2, but a VLESS+WS client
    # that negotiated http/1.1 sends an HTTP/1.1 request — protocol mismatch
    # and the WebSocket upgrade never completes (verified against the real
    # Cloudflare edge: [h2, http/1.1] -> h2 + broken WS; [http/1.1] -> 101).
    up_alpn = list(alpn)
    if client_alpn:
        up_alpn = [client_alpn]
    if up_alpn:
        try:
            up_ctx.set_alpn_protocols(up_alpn)
        except (NotImplementedError, ssl.SSLError) as exc:
            logger.debug("set_alpn_protocols unavailable: %s", exc)

    server_hostname = active_sni
    if use_client_sni and client_sni:
        server_hostname = client_sni

    # ── Connect to the real upstream and complete TLS ──────────────────────
    up_reader = up_writer = None
    try:
        up_reader, up_writer = await asyncio.open_connection(
            active_ip,
            connect_port,
            ssl=up_ctx,
            server_hostname=server_hostname,
            limit=BUFFER_SIZE,
        )
    except Exception as exc:
        logger.debug(
            "[%s] upstream connect %s:%s failed: %s",
            peer, active_ip, connect_port, exc,
        )
        _release_pair(failed=True)
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return

    logger.info(
        "[%s] MITM relay: client=%s sni=%s alpn=%s -> %s:%s sni=%s cipherSuites=%s%s",
        peer, peer, client_sni, client_alpn,
        active_ip, connect_port, server_hostname,
        cipher_suites or "default",
        " | pool_loss=%.1f%%" % (pair.combined_loss_rate * 100) if pair else "",
    )

    masker = masker_template.clone() if masker_template is not None else None
    done = asyncio.Event()
    server_responded = False

    async def _mask_sink(chunk: bytes) -> None:
        up_writer.write(chunk)
        await up_writer.drain()

    async def _c2s() -> None:
        try:
            while True:
                data = await reader.read(BUFFER_SIZE)
                if not data:
                    break
                if masker is not None:
                    await masker.send(_mask_sink, data)
                else:
                    up_writer.write(data)
                    await up_writer.drain()
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            done.set()

    async def _s2c() -> None:
        nonlocal server_responded
        try:
            while True:
                data = await up_reader.read(BUFFER_SIZE)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
                if not server_responded:
                    server_responded = True
                    if pair is not None:
                        pair.record_real_packet(lost=False)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            done.set()

    # Watcher: closes the connection when the pool drains/evicts this pair.
    async def _drain_watcher():
        if pair is None:
            return
        ev = pair.force_close_event
        while not done.is_set():
            if ev.is_set():
                logger.debug(
                    "Drain timeout reached for %s / %s — closing MITM relay "
                    "from %s", pair.ip, pair.sni, peer,
                )
                try:
                    writer.close()
                except Exception:
                    pass
                try:
                    up_writer.close()
                except Exception:
                    pass
                done.set()
                return
            await asyncio.sleep(0.5)

    c2s = loop.create_task(_c2s())
    s2c = loop.create_task(_s2c())
    watcher = loop.create_task(_drain_watcher())
    await done.wait()
    c2s.cancel()
    s2c.cancel()
    watcher.cancel()
    await asyncio.gather(c2s, s2c, watcher, return_exceptions=True)

    # If the upstream never replied, record the pair as failed.
    if not server_responded:
        _release_pair(failed=True)
    else:
        _release_pair(failed=False)

    for w in (up_writer, writer):
        try:
            w.close()
            await w.wait_closed()
        except Exception:
            pass


async def start_mitm_server(
    listen_host: str,
    listen_port: int,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    cipher_suites: Optional[str],
    alpn: List[str],
    masker_rules,
    cert_file: str,
    key_file: str,
    use_client_sni: bool = False,
    conn_manager=None,
) -> None:
    """Start the MITM relay server (TLS-terminating inbound).

    When ``conn_manager`` is supplied, each connection picks its upstream
    (IP, SNI) from the pool instead of the static ``connect_ip``/``fake_sni``.
    """
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert_file, key_file)
    # Offer the configured ALPN on the *server* side too, so clients that
    # require a negotiated protocol (e.g. VLESS+WS with alpn=http/1.1) get it.
    if alpn:
        try:
            server_ctx.set_alpn_protocols(alpn)
        except (NotImplementedError, ssl.SSLError) as exc:
            logger.debug("set_alpn_protocols unavailable: %s", exc)
    # ``SSLSocket.server_hostname`` is not populated server-side on all
    # platforms, so capture the client's SNI via the handshake callback.
    try:
        def _sni_callback(sslsocket, server_name, initial_context):
            if server_name:
                sslsocket._snispf_sni = server_name
        server_ctx.sni_callback = _sni_callback
    except (AttributeError, NotImplementedError):  # pragma: no cover
        pass

    masker_template = FinalMasker.from_rules(masker_rules) if masker_rules else None

    async def _handler(reader, writer):
        await handle_mitm_connection(
            reader,
            writer,
            connect_ip=connect_ip,
            connect_port=connect_port,
            fake_sni=fake_sni,
            cipher_suites=cipher_suites,
            alpn=alpn,
            masker_template=masker_template,
            use_client_sni=use_client_sni,
            conn_manager=conn_manager,
        )

    server = await asyncio.start_server(
        _handler, listen_host, listen_port, ssl=server_ctx
    )

    logger.info("=" * 60)
    logger.info("MITM mode (tls-decrypt / tls-repack) active")
    logger.info("Listening on %s:%d (TLS terminated with self-signed cert)",
                listen_host, listen_port)
    if conn_manager is not None:
        logger.info(
            "Upstream selection: POOL (%d pair(s), %d active slot(s))",
            len(conn_manager.explorer.stats), conn_manager.pool.slots,
        )
    else:
        logger.info("Upstream: %s:%d  SNI: %s", connect_ip, connect_port, fake_sni)
    logger.info("Upstream cipherSuites: %s", cipher_suites or "default")
    logger.info("FinalMask TCP: %s",
                "ENABLED (%d layer(s))" % len(masker_template.layers)
                if masker_template else "disabled")
    logger.info("Client ALPN: %s", alpn)
    logger.info("=" * 60)

    async with server:
        await server.serve_forever()