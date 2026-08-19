"""TLS cipher-suite helpers.

Maps human-readable OpenSSL/IANA cipher suite names (e.g.
``TLS_AES_256_GCM_SHA384``) to their 2-byte registry IDs so a custom
``cipherSuites`` string from the config can be turned into the raw
cipher-suites field of a TLS ClientHello.

The reference format (from the ``tls-repack-frommitm`` outbound used by
@patterniha's xray config) is a colon-separated list of names, e.g.::

    TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:...:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
"""

import logging
import re
import struct
from typing import List, Optional

logger = logging.getLogger("snispf.ciphers")

# IANA TLS cipher-suite registry, id -> canonical name.
CIPHER_SUITE_IDS = {
    # --- TLS 1.3 ---
    "TLS_AES_128_GCM_SHA256": 0x1301,
    "TLS_AES_256_GCM_SHA384": 0x1302,
    "TLS_CHACHA20_POLY1305_SHA256": 0x1303,
    "TLS_AES_128_CCM_SHA256": 0x1304,
    "TLS_AES_128_CCM_8_SHA256": 0x1305,
    # --- TLS 1.2 ECDHE + GCM ---
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256": 0xC02F,
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384": 0xC030,
    # --- TLS 1.2 ECDHE + CHACHA20-POLY1305 ---
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA9,
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA8,
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCAA,
    # --- TLS 1.2 ECDHE + CBC ---
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA": 0xC009,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA": 0xC00A,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA": 0xC013,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA": 0xC014,
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xC023,
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xC024,
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256": 0xC027,
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384": 0xC028,
    # --- TLS 1.2 DHE + GCM / CBC ---
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 0x009E,
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 0x009F,
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA": 0x0033,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA": 0x0039,
    "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": 0x0067,
    "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006B,
    # --- TLS 1.2 RSA + GCM / CBC ---
    "TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
    "TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
    "TLS_RSA_WITH_AES_128_CBC_SHA": 0x002F,
    "TLS_RSA_WITH_AES_256_CBC_SHA": 0x0035,
    "TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
    "TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": 0x000A,
    # --- Special ---
    "TLS_EMPTY_RENEGOTIATION_INFO_SCSV": 0x00FF,
    "TLS_FALLBACK_SCSV": 0x5600,
}

# Reverse lookup: 2-byte id -> canonical name (for diagnostics).
ID_TO_CIPHER_NAME = {v: k for k, v in CIPHER_SUITE_IDS.items()}

# Case-insensitive name lookup (the config value may use any casing).
_CIPHER_SUITE_LOOKUP = {k.lower(): v for k, v in CIPHER_SUITE_IDS.items()}

# IANA names whose OpenSSL cipher-string spelling differs from the naive
# "strip TLS_ / replace _WITH_ and _ with -" transformation.
_IANA_TO_OPENSSL_OVERRIDES = {
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256": "DHE-RSA-CHACHA20-POLY1305",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA": "DES-CBC3-SHA",
}

# IANA TLS 1.3 cipher-suite names.  OpenSSL's ``set_ciphers`` only takes
# TLS-1.2-and-below cipher strings (TLS 1.3 suites live in the separate
# ``ciphersuites`` config, which Python's stdlib ssl cannot set), so these are
# omitted from the OpenSSL cipher-list string.
_TLS13_SUITE_NAMES = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
}


def _iana_to_openssl(name: str) -> Optional[str]:
    """Convert one IANA cipher-suite name to its OpenSSL cipher-string form."""
    if name in _TLS13_SUITE_NAMES:
        return None
    if name in _IANA_TO_OPENSSL_OVERRIDES:
        return _IANA_TO_OPENSSL_OVERRIDES[name]
    s = name[4:]  # strip the "TLS_" prefix
    s = s.replace("_WITH_", "-")
    # OpenSSL drops the CBC marker and merges the AES bit size
    # (AES_256_CBC -> AES256, AES_128_GCM -> AES128-GCM).
    s = re.sub(r"AES_(\d+)_CBC", r"AES\1", s)
    s = re.sub(r"AES_(\d+)_GCM", r"AES\1-GCM", s)
    s = s.replace("_", "-")
    return s


def to_openssl_cipher_string(value) -> Optional[str]:
    """Turn a ``cipherSuites`` config value into an OpenSSL cipher-list string.

    IANA names are mapped to their OpenSSL spellings (the underscore forms are
    not accepted by ``SSLContext.set_ciphers`` on all OpenSSL builds).  TLS 1.3
    suites are omitted — Python's stdlib cannot configure them via
    ``set_ciphers`` — and left to the OpenSSL defaults.

    Returns ``None`` when nothing usable remains (empty / TLS 1.3 only / junk).
    """
    ids = parse_cipher_suite_ids(value)
    if not ids:
        return None
    parts = []
    for cid in ids:
        name = ID_TO_CIPHER_NAME.get(cid)
        if name is None:
            continue
        ossl = _iana_to_openssl(name)
        if ossl:
            parts.append(ossl)
    return ":".join(parts) if parts else None


def parse_cipher_suite_ids(value) -> Optional[List[int]]:
    """Parse a ``cipherSuites`` value into a list of 2-byte cipher-suite IDs.

    Accepts a colon / comma / whitespace separated list of cipher suite names
    (e.g. ``"TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"``)
    or raw 4-hex-digit IDs (e.g. ``"1302:c02f"`` or ``"0x1302,0xc02f"``).
    Returns ``None`` when nothing recognizable is found.
    """
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        tokens = [str(x).strip() for x in value]
    elif isinstance(value, str):
        value = value.strip()
        if not value:
            return None
        # Split on : , or whitespace.
        import re
        tokens = [t for t in re.split(r"[\s:,;]+", value) if t]
    else:
        return None

    ids: List[int] = []
    for tok in tokens:
        low = tok.lower()
        if low in _CIPHER_SUITE_LOOKUP:
            ids.append(_CIPHER_SUITE_LOOKUP[low])
            continue
        # Raw hex id like "1302", "c02f", "0x1302".
        hex_part = low
        if hex_part.startswith("0x"):
            hex_part = hex_part[2:]
        try:
            cid = int(hex_part, 16)
            if 0 < cid <= 0xFFFF:
                ids.append(cid)
                continue
        except ValueError:
            pass
        logger.warning("cipherSuites: unknown cipher suite %r — skipped", tok)

    if not ids:
        return None
    return ids


def build_cipher_suites_field(ids: List[int]) -> bytes:
    """Build the raw TLS cipher-suites field (2-byte length + 2-byte ids)."""
    body = b"".join(struct.pack("!H", cid) for cid in ids)
    return struct.pack("!H", len(body)) + body


def resolve_cipher_suites_field(value) -> Optional[bytes]:
    """Turn a config ``CIPHER_SUITES`` value into a raw ClientHello field.

    Returns ``None`` when ``value`` is empty or unrecognizable, so callers can
    fall back to the built-in default list.
    """
    ids = parse_cipher_suite_ids(value)
    if not ids:
        return None
    return build_cipher_suites_field(ids)
