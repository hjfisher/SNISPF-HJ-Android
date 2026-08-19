"""Self-signed X.509 certificate generation.

Lets the tool "build its own SSL" — generate the keypair and self-signed
certificate it presents to clients, so the operator does not have to paste a
pre-made cert/key into the config (the ``buildChain: true`` + embedded cert
idea from @patterniha's xray config).

Backends, tried in order:

1. ``cryptography`` (if installed) — preferred.
2. ``openssl`` CLI (if available).
3. Pure-Python RSA + X.509 encoder (always available, no dependencies).

The certificate's SHA-256 fingerprint is returned so the client app can pin it
(``pinnedPeerCertSha256``).
"""

import base64
import hashlib
import logging
import os
import random
import shutil
import subprocess
import tempfile
import time
from typing import Optional, Tuple

logger = logging.getLogger("snispf.certs")

# OIDs used while building the certificate.
OID_CN = (2, 5, 4, 3)
OID_O = (2, 5, 4, 10)
OID_C = (2, 5, 4, 6)
OID_RSA_ENCRYPTION = (1, 2, 840, 113549, 1, 1, 1)
OID_SHA256_WITH_RSA = (1, 2, 840, 113549, 1, 1, 11)
OID_SHA256 = (2, 16, 840, 1, 101, 3, 4, 2, 1)
OID_BASIC_CONSTRAINTS = (2, 5, 29, 19)
OID_KEY_USAGE = (2, 5, 29, 15)
OID_SUBJECT_KEY_ID = (2, 5, 29, 14)
OID_SUBJECT_ALT_NAME = (2, 5, 29, 17)


# ---------------------------------------------------------------------------
# Pure-Python backend
# ---------------------------------------------------------------------------

def _int_to_bytes(n: int, length: Optional[int] = None) -> bytes:
    b = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if length is not None and len(b) < length:
        b = b"\x00" * (length - len(b)) + b
    return b


def _is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if _is_probable_prime(n):
            return n


def _egcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _egcd(b % a, a)
    return g, y - (b // a) * x, x


def _modinv(a: int, m: int) -> int:
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("no modular inverse")
    return x % m


def _generate_rsa_key(bits: int = 2048) -> dict:
    e = 65537
    while True:
        p = _gen_prime(bits // 2)
        q = _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        try:
            d = _modinv(e, (p - 1) * (q - 1))
        except ValueError:
            continue
        return {
            "n": n, "e": e, "d": d, "p": p, "q": q,
            "dp": d % (p - 1), "dq": d % (q - 1),
            "qinv": _modinv(q % p, p),
        }


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    b = _int_to_bytes(n)
    return bytes((0x80 | len(b),)) + b


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(content)) + content


def _der_int(n: int) -> bytes:
    b = _int_to_bytes(n)
    if b[0] & 0x80:
        b = b"\x00" + b
    return _der_tlv(0x02, b)


def _der_octet_string(b: bytes) -> bytes:
    return _der_tlv(0x04, b)


def _der_bit_string(b: bytes) -> bytes:
    return _der_tlv(0x03, b"\x00" + b)


def _der_sequence(*parts: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(parts))


def _der_set(*parts: bytes) -> bytes:
    return _der_tlv(0x31, b"".join(parts))


def _der_oid(oid) -> bytes:
    def enc_one(v: int) -> bytes:
        if v == 0:
            return b"\x00"
        chunks = []
        while v:
            chunks.append(v % 128)
            v //= 128
        out = bytearray()
        for i, c in enumerate(reversed(chunks)):
            out.append(c | 0x80 if i != len(chunks) - 1 else c)
        return bytes(out)

    body = enc_one(40 * oid[0] + oid[1]) + b"".join(enc_one(x) for x in oid[2:])
    return _der_tlv(0x06, body)


def _der_name(rdns) -> bytes:
    parts = []
    for oid, val in rdns:
        attr = _der_sequence(
            _der_oid(oid), _der_tlv(0x0C, val.encode("utf-8"))
        )
        parts.append(_der_set(attr))
    return _der_sequence(*parts)


def _asn1_time(ts: int) -> bytes:
    t = time.gmtime(ts)
    if t.tm_year < 2050:
        return time.strftime("%y%m%d%H%M%SZ", t).encode("ascii")
    return time.strftime("%Y%m%d%H%M%SZ", t).encode("ascii")


def _rsa_public_key_der(key: dict) -> bytes:
    algo = _der_sequence(_der_oid(OID_RSA_ENCRYPTION), b"\x05\x00")
    rsapub = _der_sequence(_der_int(key["n"]), _der_int(key["e"]))
    return _der_sequence(algo, _der_bit_string(rsapub))


def _rsa_private_key_der(key: dict) -> bytes:
    return _der_sequence(
        _der_int(0),
        _der_int(key["n"]),
        _der_int(key["e"]),
        _der_int(key["d"]),
        _der_int(key["p"]),
        _der_int(key["q"]),
        _der_int(key["dp"]),
        _der_int(key["dq"]),
        _der_int(key["qinv"]),
    )


def _rsa_pkcs1_v15_sign(key: dict, digest: bytes) -> bytes:
    di = _der_sequence(
        _der_sequence(_der_oid(OID_SHA256), b"\x05\x00"),
        _der_octet_string(digest),
    )
    k = (key["n"].bit_length() + 7) // 8
    em = b"\x00\x01" + b"\xff" * (k - len(di) - 3) + b"\x00" + di
    m = int.from_bytes(em, "big")
    return _int_to_bytes(pow(m, key["d"], key["n"]), k)


def _build_tbs_cert_der(key: dict, cn: str, serial: int, not_before: int,
                        not_after: int) -> bytes:
    name = _der_name([
        (OID_C, "IR"),
        (OID_O, "SNISPF-HJ"),
        (OID_CN, cn),
    ])
    spki = _rsa_public_key_der(key)

    basic_constraints = _der_sequence(
        _der_oid(OID_BASIC_CONSTRAINTS),
        _der_octet_string(_der_sequence(_der_tlv(0x01, b"\xff"))),  # CA: TRUE
    )
    key_usage = _der_sequence(
        _der_oid(OID_KEY_USAGE),
        _der_octet_string(_der_bit_string(b"\xa4")),  # digitalSig|keyEnc|keyCertSign
    )
    subject_key_id = _der_sequence(
        _der_oid(OID_SUBJECT_KEY_ID),
        _der_octet_string(_der_octet_string(hashlib.sha1(spki).digest())),
    )
    san = _der_sequence(
        _der_oid(OID_SUBJECT_ALT_NAME),
        _der_octet_string(_der_sequence(
            _der_tlv(0x82, cn.encode("ascii")),
            _der_tlv(0x82, b"localhost"),
            _der_tlv(0x87, bytes((127, 0, 0, 1))),
        )),
    )
    extensions = _der_sequence(
        basic_constraints,
        key_usage,
        subject_key_id,
        san,
    )

    return _der_sequence(
        _der_tlv(0xA0, _der_int(2)),  # version v3
        _der_int(serial),
        _der_sequence(_der_oid(OID_SHA256_WITH_RSA), b"\x05\x00"),
        name,
        _der_sequence(
            _der_tlv(0x17, _asn1_time(not_before)),
            _der_tlv(0x17, _asn1_time(not_after)),
        ),
        name,
        spki,
        _der_tlv(0xA3, extensions),  # extensions [3]
    )


def _pem(kind: bytes, der: bytes) -> bytes:
    b64 = base64.b64encode(der)
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return (b"-----BEGIN " + kind + b"-----\n" + b"\n".join(lines)
            + b"\n-----END " + kind + b"-----\n")


def _generate_pure_python(cn: str, bits: int = 2048):
    key = _generate_rsa_key(bits)
    serial = random.getrandbits(63) | 1
    now = int(time.time())
    tbs = _build_tbs_cert_der(key, cn, serial, now, now + 3650 * 86400)
    sig = _rsa_pkcs1_v15_sign(key, hashlib.sha256(tbs).digest())
    cert_der = _der_sequence(
        tbs,
        _der_sequence(_der_oid(OID_SHA256_WITH_RSA), b"\x05\x00"),
        _der_bit_string(sig),
    )
    return _pem(b"CERTIFICATE", cert_der), _pem(b"RSA PRIVATE KEY",
                                                _rsa_private_key_der(key))


# ---------------------------------------------------------------------------
# Preferred backends
# ---------------------------------------------------------------------------

def _generate_with_cryptography(cn: str):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SNISPF-HJ"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])
    now = time.time()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(random.getrandbits(63) | 1)
        .not_valid_before(_dt_from(now))
        .not_valid_after(_dt_from(now + 3650 * 86400))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=True,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName(cn), x509.DNSName("localhost"),
            x509.IPAddress(_ip(127, 0, 0, 1)),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def _dt_from(ts: float):
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)


def _ip(a, b, c, d):
    from ipaddress import ip_address
    return ip_address(f"{a}.{b}.{c}.{d}")


def _generate_with_openssl(cn: str):
    if not shutil.which("openssl"):
        return None
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        cert_path = os.path.join(d, "cert.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", key_path, "-out", cert_path,
                "-days", "3650", "-nodes", "-sha256",
                "-subj", f"/C=IR/O=SNISPF-HJ/CN={cn}",
            ],
            check=True, capture_output=True, timeout=120,
        )
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        with open(key_path, "rb") as f:
            key_pem = f.read()
        return cert_pem, key_pem


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_self_signed(cn: str = "SNISPF-HJ") -> Tuple[bytes, bytes]:
    """Generate a (cert_pem, key_pem) pair, trying backends in order."""
    try:
        return _generate_with_cryptography(cn)
    except Exception as exc:  # pragma: no cover
        logger.debug("cryptography backend failed: %s", exc)
    try:
        out = _generate_with_openssl(cn)
        if out:
            return out
    except Exception as exc:  # pragma: no cover
        logger.debug("openssl backend failed: %s", exc)
    return _generate_pure_python(cn)


def der_fingerprint(cert_pem: bytes) -> str:
    """SHA-256 (hex) of the DER certificate — the value to pin."""
    der = _pem_to_der(cert_pem)
    return hashlib.sha256(der).hexdigest()


def _pem_to_der(pem: bytes) -> bytes:
    body = b"".join(
        line for line in pem.splitlines()
        if line and not line.startswith(b"-----")
    )
    return base64.b64decode(body)


def load_or_create(cert_file: Optional[str] = None,
                   key_file: Optional[str] = None,
                   cn: str = "SNISPF-HJ") -> Tuple[str, str, str]:
    """Return ``(cert_path, key_path, sha256_fingerprint)``.

    If both ``cert_file`` and ``key_file`` exist they are reused (stable
    fingerprint across restarts — good for pinning).  Otherwise a fresh
    self-signed pair is generated and cached under ``~/.snispf/``.
    """
    if cert_file and key_file and os.path.isfile(cert_file) and os.path.isfile(key_file):
        with open(cert_file, "rb") as f:
            cert_pem = f.read()
        return cert_file, key_file, der_fingerprint(cert_pem)

    cache_dir = os.path.join(os.path.expanduser("~"), ".snispf")
    os.makedirs(cache_dir, exist_ok=True)
    cert_path = cert_file or os.path.join(cache_dir, "snispf-cert.pem")
    key_path = key_file or os.path.join(cache_dir, "snispf-key.pem")

    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        with open(cert_path, "rb") as f:
            cert_pem = f.read()
        return cert_path, key_path, der_fingerprint(cert_pem)

    cert_pem, key_pem = generate_self_signed(cn)
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)
    logger.info("Generated self-signed certificate -> %s", cert_path)
    return cert_path, key_path, der_fingerprint(cert_pem)