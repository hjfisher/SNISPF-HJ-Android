"""FinalMask TCP masking.

A faithful Python port of xray-core's ``finalmask`` / ``fragment`` TCP mask
(https://xtls.github.io/en/config/transports/finalmask.html) — the technique
used in @patterniha's ``tls-repack-frommitm`` config.

The mask splits outgoing TCP data into carefully sized fragments (and, for
``"packets": "tlshello"``, re-wraps the TLS ClientHello payload as a series of
smaller TLS records) so DPI devices that fingerprint packet sizes or the TLS
ClientHello shape are fooled.

Config format (``FINALMASK_TCP`` in the config file)::

    [
      {
        "type": "fragment",
        "settings": {
          "packets": "tlshello",           // or a 1-based write range, e.g. "1-3"
          "lengths": ["5", "94", "1"],     // fragment sizes (Int32Range each)
          "delays":  ["0"],                // inter-fragment delays in ms
          "maxSplit": "0"                  // max fragments per packet (0 = unlimited)
        }
      }
    ]

Semantics (mirroring xray):

* ``packets`` selects *which* TCP writes are masked:

  - ``"tlshello"`` — only the very first write, provided it is a TLS handshake
    record (``0x16``).  The record payload is cut into fragments of the given
    ``lengths`` and every piece is re-wrapped in its own TLS record header.
    With all-zero delays the re-wrapped records are concatenated into a single
    TCP write (one packet); otherwise each record is written separately with a
    delay between them.  Bytes after the first record pass through untouched.

  - ``"N-M"`` — the 1st through Mth writes are masked at the byte level.
    Fragments are written as separate TCP writes with the configured delay.

  - ``""`` — every write is masked.

* ``lengths`` / ``delays``: the n-th element applies to the n-th fragment of
  the packet being processed; the last element is reused for all later
  fragments.  A non-final ``0`` length means "skip a round" (idle for that
  delay).

* ``maxSplit``: hard cap on how many fragments one packet may be cut into;
  ``0`` means unlimited.  When the cap is hit, the remainder is sent as a
  single fragment.

When several rules are listed, the *first* is the outermost mask and the last
is the innermost (mirroring xray's ``TcpmaskManager.WrapConnClient``, which
wraps the slice in reverse so the first config ends up outermost); each layer
tracks its own write counter and processes the output of the layer above it.
"""

import asyncio
import copy
import logging
import random
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger("snispf.finalmask")

# Async sink: ``async def sink(chunk: bytes)`` — writes one masked chunk.
Sink = Callable[[bytes], object]


class Int32Range:
    """A ``[from_, to]`` integer range; ``pick()`` returns a random value."""

    __slots__ = ("from_", "to")

    def __init__(self, from_: int, to: int):
        self.from_ = from_
        self.to = to

    def pick(self) -> int:
        if self.to <= self.from_:
            return self.from_
        return random.randint(self.from_, self.to)

    @classmethod
    def parse(cls, value) -> "Int32Range":
        """Parse ``3``, ``3-5``, ``"10-20"`` or an int into a range."""
        if isinstance(value, bool):
            v = int(value)
            return cls(v, v)
        if isinstance(value, (int, float)):
            v = int(value)
            return cls(v, v)
        text = str(value).strip()
        if "-" in text:
            a, b = text.split("-", 1)
            return cls(int(a.strip()), int(b.strip()))
        v = int(text)
        return cls(v, v)


class FragmentLayer:
    """One finalmask ``fragment`` layer (mirrors xray's ``fragmentConn``)."""

    def __init__(self, settings: dict):
        packets = str(settings.get("packets", "")).strip()
        self._tlshello = packets.lower() == "tlshello"

        if self._tlshello:
            self._packets_from, self._packets_to = 1, 1
        elif packets == "":
            # xray: empty packets -> every write is masked.
            self._packets_from, self._packets_to = 0, 0
        else:
            self._packets_from, self._packets_to = self._parse_range(packets)

        self._lengths: List[Int32Range] = [
            Int32Range.parse(x) for x in _as_list(settings.get("lengths", []))
        ]
        self._delays: List[Int32Range] = [
            Int32Range.parse(x) for x in _as_list(settings.get("delays", []))
        ]
        self._max_split = Int32Range.parse(settings.get("maxSplit", "0"))

        if not self._lengths:
            self._lengths = [Int32Range(1, 1)]
        if not self._delays:
            self._delays = [Int32Range(0, 0)]

        # Whether every delay range is exactly zero (-> the "single TCP
        # packet" ClientHello behaviour, mirroring xray's ``DelayMax == 0``).
        self._all_delays_zero = all(r.to == 0 for r in self._delays)

        self.reset()

    def reset(self) -> None:
        """Per-connection write counter (like ``fragmentConn.count``)."""
        self._count = 0

    @staticmethod
    def _parse_range(s: str) -> Tuple[int, int]:
        s = s.strip()
        if "-" in s:
            a, b = s.split("-", 1)
            return int(a), int(b)
        v = int(s)
        return v, v

    def _pick_length(self, i: int) -> int:
        if i < len(self._lengths):
            return self._lengths[i].pick()
        return self._lengths[-1].pick()

    def _pick_delay(self, i: int) -> int:
        if i < len(self._delays):
            return self._delays[i].pick()
        return self._delays[-1].pick()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, chunk: bytes) -> List[Tuple[bytes, int]]:
        """Mask one TCP write.

        Returns a list of ``(data, delay_ms)`` emissions.  ``data`` may be
        empty for "idle" rounds (the delay is still honoured).
        """
        self._count += 1
        if self._tlshello:
            return self._process_tlshello(chunk)
        return self._process_stream(chunk)

    # ------------------------------------------------------------------
    # tlshello mode
    # ------------------------------------------------------------------

    def _process_tlshello(self, p: bytes) -> List[Tuple[bytes, int]]:
        # Only the first write, only if it is a complete TLS handshake record.
        if self._count != 1 or len(p) <= 5 or p[0] != 0x16:
            return [(p, 0)]
        record_len = 5 + ((p[3] << 8) | p[4])
        if len(p) < record_len:
            return [(p, 0)]

        data = p[5:record_len]
        max_split = self._max_split.pick()
        emissions: List[Tuple[bytes, int]] = []
        concat: List[bytes] = []
        split_num = 0
        i = 0
        from_ = 0
        n = len(data)

        while from_ < n:
            length = self._pick_length(i)
            delay = self._pick_delay(i)

            if length <= 0 and i < len(self._lengths) - 1:
                # Idle round: split nothing, wait out the delay.
                if delay > 0:
                    emissions.append((b"", delay))
                i += 1
                continue

            split_num += 1
            to = from_ + length
            if to > n or (max_split > 0 and split_num >= max_split):
                to = n
            l = to - from_

            # Re-wrap this piece as its own TLS record (content type +
            # legacy version from the original record + new 2-byte length).
            record = bytes((p[0], p[1], p[2])) + bytes(((l >> 8) & 0xFF, l & 0xFF))
            record += data[from_:to]
            from_ = to

            if delay == 0 and self._all_delays_zero:
                concat.append(record)
            else:
                emissions.append((record, delay))
            i += 1

        if concat:
            emissions.append((b"".join(concat), 0))

        # Bytes after the first TLS record pass through untouched.
        if len(p) > record_len:
            emissions.append((p[record_len:], 0))

        return emissions or [(p, 0)]

    # ------------------------------------------------------------------
    # stream mode ("N-M" or "")
    # ------------------------------------------------------------------

    def _applies_stream(self) -> bool:
        if self._packets_from == 0 and self._packets_to == 0:
            return True
        return self._packets_from <= self._count <= self._packets_to

    def _process_stream(self, p: bytes) -> List[Tuple[bytes, int]]:
        if not self._applies_stream():
            return [(p, 0)]
        n = len(p)
        if n == 0:
            return [(p, 0)]

        max_split = self._max_split.pick()
        emissions: List[Tuple[bytes, int]] = []
        split_num = 0
        i = 0
        from_ = 0

        while from_ < n:
            length = self._pick_length(i)
            delay = self._pick_delay(i)

            if length <= 0 and i < len(self._lengths) - 1:
                if delay > 0:
                    emissions.append((b"", delay))
                i += 1
                continue

            split_num += 1
            to = from_ + length
            if to > n or (max_split > 0 and split_num >= max_split):
                to = n
            emissions.append((p[from_:to], delay))
            from_ = to
            i += 1

        return emissions


class FinalMasker:
    """Composes ``fragment`` layers and applies them to outgoing TCP writes.

    Layers are listed outermost-first (like xray's ``finalmask.tcp`` array,
    where the first config is the outermost mask).  Data is processed by the
    outermost layer first; each layer's emissions feed the next layer down
    until the innermost layer writes to the socket.
    """

    def __init__(self, layers: List[FragmentLayer]):
        self.layers = layers
        for layer in layers:
            layer.reset()

    @classmethod
    def from_rules(cls, rules) -> Optional["FinalMasker"]:
        """Build a masker from a raw config ``tcp`` array (or ``None``)."""
        if not rules:
            return None
        layers: List[FragmentLayer] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            if str(rule.get("type", "")).strip().lower() != "fragment":
                logger.warning(
                    "finalmask: unsupported mask type %r — skipped",
                    rule.get("type"),
                )
                continue
            settings = rule.get("settings") or {}
            try:
                layers.append(FragmentLayer(settings))
            except (TypeError, ValueError) as exc:
                logger.warning(
                    "finalmask: invalid fragment settings %r: %s", settings, exc
                )
        if not layers:
            return None
        return cls(layers)

    def clone(self) -> "FinalMasker":
        """Return a per-connection copy with fresh per-layer counters."""
        new = copy.deepcopy(self)
        for layer in new.layers:
            layer.reset()
        return new

    async def send(self, sink: Sink, data: bytes) -> None:
        """Send ``data`` through the mask layers.

        ``sink`` is an async callable that writes one (already-masked) chunk to
        the underlying connection, e.g. ``lambda d: loop.sock_sendall(sock, d)``.
        """
        await self._send_through(self.layers, sink, data)

    async def _send_through(self, layers: List[FragmentLayer], sink: Sink, data: bytes):
        if not layers:
            await sink(data)
            return
        # Outermost layer (first in the config list) processes first.
        outer = layers[0]
        for chunk, delay_ms in outer.process(data):
            if chunk:
                await self._send_through(layers[1:], sink, chunk)
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)


def _as_list(value) -> List:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    # A single value or a string of comma/space separated values.
    if isinstance(value, str):
        parts = [x.strip() for x in value.replace(",", " ").split() if x.strip()]
        return parts
    return [value]