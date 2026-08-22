"""G.711 (PCMU/PCMA) codec — decode/encode between RTP payload bytes and 16-bit PCM.

Pure Python, zero dependencies. G.711 is simple enough (a per-sample lookup,
not a real transform codec) that this is practical, unlike Opus/G.729/etc.,
which need an actual decoder library and are out of scope for this project.

Decode tables are the canonical ITU-T/Sun reference algorithm (bit-identical
to CPython's now-deprecated ``audioop.ulaw2lin``/``alaw2lin`` for all 256
byte values — verified during development, not re-checked at import time).
Encoding is nearest-neighbour quantization against those same decode
tables, rather than a separately-derived compression formula, so encode and
decode can never disagree with each other by construction — and, as a
side effect, matches but occasionally slightly *beats* audioop's classic
segment-formula encoder at segment boundaries, where its fast bit-shift
approximation isn't quite the true nearest code.

Output/input PCM is 16-bit signed, little-endian, mono, one sample per
RTP byte (G.711's fixed 8000 Hz sample rate — matches ``PCMU``/``PCMA`` in
:data:`rtpkit.lookup_payload_type`).
"""

from __future__ import annotations

import array
import bisect
import sys

__all__ = ["decode_pcmu", "encode_pcmu", "decode_pcma", "encode_pcma"]

_BIAS = 0x84


def _ulaw_decode_byte(u_val: int) -> int:
    u_val = ~u_val & 0xFF
    sign = u_val & 0x80
    exponent = (u_val >> 4) & 0x07
    mantissa = u_val & 0x0F
    magnitude = ((mantissa << 3) + _BIAS) << exponent
    sample = magnitude - _BIAS
    return -sample if sign else sample


def _alaw_decode_byte(a_val: int) -> int:
    a_val ^= 0x55
    t = (a_val & 0x0F) << 4
    seg = (a_val & 0x70) >> 4
    if seg == 0:
        t += 8
    elif seg == 1:
        t += 0x108
    else:
        t += 0x108
        t <<= seg - 1
    return t if (a_val & 0x80) else -t


def _build_encode_lut(decode_table: tuple[int, ...]) -> bytes:
    codes_by_value = sorted(range(256), key=lambda code: decode_table[code])
    sorted_values = [decode_table[code] for code in codes_by_value]

    lut = bytearray(65536)
    for sample in range(-32768, 32768):
        idx = bisect.bisect_left(sorted_values, sample)
        if idx == 0:
            nearest = 0
        elif idx == len(sorted_values):
            nearest = len(sorted_values) - 1
        elif sample - sorted_values[idx - 1] <= sorted_values[idx] - sample:
            nearest = idx - 1
        else:
            nearest = idx
        lut[sample + 32768] = codes_by_value[nearest]
    return bytes(lut)


_ULAW_DECODE = tuple(_ulaw_decode_byte(b) for b in range(256))
_ALAW_DECODE = tuple(_alaw_decode_byte(b) for b in range(256))
_ULAW_ENCODE = _build_encode_lut(_ULAW_DECODE)
_ALAW_ENCODE = _build_encode_lut(_ALAW_DECODE)


def _decode(data: bytes, table: tuple[int, ...]) -> bytes:
    samples = array.array("h", (table[b] for b in data))
    if sys.byteorder == "big":
        samples.byteswap()
    return samples.tobytes()


def _encode(pcm16le: bytes, lut: bytes) -> bytes:
    samples = array.array("h")
    samples.frombytes(pcm16le)
    if sys.byteorder == "big":
        samples.byteswap()
    return bytes(lut[sample + 32768] for sample in samples)


def decode_pcmu(data: bytes) -> bytes:
    """Decode μ-law (PCMU, RFC 3551 payload type 0) bytes to 16-bit signed LE PCM."""
    return _decode(data, _ULAW_DECODE)


def encode_pcmu(pcm16le: bytes) -> bytes:
    """Encode 16-bit signed LE PCM to μ-law (PCMU) bytes."""
    return _encode(pcm16le, _ULAW_ENCODE)


def decode_pcma(data: bytes) -> bytes:
    """Decode A-law (PCMA, RFC 3551 payload type 8) bytes to 16-bit signed LE PCM."""
    return _decode(data, _ALAW_DECODE)


def encode_pcma(pcm16le: bytes) -> bytes:
    """Encode 16-bit signed LE PCM to A-law (PCMA) bytes."""
    return _encode(pcm16le, _ALAW_ENCODE)
