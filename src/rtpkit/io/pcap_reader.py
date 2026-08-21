"""Classic (libpcap) .pcap file reader — strict and lenient modes."""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator

from ..model.errors import PcapBufferTooShort, PcapInvalidMagic, PcapTruncatedRecord
from ..model.pcap import PcapPacket

__all__ = ["read_pcap", "read_pcap_lenient"]

logger = logging.getLogger("rtpkit.io.pcap")

_GLOBAL_HEADER_SIZE = 24
_RECORD_HEADER_SIZE = 16

# magic bytes -> (byte order, fractional-second divisor)
_MAGIC_TABLE: dict[bytes, tuple[str, int]] = {
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
}


def read_pcap(data: bytes | bytearray | memoryview) -> Iterator[PcapPacket]:
    """Read a classic .pcap file in strict mode.

    Raises :class:`~rtpkit.model.errors.CaptureError` (or a subclass) on an
    unrecognised magic number or a truncated global/record header.
    """
    yield from _read_pcap(data, strict=True)


def read_pcap_lenient(data: bytes | bytearray | memoryview) -> Iterator[PcapPacket]:
    """Read a classic .pcap file in lenient mode.

    Still raises on an unrecognised magic number or a global header too
    short to read at all; a truncated trailing record stops iteration
    instead of raising, yielding whatever records were read so far.
    """
    yield from _read_pcap(data, strict=False)


def _read_pcap(data: bytes | bytearray | memoryview, *, strict: bool) -> Iterator[PcapPacket]:
    if not isinstance(data, memoryview):
        data = memoryview(data)

    buf_len = len(data)
    if buf_len < _GLOBAL_HEADER_SIZE:
        raise PcapBufferTooShort(required=_GLOBAL_HEADER_SIZE, actual=buf_len)

    magic = bytes(data[0:4])
    info = _MAGIC_TABLE.get(magic)
    if info is None:
        raise PcapInvalidMagic(magic)
    order, ts_divisor = info

    (link_type,) = struct.unpack_from(f"{order}I", data, 20)

    offset = _GLOBAL_HEADER_SIZE
    while offset < buf_len:
        remaining = buf_len - offset
        if remaining < _RECORD_HEADER_SIZE:
            if strict:
                raise PcapBufferTooShort(required=_RECORD_HEADER_SIZE, actual=remaining)
            logger.warning("Trailing %d byte(s) too short for a pcap record header — stopping", remaining)
            return

        (ts_sec, ts_frac, incl_len, orig_len) = struct.unpack_from(f"{order}IIII", data, offset)
        record_start = offset + _RECORD_HEADER_SIZE
        record_end = record_start + incl_len

        if record_end > buf_len:
            if strict:
                raise PcapTruncatedRecord(declared=incl_len, available=buf_len - record_start)
            logger.warning(
                "pcap record declares %d captured bytes, only %d available — stopping",
                incl_len,
                buf_len - record_start,
            )
            return

        yield PcapPacket(
            timestamp=ts_sec + ts_frac / ts_divisor,
            captured_length=incl_len,
            original_length=orig_len,
            link_type=link_type,
            data=data[record_start:record_end],
        )
        offset = record_end
