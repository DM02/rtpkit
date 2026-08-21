"""pcapng file reader — strict and lenient modes.

Supports Section Header Blocks (with per-section byte order), Interface
Description Blocks (for link type and timestamp resolution), Enhanced Packet
Blocks, and Simple Packet Blocks. Unrecognised block types are skipped, as
required by the pcapng spec.
"""

from __future__ import annotations

import logging
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from ..model.errors import PcapngBufferTooShort, PcapngInvalidByteOrderMagic, PcapngMalformedBlock
from ..model.pcap import PcapPacket

__all__ = ["read_pcapng", "read_pcapng_lenient"]

logger = logging.getLogger("rtpkit.io.pcapng")

_BLOCK_HEADER_SIZE = 8  # block type + block total length
_BLOCK_TRAILER_SIZE = 4  # repeated block total length
_MIN_BLOCK_SIZE = _BLOCK_HEADER_SIZE + _BLOCK_TRAILER_SIZE

_SHB_MAGIC = b"\x0a\x0d\x0d\x0a"
_SHB_TYPE = 0x0A0D0D0A
_IDB_TYPE = 0x00000001
_SPB_TYPE = 0x00000003
_EPB_TYPE = 0x00000006

_BOM_BIG_ENDIAN = b"\x1a\x2b\x3c\x4d"
_BOM_LITTLE_ENDIAN = b"\x4d\x3c\x2b\x1a"

_OPT_ENDOFOPT = 0
_OPT_IF_TSRESOL = 9
_DEFAULT_TS_RESOL = 1_000_000  # microseconds, per spec default


@dataclass
class _Interface:
    link_type: int
    ts_resolution: int


def read_pcapng(data: bytes | bytearray | memoryview) -> Iterator[PcapPacket]:
    """Read a pcapng file in strict mode.

    Raises :class:`~rtpkit.model.errors.CaptureError` (or a subclass) on a
    truncated block header, an unrecognised byte-order magic, a block whose
    declared length overruns the buffer, or a malformed block body.
    """
    yield from _read_pcapng(data, strict=True)


def read_pcapng_lenient(data: bytes | bytearray | memoryview) -> Iterator[PcapPacket]:
    """Read a pcapng file in lenient mode.

    A block whose declared length overruns the buffer stops iteration.
    A malformed individual block body (IDB/EPB/SPB) is skipped with a
    warning. Still raises if the file doesn't start with a valid Section
    Header Block, since nothing after it can be interpreted without one.
    """
    yield from _read_pcapng(data, strict=False)


def _read_pcapng(data: bytes | bytearray | memoryview, *, strict: bool) -> Iterator[PcapPacket]:
    if not isinstance(data, memoryview):
        data = memoryview(data)

    buf_len = len(data)
    if buf_len < _MIN_BLOCK_SIZE:
        raise PcapngBufferTooShort(required=_MIN_BLOCK_SIZE, actual=buf_len)

    order: str | None = None
    interfaces: list[_Interface] = []
    offset = 0

    while offset < buf_len:
        remaining = buf_len - offset
        if remaining < _MIN_BLOCK_SIZE:
            if strict:
                raise PcapngBufferTooShort(required=_MIN_BLOCK_SIZE, actual=remaining)
            logger.warning("Trailing %d byte(s) too short for a pcapng block — stopping", remaining)
            return

        raw_type = bytes(data[offset : offset + 4])

        if raw_type == _SHB_MAGIC:
            # remaining >= _MIN_BLOCK_SIZE (12) is already guaranteed above, which is
            # exactly enough to read block type + block total length + byte-order magic.
            bom = bytes(data[offset + 8 : offset + 12])
            if bom == _BOM_BIG_ENDIAN:
                order = ">"
            elif bom == _BOM_LITTLE_ENDIAN:
                order = "<"
            else:
                raise PcapngInvalidByteOrderMagic(bom)
            interfaces = []

        if order is None:
            raise PcapngMalformedBlock("file does not start with a Section Header Block")

        (block_type,) = struct.unpack_from(f"{order}I", data, offset)
        (block_total_length,) = struct.unpack_from(f"{order}I", data, offset + 4)
        block_end = offset + block_total_length

        if block_total_length < _MIN_BLOCK_SIZE or block_end > buf_len:
            if strict:
                raise PcapngMalformedBlock(f"block declares {block_total_length} bytes, unavailable")
            logger.warning("pcapng block declares %d bytes, unavailable — stopping", block_total_length)
            return

        body = data[offset + _BLOCK_HEADER_SIZE : block_end - _BLOCK_TRAILER_SIZE]

        try:
            if block_type == _IDB_TYPE:
                interfaces.append(_parse_idb(body, order))
            elif block_type == _EPB_TYPE:
                packet = _parse_epb(body, order, interfaces)
                yield packet
            elif block_type == _SPB_TYPE:
                yield _parse_spb(body, order, interfaces)
            # SHB and unrecognised block types carry nothing to yield.
        except PcapngMalformedBlock:
            if strict:
                raise
            logger.warning("Skipping malformed pcapng block (type=0x%08x)", block_type)

        offset = block_end


def _iter_options(data: memoryview, order: str) -> Iterator[tuple[int, memoryview]]:
    pos = 0
    while pos + 4 <= len(data):
        (code, length) = struct.unpack_from(f"{order}HH", data, pos)
        pos += 4
        if code == _OPT_ENDOFOPT:
            return
        if pos + length > len(data):
            return
        yield (code, data[pos : pos + length])
        pos += length + ((-length) % 4)


def _parse_if_tsresol(options: memoryview, order: str) -> int:
    for code, value in _iter_options(options, order):
        if code == _OPT_IF_TSRESOL and len(value) >= 1:
            raw: int = value[0]
            result: int = 2 ** (raw & 0x7F) if raw & 0x80 else 10**raw
            return result
    return _DEFAULT_TS_RESOL


def _parse_idb(body: memoryview, order: str) -> _Interface:
    if len(body) < 8:
        raise PcapngMalformedBlock(f"IDB body too short: {len(body)} bytes")
    (link_type, _reserved, _snaplen) = struct.unpack_from(f"{order}HHI", body, 0)
    ts_resolution = _parse_if_tsresol(body[8:], order)
    return _Interface(link_type=link_type, ts_resolution=ts_resolution)


def _parse_epb(body: memoryview, order: str, interfaces: list[_Interface]) -> PcapPacket:
    if len(body) < 20:
        raise PcapngMalformedBlock(f"EPB body too short: {len(body)} bytes")
    (iface_id, ts_high, ts_low, cap_len, orig_len) = struct.unpack_from(f"{order}IIIII", body, 0)
    data_end = 20 + cap_len
    if data_end > len(body):
        raise PcapngMalformedBlock(f"EPB declares {cap_len} captured bytes, only {len(body) - 20} available")
    if iface_id >= len(interfaces):
        raise PcapngMalformedBlock(f"EPB references unknown interface {iface_id}")

    iface = interfaces[iface_id]
    ts_ticks = (ts_high << 32) | ts_low
    return PcapPacket(
        timestamp=ts_ticks / iface.ts_resolution,
        captured_length=cap_len,
        original_length=orig_len,
        link_type=iface.link_type,
        data=body[20:data_end],
    )


def _parse_spb(body: memoryview, order: str, interfaces: list[_Interface]) -> PcapPacket:
    if len(body) < 4:
        raise PcapngMalformedBlock(f"SPB body too short: {len(body)} bytes")
    (orig_len,) = struct.unpack_from(f"{order}I", body, 0)
    # SPB has no explicit captured-length field — anything beyond orig_len in the
    # (4-byte-aligned) body is block padding, not packet data.
    captured_length = min(orig_len, len(body) - 4)
    packet_data = body[4 : 4 + captured_length]
    link_type = interfaces[0].link_type if interfaces else 0
    return PcapPacket(
        timestamp=0.0,
        captured_length=captured_length,
        original_length=orig_len,
        link_type=link_type,
        data=packet_data,
    )
