"""pcapng file writer — the inverse of pcapng_reader.read_pcapng.

Unlike classic pcap, pcapng supports multiple link types in one file: an
Interface Description Block is emitted for each distinct link_type seen
(in first-appearance order), and every Enhanced Packet Block references
the right one. Always writes little-endian, microsecond resolution,
one section, no options beyond what a block requires structurally.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

from ..model.pcap import PcapPacket

__all__ = ["write_pcapng"]

_SHB_TYPE = 0x0A0D0D0A
_IDB_TYPE = 0x00000001
_EPB_TYPE = 0x00000006
_BOM_LITTLE_ENDIAN = b"\x4d\x3c\x2b\x1a"


def write_pcapng(packets: Iterable[PcapPacket]) -> bytes:
    """Serialize *packets* as a pcapng file."""
    packets = list(packets)

    interfaces: dict[int, int] = {}
    for pkt in packets:
        if pkt.link_type not in interfaces:
            interfaces[pkt.link_type] = len(interfaces)

    parts = [_build_shb()]
    for link_type in interfaces:
        parts.append(_build_idb(link_type))
    for pkt in packets:
        parts.append(_build_epb(interfaces[pkt.link_type], pkt))

    return b"".join(parts)


def _wrap_block(block_type: int, body: bytes) -> bytes:
    padded_body = body + b"\x00" * ((-len(body)) % 4)
    total_len = 8 + len(padded_body) + 4
    return struct.pack("<II", block_type, total_len) + padded_body + struct.pack("<I", total_len)


def _build_shb() -> bytes:
    body = _BOM_LITTLE_ENDIAN + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    return _wrap_block(_SHB_TYPE, body)


def _build_idb(link_type: int) -> bytes:
    body = struct.pack("<HHI", link_type, 0, 262144)
    return _wrap_block(_IDB_TYPE, body)


def _build_epb(iface_id: int, pkt: PcapPacket) -> bytes:
    data = bytes(pkt.data)
    ts_ticks = round(pkt.timestamp * 1_000_000)
    ts_high = (ts_ticks >> 32) & 0xFFFFFFFF
    ts_low = ts_ticks & 0xFFFFFFFF
    body = struct.pack("<IIIII", iface_id, ts_high, ts_low, len(data), pkt.original_length) + data
    return _wrap_block(_EPB_TYPE, body)
