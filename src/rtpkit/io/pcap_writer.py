"""Classic (libpcap) .pcap file writer — the inverse of pcap_reader.read_pcap.

Always writes little-endian, microsecond-resolution records (the common
default virtually every tool reads) regardless of what the source capture
used — round-tripping through read_pcap -> write_pcap can change the file's
byte order and sub-microsecond timestamp precision, never the packet data.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

from ..model.errors import PcapWriteError
from ..model.pcap import PcapPacket

__all__ = ["write_pcap"]

_MAGIC_LE_US = b"\xd4\xc3\xb2\xa1"


def write_pcap(packets: Iterable[PcapPacket], *, link_type: int | None = None) -> bytes:
    """Serialize *packets* as a classic .pcap file.

    Classic pcap has one global link type per file, unlike pcapng. If
    *link_type* isn't given, it's taken from the first packet, and every
    packet must share it — raises :class:`~rtpkit.model.errors.PcapWriteError`
    on a mismatch, since silently relabeling a packet's link type would
    make every downstream reader misinterpret its bytes. Pass *link_type*
    explicitly to write an empty file, or to force it deliberately.
    """
    packets = list(packets)

    if link_type is None:
        if not packets:
            raise PcapWriteError("link_type is required to write an empty pcap file")
        link_type = packets[0].link_type

    for i, pkt in enumerate(packets):
        if pkt.link_type != link_type:
            raise PcapWriteError(
                f"packet {i} has link_type {pkt.link_type}, expected {link_type} "
                "(classic pcap has one global link type per file — use write_pcapng for mixed link types)"
            )

    parts = [_MAGIC_LE_US + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, link_type)]
    for pkt in packets:
        data = bytes(pkt.data)
        ts_sec, ts_usec = _split_timestamp(pkt.timestamp)
        parts.append(struct.pack("<IIII", ts_sec, ts_usec, len(data), pkt.original_length))
        parts.append(data)

    return b"".join(parts)


def _split_timestamp(timestamp: float) -> tuple[int, int]:
    ts_sec = int(timestamp)
    ts_usec = round((timestamp - ts_sec) * 1_000_000)
    if ts_usec >= 1_000_000:
        ts_sec += 1
        ts_usec -= 1_000_000
    return ts_sec, ts_usec
