"""Serialize RTCP packet models back to bytes — the inverse of parser.rtcp_parser.parse_rtcp.

Unlike RTP (one packet, several interacting optional fields — CSRC,
extension, padding — best modelled as a fluent builder), RTCP's complexity
is having five distinct packet shapes rather than one packet with many
options. The model dataclasses (SenderReport, ReportBlock, ...) already
carry every field needed, so there's nothing a fluent API would add over
just constructing them directly — build_rtcp only needs to serialize
already-built dataclasses to wire bytes, mirroring write_pcap's
"sequence of model objects -> bytes" shape rather than RtpBuilder's.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

from ..model.errors import RtcpBuildError
from ..model.rtcp import (
    ApplicationDefined,
    Goodbye,
    ReceiverReport,
    ReportBlock,
    RtcpPacket,
    RtcpPacketType,
    SdesChunk,
    SdesItem,
    SenderReport,
    SourceDescription,
)

__all__ = ["build_rtcp"]

_MAX_COUNT = 31  # 5-bit RC/SC/subtype field
_U8 = 0xFF
_I24_MIN = -(1 << 23)
_I24_MAX = (1 << 23) - 1


def build_rtcp(packets: Sequence[RtcpPacket]) -> bytes:
    """Serialize *packets* into a compound RTCP buffer.

    Each packet's own ``padding_size`` (0 for none) controls whether that
    packet gets RTCP-level padding — the trailing padding bytes are
    generated here, not supplied by the caller. Raises
    :class:`~rtpkit.model.errors.RtcpBuildError` on any field that doesn't
    fit the wire format (e.g. more than 31 report blocks, an out-of-range
    padding count, a non-4-character APP name).
    """
    return b"".join(_build_one(pkt) for pkt in packets)


def _build_one(pkt: RtcpPacket) -> bytes:
    try:
        if isinstance(pkt, SenderReport):
            count, packet_type, body = _serialize_sr(pkt)
        elif isinstance(pkt, ReceiverReport):
            count, packet_type, body = _serialize_rr(pkt)
        elif isinstance(pkt, SourceDescription):
            count, packet_type, body = _serialize_sdes(pkt)
        elif isinstance(pkt, Goodbye):
            count, packet_type, body = _serialize_bye(pkt)
        elif isinstance(pkt, ApplicationDefined):
            count, packet_type, body = _serialize_app(pkt)
        else:
            raise RtcpBuildError("packets", f"unsupported packet type {type(pkt).__name__}")
    except struct.error as exc:
        # a plain 32-bit field (ssrc, ntp fields, timestamps, ...) didn't fit — the fields with
        # protocol-specific ranges narrower than "fits in 32 bits" are validated explicitly above.
        raise RtcpBuildError(type(pkt).__name__, str(exc)) from exc

    if not 0 <= pkt.padding_size <= _U8:
        raise RtcpBuildError("padding_size", f"must be 0-255, got {pkt.padding_size}")
    if pkt.padding_size % 4 != 0:
        # the content is always 4-byte aligned by the time padding is appended (see below), so
        # the padding count itself must be a multiple of 4 for the packet to stay aligned.
        raise RtcpBuildError("padding_size", f"must be a multiple of 4, got {pkt.padding_size}")

    body += b"\x00" * ((-len(body)) % 4)  # structural 4-byte alignment (e.g. an unpadded BYE reason)
    if pkt.padding_size:
        body += b"\x00" * (pkt.padding_size - 1) + bytes([pkt.padding_size])

    byte0 = (2 << 6) | (int(bool(pkt.padding_size)) << 5) | (count & 0x1F)
    return struct.pack("!BBH", byte0, packet_type, len(body) // 4) + body


def _require_count(count: int, field: str) -> None:
    if count > _MAX_COUNT:
        raise RtcpBuildError(field, f"at most {_MAX_COUNT} entries (5-bit field), got {count}")


def _serialize_report_block(rb: ReportBlock) -> bytes:
    if not 0 <= rb.fraction_lost <= _U8:
        raise RtcpBuildError("fraction_lost", f"must fit in 8 bits, got {rb.fraction_lost}")
    if not _I24_MIN <= rb.cumulative_lost <= _I24_MAX:
        raise RtcpBuildError("cumulative_lost", f"must fit in a signed 24-bit field, got {rb.cumulative_lost}")
    flcl = ((rb.fraction_lost & 0xFF) << 24) | (rb.cumulative_lost & 0xFFFFFF)
    return struct.pack(
        "!IIIII",
        rb.ssrc,
        flcl,
        rb.extended_highest_sequence,
        rb.jitter,
        rb.last_sr,
    ) + struct.pack("!I", rb.delay_since_last_sr)


def _serialize_sr(pkt: SenderReport) -> tuple[int, int, bytes]:
    _require_count(len(pkt.report_blocks), "report_blocks")
    info = pkt.sender_info
    body = struct.pack(
        "!IIIIII",
        pkt.ssrc,
        info.ntp_seconds,
        info.ntp_fraction,
        info.rtp_timestamp,
        info.packet_count,
        info.octet_count,
    )
    body += b"".join(_serialize_report_block(rb) for rb in pkt.report_blocks)
    return len(pkt.report_blocks), RtcpPacketType.SR, body


def _serialize_rr(pkt: ReceiverReport) -> tuple[int, int, bytes]:
    _require_count(len(pkt.report_blocks), "report_blocks")
    body = struct.pack("!I", pkt.ssrc) + b"".join(_serialize_report_block(rb) for rb in pkt.report_blocks)
    return len(pkt.report_blocks), RtcpPacketType.RR, body


def _serialize_sdes_item(item: SdesItem) -> bytes:
    if not 1 <= item.type <= _U8:
        raise RtcpBuildError("type", f"must be 1-255 (0 is reserved), got {item.type}")
    data = bytes(item.text)
    if len(data) > _U8:
        raise RtcpBuildError("text", f"at most 255 bytes, got {len(data)}")
    return struct.pack("BB", item.type, len(data)) + data


def _serialize_sdes_chunk(chunk: SdesChunk) -> bytes:
    items = b"".join(_serialize_sdes_item(i) for i in chunk.items)
    raw = struct.pack("!I", chunk.ssrc) + items + b"\x00"
    return raw + b"\x00" * ((-len(raw)) % 4)


def _serialize_sdes(pkt: SourceDescription) -> tuple[int, int, bytes]:
    _require_count(len(pkt.chunks), "chunks")
    body = b"".join(_serialize_sdes_chunk(c) for c in pkt.chunks)
    return len(pkt.chunks), RtcpPacketType.SDES, body


def _serialize_bye(pkt: Goodbye) -> tuple[int, int, bytes]:
    _require_count(len(pkt.sources), "sources")
    body = struct.pack(f"!{len(pkt.sources)}I", *pkt.sources) if pkt.sources else b""
    if pkt.reason is not None:
        reason = bytes(pkt.reason)
        if len(reason) > _U8:
            raise RtcpBuildError("reason", f"at most 255 bytes, got {len(reason)}")
        body += struct.pack("B", len(reason)) + reason
    return len(pkt.sources), RtcpPacketType.BYE, body


def _serialize_app(pkt: ApplicationDefined) -> tuple[int, int, bytes]:
    if not 0 <= pkt.subtype <= _MAX_COUNT:
        raise RtcpBuildError("subtype", f"must fit in 5 bits (0-31), got {pkt.subtype}")
    try:
        name = pkt.name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RtcpBuildError("name", f"must be ASCII, got {pkt.name!r}") from exc
    if len(name) != 4:
        raise RtcpBuildError("name", f"must be exactly 4 ASCII characters, got {pkt.name!r}")
    body = struct.pack("!I", pkt.ssrc) + name + bytes(pkt.data)
    return pkt.subtype, RtcpPacketType.APP, body
