"""RTCP compound-packet parser — strict and lenient modes."""

from __future__ import annotations

import logging
import struct

from ..model.errors import (
    RtcpBufferTooShort,
    RtcpInvalidVersion,
    RtcpLengthMismatch,
    RtcpMalformedPacket,
)
from ..model.rtcp import (
    ApplicationDefined,
    Goodbye,
    ReportBlock,
    RtcpPacket,
    RtcpPacketType,
    SdesChunk,
    SdesItem,
    SenderInfo,
    SourceDescription,
)
from ..model.rtcp import ReceiverReport as ReceiverReportModel
from ..model.rtcp import SenderReport as SenderReportModel

__all__ = ["parse_rtcp", "parse_rtcp_lenient"]

logger = logging.getLogger("rtpkit.parser.rtcp")

_HEADER_SIZE = 4
_REPORT_BLOCK_SIZE = 24


def parse_rtcp(data: bytes | bytearray | memoryview) -> tuple[RtcpPacket, ...]:
    """Parse a compound RTCP packet in strict mode.

    Raises :class:`~rtpkit.model.errors.RtcpError` (or a subclass) on any
    protocol violation, including wrong version, truncated buffers,
    a declared length exceeding the buffer, and malformed or unrecognised
    packet bodies.
    """
    return _parse_compound(data, strict=True)


def parse_rtcp_lenient(data: bytes | bytearray | memoryview) -> tuple[RtcpPacket, ...]:
    """Parse a compound RTCP packet in lenient (best-effort) mode.

    Only raises :class:`~rtpkit.model.errors.RtcpBufferTooShort` when the
    buffer is too short to contain even one packet header. Malformed or
    unrecognised individual packets are skipped (logged as warnings); a
    packet whose declared length overruns the buffer stops parsing there,
    returning whatever packets were parsed so far.
    """
    return _parse_compound(data, strict=False)


def _parse_compound(data: bytes | bytearray | memoryview, *, strict: bool) -> tuple[RtcpPacket, ...]:
    if not isinstance(data, memoryview):
        data = memoryview(data)

    buf_len = len(data)
    if buf_len < _HEADER_SIZE:
        raise RtcpBufferTooShort(required=_HEADER_SIZE, actual=buf_len)

    packets: list[RtcpPacket] = []
    offset = 0

    while offset < buf_len:
        remaining = buf_len - offset
        if remaining < _HEADER_SIZE:
            if strict:
                raise RtcpBufferTooShort(required=_HEADER_SIZE, actual=remaining)
            logger.warning("Trailing %d byte(s) too short for an RTCP header — stopping", remaining)
            break

        first_byte: int = data[offset]
        version = (first_byte >> 6) & 0x03
        padding_flag = bool((first_byte >> 5) & 0x01)
        count = first_byte & 0x1F
        packet_type: int = data[offset + 1]
        (length_words,) = struct.unpack_from("!H", data, offset + 2)
        packet_len = (length_words + 1) * 4
        packet_end = offset + packet_len

        if version != 2:
            if strict:
                raise RtcpInvalidVersion(version)
            logger.warning("RTCP version %d (expected 2) — continuing in lenient mode", version)

        if packet_end > buf_len:
            if strict:
                raise RtcpLengthMismatch(declared=packet_len, available=remaining)
            logger.warning("RTCP packet declares %d bytes, only %d available — stopping", packet_len, remaining)
            break

        body = data[offset + _HEADER_SIZE : packet_end]
        padding_size = 0
        content_end = len(body)

        if padding_flag:
            if len(body) < 1:
                if strict:
                    raise RtcpMalformedPacket("padding flag set but packet body is empty")
                logger.warning("RTCP padding flag set but packet body is empty — ignoring padding")
            else:
                pad_count: int = body[-1]
                if pad_count == 0 or pad_count > len(body):
                    if strict:
                        raise RtcpMalformedPacket(f"invalid padding count {pad_count}")
                    logger.warning("RTCP invalid padding count %d — ignoring padding", pad_count)
                else:
                    padding_size = pad_count
                    content_end = len(body) - pad_count

        content = body[:content_end]

        try:
            packet = _parse_one(packet_type, count, content, padding_size)
        except RtcpMalformedPacket:
            if strict:
                raise
            logger.warning("Skipping malformed/unrecognised RTCP packet (type=%d)", packet_type)
            packet = None

        if packet is not None:
            packets.append(packet)

        offset = packet_end

    return tuple(packets)


def _parse_one(packet_type: int, count: int, content: memoryview, padding_size: int) -> RtcpPacket:
    if packet_type == RtcpPacketType.SR:
        return _parse_sr(content, count, padding_size)
    if packet_type == RtcpPacketType.RR:
        return _parse_rr(content, count, padding_size)
    if packet_type == RtcpPacketType.SDES:
        return _parse_sdes(content, count, padding_size)
    if packet_type == RtcpPacketType.BYE:
        return _parse_bye(content, count, padding_size)
    if packet_type == RtcpPacketType.APP:
        return _parse_app(content, count, padding_size)
    raise RtcpMalformedPacket(f"unknown RTCP packet type {packet_type}")


def _parse_report_blocks(data: memoryview, rc: int) -> tuple[ReportBlock, ...]:
    needed = rc * _REPORT_BLOCK_SIZE
    if len(data) < needed:
        raise RtcpMalformedPacket(f"need {needed} bytes for {rc} report block(s), got {len(data)}")

    blocks = []
    for i in range(rc):
        off = i * _REPORT_BLOCK_SIZE
        (ssrc,) = struct.unpack_from("!I", data, off)
        (fraction_and_lost,) = struct.unpack_from("!I", data, off + 4)
        fraction_lost = (fraction_and_lost >> 24) & 0xFF
        cumulative_lost = fraction_and_lost & 0xFFFFFF
        if cumulative_lost & 0x800000:  # sign-extend the 24-bit two's-complement count
            cumulative_lost -= 0x1000000
        (ext_highest, jitter, last_sr, dlsr) = struct.unpack_from("!IIII", data, off + 8)
        blocks.append(
            ReportBlock(
                ssrc=ssrc,
                fraction_lost=fraction_lost,
                cumulative_lost=cumulative_lost,
                extended_highest_sequence=ext_highest,
                jitter=jitter,
                last_sr=last_sr,
                delay_since_last_sr=dlsr,
            )
        )
    return tuple(blocks)


def _parse_sr(content: memoryview, rc: int, padding_size: int) -> SenderReportModel:
    if len(content) < 24:
        raise RtcpMalformedPacket(f"SR needs at least 24 bytes (SSRC + sender info), got {len(content)}")
    (ssrc,) = struct.unpack_from("!I", content, 0)
    (ntp_sec, ntp_frac, rtp_ts, pkt_cnt, oct_cnt) = struct.unpack_from("!IIIII", content, 4)
    sender_info = SenderInfo(
        ntp_seconds=ntp_sec,
        ntp_fraction=ntp_frac,
        rtp_timestamp=rtp_ts,
        packet_count=pkt_cnt,
        octet_count=oct_cnt,
    )
    blocks = _parse_report_blocks(content[24:], rc)
    return SenderReportModel(ssrc=ssrc, sender_info=sender_info, report_blocks=blocks, padding_size=padding_size)


def _parse_rr(content: memoryview, rc: int, padding_size: int) -> ReceiverReportModel:
    if len(content) < 4:
        raise RtcpMalformedPacket(f"RR needs at least 4 bytes (SSRC), got {len(content)}")
    (ssrc,) = struct.unpack_from("!I", content, 0)
    blocks = _parse_report_blocks(content[4:], rc)
    return ReceiverReportModel(ssrc=ssrc, report_blocks=blocks, padding_size=padding_size)


def _parse_sdes(content: memoryview, sc: int, padding_size: int) -> SourceDescription:
    chunks = []
    pos = 0

    for _ in range(sc):
        chunk_begin = pos
        if pos + 4 > len(content):
            raise RtcpMalformedPacket("SDES chunk truncated (missing SSRC)")
        (ssrc,) = struct.unpack_from("!I", content, pos)
        pos += 4

        items = []
        while True:
            if pos >= len(content):
                raise RtcpMalformedPacket("SDES chunk missing null terminator")
            item_type: int = content[pos]
            if item_type == 0:
                pos += 1
                break
            if pos + 2 > len(content):
                raise RtcpMalformedPacket("SDES item header truncated")
            item_len: int = content[pos + 1]
            item_start = pos + 2
            item_end = item_start + item_len
            if item_end > len(content):
                raise RtcpMalformedPacket("SDES item data truncated")
            items.append(SdesItem(type=item_type, text=content[item_start:item_end]))
            pos = item_end

        pad = (-(pos - chunk_begin)) % 4
        if pos + pad > len(content):
            raise RtcpMalformedPacket("SDES chunk padding truncated")
        pos += pad

        chunks.append(SdesChunk(ssrc=ssrc, items=tuple(items)))

    return SourceDescription(chunks=tuple(chunks), padding_size=padding_size)


def _parse_bye(content: memoryview, sc: int, padding_size: int) -> Goodbye:
    needed = sc * 4
    if len(content) < needed:
        raise RtcpMalformedPacket(f"BYE needs {needed} bytes for {sc} source(s), got {len(content)}")
    sources = struct.unpack_from(f"!{sc}I", content, 0) if sc else ()

    pos = needed
    reason: memoryview | None = None
    if pos < len(content):
        reason_len: int = content[pos]
        pos += 1
        if pos + reason_len > len(content):
            raise RtcpMalformedPacket("BYE reason text truncated")
        reason = content[pos : pos + reason_len]

    return Goodbye(sources=sources, reason=reason, padding_size=padding_size)


def _parse_app(content: memoryview, subtype: int, padding_size: int) -> ApplicationDefined:
    if len(content) < 8:
        raise RtcpMalformedPacket(f"APP needs at least 8 bytes (SSRC + name), got {len(content)}")
    (ssrc,) = struct.unpack_from("!I", content, 0)
    name = bytes(content[4:8]).decode("ascii", errors="replace")
    return ApplicationDefined(subtype=subtype, ssrc=ssrc, name=name, data=content[8:], padding_size=padding_size)
