"""Tests for parse_rtcp() and parse_rtcp_lenient()."""

from __future__ import annotations

import struct

import pytest

from rtpkit import (
    ApplicationDefined,
    Goodbye,
    ReceiverReport,
    RtcpBufferTooShort,
    RtcpInvalidVersion,
    RtcpLengthMismatch,
    RtcpMalformedPacket,
    SdesItemType,
    SenderReport,
    SourceDescription,
    parse_rtcp,
    parse_rtcp_lenient,
)

from .conftest import (
    build_app,
    build_bye,
    build_report_block,
    build_rr,
    build_rtcp_header,
    build_sdes,
    build_sdes_chunk,
    build_sdes_item,
    build_sr,
)


class TestSenderReport:
    def test_minimal(self) -> None:
        raw = build_sr(ssrc=0xAABBCCDD, ntp_sec=1, ntp_frac=2, rtp_ts=3, pkt_cnt=4, oct_cnt=5)
        (pkt,) = parse_rtcp(raw)

        assert isinstance(pkt, SenderReport)
        assert pkt.ssrc == 0xAABBCCDD
        assert pkt.sender_info.ntp_seconds == 1
        assert pkt.sender_info.ntp_fraction == 2
        assert pkt.sender_info.rtp_timestamp == 3
        assert pkt.sender_info.packet_count == 4
        assert pkt.sender_info.octet_count == 5
        assert pkt.report_blocks == ()
        assert pkt.padding_size == 0

    def test_ntp_timestamp_property(self) -> None:
        raw = build_sr(ssrc=1, ntp_sec=100, ntp_frac=2**31)
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, SenderReport)
        assert pkt.sender_info.ntp_timestamp == pytest.approx(100.5)

    def test_with_report_blocks(self) -> None:
        block = build_report_block(
            ssrc=0x11111111, fraction_lost=10, cumulative_lost=-5, ext_highest=1000, jitter=7, last_sr=8, dlsr=9
        )
        raw = build_sr(ssrc=1, report_blocks=(block,))
        (pkt,) = parse_rtcp(raw)

        assert isinstance(pkt, SenderReport)
        assert len(pkt.report_blocks) == 1
        rb = pkt.report_blocks[0]
        assert rb.ssrc == 0x11111111
        assert rb.fraction_lost == 10
        assert rb.cumulative_lost == -5
        assert rb.extended_highest_sequence == 1000
        assert rb.jitter == 7
        assert rb.last_sr == 8
        assert rb.delay_since_last_sr == 9

    def test_with_padding(self) -> None:
        raw = build_sr(ssrc=1, padding=4)
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, SenderReport)
        assert pkt.padding_size == 4

    def test_too_short_raises(self) -> None:
        raw = build_rtcp_header(count=0, pt=200, length_words=0)  # header only, no SSRC/sender-info
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_report_block_count_exceeds_available_data_raises(self) -> None:
        # header claims 1 report block (RC=1), but none actually follow
        raw = bytearray(build_sr(ssrc=1))
        raw[0] = (raw[0] & 0xE0) | 1
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(bytes(raw))


class TestReceiverReport:
    def test_minimal(self) -> None:
        raw = build_rr(ssrc=0x01020304)
        (pkt,) = parse_rtcp(raw)

        assert isinstance(pkt, ReceiverReport)
        assert pkt.ssrc == 0x01020304
        assert pkt.report_blocks == ()

    def test_with_multiple_report_blocks(self) -> None:
        blocks = (build_report_block(ssrc=1), build_report_block(ssrc=2))
        raw = build_rr(ssrc=99, report_blocks=blocks)
        (pkt,) = parse_rtcp(raw)

        assert isinstance(pkt, ReceiverReport)
        assert len(pkt.report_blocks) == 2
        assert pkt.report_blocks[0].ssrc == 1
        assert pkt.report_blocks[1].ssrc == 2

    def test_too_short_raises(self) -> None:
        raw = build_rtcp_header(count=0, pt=201, length_words=0)  # no SSRC at all
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)


class TestSourceDescription:
    def test_single_chunk_single_item(self) -> None:
        chunk = build_sdes_chunk(ssrc=1, items=build_sdes_item(SdesItemType.CNAME, b"alice@example.com"))
        raw = build_sdes(chunks=(chunk,))
        (pkt,) = parse_rtcp(raw)

        assert isinstance(pkt, SourceDescription)
        assert len(pkt.chunks) == 1
        assert pkt.chunks[0].ssrc == 1
        assert len(pkt.chunks[0].items) == 1
        item = pkt.chunks[0].items[0]
        assert item.type == SdesItemType.CNAME
        assert bytes(item.text) == b"alice@example.com"

    def test_multiple_items_and_chunks(self) -> None:
        chunk1 = build_sdes_chunk(
            ssrc=1,
            items=build_sdes_item(SdesItemType.CNAME, b"a") + build_sdes_item(SdesItemType.TOOL, b"rtpkit"),
        )
        chunk2 = build_sdes_chunk(ssrc=2, items=build_sdes_item(SdesItemType.CNAME, b"b"))
        raw = build_sdes(chunks=(chunk1, chunk2))
        (pkt,) = parse_rtcp(raw)

        assert isinstance(pkt, SourceDescription)
        assert len(pkt.chunks) == 2
        assert len(pkt.chunks[0].items) == 2
        assert bytes(pkt.chunks[0].items[1].text) == b"rtpkit"
        assert pkt.chunks[1].ssrc == 2

    def test_chunk_padding_to_32_bits(self) -> None:
        # SSRC(4) + type/len(2) + "ab"(2) + terminator(1) = 9 bytes -> padded to 12
        chunk = build_sdes_chunk(ssrc=1, items=build_sdes_item(SdesItemType.CNAME, b"ab"))
        assert len(chunk) == 12
        raw = build_sdes(chunks=(chunk,))
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, SourceDescription)
        assert bytes(pkt.chunks[0].items[0].text) == b"ab"

    def test_missing_terminator_raises(self) -> None:
        chunk = struct.pack("!I", 1) + build_sdes_item(SdesItemType.CNAME, b"ab")  # no null terminator, no padding
        raw = build_sdes(chunks=(chunk,))
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_chunk_count_exceeds_available_data_raises(self) -> None:
        chunk = build_sdes_chunk(ssrc=1, items=build_sdes_item(SdesItemType.CNAME, b"x"))
        raw = build_rtcp_header(count=2, pt=202, length_words=len(chunk) // 4) + chunk
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_item_header_truncated_raises(self) -> None:
        content = (
            struct.pack("!I", 1)
            + bytes([1, 1, 0x41])  # item: type=1, len=1, data=b"A"
            + bytes([1, 2, 0x42, 0x43])  # item: type=1, len=2, data=b"BC"
            + bytes([1])  # dangling type byte, no length byte follows
        )
        raw = build_rtcp_header(count=1, pt=202, length_words=len(content) // 4) + content
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_item_data_truncated_raises(self) -> None:
        content = struct.pack("!I", 1) + bytes([1, 0]) + bytes([1, 5])  # 2nd item claims 5 bytes, 0 follow
        raw = build_rtcp_header(count=1, pt=202, length_words=len(content) // 4) + content
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_chunk_padding_truncated_by_rtcp_level_padding_raises(self) -> None:
        # RTCP-level padding (P bit) strips the body to 5 bytes (ssrc + terminator), leaving no
        # room for the chunk's own 3-byte 32-bit alignment padding.
        body = struct.pack("!I", 1) + b"\x00" + b"\x00\x00" + struct.pack("B", 3)
        raw = build_rtcp_header(count=1, pt=202, length_words=len(body) // 4, padding=True) + body
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)


class TestGoodbye:
    def test_no_reason(self) -> None:
        raw = build_bye(sources=(1, 2, 3))
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, Goodbye)
        assert pkt.sources == (1, 2, 3)
        assert pkt.reason is None

    def test_with_reason(self) -> None:
        raw = build_bye(sources=(1,), reason=b"testing")
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, Goodbye)
        assert pkt.reason is not None
        assert bytes(pkt.reason) == b"testing"

    def test_empty(self) -> None:
        raw = build_bye()
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, Goodbye)
        assert pkt.sources == ()

    def test_source_count_exceeds_available_data_raises(self) -> None:
        raw = build_rtcp_header(count=2, pt=203, length_words=1) + struct.pack("!I", 1)
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_reason_truncated_raises(self) -> None:
        # reason length byte says 10, but only 3 bytes follow within the declared packet length
        content = struct.pack("!I", 1) + struct.pack("B", 10) + b"\x00\x00\x00"
        raw = build_rtcp_header(count=1, pt=203, length_words=len(content) // 4) + content
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)


class TestApplicationDefined:
    def test_no_data(self) -> None:
        raw = build_app(subtype=5, ssrc=42, name=b"test")
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, ApplicationDefined)
        assert pkt.subtype == 5
        assert pkt.ssrc == 42
        assert pkt.name == "test"
        assert bytes(pkt.data) == b""

    def test_with_data(self) -> None:
        raw = build_app(subtype=0, ssrc=1, name=b"XYZW", data=b"\x01\x02\x03\x04")
        (pkt,) = parse_rtcp(raw)
        assert isinstance(pkt, ApplicationDefined)
        assert pkt.name == "XYZW"
        assert bytes(pkt.data) == b"\x01\x02\x03\x04"

    def test_too_short_raises(self) -> None:
        raw = build_rtcp_header(count=0, pt=204, length_words=1) + struct.pack("!I", 1)  # missing name
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)


class TestCompoundPackets:
    def test_sr_then_sdes(self) -> None:
        sr = build_sr(ssrc=1)
        sdes = build_sdes(chunks=(build_sdes_chunk(ssrc=1, items=build_sdes_item(SdesItemType.CNAME, b"x")),))
        packets = parse_rtcp(sr + sdes)

        assert len(packets) == 2
        assert isinstance(packets[0], SenderReport)
        assert isinstance(packets[1], SourceDescription)

    def test_rr_sdes_bye(self) -> None:
        rr = build_rr(ssrc=1)
        sdes = build_sdes(chunks=(build_sdes_chunk(ssrc=1, items=b""),))
        bye = build_bye(sources=(1,))
        packets = parse_rtcp(rr + sdes + bye)

        assert [type(p) for p in packets] == [ReceiverReport, SourceDescription, Goodbye]


class TestStrictErrors:
    def test_empty_buffer_raises(self) -> None:
        with pytest.raises(RtcpBufferTooShort):
            parse_rtcp(b"")

    def test_trailing_garbage_raises(self) -> None:
        raw = build_rr(ssrc=1) + b"\x00\x00"
        with pytest.raises(RtcpBufferTooShort):
            parse_rtcp(raw)

    def test_invalid_version_raises(self) -> None:
        raw = build_rr(ssrc=1, version=1)
        with pytest.raises(RtcpInvalidVersion) as exc_info:
            parse_rtcp(raw)
        assert exc_info.value.version == 1

    def test_length_overrun_raises(self) -> None:
        raw = build_rtcp_header(count=0, pt=201, length_words=100) + struct.pack("!I", 1)
        with pytest.raises(RtcpLengthMismatch):
            parse_rtcp(raw)

    def test_unknown_packet_type_raises(self) -> None:
        raw = build_rtcp_header(count=0, pt=199, length_words=0)
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_bad_padding_count_raises(self) -> None:
        # padding bit set, but last byte claims more padding than the whole body
        body = struct.pack("!I", 1) + b"\x00\x00\x00" + struct.pack("B", 200)
        raw = build_rtcp_header(count=0, pt=201, length_words=len(body) // 4, padding=True) + body
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_padding_flag_with_empty_body_raises(self) -> None:
        raw = build_rtcp_header(count=0, pt=201, length_words=0, padding=True)
        with pytest.raises(RtcpMalformedPacket):
            parse_rtcp(raw)

    def test_accepts_memoryview_input(self) -> None:
        raw = build_rr(ssrc=1)
        (pkt,) = parse_rtcp(memoryview(raw))
        assert isinstance(pkt, ReceiverReport)


class TestLenientMode:
    def test_invalid_version_is_tolerated(self) -> None:
        raw = build_rr(ssrc=1, version=3)
        (pkt,) = parse_rtcp_lenient(raw)
        assert isinstance(pkt, ReceiverReport)

    def test_unknown_packet_type_is_skipped(self) -> None:
        unknown = build_rtcp_header(count=0, pt=199, length_words=0)
        rr = build_rr(ssrc=1)
        packets = parse_rtcp_lenient(unknown + rr)
        assert len(packets) == 1
        assert isinstance(packets[0], ReceiverReport)

    def test_length_overrun_stops_and_returns_partial(self) -> None:
        rr = build_rr(ssrc=1)
        truncated = build_rtcp_header(count=0, pt=201, length_words=100) + struct.pack("!I", 2)
        packets = parse_rtcp_lenient(rr + truncated)
        assert len(packets) == 1
        assert isinstance(packets[0], ReceiverReport)

    def test_still_raises_on_empty_buffer(self) -> None:
        with pytest.raises(RtcpBufferTooShort):
            parse_rtcp_lenient(b"")

    def test_malformed_packet_is_skipped(self) -> None:
        bad_sdes = build_sdes(chunks=(struct.pack("!I", 1) + build_sdes_item(SdesItemType.CNAME, b"ab"),))
        rr = build_rr(ssrc=1)
        packets = parse_rtcp_lenient(bad_sdes + rr)
        assert len(packets) == 1
        assert isinstance(packets[0], ReceiverReport)

    def test_trailing_garbage_stops_without_raising(self) -> None:
        raw = build_rr(ssrc=1) + b"\x00\x00"
        (pkt,) = parse_rtcp_lenient(raw)
        assert isinstance(pkt, ReceiverReport)

    def test_padding_flag_with_empty_body_is_tolerated(self) -> None:
        raw = build_rtcp_header(count=0, pt=201, length_words=0, padding=True)
        assert parse_rtcp_lenient(raw) == ()

    def test_bad_padding_count_is_ignored(self) -> None:
        body = struct.pack("!I", 1) + b"\x00\x00\x00" + struct.pack("B", 200)
        raw = build_rtcp_header(count=0, pt=201, length_words=len(body) // 4, padding=True) + body
        (pkt,) = parse_rtcp_lenient(raw)
        assert isinstance(pkt, ReceiverReport)
        assert pkt.padding_size == 0
