"""Tests for build_rtcp()."""

from __future__ import annotations

import pytest

from rtpkit import (
    ApplicationDefined,
    Goodbye,
    ReceiverReport,
    ReportBlock,
    RtcpBuildError,
    SdesChunk,
    SdesItem,
    SenderInfo,
    SenderReport,
    SourceDescription,
    build_rtcp,
    parse_rtcp,
)


class TestRoundTrip:
    def test_sender_report(self) -> None:
        sr = SenderReport(
            ssrc=0xAABBCCDD,
            sender_info=SenderInfo(ntp_seconds=1, ntp_fraction=2, rtp_timestamp=3, packet_count=4, octet_count=5),
            report_blocks=(),
            padding_size=0,
        )
        (parsed,) = parse_rtcp(build_rtcp([sr]))
        assert parsed == sr

    def test_sender_report_with_report_blocks(self) -> None:
        rb = ReportBlock(
            ssrc=1,
            fraction_lost=10,
            cumulative_lost=-5,
            extended_highest_sequence=1000,
            jitter=7,
            last_sr=8,
            delay_since_last_sr=9,
        )
        sr = SenderReport(
            ssrc=1,
            sender_info=SenderInfo(ntp_seconds=0, ntp_fraction=0, rtp_timestamp=0, packet_count=0, octet_count=0),
            report_blocks=(rb, rb),
            padding_size=0,
        )
        (parsed,) = parse_rtcp(build_rtcp([sr]))
        assert parsed == sr

    def test_receiver_report(self) -> None:
        rr = ReceiverReport(ssrc=42, report_blocks=(), padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([rr]))
        assert parsed == rr

    def test_source_description_multi_chunk_multi_item(self) -> None:
        sdes = SourceDescription(
            chunks=(
                SdesChunk(ssrc=1, items=(SdesItem(type=1, text=b"alice"), SdesItem(type=6, text=b"rtpkit"))),
                SdesChunk(ssrc=2, items=(SdesItem(type=1, text=b"bob"),)),
            ),
            padding_size=0,
        )
        (parsed,) = parse_rtcp(build_rtcp([sdes]))
        assert parsed == sdes

    def test_source_description_empty_chunk(self) -> None:
        sdes = SourceDescription(chunks=(SdesChunk(ssrc=1, items=()),), padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([sdes]))
        assert parsed == sdes

    def test_goodbye_no_reason(self) -> None:
        bye = Goodbye(sources=(1, 2, 3), reason=None, padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([bye]))
        assert parsed == bye

    def test_goodbye_with_reason(self) -> None:
        bye = Goodbye(sources=(1,), reason=b"testing", padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([bye]))
        assert parsed == bye

    def test_goodbye_empty(self) -> None:
        bye = Goodbye(sources=(), reason=None, padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([bye]))
        assert parsed == bye

    def test_application_defined(self) -> None:
        app = ApplicationDefined(subtype=5, ssrc=1, name="test", data=b"\x01\x02\x03\x04", padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([app]))
        assert parsed == app

    def test_application_defined_no_data(self) -> None:
        app = ApplicationDefined(subtype=0, ssrc=1, name="abcd", data=b"", padding_size=0)
        (parsed,) = parse_rtcp(build_rtcp([app]))
        assert parsed == app

    @pytest.mark.parametrize("padding", [4, 8, 252])
    def test_padding_round_trips(self, padding: int) -> None:
        rr = ReceiverReport(ssrc=1, report_blocks=(), padding_size=padding)
        (parsed,) = parse_rtcp(build_rtcp([rr]))
        assert parsed == rr
        assert parsed.padding_size == padding

    def test_compound_packet(self) -> None:
        sr = SenderReport(
            ssrc=1,
            sender_info=SenderInfo(ntp_seconds=0, ntp_fraction=0, rtp_timestamp=0, packet_count=0, octet_count=0),
            report_blocks=(),
            padding_size=0,
        )
        sdes = SourceDescription(chunks=(SdesChunk(ssrc=1, items=(SdesItem(type=1, text=b"x"),)),), padding_size=0)
        bye = Goodbye(sources=(1,), reason=None, padding_size=0)

        parsed = parse_rtcp(build_rtcp([sr, sdes, bye]))
        assert [type(p) for p in parsed] == [SenderReport, SourceDescription, Goodbye]
        assert list(parsed) == [sr, sdes, bye]


class TestErrors:
    def test_too_many_report_blocks_raises(self) -> None:
        rb = ReportBlock(
            ssrc=1,
            fraction_lost=0,
            cumulative_lost=0,
            extended_highest_sequence=0,
            jitter=0,
            last_sr=0,
            delay_since_last_sr=0,
        )
        rr = ReceiverReport(ssrc=1, report_blocks=(rb,) * 32, padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([rr])

    def test_too_many_chunks_raises(self) -> None:
        sdes = SourceDescription(chunks=(SdesChunk(ssrc=1, items=()),) * 32, padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([sdes])

    def test_too_many_sources_raises(self) -> None:
        bye = Goodbye(sources=tuple(range(32)), reason=None, padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([bye])

    def test_fraction_lost_out_of_range_raises(self) -> None:
        rb = ReportBlock(
            ssrc=1,
            fraction_lost=256,
            cumulative_lost=0,
            extended_highest_sequence=0,
            jitter=0,
            last_sr=0,
            delay_since_last_sr=0,
        )
        rr = ReceiverReport(ssrc=1, report_blocks=(rb,), padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([rr])

    @pytest.mark.parametrize("value", [-(1 << 23) - 1, (1 << 23)])
    def test_cumulative_lost_out_of_range_raises(self, value: int) -> None:
        rb = ReportBlock(
            ssrc=1,
            fraction_lost=0,
            cumulative_lost=value,
            extended_highest_sequence=0,
            jitter=0,
            last_sr=0,
            delay_since_last_sr=0,
        )
        rr = ReceiverReport(ssrc=1, report_blocks=(rb,), padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([rr])

    def test_ssrc_out_of_range_raises(self) -> None:
        rr = ReceiverReport(ssrc=0x1_0000_0000, report_blocks=(), padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([rr])

    @pytest.mark.parametrize("padding", [-1, 256])
    def test_padding_out_of_range_raises(self, padding: int) -> None:
        rr = ReceiverReport(ssrc=1, report_blocks=(), padding_size=padding)
        with pytest.raises(RtcpBuildError):
            build_rtcp([rr])

    @pytest.mark.parametrize("padding", [1, 2, 3, 5, 255])
    def test_padding_not_a_multiple_of_four_raises(self, padding: int) -> None:
        # padding must round the packet up to a 4-byte boundary, so a non-multiple-of-4 count
        # can never itself produce an aligned packet — this used to silently build a corrupt one
        rr = ReceiverReport(ssrc=1, report_blocks=(), padding_size=padding)
        with pytest.raises(RtcpBuildError):
            build_rtcp([rr])

    def test_app_subtype_out_of_range_raises(self) -> None:
        app = ApplicationDefined(subtype=32, ssrc=1, name="test", data=b"", padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([app])

    def test_app_name_wrong_length_raises(self) -> None:
        app = ApplicationDefined(subtype=0, ssrc=1, name="toolong", data=b"", padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([app])

    def test_app_name_non_ascii_raises(self) -> None:
        app = ApplicationDefined(subtype=0, ssrc=1, name="café", data=b"", padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([app])

    def test_sdes_item_type_zero_raises(self) -> None:
        sdes = SourceDescription(chunks=(SdesChunk(ssrc=1, items=(SdesItem(type=0, text=b"x"),)),), padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([sdes])

    def test_sdes_item_text_too_long_raises(self) -> None:
        sdes = SourceDescription(
            chunks=(SdesChunk(ssrc=1, items=(SdesItem(type=1, text=b"x" * 256),)),), padding_size=0
        )
        with pytest.raises(RtcpBuildError):
            build_rtcp([sdes])

    def test_bye_reason_too_long_raises(self) -> None:
        bye = Goodbye(sources=(1,), reason=b"x" * 256, padding_size=0)
        with pytest.raises(RtcpBuildError):
            build_rtcp([bye])

    def test_unsupported_packet_type_raises(self) -> None:
        with pytest.raises(RtcpBuildError):
            build_rtcp(["not a packet"])  # type: ignore[list-item]
