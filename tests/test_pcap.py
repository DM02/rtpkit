"""Tests for read_pcap() and read_pcap_lenient()."""

from __future__ import annotations

import pytest

from rtpkit import PcapBufferTooShort, PcapInvalidMagic, PcapTruncatedRecord, read_pcap, read_pcap_lenient

from .conftest import build_pcap_global_header, build_pcap_record


class TestHappyPath:
    def test_no_records(self) -> None:
        raw = build_pcap_global_header(link_type=1)
        assert list(read_pcap(raw)) == []

    def test_single_record(self) -> None:
        raw = build_pcap_global_header(link_type=1) + build_pcap_record(100, 500_000, b"\xaa\xbb\xcc")
        (pkt,) = list(read_pcap(raw))

        assert pkt.timestamp == pytest.approx(100.5)
        assert pkt.captured_length == 3
        assert pkt.original_length == 3
        assert pkt.link_type == 1
        assert bytes(pkt.data) == b"\xaa\xbb\xcc"

    def test_multiple_records(self) -> None:
        raw = (
            build_pcap_global_header(link_type=1)
            + build_pcap_record(1, 0, b"\x01")
            + build_pcap_record(2, 0, b"\x02\x02")
        )
        packets = list(read_pcap(raw))

        assert len(packets) == 2
        assert bytes(packets[0].data) == b"\x01"
        assert bytes(packets[1].data) == b"\x02\x02"

    @pytest.mark.parametrize(
        ("magic", "order"),
        [
            (b"\xd4\xc3\xb2\xa1", "<"),  # LE, microsecond
            (b"\xa1\xb2\xc3\xd4", ">"),  # BE, microsecond
        ],
    )
    def test_byte_order_variants(self, magic: bytes, order: str) -> None:
        raw = build_pcap_global_header(link_type=1, order=order, magic=magic) + build_pcap_record(
            1, 0, b"\xff", order=order
        )
        (pkt,) = list(read_pcap(raw))
        assert bytes(pkt.data) == b"\xff"

    def test_nanosecond_resolution(self) -> None:
        raw = build_pcap_global_header(link_type=1, magic=b"\x4d\x3c\xb2\xa1") + build_pcap_record(
            1, 500_000_000, b"\x01"
        )
        (pkt,) = list(read_pcap(raw))
        assert pkt.timestamp == pytest.approx(1.5)

    def test_data_is_zero_copy_view(self) -> None:
        raw = bytearray(build_pcap_global_header(link_type=1) + build_pcap_record(1, 0, b"\x01"))
        (pkt,) = list(read_pcap(raw))
        raw[-1] = 0xFF
        assert bytes(pkt.data) == b"\xff"


class TestStrictErrors:
    def test_buffer_too_short_for_global_header(self) -> None:
        with pytest.raises(PcapBufferTooShort):
            list(read_pcap(b"\x00" * 10))

    def test_invalid_magic(self) -> None:
        with pytest.raises(PcapInvalidMagic) as exc_info:
            list(read_pcap(b"\x00" * 24))
        assert exc_info.value.magic == b"\x00\x00\x00\x00"

    def test_truncated_record_header(self) -> None:
        raw = build_pcap_global_header(link_type=1) + b"\x00" * 5
        with pytest.raises(PcapBufferTooShort):
            list(read_pcap(raw))

    def test_truncated_record_data(self) -> None:
        header = build_pcap_global_header(link_type=1)
        record_header = build_pcap_record(1, 0, b"\xaa\xbb\xcc\xdd")[:16]
        with pytest.raises(PcapTruncatedRecord):
            list(read_pcap(header + record_header + b"\xaa"))


class TestLenientMode:
    def test_truncated_record_header_stops(self) -> None:
        raw = build_pcap_global_header(link_type=1) + build_pcap_record(1, 0, b"\x01") + b"\x00" * 5
        packets = list(read_pcap_lenient(raw))
        assert len(packets) == 1

    def test_truncated_record_data_stops(self) -> None:
        header = build_pcap_global_header(link_type=1)
        good = build_pcap_record(1, 0, b"\x01")
        record_header = build_pcap_record(2, 0, b"\xaa\xbb\xcc\xdd")[:16]
        packets = list(read_pcap_lenient(header + good + record_header + b"\xaa"))
        assert len(packets) == 1

    def test_still_raises_on_bad_magic(self) -> None:
        with pytest.raises(PcapInvalidMagic):
            list(read_pcap_lenient(b"\x00" * 24))

    def test_still_raises_on_too_short_global_header(self) -> None:
        with pytest.raises(PcapBufferTooShort):
            list(read_pcap_lenient(b"\x00" * 10))
