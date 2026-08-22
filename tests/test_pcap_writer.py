"""Tests for write_pcap()."""

from __future__ import annotations

import pytest

from rtpkit import PcapPacket, PcapWriteError, read_pcap, write_pcap


def _pkt(data: bytes, timestamp: float = 1.0, link_type: int = 1) -> PcapPacket:
    return PcapPacket(
        timestamp=timestamp,
        captured_length=len(data),
        original_length=len(data),
        link_type=link_type,
        data=memoryview(data),
    )


class TestHappyPath:
    def test_empty_with_explicit_link_type(self) -> None:
        raw = write_pcap([], link_type=1)
        assert list(read_pcap(raw)) == []

    def test_single_packet_round_trips(self) -> None:
        pkt = _pkt(b"\xaa\xbb\xcc", timestamp=1700000000.5, link_type=1)
        raw = write_pcap([pkt])
        (got,) = list(read_pcap(raw))

        assert bytes(got.data) == b"\xaa\xbb\xcc"
        assert got.link_type == 1
        assert got.captured_length == 3
        assert got.original_length == 3
        assert got.timestamp == pytest.approx(1700000000.5, abs=1e-6)

    def test_multiple_packets_round_trip_in_order(self) -> None:
        pkts = [_pkt(b"\x01"), _pkt(b"\x02\x02"), _pkt(b"\x03\x03\x03")]
        raw = write_pcap(pkts)
        got = list(read_pcap(raw))

        assert [bytes(p.data) for p in got] == [b"\x01", b"\x02\x02", b"\x03\x03\x03"]

    def test_original_length_can_exceed_captured(self) -> None:
        pkt = PcapPacket(
            timestamp=1.0, captured_length=3, original_length=100, link_type=1, data=memoryview(b"\xaa\xbb\xcc")
        )
        raw = write_pcap([pkt])
        (got,) = list(read_pcap(raw))
        assert got.captured_length == 3
        assert got.original_length == 100

    def test_link_type_taken_from_first_packet(self) -> None:
        raw = write_pcap([_pkt(b"\x01", link_type=113)])
        (got,) = list(read_pcap(raw))
        assert got.link_type == 113

    def test_explicit_link_type_matching_packets_is_accepted(self) -> None:
        raw = write_pcap([_pkt(b"\x01", link_type=1)], link_type=1)
        (got,) = list(read_pcap(raw))
        assert got.link_type == 1

    def test_fractional_second_rounding(self) -> None:
        # 0.1 isn't exactly representable in binary float; must still round-trip to the microsecond
        pkt = _pkt(b"\x01", timestamp=10.1)
        raw = write_pcap([pkt])
        (got,) = list(read_pcap(raw))
        assert got.timestamp == pytest.approx(10.1, abs=1e-6)

    def test_fractional_part_rounding_up_to_a_full_second_carries(self) -> None:
        # a fractional part that rounds to exactly 1_000_000us must carry into the next second
        pkt = _pkt(b"\x01", timestamp=2.9999999)
        raw = write_pcap([pkt])
        (got,) = list(read_pcap(raw))
        assert got.timestamp == pytest.approx(3.0, abs=1e-6)

    def test_output_is_readable_by_lenient_reader_too(self) -> None:
        raw = write_pcap([_pkt(b"\x01"), _pkt(b"\x02")])
        from rtpkit import read_pcap_lenient

        assert len(list(read_pcap_lenient(raw))) == 2


class TestErrors:
    def test_empty_without_link_type_raises(self) -> None:
        with pytest.raises(PcapWriteError):
            write_pcap([])

    def test_inconsistent_link_types_raise(self) -> None:
        with pytest.raises(PcapWriteError):
            write_pcap([_pkt(b"\x01", link_type=1), _pkt(b"\x02", link_type=113)])

    def test_explicit_link_type_mismatch_raises(self) -> None:
        with pytest.raises(PcapWriteError):
            write_pcap([_pkt(b"\x01", link_type=1)], link_type=113)
