"""Tests for write_pcapng()."""

from __future__ import annotations

import pytest

from rtpkit import PcapPacket, read_pcapng, write_pcapng


def _pkt(data: bytes, timestamp: float = 1.0, link_type: int = 1) -> PcapPacket:
    return PcapPacket(
        timestamp=timestamp,
        captured_length=len(data),
        original_length=len(data),
        link_type=link_type,
        data=memoryview(data),
    )


class TestHappyPath:
    def test_empty(self) -> None:
        raw = write_pcapng([])
        assert list(read_pcapng(raw)) == []

    def test_single_packet_round_trips(self) -> None:
        pkt = _pkt(b"\xaa\xbb\xcc", timestamp=1700000000.5, link_type=1)
        raw = write_pcapng([pkt])
        (got,) = list(read_pcapng(raw))

        assert bytes(got.data) == b"\xaa\xbb\xcc"
        assert got.link_type == 1
        assert got.timestamp == pytest.approx(1700000000.5, abs=1e-6)

    def test_multiple_packets_round_trip_in_order(self) -> None:
        pkts = [_pkt(b"\x01"), _pkt(b"\x02\x02"), _pkt(b"\x03\x03\x03")]
        raw = write_pcapng(pkts)
        got = list(read_pcapng(raw))
        assert [bytes(p.data) for p in got] == [b"\x01", b"\x02\x02", b"\x03\x03\x03"]

    def test_mixed_link_types_get_separate_interfaces(self) -> None:
        pkts = [_pkt(b"\x01", link_type=1), _pkt(b"\x02", link_type=113), _pkt(b"\x03", link_type=1)]
        raw = write_pcapng(pkts)
        got = list(read_pcapng(raw))

        assert [p.link_type for p in got] == [1, 113, 1]
        assert [bytes(p.data) for p in got] == [b"\x01", b"\x02", b"\x03"]

    def test_original_length_preserved(self) -> None:
        pkt = PcapPacket(
            timestamp=1.0, captured_length=3, original_length=100, link_type=1, data=memoryview(b"\xaa\xbb\xcc")
        )
        raw = write_pcapng([pkt])
        (got,) = list(read_pcapng(raw))
        assert got.original_length == 100
        assert got.captured_length == 3

    def test_odd_length_payload_padding_is_stripped_on_read(self) -> None:
        # 3-byte payload forces block-alignment padding; read_pcapng must not leak it
        pkt = _pkt(b"\x01\x02\x03")
        raw = write_pcapng([pkt])
        (got,) = list(read_pcapng(raw))
        assert bytes(got.data) == b"\x01\x02\x03"

    def test_fractional_second_rounding(self) -> None:
        raw = write_pcapng([_pkt(b"\x01", timestamp=10.1)])
        (got,) = list(read_pcapng(raw))
        assert got.timestamp == pytest.approx(10.1, abs=1e-6)
