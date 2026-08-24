"""Tests for encapsulate_udp()."""

from __future__ import annotations

import struct

import pytest

from rtpkit import EncapsulationError, decapsulate_udp, encapsulate_udp

_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LINUX_SLL = 113


def _verify_checksum(data: bytes) -> int:
    """RFC 1071 checksum of data (checksum field included) — correct iff this folds to 0xFFFF."""
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


class TestRoundTrip:
    @pytest.mark.parametrize("link_type", [_DLT_EN10MB, _DLT_LINUX_SLL, _DLT_RAW])
    def test_ipv4(self, link_type: int) -> None:
        frame = encapsulate_udp(link_type, "192.168.1.10", "192.168.1.20", 5004, 5006, b"\xaa\xbb\xcc")
        result = decapsulate_udp(link_type, frame)

        assert result is not None
        assert result.src_ip == "192.168.1.10"
        assert result.dst_ip == "192.168.1.20"
        assert result.src_port == 5004
        assert result.dst_port == 5006
        assert bytes(result.payload) == b"\xaa\xbb\xcc"

    @pytest.mark.parametrize("link_type", [_DLT_EN10MB, _DLT_LINUX_SLL, _DLT_RAW])
    def test_ipv6(self, link_type: int) -> None:
        frame = encapsulate_udp(link_type, "2001:db8::1", "2001:db8::2", 1, 2, b"\xde\xad\xbe\xef")
        result = decapsulate_udp(link_type, frame)

        assert result is not None
        assert result.src_ip == "2001:db8::1"
        assert result.dst_ip == "2001:db8::2"
        assert bytes(result.payload) == b"\xde\xad\xbe\xef"

    def test_empty_payload(self) -> None:
        frame = encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "10.0.0.2", 1, 2, b"")
        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        assert bytes(result.payload) == b""

    def test_accepts_bytearray_and_memoryview(self) -> None:
        frame1 = encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "10.0.0.2", 1, 2, bytearray(b"\x01\x02"))
        frame2 = encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "10.0.0.2", 1, 2, memoryview(b"\x01\x02"))
        assert frame1 == frame2

    def test_realistic_rtp_payload_round_trips(self) -> None:
        from rtpkit import RtpBuilder, parse_rtp

        rtp = RtpBuilder().with_payload_type(8).with_sequence_number(100).with_payload(b"\xd5" * 160).build()
        frame = encapsulate_udp(_DLT_EN10MB, "192.168.1.10", "192.168.1.20", 6730, 6730, rtp)
        result = decapsulate_udp(_DLT_EN10MB, frame)

        assert result is not None
        pkt = parse_rtp(bytes(result.payload))
        assert pkt.payload_type == 8
        assert pkt.sequence_number == 100


class TestChecksums:
    def test_ipv4_header_checksum_is_valid(self) -> None:
        frame = encapsulate_udp(_DLT_RAW, "10.1.2.3", "10.4.5.6", 1, 2, b"\xaa")
        assert _verify_checksum(frame[:20]) == 0xFFFF

    def test_ipv4_udp_checksum_is_valid(self) -> None:
        src, dst = "10.1.2.3", "10.4.5.6"
        frame = encapsulate_udp(_DLT_RAW, src, dst, 111, 222, b"\xaa\xbb\xcc")
        udp_segment = frame[20:]

        import ipaddress

        pseudo = (
            ipaddress.IPv4Address(src).packed
            + ipaddress.IPv4Address(dst).packed
            + struct.pack("!BBH", 0, 17, len(udp_segment))
        )
        assert _verify_checksum(pseudo + udp_segment) == 0xFFFF

    def test_ipv6_udp_checksum_is_valid(self) -> None:
        src, dst = "2001:db8::1", "2001:db8::2"
        frame = encapsulate_udp(_DLT_RAW, src, dst, 111, 222, b"\xaa\xbb\xcc")
        udp_segment = frame[40:]

        import ipaddress

        pseudo = (
            ipaddress.IPv6Address(src).packed
            + ipaddress.IPv6Address(dst).packed
            + struct.pack("!I3xB", len(udp_segment), 17)
        )
        assert _verify_checksum(pseudo + udp_segment) == 0xFFFF

    def test_computed_zero_checksum_is_sent_as_all_ones(self) -> None:
        # crafted payload that makes the raw UDP checksum compute to exactly 0
        frame = encapsulate_udp(_DLT_RAW, "0.0.0.0", "0.0.0.0", 0, 0, b"\xff\xda")
        udp_segment = frame[20:]
        (checksum,) = struct.unpack_from("!H", udp_segment, 6)
        assert checksum == 0xFFFF


class TestErrors:
    def test_mismatched_ip_versions_raises(self) -> None:
        with pytest.raises(EncapsulationError):
            encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "2001:db8::1", 1, 2, b"\x01")

    def test_unsupported_link_type_raises(self) -> None:
        with pytest.raises(EncapsulationError):
            encapsulate_udp(999, "10.0.0.1", "10.0.0.2", 1, 2, b"\x01")

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(EncapsulationError):
            encapsulate_udp(_DLT_EN10MB, "not-an-ip", "10.0.0.2", 1, 2, b"\x01")

    @pytest.mark.parametrize("port", [-1, 65536])
    def test_port_out_of_range_raises(self, port: int) -> None:
        with pytest.raises(EncapsulationError):
            encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "10.0.0.2", port, 2, b"\x01")
        with pytest.raises(EncapsulationError):
            encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "10.0.0.2", 1, port, b"\x01")

    def test_ipv4_payload_too_large_raises(self) -> None:
        with pytest.raises(EncapsulationError):
            encapsulate_udp(_DLT_EN10MB, "10.0.0.1", "10.0.0.2", 1, 2, b"\x00" * 70000)

    def test_ipv4_payload_at_limit_is_accepted(self) -> None:
        payload = b"\x00" * (0xFFFF - 20 - 8)
        frame = encapsulate_udp(_DLT_RAW, "10.0.0.1", "10.0.0.2", 1, 2, payload)
        result = decapsulate_udp(_DLT_RAW, frame)
        assert result is not None
        assert len(result.payload) == len(payload)
