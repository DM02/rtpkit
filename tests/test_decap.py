"""Tests for decapsulate_udp()."""

from __future__ import annotations

import struct

from rtpkit import decapsulate_udp

from .conftest import (
    build_ethernet_frame,
    build_ipv4_packet,
    build_ipv6_ext_header,
    build_ipv6_packet,
    build_sll_frame,
    build_udp_datagram,
)

_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LINUX_SLL = 113
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_PROTO_UDP = 17
_PROTO_TCP = 6
_PROTO_HOPOPT = 0


def _eth_ipv4_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp = build_udp_datagram(src_port, dst_port, payload)
    ip = build_ipv4_packet(_PROTO_UDP, src_ip, dst_ip, udp)
    return build_ethernet_frame(_ETHERTYPE_IPV4, ip)


class TestEthernetIPv4:
    def test_happy_path(self) -> None:
        frame = _eth_ipv4_udp("10.0.0.1", "10.0.0.2", 5004, 5006, b"\xaa\xbb\xcc")
        result = decapsulate_udp(_DLT_EN10MB, frame)

        assert result is not None
        assert result.src_ip == "10.0.0.1"
        assert result.dst_ip == "10.0.0.2"
        assert result.src_port == 5004
        assert result.dst_port == 5006
        assert bytes(result.payload) == b"\xaa\xbb\xcc"

    def test_single_vlan_tag(self) -> None:
        udp = build_udp_datagram(1, 2, b"\x01")
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", udp)
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, ip, vlan_tags=(100,))
        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        assert bytes(result.payload) == b"\x01"

    def test_double_vlan_tag(self) -> None:
        udp = build_udp_datagram(1, 2, b"\x02")
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", udp)
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, ip, vlan_tags=(100, 200))
        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        assert bytes(result.payload) == b"\x02"

    def test_non_udp_protocol_returns_none(self) -> None:
        ip = build_ipv4_packet(_PROTO_TCP, "1.2.3.4", "5.6.7.8", b"\x00" * 20)
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, ip)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_ipv4_with_options(self) -> None:
        udp = build_udp_datagram(1, 2, b"\x03")
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", udp, ihl_words=8)
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, ip)
        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        assert bytes(result.payload) == b"\x03"

    def test_truncated_ethernet_header_returns_none(self) -> None:
        assert decapsulate_udp(_DLT_EN10MB, b"\x00" * 10) is None

    def test_truncated_ip_header_returns_none(self) -> None:
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, b"\x45\x00")
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_truncated_udp_header_returns_none(self) -> None:
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", b"\x00\x00\x00")
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, ip)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_unsupported_ethertype_returns_none(self) -> None:
        frame = build_ethernet_frame(0x0806, b"\x00" * 28)  # ARP
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_truncated_vlan_tag_returns_none(self) -> None:
        frame = b"\x00" * 12 + struct.pack("!H", 0x8100) + b"\x00\x01"  # TPID present, TCI+ethertype missing
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_declared_version_mismatch_returns_none(self) -> None:
        # ethertype says IPv4 but the payload's version nibble says otherwise
        bogus_ip = bytes([0x60]) + b"\x00" * 19
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, bogus_ip)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_ihl_below_minimum_returns_none(self) -> None:
        udp = build_udp_datagram(1, 2, b"\x01")
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", udp)
        bad_ip = bytes([0x44]) + ip[1:]  # IHL=4 words (16 bytes), below the 20-byte minimum
        frame = build_ethernet_frame(_ETHERTYPE_IPV4, bad_ip)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None


class TestEthernetIPv6:
    def test_happy_path(self) -> None:
        udp = build_udp_datagram(1, 2, b"\xaa")
        ip6 = build_ipv6_packet(_PROTO_UDP, "2001:db8::1", "2001:db8::2", udp)
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, ip6)

        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        assert result.src_ip == "2001:db8::1"
        assert result.dst_ip == "2001:db8::2"
        assert bytes(result.payload) == b"\xaa"

    def test_with_hop_by_hop_extension_header(self) -> None:
        udp = build_udp_datagram(1, 2, b"\xbb")
        ext = build_ipv6_ext_header(next_header=_PROTO_UDP, ext_len_words=0)
        ip6 = build_ipv6_packet(_PROTO_HOPOPT, "::1", "::2", ext + udp)
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, ip6)

        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        assert bytes(result.payload) == b"\xbb"

    def test_non_udp_next_header_returns_none(self) -> None:
        ip6 = build_ipv6_packet(_PROTO_TCP, "::1", "::2", b"\x00" * 20)
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, ip6)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_truncated_ipv6_header_returns_none(self) -> None:
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, b"\x60\x00\x00\x00")
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_declared_version_mismatch_returns_none(self) -> None:
        bogus_ip6 = bytes([0x45]) + b"\x00" * 39
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, bogus_ip6)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_extension_header_truncated_before_length_byte_returns_none(self) -> None:
        # HopByHop next-header byte present, but the hdr_ext_len byte is missing
        ip6 = build_ipv6_packet(_PROTO_HOPOPT, "::1", "::2", b"\x11")
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, ip6)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_extension_header_declares_more_than_available_returns_none(self) -> None:
        ext = struct.pack("BB", _PROTO_UDP, 5)  # claims (5+1)*8 = 48 bytes, far more than present
        ip6 = build_ipv6_packet(_PROTO_HOPOPT, "::1", "::2", ext)
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, ip6)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None

    def test_extension_header_chain_exhausts_hop_limit_returns_none(self) -> None:
        # 9 chained HopByHop headers — one more than the walker's iteration cap
        chain = b"".join(build_ipv6_ext_header(next_header=_PROTO_HOPOPT, ext_len_words=0) for _ in range(9))
        ip6 = build_ipv6_packet(_PROTO_HOPOPT, "::1", "::2", chain)
        frame = build_ethernet_frame(_ETHERTYPE_IPV6, ip6)
        assert decapsulate_udp(_DLT_EN10MB, frame) is None


class TestLinuxCooked:
    def test_happy_path(self) -> None:
        udp = build_udp_datagram(1, 2, b"\xcc")
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", udp)
        frame = build_sll_frame(_ETHERTYPE_IPV4, ip)

        result = decapsulate_udp(_DLT_LINUX_SLL, frame)
        assert result is not None
        assert bytes(result.payload) == b"\xcc"

    def test_truncated_header_returns_none(self) -> None:
        assert decapsulate_udp(_DLT_LINUX_SLL, b"\x00" * 10) is None


class TestRawIp:
    def test_ipv4(self) -> None:
        udp = build_udp_datagram(1, 2, b"\xdd")
        ip = build_ipv4_packet(_PROTO_UDP, "1.2.3.4", "5.6.7.8", udp)
        result = decapsulate_udp(_DLT_RAW, ip)
        assert result is not None
        assert bytes(result.payload) == b"\xdd"

    def test_ipv6(self) -> None:
        udp = build_udp_datagram(1, 2, b"\xee")
        ip6 = build_ipv6_packet(_PROTO_UDP, "::1", "::2", udp)
        result = decapsulate_udp(_DLT_RAW, ip6)
        assert result is not None
        assert bytes(result.payload) == b"\xee"

    def test_empty_returns_none(self) -> None:
        assert decapsulate_udp(_DLT_RAW, b"") is None

    def test_unrecognised_version_returns_none(self) -> None:
        assert decapsulate_udp(_DLT_RAW, bytes([0x50]) + b"\x00" * 20) is None


class TestUnsupportedLinkType:
    def test_unknown_link_type_returns_none(self) -> None:
        assert decapsulate_udp(999, b"\x00" * 64) is None


class TestZeroCopy:
    def test_payload_is_a_view_into_the_original_frame(self) -> None:
        frame = bytearray(_eth_ipv4_udp("1.2.3.4", "5.6.7.8", 1, 2, b"\x11\x22\x33"))
        result = decapsulate_udp(_DLT_EN10MB, frame)
        assert result is not None
        frame[-1] = 0xFF
        assert bytes(result.payload) == b"\x11\x22\xff"


def test_bytes_input_accepted() -> None:
    frame = _eth_ipv4_udp("1.2.3.4", "5.6.7.8", 1, 2, b"\x01")
    result = decapsulate_udp(_DLT_EN10MB, bytes(frame))
    assert result is not None
    assert bytes(result.payload) == b"\x01"
