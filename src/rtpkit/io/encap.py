"""Wrap a UDP payload into a link/IP/UDP frame — the inverse of decap.decapsulate_udp.

Unlike decapsulate_udp, this *does* raise: decapsulate_udp scans arbitrary,
untrusted capture data where "not UDP" is simply not applicable, not an
error. encapsulate_udp instead builds a frame from parameters the caller
supplies directly, closer in spirit to RtpBuilder or write_pcap — invalid
input here is the caller's mistake, so it's surfaced as a typed error
rather than silently producing something misleading.
"""

from __future__ import annotations

import ipaddress
import struct

from ..model.errors import EncapsulationError

__all__ = ["encapsulate_udp"]

_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LINUX_SLL = 113

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD

_PROTO_UDP = 17

_DUMMY_DST_MAC = b"\x00\x00\x00\x00\x00\x01"
_DUMMY_SRC_MAC = b"\x00\x00\x00\x00\x00\x02"

_MAX_UDP_PAYLOAD_V4 = 0xFFFF - 20 - 8
_MAX_UDP_PAYLOAD_V6 = 0xFFFF - 8


def encapsulate_udp(
    link_type: int,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes | bytearray | memoryview,
) -> bytes:
    """Wrap *payload* in a UDP/IP/link frame, ready to embed in a :class:`~rtpkit.model.pcap.PcapPacket`.

    IP version is taken from *src_ip*/*dst_ip* (both must match). Ethernet
    and Linux cooked capture frames get dummy MAC addresses — irrelevant to
    the RTP/RTCP payload they carry. IPv4 header and UDP checksums (both IP
    versions) are computed correctly, so the result opens cleanly in
    Wireshark/tcpdump rather than showing as corrupt.

    Raises :class:`~rtpkit.model.errors.EncapsulationError` on an
    unsupported *link_type*, mismatched IP versions, an out-of-range port,
    or a payload too large to fit the 16-bit length fields.
    """
    payload = bytes(payload)
    src_addr = _parse_ip(src_ip)
    dst_addr = _parse_ip(dst_ip)
    if src_addr.version != dst_addr.version:
        raise EncapsulationError(
            f"src_ip and dst_ip must be the same IP version, got v{src_addr.version} and v{dst_addr.version}"
        )
    _validate_port(src_port, "src_port")
    _validate_port(dst_port, "dst_port")

    ip_version = src_addr.version
    max_payload = _MAX_UDP_PAYLOAD_V4 if ip_version == 4 else _MAX_UDP_PAYLOAD_V6
    if len(payload) > max_payload:
        raise EncapsulationError(
            f"payload of {len(payload)} bytes exceeds the {max_payload}-byte UDP/IPv{ip_version} limit"
        )

    udp_segment = _build_udp(src_ip, dst_ip, src_port, dst_port, payload, ip_version)
    if ip_version == 4:
        ip_packet = _build_ipv4(src_ip, dst_ip, udp_segment)
        ethertype = _ETHERTYPE_IPV4
    else:
        ip_packet = _build_ipv6(src_ip, dst_ip, udp_segment)
        ethertype = _ETHERTYPE_IPV6

    if link_type == _DLT_EN10MB:
        return _DUMMY_DST_MAC + _DUMMY_SRC_MAC + struct.pack("!H", ethertype) + ip_packet
    if link_type == _DLT_LINUX_SLL:
        return struct.pack("!HHH8sH", 0, 1, 0, b"\x00" * 8, ethertype) + ip_packet
    if link_type == _DLT_RAW:
        return ip_packet
    raise EncapsulationError(f"unsupported link_type {link_type} (supported: EN10MB=1, LINUX_SLL=113, RAW=101)")


def _parse_ip(address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(address)
    except ValueError as exc:
        raise EncapsulationError(f"invalid IP address {address!r}: {exc}") from exc


def _validate_port(port: int, name: str) -> None:
    if not 0 <= port <= 0xFFFF:
        raise EncapsulationError(f"{name} must fit in 16 bits, got {port}")


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _build_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes, ip_version: int) -> bytes:
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    checksum = _udp_checksum(src_ip, dst_ip, segment, ip_version)
    return struct.pack("!HHHH", src_port, dst_port, length, checksum) + payload


def _udp_checksum(src_ip: str, dst_ip: str, udp_segment: bytes, ip_version: int) -> int:
    if ip_version == 4:
        pseudo = (
            ipaddress.IPv4Address(src_ip).packed
            + ipaddress.IPv4Address(dst_ip).packed
            + struct.pack("!BBH", 0, _PROTO_UDP, len(udp_segment))
        )
    else:
        pseudo = (
            ipaddress.IPv6Address(src_ip).packed
            + ipaddress.IPv6Address(dst_ip).packed
            + struct.pack("!I3xB", len(udp_segment), _PROTO_UDP)
        )
    checksum = _checksum16(pseudo + udp_segment)
    # RFC 768/8200: a computed checksum of zero is transmitted as all-ones.
    return checksum if checksum != 0 else 0xFFFF


def _build_ipv4(src_ip: str, dst_ip: str, udp_segment: bytes) -> bytes:
    total_length = 20 + len(udp_segment)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        _PROTO_UDP,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    checksum = _checksum16(header)
    header = header[:10] + struct.pack("!H", checksum) + header[12:]
    return header + udp_segment


def _build_ipv6(src_ip: str, dst_ip: str, udp_segment: bytes) -> bytes:
    header = struct.pack("!IHBB", 6 << 28, len(udp_segment), _PROTO_UDP, 64)
    header += ipaddress.IPv6Address(src_ip).packed + ipaddress.IPv6Address(dst_ip).packed
    return header + udp_segment
