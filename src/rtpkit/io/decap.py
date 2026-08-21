"""Strip link/IP/UDP layers off a captured frame to recover its UDP payload.

Unlike the RTP/RTCP/pcap parsers, this never raises: most frames in a real
capture simply aren't UDP (ARP, TCP, other ethertypes...), and that isn't a
protocol violation, just "not applicable" — so any unsupported or malformed
layer just yields ``None`` rather than an exception.
"""

from __future__ import annotations

import ipaddress
import struct

from ..model.net import DecapsulatedUdp

__all__ = ["decapsulate_udp"]

_DLT_EN10MB = 1
_DLT_RAW = 101
_DLT_LINUX_SLL = 113

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_VLAN = 0x8100
_MAX_VLAN_TAGS = 2

_PROTO_UDP = 17

_IPV6_HOPBYHOP = 0
_IPV6_ROUTING = 43
_IPV6_FRAGMENT = 44
_IPV6_DESTOPTS = 60
_IPV6_EXT_HEADERS = frozenset({_IPV6_HOPBYHOP, _IPV6_ROUTING, _IPV6_FRAGMENT, _IPV6_DESTOPTS})
_MAX_IPV6_EXT_HEADERS = 8


def decapsulate_udp(link_type: int, frame: bytes | bytearray | memoryview) -> DecapsulatedUdp | None:
    """Recover the UDP datagram inside a captured frame, or ``None``.

    Supports Ethernet II (with up to two stacked 802.1Q/QinQ tags), Linux
    "cooked" capture (DLT_LINUX_SLL), and raw IP (no link layer) as *link_type*,
    and IPv4 or IPv6 (walking the common extension header chain) above that.
    """
    if not isinstance(frame, memoryview):
        frame = memoryview(frame)

    stripped = _strip_link_layer(link_type, frame)
    if stripped is None:
        return None
    ethertype, ip_packet = stripped

    if ethertype == _ETHERTYPE_IPV4:
        return _decap_ipv4(ip_packet)
    if ethertype == _ETHERTYPE_IPV6:
        return _decap_ipv6(ip_packet)
    return None


def _strip_link_layer(link_type: int, frame: memoryview) -> tuple[int, memoryview] | None:
    if link_type == _DLT_EN10MB:
        return _strip_ethernet(frame)
    if link_type == _DLT_LINUX_SLL:
        return _strip_sll(frame)
    if link_type == _DLT_RAW:
        return _strip_raw(frame)
    return None


def _strip_ethernet(frame: memoryview) -> tuple[int, memoryview] | None:
    if len(frame) < 14:
        return None
    (ethertype,) = struct.unpack_from("!H", frame, 12)
    offset = 14
    for _ in range(_MAX_VLAN_TAGS):
        if ethertype != _ETHERTYPE_VLAN:
            break
        if len(frame) < offset + 4:
            return None
        (ethertype,) = struct.unpack_from("!H", frame, offset + 2)
        offset += 4
    return (ethertype, frame[offset:])


def _strip_sll(frame: memoryview) -> tuple[int, memoryview] | None:
    if len(frame) < 16:
        return None
    (ethertype,) = struct.unpack_from("!H", frame, 14)
    return (ethertype, frame[16:])


def _strip_raw(frame: memoryview) -> tuple[int, memoryview] | None:
    if len(frame) < 1:
        return None
    version = (frame[0] >> 4) & 0x0F
    if version == 4:
        return (_ETHERTYPE_IPV4, frame)
    if version == 6:
        return (_ETHERTYPE_IPV6, frame)
    return None


def _decap_ipv4(data: memoryview) -> DecapsulatedUdp | None:
    if len(data) < 20:
        return None
    if (data[0] >> 4) & 0x0F != 4:
        return None
    header_len = (data[0] & 0x0F) * 4
    if header_len < 20 or header_len > len(data):
        return None
    if data[9] != _PROTO_UDP:
        return None

    (total_length,) = struct.unpack_from("!H", data, 2)
    end = total_length if header_len <= total_length <= len(data) else len(data)

    src_ip = str(ipaddress.IPv4Address(bytes(data[12:16])))
    dst_ip = str(ipaddress.IPv4Address(bytes(data[16:20])))
    return _decap_udp(data[header_len:end], src_ip, dst_ip)


def _decap_ipv6(data: memoryview) -> DecapsulatedUdp | None:
    if len(data) < 40:
        return None
    if (data[0] >> 4) & 0x0F != 6:
        return None

    next_header = data[6]
    src_ip = str(ipaddress.IPv6Address(bytes(data[8:24])))
    dst_ip = str(ipaddress.IPv6Address(bytes(data[24:40])))

    offset = 40
    for _ in range(_MAX_IPV6_EXT_HEADERS):
        if next_header not in _IPV6_EXT_HEADERS:
            break
        if len(data) < offset + 2:
            return None
        following = data[offset]
        ext_len = 8 if next_header == _IPV6_FRAGMENT else (data[offset + 1] + 1) * 8
        if len(data) < offset + ext_len:
            return None
        next_header = following
        offset += ext_len

    if next_header != _PROTO_UDP:
        return None
    return _decap_udp(data[offset:], src_ip, dst_ip)


def _decap_udp(data: memoryview, src_ip: str, dst_ip: str) -> DecapsulatedUdp | None:
    if len(data) < 8:
        return None
    (src_port, dst_port, length) = struct.unpack_from("!HHH", data, 0)
    end = length if 8 <= length <= len(data) else len(data)
    return DecapsulatedUdp(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, payload=data[8:end])
