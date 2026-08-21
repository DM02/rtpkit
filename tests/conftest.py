"""Shared fixtures and helpers for building raw RTP/RTCP packets in tests."""

from __future__ import annotations

import ipaddress
import struct

from rtpkit import RtcpPacketType


class RtpBuilder:
    """Fluent builder that produces raw RTP byte buffers.

    Usage::

        raw = (
            RtpBuilder()
            .with_payload_type(8)
            .with_seq(1000)
            .with_timestamp(160_000)
            .with_ssrc(0xDEADBEEF)
            .with_csrc([1, 2, 3])
            .with_extension(profile=0xBEDE, data=b'\\x12\\x03AAA\\x00')
            .with_payload(b'\\x80' * 160)
            .with_padding(4)
            .build()
        )
    """

    def __init__(self) -> None:
        self._version: int = 2
        self._padding: int = 0      # number of padding bytes (0 = off)
        self._marker: bool = False
        self._payload_type: int = 0
        self._seq: int = 0
        self._timestamp: int = 0
        self._ssrc: int = 0
        self._csrc: list[int] = []
        self._ext_profile: int | None = None
        self._ext_data: bytes = b""
        self._payload: bytes = b""

    # -- setters (fluent) ---------------------------------------------------

    def with_version(self, v: int) -> RtpBuilder:
        self._version = v
        return self

    def with_marker(self, m: bool = True) -> RtpBuilder:
        self._marker = m
        return self

    def with_payload_type(self, pt: int) -> RtpBuilder:
        self._payload_type = pt
        return self

    def with_seq(self, seq: int) -> RtpBuilder:
        self._seq = seq
        return self

    def with_timestamp(self, ts: int) -> RtpBuilder:
        self._timestamp = ts
        return self

    def with_ssrc(self, ssrc: int) -> RtpBuilder:
        self._ssrc = ssrc
        return self

    def with_csrc(self, csrc: list[int]) -> RtpBuilder:
        self._csrc = list(csrc)
        return self

    def with_extension(self, profile: int, data: bytes) -> RtpBuilder:
        """Set extension; *data* length must be a multiple of 4."""
        assert len(data) % 4 == 0, "extension data must be 32-bit aligned"
        self._ext_profile = profile
        self._ext_data = data
        return self

    def with_payload(self, payload: bytes) -> RtpBuilder:
        self._payload = payload
        return self

    def with_padding(self, n: int) -> RtpBuilder:
        """Add *n* bytes of padding (the last byte encodes the count)."""
        assert n >= 1, "padding must be at least 1 byte"
        self._padding = n
        return self

    # -- build --------------------------------------------------------------

    def build(self) -> bytes:
        """Assemble and return the raw RTP packet bytes."""
        cc = len(self._csrc)
        has_ext = self._ext_profile is not None
        has_pad = self._padding > 0

        # Byte 0:  V(2) | P(1) | X(1) | CC(4)
        byte0 = (
            ((self._version & 0x03) << 6)
            | (int(has_pad) << 5)
            | (int(has_ext) << 4)
            | (cc & 0x0F)
        )

        # Byte 1:  M(1) | PT(7)
        byte1 = (int(self._marker) << 7) | (self._payload_type & 0x7F)

        parts: list[bytes] = []

        # Fixed header: 12 bytes
        parts.append(struct.pack(
            "!BBHII",
            byte0,
            byte1,
            self._seq & 0xFFFF,
            self._timestamp & 0xFFFFFFFF,
            self._ssrc & 0xFFFFFFFF,
        ))

        # CSRC
        if cc:
            parts.append(struct.pack(f"!{cc}I", *self._csrc))

        # Extension
        if has_ext:
            assert self._ext_profile is not None
            ext_words = len(self._ext_data) // 4
            parts.append(struct.pack("!HH", self._ext_profile, ext_words))
            parts.append(self._ext_data)

        # Payload
        parts.append(self._payload)

        # Padding
        if has_pad:
            parts.append(b"\x00" * (self._padding - 1))
            parts.append(struct.pack("B", self._padding))

        return b"".join(parts)


# -- RTCP raw-packet builders (test-only, mirror the wire format directly) --


def build_rtcp_header(count: int, pt: int, length_words: int, padding: bool = False, version: int = 2) -> bytes:
    byte0 = ((version & 0x03) << 6) | ((1 if padding else 0) << 5) | (count & 0x1F)
    return struct.pack("!BBH", byte0, pt, length_words)


def _finish_rtcp_packet(pt: int, count: int, body: bytes, padding: int, version: int = 2) -> bytes:
    if padding:
        body = body + b"\x00" * (padding - 1) + struct.pack("B", padding)
    assert len(body) % 4 == 0
    return build_rtcp_header(count, pt, len(body) // 4, padding=bool(padding), version=version) + body


def build_report_block(
    ssrc: int,
    fraction_lost: int = 0,
    cumulative_lost: int = 0,
    ext_highest: int = 0,
    jitter: int = 0,
    last_sr: int = 0,
    dlsr: int = 0,
) -> bytes:
    flcl = ((fraction_lost & 0xFF) << 24) | (cumulative_lost & 0xFFFFFF)
    return struct.pack("!IIIIII", ssrc, flcl, ext_highest, jitter, last_sr, dlsr)


def build_sr(
    ssrc: int,
    ntp_sec: int = 0,
    ntp_frac: int = 0,
    rtp_ts: int = 0,
    pkt_cnt: int = 0,
    oct_cnt: int = 0,
    report_blocks: tuple[bytes, ...] = (),
    padding: int = 0,
    version: int = 2,
) -> bytes:
    body = struct.pack("!IIIIII", ssrc, ntp_sec, ntp_frac, rtp_ts, pkt_cnt, oct_cnt) + b"".join(report_blocks)
    return _finish_rtcp_packet(RtcpPacketType.SR, len(report_blocks), body, padding, version)


def build_rr(
    ssrc: int,
    report_blocks: tuple[bytes, ...] = (),
    padding: int = 0,
    version: int = 2,
) -> bytes:
    body = struct.pack("!I", ssrc) + b"".join(report_blocks)
    return _finish_rtcp_packet(RtcpPacketType.RR, len(report_blocks), body, padding, version)


def build_sdes_item(item_type: int, text: bytes) -> bytes:
    return struct.pack("BB", item_type, len(text)) + text


def build_sdes_chunk(ssrc: int, items: bytes) -> bytes:
    chunk = struct.pack("!I", ssrc) + items + b"\x00"
    return chunk + b"\x00" * ((-len(chunk)) % 4)


def build_sdes(chunks: tuple[bytes, ...], padding: int = 0, version: int = 2) -> bytes:
    body = b"".join(chunks)
    return _finish_rtcp_packet(RtcpPacketType.SDES, len(chunks), body, padding, version)


def build_bye(
    sources: tuple[int, ...] = (),
    reason: bytes | None = None,
    padding: int = 0,
    version: int = 2,
) -> bytes:
    body = struct.pack(f"!{len(sources)}I", *sources) if sources else b""
    if reason is not None:
        body += struct.pack("B", len(reason)) + reason
        body += b"\x00" * ((-len(body)) % 4)
    return _finish_rtcp_packet(RtcpPacketType.BYE, len(sources), body, padding, version)


def build_app(
    subtype: int,
    ssrc: int,
    name: bytes,
    data: bytes = b"",
    padding: int = 0,
    version: int = 2,
) -> bytes:
    assert len(name) == 4, "APP name must be exactly 4 bytes"
    body = struct.pack("!I", ssrc) + name + data
    return _finish_rtcp_packet(RtcpPacketType.APP, subtype, body, padding, version)


# -- classic pcap builders (test-only) --

_PCAP_MAGIC_US = b"\xd4\xc3\xb2\xa1"


def build_pcap_global_header(link_type: int, order: str = "<", magic: bytes = _PCAP_MAGIC_US) -> bytes:
    return magic + struct.pack(f"{order}HHiIII", 2, 4, 0, 0, 262144, link_type)


def build_pcap_record(ts_sec: int, ts_frac: int, data: bytes, order: str = "<") -> bytes:
    return struct.pack(f"{order}IIII", ts_sec, ts_frac, len(data), len(data)) + data


# -- pcapng builders (test-only) --


def build_pcapng_block(block_type: int, body: bytes, order: str = "<") -> bytes:
    padded_body = body + b"\x00" * ((-len(body)) % 4)
    total_len = 8 + len(padded_body) + 4
    return struct.pack(f"{order}II", block_type, total_len) + padded_body + struct.pack(f"{order}I", total_len)


def build_shb(order: str = "<") -> bytes:
    bom = b"\x4d\x3c\x2b\x1a" if order == "<" else b"\x1a\x2b\x3c\x4d"
    body = bom + struct.pack(f"{order}HH", 1, 0) + struct.pack(f"{order}q", -1)
    return build_pcapng_block(0x0A0D0D0A, body, order)


def build_idb(link_type: int, order: str = "<", if_tsresol: int | None = None) -> bytes:
    body = struct.pack(f"{order}HHI", link_type, 0, 262144)
    if if_tsresol is not None:
        body += struct.pack(f"{order}HH", 9, 1) + bytes([if_tsresol]) + b"\x00\x00\x00"
        body += struct.pack(f"{order}HH", 0, 0)
    return build_pcapng_block(0x00000001, body, order)


def build_epb(
    iface_id: int,
    ts_ticks: int,
    packet_data: bytes,
    order: str = "<",
    orig_len: int | None = None,
) -> bytes:
    if orig_len is None:
        orig_len = len(packet_data)
    ts_high = (ts_ticks >> 32) & 0xFFFFFFFF
    ts_low = ts_ticks & 0xFFFFFFFF
    body = struct.pack(f"{order}IIIII", iface_id, ts_high, ts_low, len(packet_data), orig_len) + packet_data
    return build_pcapng_block(0x00000006, body, order)


def build_spb(packet_data: bytes, order: str = "<", orig_len: int | None = None) -> bytes:
    if orig_len is None:
        orig_len = len(packet_data)
    body = struct.pack(f"{order}I", orig_len) + packet_data
    return build_pcapng_block(0x00000003, body, order)


# -- Ethernet/IP/UDP builders (test-only) --


def build_ethernet_frame(ethertype: int, payload: bytes, vlan_tags: tuple[int, ...] = ()) -> bytes:
    frame = b"\x00" * 6 + b"\x00" * 6
    for tci in vlan_tags:
        frame += struct.pack("!HH", 0x8100, tci)
    return frame + struct.pack("!H", ethertype) + payload


def build_sll_frame(ethertype: int, payload: bytes) -> bytes:
    return b"\x00" * 14 + struct.pack("!H", ethertype) + payload


def build_ipv4_packet(
    protocol: int,
    src_ip: str,
    dst_ip: str,
    payload: bytes,
    total_length: int | None = None,
    ihl_words: int = 5,
) -> bytes:
    if total_length is None:
        total_length = ihl_words * 4 + len(payload)
    header = struct.pack(
        "!BBHHHBBH", (4 << 4) | ihl_words, 0, total_length, 0, 0, 64, protocol, 0
    )
    header += ipaddress.IPv4Address(src_ip).packed + ipaddress.IPv4Address(dst_ip).packed
    header += b"\x00" * ((ihl_words - 5) * 4)
    return header + payload


def build_ipv6_packet(next_header: int, src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    header = struct.pack("!IHBB", (6 << 28), len(payload), next_header, 64)
    header += ipaddress.IPv6Address(src_ip).packed + ipaddress.IPv6Address(dst_ip).packed
    return header + payload


def build_ipv6_ext_header(next_header: int, ext_len_words: int = 0) -> bytes:
    # HopByHop/Routing/DestinationOptions layout: next_header(1) + hdr_ext_len(1) + data, total (hdr_ext_len+1)*8
    total = (ext_len_words + 1) * 8
    return struct.pack("BB", next_header, ext_len_words) + b"\x00" * (total - 2)


def build_udp_datagram(src_port: int, dst_port: int, payload: bytes, length: int | None = None) -> bytes:
    if length is None:
        length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
