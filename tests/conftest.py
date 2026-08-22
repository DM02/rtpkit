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
        self._padding: int = 0  # number of padding bytes (0 = off)
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
        byte0 = ((self._version & 0x03) << 6) | (int(has_pad) << 5) | (int(has_ext) << 4) | (cc & 0x0F)

        # Byte 1:  M(1) | PT(7)
        byte1 = (int(self._marker) << 7) | (self._payload_type & 0x7F)

        parts: list[bytes] = []

        # Fixed header: 12 bytes
        parts.append(
            struct.pack(
                "!BBHII",
                byte0,
                byte1,
                self._seq & 0xFFFF,
                self._timestamp & 0xFFFFFFFF,
                self._ssrc & 0xFFFFFFFF,
            )
        )

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
    header = struct.pack("!BBHHHBBH", (4 << 4) | ihl_words, 0, total_length, 0, 0, 64, protocol, 0)
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


# -- real-world samples (test-only) --
#
# UDP payload bytes only (post-decapsulation, no IP/MAC/port info) extracted from a
# private LAN VoIP capture used to validate rtpkit against real traffic. Two genuine
# RTP streams (different ptime/SSRC) plus the payload that triggered a real
# RtpFlowClassifier false positive: a non-RTP broadcast protocol on port 10102 with a
# byte-compatible-with-RTP header, but a frozen SSRC and sequence number — this is what
# motivated the sequence_progressing check in rtpkit.detection.flow.

REAL_RTP_STREAM_A = (
    bytes.fromhex("8008549fa511735f2f0cd2b2" + "d5" * 80),
    bytes.fromhex("800854a0a51173ad2f0cd2b2" + "d5" * 80),
    bytes.fromhex("800854a1a51173fd2f0cd2b2" + "d5" * 80),
    bytes.fromhex("800854a2a511744d2f0cd2b2" + "d5" * 80),
    bytes.fromhex("800854a3a511749d2f0cd2b2" + "d5" * 80),
)

REAL_RTP_STREAM_B = (
    bytes.fromhex("80085e780000778d000036c2" + "d5" * 160),
    bytes.fromhex("80085e790000782d000036c2" + "d5" * 160),
    bytes.fromhex("80085e7a000078cd000036c2" + "d5" * 160),
    bytes.fromhex("80085e7b0000796d000036c2" + "d5" * 160),
    bytes.fromhex("80085e7c00007a0d000036c2" + "d5" * 160),
)

REAL_BROADCAST_FALSE_POSITIVE = (
    bytes.fromhex(
        "88360064e50ca94be7a63893abc92a76ef33113b64715a5d611327908b8c7d78"
        "30d686e9c2ae3a9934ea04ef3c1f06fa2f5953262e3f806925b3bf9c6114d860c"
        "17d830d8c45a3828f4840e1736a1a9a9d6498cb3ff25d7c55bf646d3bf80ddd4b"
        "0532407a1a8b0475f24c4ce3f87d82b4e953967cbf6cbfb90a3b7dec71e9b20a5"
        "87ab30ed9ee10aa798db94fd9d82c426729c017cde257feea02a0b57d72197766"
        "d9d18326d033e5cd62a1a878c42e872fa19b75b973572e02d384b0f0280af013b"
        "caee4f5b09d2b995c1d032b0dc54de0d172330dcc20ee3c2409ac3780d91c71b2"
        "053e6f7fea2cb21bc7f9cb5c6134cc232a10042ac4de6225d6f3a637e1ce7b47f"
        "0d1364c3934cc232a10042ac44bf14fb02ea475f642c5430189baef993b7984367"
        "df9dbe4e057a4b4c214cead545e5266b26aee25d051415a5087ecf1dc37e340e4"
        "8808d788147c23ceaafb9a91bcdfb0648e8b401d0085e0379b737f17dd66921e6"
        "de704023c327e36db3b69bd22d8f7925ebb7fff93f00ab85b8ff2215b3a5ff275"
        "87199b2d212d6ba142c7eb200204794a502537e24ce641070d6c87df73e11205"
        "f05e44b1730aef460ed3e0c1d4fc6ed74006407d4af081cbbe7763c265a559903"
        "ce195beb5063a344387f69ec0860882e02fb61e7f99ca041174e72b86d3a23cc2"
        "364baf5ca79b264104654e9b2f66abaf844baf5ca79b2641045a638f91f53018a"
        "258f785672b5cbeab6a61c4f61d68878c0cf2cbb03ce316ee44ef2a9412c1bfe8"
        "cf0d45c29569977147dd5faed8f1291ea03776837975ca9b6d56d6f5e5c26f8d7"
        "9bac76969d29bddbd156db3290f65a8a6cad6cb4bce75dca343d35b2ed89999ae"
        "3b515a440d8942ddebd9545d3f836649106dd7282c1bd75aaa978ed7d39fe2387"
        "44b60b0df43ab9030a0083a76578e1d3932f3ef02c70fc0eaa386f2f50e83f983"
        "1cda1a6bd679e50b82b6801f029faeb545e4e59845d8c3b6fc13d1af5858cf278"
        "50c240d7fa400b5131232b10afa03db9c73358233d79af2e01c5fefba8b8878b"
        "9e97bfa6fda85937e0247e64d863e35e0deae9f3a66cd14fe6f35dc0daa58f785"
        "672b5cbeab4a1c69c23b967b71e1cc945458fe26ab6597512e68f208d7aa0382a"
        "f06949a4459c6102fdf89679d5812db41b98c7cf5f6931d5f4eb010c905e611c8"
        "68232d109434345af4ac8b11a1fb6f728d24e07d4da70fb700a496971cc80e7bf"
        "3b6cb1377a96f00fc83f8219434345af4ac8b119aa90050e34969929db2ce8c51"
        "dad15da629f7082844660e835d94147547fe1ee99504aa0f30bda8a3ca40b153"
        "bb795b914d94154c2075086bb8d6b3e63a8740d45418ff17f8765b42063663473"
        "820af067e715e4c50f16ba1acb7dd49eb019ea3de50cd3a45d64297bb4d7d1b65"
        "01c78dbbbe23569f237944392305162a10083561d6f223221195f135653e2df3"
        "347cd9632240e20b318a23b5d8de8f94f110f1bae087cbdacaa58d81afb92de78"
        "d1a5a8c8da7d7799c1f66f9551c552b2f5c5a3c6e82632657636bf9c76c7cfc5981"
    ),
    bytes.fromhex(
        "88360064e50ca94be7a63893abc92a76ef33113b64715a5d611327908b8c7d78"
        "30d686e9c2ae3a9934ea04ef3c1f06fa2f5953262e3f806925b3bf9c6114d860c"
        "8e1f382c8958befb4f9acb500ecdc8f97c994f0b0331a6bee128fdfce65c6e713"
        "f635f52e771e83ffc433f792da60e0d2ff2b95bb08c4b754d2d358a8af56d072b"
        "7cd5df2d4727494b4a3a44007a236cc681c9c0ec907d94835da90c34e6281b5fd"
        "b983ac6288f4e4fbb42eaddb7389207482503d54a6b2ec179267edbdda9d7bd2e"
        "ea3c61f0074ca80215b96e093a59a46fdb59ca4ad1935dc11ab3ec39a31402b3c"
        "279ca5a3bb3a6687c116234640ac0eb80b7a38f14a8d81afb92de78d1a5a8c8da"
        "7d7799c1f66f9551c552b2f5c5a3c6e826326576329ec7ceef07e96ca"
    ),
)
