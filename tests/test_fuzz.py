"""Fuzz rtpkit's own parsers with rtpkit.fuzz — they must never crash on garbage.

Strict entry points may only raise their documented typed error(s); lenient
entry points may only raise the one narrow exception each is documented to
still raise. Anything else is a bug in the parser, not a bug in this test.
"""

from __future__ import annotations

import random

import pytest

from rtpkit import (
    CaptureError,
    PcapBufferTooShort,
    PcapInvalidMagic,
    PcapngBufferTooShort,
    PcapngInvalidByteOrderMagic,
    PcapngMalformedBlock,
    RtcpBufferTooShort,
    RtcpError,
    RtpBufferTooShort,
    RtpBuilder,
    RtpError,
    decapsulate_udp,
    fuzz_cases,
    fuzz_parser,
    parse_rtcp,
    parse_rtcp_lenient,
    parse_rtp,
    parse_rtp_lenient,
    read_pcap,
    read_pcap_lenient,
    read_pcapng,
    read_pcapng_lenient,
)

from .conftest import (
    build_bye,
    build_epb,
    build_ethernet_frame,
    build_idb,
    build_ipv4_packet,
    build_ipv6_packet,
    build_pcap_global_header,
    build_pcap_record,
    build_rr,
    build_sdes,
    build_sdes_chunk,
    build_sdes_item,
    build_shb,
    build_sll_frame,
    build_sr,
    build_udp_datagram,
)

_CASES_PER_PARSER = 800

RTP_SEEDS = [
    RtpBuilder().build(),
    RtpBuilder().with_payload_type(8).with_sequence_number(1000).with_payload(b"\xaa" * 160).build(),
    RtpBuilder().with_csrc([1, 2, 3]).with_extension(0xBEDE, b"\x11\x22\x33\x00").with_payload(b"\x00" * 20).build(),
    RtpBuilder().with_padding(4).with_payload(b"\xaa" * 16).build(),
]

RTCP_SEEDS = [
    build_sr(ssrc=1),
    build_rr(ssrc=1),
    build_sdes(chunks=(build_sdes_chunk(ssrc=1, items=build_sdes_item(1, b"alice")),)),
    build_bye(sources=(1, 2), reason=b"done"),
]

_PCAP_SEED = (
    build_pcap_global_header(link_type=1) + build_pcap_record(1, 0, b"\xaa" * 20) + build_pcap_record(2, 0, b"\xbb" * 5)
)

_PCAPNG_SEED = build_shb() + build_idb(link_type=1) + build_epb(0, 1_000_000, b"\xaa" * 20)

_ETH_IPV4_SEED = build_ethernet_frame(
    0x0800, build_ipv4_packet(17, "10.0.0.1", "10.0.0.2", build_udp_datagram(5004, 5006, b"\xaa" * 20))
)
_ETH_IPV6_SEED = build_ethernet_frame(
    0x86DD, build_ipv6_packet(17, "2001:db8::1", "2001:db8::2", build_udp_datagram(5004, 5006, b"\xaa" * 20))
)
_SLL_SEED = build_sll_frame(
    0x0800, build_ipv4_packet(17, "10.0.0.1", "10.0.0.2", build_udp_datagram(1, 2, b"\xaa" * 20))
)
_RAW_SEED = build_ipv4_packet(17, "10.0.0.1", "10.0.0.2", build_udp_datagram(1, 2, b"\xaa" * 20))


def _crash_report(result) -> str:  # type: ignore[no-untyped-def]
    return "\n".join(f"{c.exception_type}: {c.message} | input={c.input.hex()}" for c in result.crashes[:5])


def test_fuzz_parse_rtp_strict() -> None:
    rng = random.Random(1)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=RTP_SEEDS))
    result = fuzz_parser(parse_rtp, cases, allowed_exceptions=RtpError)
    assert result.ok, _crash_report(result)


def test_fuzz_parse_rtp_lenient() -> None:
    rng = random.Random(2)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=RTP_SEEDS))
    result = fuzz_parser(parse_rtp_lenient, cases, allowed_exceptions=RtpBufferTooShort)
    assert result.ok, _crash_report(result)


def test_fuzz_parse_rtcp_strict() -> None:
    rng = random.Random(3)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=RTCP_SEEDS))
    result = fuzz_parser(parse_rtcp, cases, allowed_exceptions=RtcpError)
    assert result.ok, _crash_report(result)


def test_fuzz_parse_rtcp_lenient() -> None:
    rng = random.Random(4)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=RTCP_SEEDS))
    result = fuzz_parser(parse_rtcp_lenient, cases, allowed_exceptions=RtcpBufferTooShort)
    assert result.ok, _crash_report(result)


def test_fuzz_read_pcap_strict() -> None:
    rng = random.Random(5)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=[_PCAP_SEED]))
    result = fuzz_parser(lambda d: list(read_pcap(d)), cases, allowed_exceptions=CaptureError)
    assert result.ok, _crash_report(result)


def test_fuzz_read_pcap_lenient() -> None:
    rng = random.Random(6)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=[_PCAP_SEED]))
    result = fuzz_parser(
        lambda d: list(read_pcap_lenient(d)), cases, allowed_exceptions=(PcapBufferTooShort, PcapInvalidMagic)
    )
    assert result.ok, _crash_report(result)


def test_fuzz_read_pcapng_strict() -> None:
    rng = random.Random(7)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=[_PCAPNG_SEED]))
    result = fuzz_parser(lambda d: list(read_pcapng(d)), cases, allowed_exceptions=CaptureError)
    assert result.ok, _crash_report(result)


def test_fuzz_read_pcapng_lenient() -> None:
    rng = random.Random(8)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=[_PCAPNG_SEED]))
    result = fuzz_parser(
        lambda d: list(read_pcapng_lenient(d)),
        cases,
        allowed_exceptions=(PcapngBufferTooShort, PcapngInvalidByteOrderMagic, PcapngMalformedBlock),
    )
    assert result.ok, _crash_report(result)


@pytest.mark.parametrize(
    ("link_type", "seed"),
    [(1, _ETH_IPV4_SEED), (1, _ETH_IPV6_SEED), (113, _SLL_SEED), (101, _RAW_SEED)],
    ids=["ethernet-ipv4", "ethernet-ipv6", "linux-sll", "raw-ip"],
)
def test_fuzz_decapsulate_udp_never_raises(link_type: int, seed: bytes) -> None:
    rng = random.Random(9)
    cases = list(fuzz_cases(rng, _CASES_PER_PARSER, seeds=[seed]))
    result = fuzz_parser(lambda d, lt=link_type: decapsulate_udp(lt, d), cases)
    assert result.ok, _crash_report(result)
