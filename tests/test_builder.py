"""Tests for rtpkit.builder — RtpBuilder and build_header_extension."""

from __future__ import annotations

import pytest

from rtpkit import (
    ExtensionElement,
    ExtensionProfile,
    RtpBuildError,
    RtpBuilder,
    build_header_extension,
    parse_extension_elements,
    parse_rtp,
)


def test_build_minimal_round_trips_through_parse_rtp() -> None:
    pkt = RtpBuilder().build_packet()

    assert pkt.version == 2
    assert pkt.padding is False
    assert pkt.extension is False
    assert pkt.marker is False
    assert pkt.payload_type == 0
    assert pkt.sequence_number == 0
    assert pkt.timestamp == 0
    assert pkt.ssrc == 0
    assert pkt.csrc == ()
    assert bytes(pkt.payload) == b""


def test_build_sets_all_fixed_header_fields() -> None:
    pkt = (
        RtpBuilder()
        .with_marker(True)
        .with_payload_type(8)
        .with_sequence_number(1000)
        .with_timestamp(160_000)
        .with_ssrc(0xDEADBEEF)
        .with_payload(b"\xaa" * 16)
        .build_packet()
    )

    assert pkt.marker is True
    assert pkt.payload_type == 8
    assert pkt.sequence_number == 1000
    assert pkt.timestamp == 160_000
    assert pkt.ssrc == 0xDEADBEEF
    assert bytes(pkt.payload) == b"\xaa" * 16


def test_build_with_csrc() -> None:
    pkt = RtpBuilder().with_csrc([0x11111111, 0x22222222]).build_packet()

    assert pkt.cc == 2
    assert pkt.csrc == (0x11111111, 0x22222222)


def test_build_with_padding() -> None:
    pkt = RtpBuilder().with_payload(b"\xaa" * 10).with_padding(4).build_packet()

    assert pkt.padding is True
    assert pkt.padding_size == 4
    assert bytes(pkt.payload) == b"\xaa" * 10


def test_padding_zero_means_disabled() -> None:
    pkt = RtpBuilder().with_padding(0).build_packet()
    assert pkt.padding is False


def test_build_with_raw_extension() -> None:
    pkt = RtpBuilder().with_extension(0xBEDE, b"\x11\x05\x0a\x00").build_packet()

    assert pkt.extension is True
    assert pkt.header_extension is not None
    assert pkt.header_extension.profile == 0xBEDE
    assert bytes(pkt.header_extension.data) == b"\x11\x05\x0a\x00"


@pytest.mark.parametrize("profile", [ExtensionProfile.ONE_BYTE, ExtensionProfile.TWO_BYTE])
def test_build_with_extension_elements_round_trips(profile: ExtensionProfile) -> None:
    elements = (ExtensionElement(id=1, data=b"\x2a"), ExtensionElement(id=2, data=b"\x01\x02"))

    pkt = RtpBuilder().with_extension_elements(elements, profile=profile).build_packet()

    assert pkt.header_extension is not None
    parsed = parse_extension_elements(pkt.header_extension)
    assert len(parsed) == 2
    assert parsed[0].id == 1
    assert bytes(parsed[0].data) == b"\x2a"
    assert parsed[1].id == 2
    assert bytes(parsed[1].data) == b"\x01\x02"


def test_build_bytes_matches_parse_rtp() -> None:
    raw = RtpBuilder().with_payload_type(8).with_sequence_number(42).build()
    pkt = parse_rtp(raw)
    assert pkt.payload_type == 8
    assert pkt.sequence_number == 42


@pytest.mark.parametrize(
    "make",
    [
        lambda: RtpBuilder().with_version(4),
        lambda: RtpBuilder().with_version(-1),
        lambda: RtpBuilder().with_payload_type(128),
        lambda: RtpBuilder().with_sequence_number(-1),
        lambda: RtpBuilder().with_sequence_number(0x10000),
        lambda: RtpBuilder().with_timestamp(-1),
        lambda: RtpBuilder().with_timestamp(0x1_0000_0000),
        lambda: RtpBuilder().with_ssrc(-1),
        lambda: RtpBuilder().with_ssrc(0x1_0000_0000),
        lambda: RtpBuilder().with_csrc(list(range(16))),
        lambda: RtpBuilder().with_csrc([-1]),
        lambda: RtpBuilder().with_extension(0x10000, b""),
        lambda: RtpBuilder().with_extension(0xBEDE, b"\x00\x00\x00"),
        lambda: RtpBuilder().with_padding(-1),
        lambda: RtpBuilder().with_padding(256),
    ],
)
def test_build_rejects_out_of_range_fields(make: "object") -> None:
    builder = make()  # type: ignore[operator]
    with pytest.raises(RtpBuildError):
        builder.build()


def test_build_rejects_extension_word_count_overflow() -> None:
    oversized = b"\x00" * ((0xFFFF + 1) * 4)
    with pytest.raises(RtpBuildError):
        RtpBuilder().with_extension(0xBEDE, oversized).build()


def test_build_header_extension_rejects_unknown_profile() -> None:
    with pytest.raises(RtpBuildError):
        build_header_extension([ExtensionElement(id=1, data=b"\x00")], profile=ExtensionProfile.UNKNOWN)


@pytest.mark.parametrize(
    "elements",
    [
        [ExtensionElement(id=0, data=b"\x00")],
        [ExtensionElement(id=15, data=b"\x00")],
        [ExtensionElement(id=1, data=b"")],
        [ExtensionElement(id=1, data=b"\x00" * 17)],
    ],
)
def test_build_one_byte_extension_rejects_invalid_elements(elements: list[ExtensionElement]) -> None:
    with pytest.raises(RtpBuildError):
        build_header_extension(elements, profile=ExtensionProfile.ONE_BYTE)


@pytest.mark.parametrize(
    "elements",
    [
        [ExtensionElement(id=0, data=b"\x00")],
        [ExtensionElement(id=256, data=b"\x00")],
        [ExtensionElement(id=1, data=b"\x00" * 256)],
    ],
)
def test_build_two_byte_extension_rejects_invalid_elements(elements: list[ExtensionElement]) -> None:
    with pytest.raises(RtpBuildError):
        build_header_extension(elements, profile=ExtensionProfile.TWO_BYTE)
