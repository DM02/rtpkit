"""Tests for parse_rtp() and parse_rtp_lenient()."""

from __future__ import annotations

import struct

import pytest

from rtpkit import (
    RtpBufferTooShort,
    RtpExtensionError,
    RtpInvalidVersion,
    RtpPaddingError,
    parse_rtp,
    parse_rtp_lenient,
)
from .conftest import RtpBuilder


class TestHappyPath:
    """Packets that should parse without any errors."""

    def test_minimal_12_bytes(self) -> None:
        raw = RtpBuilder().with_seq(42).with_timestamp(800).with_ssrc(0x01020304).build()
        pkt = parse_rtp(raw)

        assert pkt.version == 2
        assert pkt.padding is False
        assert pkt.extension is False
        assert pkt.marker is False
        assert pkt.payload_type == 0
        assert pkt.sequence_number == 42
        assert pkt.timestamp == 800
        assert pkt.ssrc == 0x01020304
        assert pkt.csrc == ()
        assert pkt.cc == 0
        assert pkt.header_extension is None
        assert len(pkt.payload) == 0
        assert pkt.padding_size == 0
        assert pkt.header_size == 12
        assert pkt.total_size == 12

    def test_with_payload(self) -> None:
        payload = bytes(range(160))
        raw = RtpBuilder().with_payload_type(8).with_seq(100).with_payload(payload).build()
        pkt = parse_rtp(raw)

        assert pkt.payload_type == 8
        assert bytes(pkt.payload) == payload
        assert pkt.total_size == 12 + 160

    def test_with_csrc(self) -> None:
        csrc_list = [0x11111111, 0x22222222, 0x33333333]
        raw = RtpBuilder().with_csrc(csrc_list).with_payload(b"\xff" * 10).build()
        pkt = parse_rtp(raw)

        assert pkt.cc == 3
        assert pkt.csrc == tuple(csrc_list)
        assert pkt.header_size == 12 + 3 * 4

    def test_with_generic_extension(self) -> None:
        ext_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        raw = RtpBuilder().with_extension(profile=0xABCD, data=ext_data).build()
        pkt = parse_rtp(raw)

        assert pkt.extension is True
        assert pkt.header_extension is not None
        assert pkt.header_extension.profile == 0xABCD
        assert pkt.header_extension.length == 2
        assert bytes(pkt.header_extension.data) == ext_data
        assert pkt.header_size == 24

    def test_with_one_byte_extension(self) -> None:
        ext_data = bytes([0x12, 0xAA, 0xBB, 0xCC])
        raw = RtpBuilder().with_extension(profile=0xBEDE, data=ext_data).build()
        pkt = parse_rtp(raw)

        assert pkt.header_extension is not None
        assert pkt.header_extension.profile == 0xBEDE

    def test_with_two_byte_extension(self) -> None:
        ext_data = bytes([0x05, 0x02, 0xAA, 0xBB])
        raw = RtpBuilder().with_extension(profile=0x1000, data=ext_data).build()
        pkt = parse_rtp(raw)

        assert pkt.header_extension is not None
        assert pkt.header_extension.profile == 0x1000

    def test_with_padding(self) -> None:
        payload = b"\x80" * 20
        raw = RtpBuilder().with_payload(payload).with_padding(4).build()
        pkt = parse_rtp(raw)

        assert pkt.padding is True
        assert pkt.padding_size == 4
        assert bytes(pkt.payload) == payload

    def test_full_combination(self) -> None:
        csrc_list = [0xAAAAAAAA, 0xBBBBBBBB]
        ext_data = b"\xDE\xAD\xBE\xEF"
        payload = b"\x01" * 50
        raw = (
            RtpBuilder()
            .with_marker()
            .with_payload_type(111)
            .with_seq(65535)
            .with_timestamp(0xFFFFFFFF)
            .with_ssrc(0xCAFEBABE)
            .with_csrc(csrc_list)
            .with_extension(profile=0xBEDE, data=ext_data)
            .with_payload(payload)
            .with_padding(8)
            .build()
        )
        pkt = parse_rtp(raw)

        assert pkt.marker is True
        assert pkt.payload_type == 111
        assert pkt.sequence_number == 65535
        assert pkt.timestamp == 0xFFFFFFFF
        assert pkt.ssrc == 0xCAFEBABE
        assert pkt.cc == 2
        assert pkt.csrc == tuple(csrc_list)
        assert pkt.extension is True
        assert pkt.padding is True
        assert pkt.padding_size == 8
        assert bytes(pkt.payload) == payload


class TestEdgeCases:
    """Boundary / unusual but valid packets."""

    def test_exactly_12_bytes(self) -> None:
        raw = RtpBuilder().build()
        pkt = parse_rtp(raw)
        assert len(pkt.payload) == 0
        assert pkt.total_size == 12

    def test_max_csrc_15(self) -> None:
        csrc_list = list(range(1, 16))
        raw = RtpBuilder().with_csrc(csrc_list).build()
        pkt = parse_rtp(raw)
        assert pkt.cc == 15
        assert pkt.csrc == tuple(csrc_list)

    def test_extension_length_zero(self) -> None:
        raw = RtpBuilder().with_extension(profile=0x1234, data=b"").build()
        pkt = parse_rtp(raw)
        assert pkt.header_extension is not None
        assert pkt.header_extension.length == 0
        assert len(pkt.header_extension.data) == 0

    def test_padding_one_byte(self) -> None:
        raw = RtpBuilder().with_payload(b"\xAA" * 10).with_padding(1).build()
        pkt = parse_rtp(raw)
        assert pkt.padding_size == 1
        assert bytes(pkt.payload) == b"\xAA" * 10

    def test_padding_consumes_all_after_header(self) -> None:
        raw = RtpBuilder().with_payload(b"").with_padding(4).build()
        pkt = parse_rtp(raw)
        assert pkt.padding_size == 4
        assert len(pkt.payload) == 0

    def test_marker_bit(self) -> None:
        raw = RtpBuilder().with_marker().with_seq(999).build()
        pkt = parse_rtp(raw)
        assert pkt.marker is True

    def test_all_payload_types(self) -> None:
        for pt in (0, 127):
            raw = RtpBuilder().with_payload_type(pt).build()
            pkt = parse_rtp(raw)
            assert pkt.payload_type == pt


class TestStrictErrors:
    """parse_rtp() must raise specific exceptions on invalid input."""

    def test_empty_buffer(self) -> None:
        with pytest.raises(RtpBufferTooShort) as exc_info:
            parse_rtp(b"")
        assert exc_info.value.required == 12
        assert exc_info.value.actual == 0

    def test_buffer_too_short_11_bytes(self) -> None:
        with pytest.raises(RtpBufferTooShort) as exc_info:
            parse_rtp(b"\x80" * 11)
        assert exc_info.value.actual == 11

    @pytest.mark.parametrize("version", [0, 1, 3])
    def test_invalid_version(self, version: int) -> None:
        raw = RtpBuilder().with_version(version).build()
        with pytest.raises(RtpInvalidVersion) as exc_info:
            parse_rtp(raw)
        assert exc_info.value.version == version

    def test_csrc_truncated(self) -> None:
        raw = RtpBuilder().with_csrc([1, 2, 3, 4, 5]).build()
        truncated = raw[:20]
        with pytest.raises(RtpBufferTooShort):
            parse_rtp(truncated)

    def test_extension_header_truncated(self) -> None:
        raw = RtpBuilder().with_extension(profile=0xBEDE, data=b"\x00" * 4).build()
        truncated = raw[:12]
        with pytest.raises(RtpExtensionError):
            parse_rtp(truncated)

    def test_extension_data_truncated(self) -> None:
        raw = RtpBuilder().with_extension(profile=0xBEDE, data=b"\x00" * 8).build()
        truncated = raw[:18]
        with pytest.raises(RtpExtensionError):
            parse_rtp(truncated)

    def test_padding_zero(self) -> None:
        raw = bytearray(RtpBuilder().with_padding(4).build())
        raw[-1] = 0
        with pytest.raises(RtpPaddingError) as exc_info:
            parse_rtp(bytes(raw))
        assert exc_info.value.padding_value == 0

    def test_padding_overflow(self) -> None:
        raw = bytearray(RtpBuilder().with_payload(b"\x00" * 2).with_padding(1).build())
        raw[-1] = 200
        with pytest.raises(RtpPaddingError) as exc_info:
            parse_rtp(bytes(raw))
        assert exc_info.value.padding_value == 200


class TestLenientMode:
    """parse_rtp_lenient() should recover from non-critical problems."""

    def test_still_raises_on_too_short(self) -> None:
        with pytest.raises(RtpBufferTooShort):
            parse_rtp_lenient(b"\x00" * 5)

    @pytest.mark.parametrize("version", [0, 1, 3])
    def test_wrong_version_no_raise(self, version: int) -> None:
        raw = RtpBuilder().with_version(version).with_payload(b"\xAA").build()
        pkt = parse_rtp_lenient(raw)
        assert pkt.version == version
        assert bytes(pkt.payload) == b"\xAA"

    def test_broken_extension_skipped(self) -> None:
        raw = RtpBuilder().with_extension(profile=0xBEDE, data=b"\x00" * 8).build()
        truncated = raw[:14]
        pkt = parse_rtp_lenient(truncated)
        assert pkt.extension is True
        assert pkt.header_extension is None

    def test_padding_overflow_ignored(self) -> None:
        raw = bytearray(RtpBuilder().with_payload(b"\xBB" * 4).with_padding(1).build())
        raw[-1] = 200
        pkt = parse_rtp_lenient(bytes(raw))
        assert pkt.padding is True
        assert pkt.padding_size == 0

    def test_padding_zero_ignored(self) -> None:
        raw = bytearray(RtpBuilder().with_padding(2).build())
        raw[-1] = 0
        pkt = parse_rtp_lenient(bytes(raw))
        assert pkt.padding_size == 0

    def test_csrc_truncated_clamped(self) -> None:
        raw = RtpBuilder().with_csrc([1, 2, 3, 4, 5]).build()
        truncated = raw[:20]
        pkt = parse_rtp_lenient(truncated)
        assert pkt.cc == 2

    def test_extension_data_truncated_skipped(self) -> None:
        raw = RtpBuilder().with_extension(profile=0xBEDE, data=b"\x00" * 8).build()
        truncated = raw[:18]
        pkt = parse_rtp_lenient(truncated)
        assert pkt.extension is True
        assert pkt.header_extension is None

    def test_padding_no_bytes_after_header(self) -> None:
        raw = bytearray(12)
        raw[0] = 0x80 | 0x20  # V=2, P=1
        pkt = parse_rtp_lenient(bytes(raw))
        assert pkt.padding is True
        assert pkt.padding_size == 0


class TestZeroCopy:
    """Verify that payloads are memoryview references, not copies."""

    def test_payload_shares_buffer(self) -> None:
        raw = RtpBuilder().with_payload(b"\x01\x02\x03\x04").build()
        buf = bytearray(raw)
        pkt = parse_rtp(buf)
        assert pkt.payload.obj is buf

    def test_mutation_visible(self) -> None:
        raw = bytearray(RtpBuilder().with_payload(b"\x00\x00\x00\x00").build())
        pkt = parse_rtp(raw)
        assert pkt.payload[0] == 0
        raw[12] = 0xFF
        assert pkt.payload[0] == 0xFF

    def test_accepts_memoryview_input(self) -> None:
        raw = RtpBuilder().with_payload(b"\xAB").build()
        pkt = parse_rtp(memoryview(bytearray(raw)))
        assert bytes(pkt.payload) == b"\xAB"

    def test_accepts_bytes(self) -> None:
        pkt = parse_rtp(RtpBuilder().with_payload(b"\xCD").build())
        assert bytes(pkt.payload) == b"\xCD"

    def test_accepts_bytearray(self) -> None:
        pkt = parse_rtp(bytearray(RtpBuilder().with_payload(b"\xEF").build()))
        assert bytes(pkt.payload) == b"\xEF"


class TestImmutability:
    """RtpPacket should be frozen."""

    def test_cannot_set_attribute(self) -> None:
        pkt = parse_rtp(RtpBuilder().build())
        with pytest.raises(AttributeError):
            pkt.version = 3  # type: ignore[misc]

    def test_cannot_set_payload(self) -> None:
        pkt = parse_rtp(RtpBuilder().with_payload(b"\x00").build())
        with pytest.raises(AttributeError):
            pkt.payload = memoryview(b"\xFF")  # type: ignore[misc]
