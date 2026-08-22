"""Tests for parse_extension_elements()."""

from __future__ import annotations

from rtpkit.model.extension import (
    ExtensionProfile,
    HeaderExtension,
    classify_profile,
    parse_extension_elements,
)


class TestClassifyProfile:
    def test_one_byte(self) -> None:
        assert classify_profile(0xBEDE) is ExtensionProfile.ONE_BYTE

    def test_two_byte_exact(self) -> None:
        assert classify_profile(0x1000) is ExtensionProfile.TWO_BYTE

    def test_two_byte_with_appbits(self) -> None:
        assert classify_profile(0x1005) is ExtensionProfile.TWO_BYTE
        assert classify_profile(0x100F) is ExtensionProfile.TWO_BYTE

    def test_unknown(self) -> None:
        assert classify_profile(0xABCD) is ExtensionProfile.UNKNOWN
        assert classify_profile(0x0000) is ExtensionProfile.UNKNOWN


class TestOneByteParsing:
    def _make_ext(self, data: bytes) -> HeaderExtension:
        return HeaderExtension(profile=0xBEDE, length=len(data) // 4, data=memoryview(data))

    def test_single_element(self) -> None:
        data = bytes([0x12, 0xAA, 0xBB, 0xCC])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 1
        assert elems[0].id == 1
        assert bytes(elems[0].data) == b"\xaa\xbb\xcc"

    def test_multiple_elements(self) -> None:
        data = bytes([0x30, 0xDD, 0x51, 0xEE, 0xFF, 0x00, 0x00, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 2
        assert elems[0].id == 3
        assert bytes(elems[0].data) == b"\xdd"
        assert elems[1].id == 5
        assert bytes(elems[1].data) == b"\xee\xff"

    def test_padding_between_elements(self) -> None:
        data = bytes([0x20, 0xAA, 0x00, 0x00, 0x40, 0xBB, 0x00, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 2
        assert elems[0].id == 2
        assert elems[1].id == 4

    def test_id15_terminates(self) -> None:
        data = bytes([0xF0, 0x00, 0x00, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 0

    def test_truncated_element_data(self) -> None:
        data = bytes([0x1F, 0xAA, 0xBB, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 0

    def test_empty_extension(self) -> None:
        elems = parse_extension_elements(self._make_ext(b""))
        assert len(elems) == 0


class TestTwoByteParsing:
    def _make_ext(self, data: bytes) -> HeaderExtension:
        return HeaderExtension(profile=0x1000, length=len(data) // 4, data=memoryview(data))

    def test_single_element(self) -> None:
        data = bytes([0x05, 0x02, 0xAA, 0xBB])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 1
        assert elems[0].id == 5
        assert bytes(elems[0].data) == b"\xaa\xbb"

    def test_element_with_zero_length(self) -> None:
        data = bytes([0x0A, 0x00, 0x00, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 1
        assert elems[0].id == 10
        assert len(elems[0].data) == 0

    def test_multiple_elements(self) -> None:
        data = bytes([0x01, 0x01, 0xAA, 0x02, 0x01, 0xBB, 0x00, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 2
        assert elems[0].id == 1
        assert elems[1].id == 2

    def test_padding_id_zero(self) -> None:
        data = bytes([0x00, 0x00, 0x05, 0x01, 0xCC, 0x00, 0x00, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 1
        assert elems[0].id == 5

    def test_truncated(self) -> None:
        data = bytes([0x05, 0x0A, 0xAA, 0x00])
        elems = parse_extension_elements(self._make_ext(data))
        assert len(elems) == 0

    def test_empty(self) -> None:
        elems = parse_extension_elements(self._make_ext(b""))
        assert len(elems) == 0


class TestUnknownProfile:
    def test_returns_empty_tuple(self) -> None:
        ext = HeaderExtension(profile=0xABCD, length=1, data=memoryview(b"\x00\x00\x00\x00"))
        assert parse_extension_elements(ext) == ()


class TestHeaderExtensionClassify:
    def test_one_byte(self) -> None:
        ext = HeaderExtension(profile=0xBEDE, length=0, data=memoryview(b""))
        assert ext.classify() is ExtensionProfile.ONE_BYTE

    def test_two_byte(self) -> None:
        ext = HeaderExtension(profile=0x1003, length=0, data=memoryview(b""))
        assert ext.classify() is ExtensionProfile.TWO_BYTE

    def test_unknown(self) -> None:
        ext = HeaderExtension(profile=0x5555, length=0, data=memoryview(b""))
        assert ext.classify() is ExtensionProfile.UNKNOWN
