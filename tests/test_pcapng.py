"""Tests for read_pcapng() and read_pcapng_lenient()."""

from __future__ import annotations

import struct

import pytest

from rtpkit import (
    PcapngBufferTooShort,
    PcapngInvalidByteOrderMagic,
    PcapngMalformedBlock,
    read_pcapng,
    read_pcapng_lenient,
)

from .conftest import build_epb, build_idb, build_pcapng_block, build_shb, build_spb


class TestHappyPath:
    @pytest.mark.parametrize("order", ["<", ">"])
    def test_single_interface_single_packet(self, order: str) -> None:
        raw = build_shb(order) + build_idb(link_type=1, order=order) + build_epb(0, 1_000_000, b"\xaa\xbb", order=order)
        (pkt,) = list(read_pcapng(raw))

        assert pkt.link_type == 1
        assert bytes(pkt.data) == b"\xaa\xbb"
        assert pkt.timestamp == pytest.approx(1.0)

    def test_multiple_interfaces(self) -> None:
        raw = (
            build_shb()
            + build_idb(link_type=1)
            + build_idb(link_type=113)
            + build_epb(0, 0, b"\x01")
            + build_epb(1, 0, b"\x02")
        )
        packets = list(read_pcapng(raw))

        assert packets[0].link_type == 1
        assert packets[1].link_type == 113

    def test_custom_ts_resolution_nanoseconds(self) -> None:
        raw = build_shb() + build_idb(link_type=1, if_tsresol=9) + build_epb(0, 1_500_000_000, b"\x01")
        (pkt,) = list(read_pcapng(raw))
        assert pkt.timestamp == pytest.approx(1.5)

    def test_custom_ts_resolution_power_of_two(self) -> None:
        raw = build_shb() + build_idb(link_type=1, if_tsresol=0x80 | 10) + build_epb(0, 1536, b"\x01")
        (pkt,) = list(read_pcapng(raw))
        assert pkt.timestamp == pytest.approx(1536 / 1024)

    def test_simple_packet_block(self) -> None:
        raw = build_shb() + build_idb(link_type=1) + build_spb(b"\xaa\xbb\xcc")
        (pkt,) = list(read_pcapng(raw))
        assert bytes(pkt.data) == b"\xaa\xbb\xcc"
        assert pkt.link_type == 1

    def test_unknown_block_type_is_skipped(self) -> None:
        unknown = build_pcapng_block(0x99999999, b"\x01\x02\x03\x04")
        raw = build_shb() + build_idb(link_type=1) + unknown + build_epb(0, 0, b"\x01")
        (pkt,) = list(read_pcapng(raw))
        assert bytes(pkt.data) == b"\x01"

    def test_multiple_sections_reset_interfaces(self) -> None:
        section1 = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x01")
        section2 = build_shb(order=">") + build_idb(link_type=113, order=">") + build_epb(0, 0, b"\x02", order=">")
        packets = list(read_pcapng(section1 + section2))

        assert packets[0].link_type == 1
        assert packets[1].link_type == 113

    def test_accepts_memoryview_input(self) -> None:
        raw = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x01")
        (pkt,) = list(read_pcapng(memoryview(raw)))
        assert bytes(pkt.data) == b"\x01"

    def test_idb_with_no_tsresol_option_defaults_to_microseconds(self) -> None:
        idb_body = struct.pack("<HHI", 1, 0, 262144) + struct.pack("<HH", 0, 0)  # explicit opt_endofopt, no options
        raw = build_shb() + build_pcapng_block(0x00000001, idb_body) + build_epb(0, 2_000_000, b"\x01")
        (pkt,) = list(read_pcapng(raw))
        assert pkt.timestamp == pytest.approx(2.0)

    def test_idb_with_malformed_option_length_defaults_to_microseconds(self) -> None:
        # declares a 100-byte option value, but none follow
        idb_body = struct.pack("<HHI", 1, 0, 262144) + struct.pack("<HH", 9, 100)
        raw = build_shb() + build_pcapng_block(0x00000001, idb_body) + build_epb(0, 2_000_000, b"\x01")
        (pkt,) = list(read_pcapng(raw))
        assert pkt.timestamp == pytest.approx(2.0)

    def test_data_is_zero_copy_view(self) -> None:
        shb = build_shb()
        idb = build_idb(link_type=1)
        epb = build_epb(0, 0, b"\x01")
        raw = bytearray(shb + idb + epb)

        data_offset = len(shb) + len(idb) + 8 + 20  # block header + fixed EPB fields
        (pkt,) = list(read_pcapng(raw))
        raw[data_offset] = 0xFF
        assert bytes(pkt.data) == b"\xff"


class TestStrictErrors:
    def test_empty_buffer_raises(self) -> None:
        with pytest.raises(PcapngBufferTooShort):
            list(read_pcapng(b""))

    def test_missing_section_header_raises(self) -> None:
        raw = build_idb(link_type=1)
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))

    def test_invalid_byte_order_magic_raises(self) -> None:
        raw = struct.pack("<II", 0x0A0D0D0A, 16) + b"\x00\x00\x00\x00" + struct.pack("<I", 16)
        with pytest.raises(PcapngInvalidByteOrderMagic):
            list(read_pcapng(raw))

    def test_block_length_overrun_raises(self) -> None:
        raw = build_shb() + struct.pack("<II", 0x00000001, 1000) + b"\x00" * 8
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))

    def test_idb_too_short_raises(self) -> None:
        raw = build_shb() + build_pcapng_block(0x00000001, b"\x01\x02")
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))

    def test_epb_too_short_raises(self) -> None:
        raw = build_shb() + build_idb(link_type=1) + build_pcapng_block(0x00000006, b"\x00" * 8)
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))

    def test_epb_declares_more_captured_bytes_than_present_raises(self) -> None:
        body = struct.pack("<IIIII", 0, 0, 0, 100, 100)
        raw = build_shb() + build_idb(link_type=1) + build_pcapng_block(0x00000006, body)
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))

    def test_epb_unknown_interface_raises(self) -> None:
        raw = build_shb() + build_idb(link_type=1) + build_epb(iface_id=5, ts_ticks=0, packet_data=b"\x01")
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))

    def test_spb_too_short_raises(self) -> None:
        raw = build_shb() + build_idb(link_type=1) + build_pcapng_block(0x00000003, b"")
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng(raw))


class TestLenientMode:
    def test_malformed_block_is_skipped(self) -> None:
        bad_epb = build_pcapng_block(0x00000006, b"\x00" * 8)
        good_epb = build_epb(0, 0, b"\x01")
        raw = build_shb() + build_idb(link_type=1) + bad_epb + good_epb
        packets = list(read_pcapng_lenient(raw))
        assert len(packets) == 1
        assert bytes(packets[0].data) == b"\x01"

    def test_block_length_overrun_stops(self) -> None:
        good = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x01")
        truncated = struct.pack("<II", 0x00000006, 1000) + b"\x00" * 8
        packets = list(read_pcapng_lenient(good + truncated))
        assert len(packets) == 1

    def test_still_raises_on_missing_section_header(self) -> None:
        with pytest.raises(PcapngMalformedBlock):
            list(read_pcapng_lenient(build_idb(link_type=1)))

    def test_still_raises_on_invalid_byte_order_magic(self) -> None:
        raw = struct.pack("<II", 0x0A0D0D0A, 16) + b"\x00\x00\x00\x00" + struct.pack("<I", 16)
        with pytest.raises(PcapngInvalidByteOrderMagic):
            list(read_pcapng_lenient(raw))

    def test_trailing_short_block_stops(self) -> None:
        raw = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x01") + b"\x00\x00\x00"
        packets = list(read_pcapng_lenient(raw))
        assert len(packets) == 1


def test_strict_raises_on_trailing_short_block() -> None:
    raw = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x01") + b"\x00\x00\x00"
    with pytest.raises(PcapngBufferTooShort):
        list(read_pcapng(raw))
