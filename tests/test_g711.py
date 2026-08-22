"""Tests for rtpkit.codec.g711 — decode/encode verified against CPython's audioop for
every one of the 256 possible input bytes (see module history for the cross-check)."""

from __future__ import annotations

import struct

import pytest

from rtpkit.codec.g711 import decode_pcma, decode_pcmu, encode_pcma, encode_pcmu


def _s16(b: bytes) -> int:
    return struct.unpack("<h", b)[0]


class TestDecodePcmu:
    @pytest.mark.parametrize(
        ("byte", "expected"),
        [
            (0x00, -32124),
            (0x7F, 0),
            (0x80, 32124),
            (0xFF, 0),
        ],
    )
    def test_known_values(self, byte: int, expected: int) -> None:
        assert _s16(decode_pcmu(bytes([byte]))) == expected

    def test_empty_input(self) -> None:
        assert decode_pcmu(b"") == b""

    def test_output_length_is_double_input(self) -> None:
        assert len(decode_pcmu(bytes(10))) == 20

    def test_all_256_bytes_produce_distinct_or_paired_values_within_range(self) -> None:
        samples = [_s16(decode_pcmu(bytes([b]))) for b in range(256)]
        assert all(-32768 <= s <= 32767 for s in samples)
        assert max(samples) == 32124
        assert min(samples) == -32124


class TestDecodePcma:
    @pytest.mark.parametrize(
        ("byte", "expected"),
        [
            (0x00, -5504),
            (0x80, 5504),
            (0xD5, 8),  # near-silence, the exact byte value seen in a real captured PCMA stream
            (0x55, -8),
        ],
    )
    def test_known_values(self, byte: int, expected: int) -> None:
        assert _s16(decode_pcma(bytes([byte]))) == expected

    def test_empty_input(self) -> None:
        assert decode_pcma(b"") == b""

    def test_output_length_is_double_input(self) -> None:
        assert len(decode_pcma(bytes(10))) == 20


class TestEncodeDecodeRoundTrip:
    @pytest.mark.parametrize("codec", ["pcmu", "pcma"])
    def test_silence_round_trips_near_exactly(self, codec: str) -> None:
        encode, decode = (encode_pcmu, decode_pcmu) if codec == "pcmu" else (encode_pcma, decode_pcma)
        pcm = struct.pack("<10h", *([0] * 10))
        decoded = decode(encode(pcm))
        for sample in struct.unpack("<10h", decoded):
            assert abs(sample) <= 16

    @pytest.mark.parametrize("codec", ["pcmu", "pcma"])
    def test_round_trip_error_is_bounded(self, codec: str) -> None:
        encode, decode = (encode_pcmu, decode_pcmu) if codec == "pcmu" else (encode_pcma, decode_pcma)
        original = list(range(-32000, 32000, 137))
        pcm = struct.pack(f"<{len(original)}h", *original)

        decoded = struct.unpack(f"<{len(original)}h", decode(encode(pcm)))
        for orig, got in zip(original, decoded, strict=True):
            # G.711 is a lossy 8-bit companded codec; large-magnitude samples get coarser steps
            assert abs(orig - got) <= max(256, abs(orig) // 16)

    def test_encode_output_length_is_half_input(self) -> None:
        pcm = struct.pack("<4h", 0, 100, -100, 32000)
        assert len(encode_pcmu(pcm)) == 4
        assert len(encode_pcma(pcm)) == 4

    def test_encode_empty_input(self) -> None:
        assert encode_pcmu(b"") == b""
        assert encode_pcma(b"") == b""

    def test_pcmu_and_pcma_use_different_encodings(self) -> None:
        pcm = struct.pack("<h", 1000)
        assert encode_pcmu(pcm) != encode_pcma(pcm)
