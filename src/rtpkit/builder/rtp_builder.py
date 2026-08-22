"""Fluent RTP packet builder — the inverse of parser.rtp_parser.parse_rtp."""

from __future__ import annotations

import struct
from collections.abc import Sequence

from ..model.errors import RtpBuildError
from ..model.extension import ExtensionElement, ExtensionProfile, build_header_extension
from ..model.packet import RtpPacket
from ..parser.rtp_parser import parse_rtp

__all__ = ["RtpBuilder"]

_MAX_CSRC = 15
_U16 = 0xFFFF
_U32 = 0xFFFFFFFF


class RtpBuilder:
    """Fluent builder for raw RTP packets.

    Usage::

        pkt = (
            RtpBuilder()
            .with_payload_type(8)
            .with_sequence_number(1000)
            .with_timestamp(160_000)
            .with_ssrc(0xDEADBEEF)
            .with_payload(b"\\x80" * 160)
            .build_packet()
        )
    """

    def __init__(self) -> None:
        self._version: int = 2
        self._padding: int = 0
        self._marker: bool = False
        self._payload_type: int = 0
        self._seq: int = 0
        self._timestamp: int = 0
        self._ssrc: int = 0
        self._csrc: list[int] = []
        self._ext_profile: int | None = None
        self._ext_data: bytes = b""
        self._payload: bytes = b""

    def with_version(self, version: int) -> RtpBuilder:
        self._version = version
        return self

    def with_marker(self, marker: bool = True) -> RtpBuilder:
        self._marker = marker
        return self

    def with_payload_type(self, payload_type: int) -> RtpBuilder:
        self._payload_type = payload_type
        return self

    def with_sequence_number(self, seq: int) -> RtpBuilder:
        self._seq = seq
        return self

    def with_timestamp(self, timestamp: int) -> RtpBuilder:
        self._timestamp = timestamp
        return self

    def with_ssrc(self, ssrc: int) -> RtpBuilder:
        self._ssrc = ssrc
        return self

    def with_csrc(self, csrc: Sequence[int]) -> RtpBuilder:
        self._csrc = list(csrc)
        return self

    def with_extension(self, profile: int, data: bytes) -> RtpBuilder:
        self._ext_profile = profile
        self._ext_data = bytes(data)
        return self

    def with_extension_elements(
        self,
        elements: Sequence[ExtensionElement],
        profile: ExtensionProfile = ExtensionProfile.ONE_BYTE,
    ) -> RtpBuilder:
        ext = build_header_extension(elements, profile=profile)
        return self.with_extension(ext.profile, bytes(ext.data))

    def with_payload(self, payload: bytes) -> RtpBuilder:
        self._payload = bytes(payload)
        return self

    def with_padding(self, count: int) -> RtpBuilder:
        """*count* bytes of padding; the last byte encodes *count*. 0 disables padding."""
        self._padding = count
        return self

    def build(self) -> bytes:
        self._validate()

        cc = len(self._csrc)
        has_ext = self._ext_profile is not None
        has_pad = self._padding > 0

        byte0 = ((self._version & 0x03) << 6) | (int(has_pad) << 5) | (int(has_ext) << 4) | (cc & 0x0F)
        byte1 = (int(self._marker) << 7) | (self._payload_type & 0x7F)

        parts: list[bytes] = [struct.pack("!BBHII", byte0, byte1, self._seq, self._timestamp, self._ssrc)]

        if cc:
            parts.append(struct.pack(f"!{cc}I", *self._csrc))

        if has_ext:
            assert self._ext_profile is not None
            parts.append(struct.pack("!HH", self._ext_profile, len(self._ext_data) // 4))
            parts.append(self._ext_data)

        parts.append(self._payload)

        if has_pad:
            parts.append(b"\x00" * (self._padding - 1))
            parts.append(struct.pack("B", self._padding))

        return b"".join(parts)

    def build_packet(self) -> RtpPacket:
        """Build then parse, so the result matches what :func:`parse_rtp` would produce."""
        return parse_rtp(self.build())

    def _validate(self) -> None:
        if not 0 <= self._version <= 3:
            raise RtpBuildError("version", f"must be 0-3, got {self._version}")
        if not 0 <= self._payload_type <= 127:
            raise RtpBuildError("payload_type", f"must be 0-127, got {self._payload_type}")
        if not 0 <= self._seq <= _U16:
            raise RtpBuildError("sequence_number", f"must fit in 16 bits, got {self._seq}")
        if not 0 <= self._timestamp <= _U32:
            raise RtpBuildError("timestamp", f"must fit in 32 bits, got {self._timestamp}")
        if not 0 <= self._ssrc <= _U32:
            raise RtpBuildError("ssrc", f"must fit in 32 bits, got {self._ssrc}")
        if len(self._csrc) > _MAX_CSRC:
            raise RtpBuildError("csrc", f"at most {_MAX_CSRC} entries, got {len(self._csrc)}")
        for i, c in enumerate(self._csrc):
            if not 0 <= c <= _U32:
                raise RtpBuildError("csrc", f"entry {i} must fit in 32 bits, got {c}")
        if self._ext_profile is not None:
            if not 0 <= self._ext_profile <= _U16:
                raise RtpBuildError("extension profile", f"must fit in 16 bits, got {self._ext_profile}")
            if len(self._ext_data) % 4 != 0:
                raise RtpBuildError("extension data", f"length must be a multiple of 4, got {len(self._ext_data)}")
            if len(self._ext_data) // 4 > _U16:
                raise RtpBuildError("extension data", "word count exceeds 16 bits")
        if self._padding and not 1 <= self._padding <= 255:
            raise RtpBuildError("padding", f"must be 1-255, got {self._padding}")
