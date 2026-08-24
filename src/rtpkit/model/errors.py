"""RTP parsing error hierarchy.

All exceptions raised by rtpkit inherit from :class:`RtpError`,
so callers can catch the base class for a broad filter or specific
subclasses for targeted handling.
"""

from __future__ import annotations

__all__ = [
    "RtpError",
    "RtpBufferTooShort",
    "RtpInvalidVersion",
    "RtpPaddingError",
    "RtpExtensionError",
    "RtpBuildError",
    "RtcpError",
    "RtcpBufferTooShort",
    "RtcpInvalidVersion",
    "RtcpLengthMismatch",
    "RtcpMalformedPacket",
    "CaptureError",
    "PcapWriteError",
    "PcapBufferTooShort",
    "PcapInvalidMagic",
    "PcapTruncatedRecord",
    "PcapngBufferTooShort",
    "PcapngInvalidByteOrderMagic",
    "PcapngMalformedBlock",
    "EncapsulationError",
]


class RtpError(Exception):
    """Base class for all RTP parsing errors."""


class RtpBufferTooShort(RtpError):
    """The supplied buffer is too short to contain the declared fields.

    Attributes:
        required: Minimum number of bytes expected.
        actual:   Number of bytes actually available.
    """

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"Buffer too short: need at least {required} bytes, got {actual}")


class RtpInvalidVersion(RtpError):
    """The RTP version field is not 2.

    Attributes:
        version: The version value found in the packet.
    """

    def __init__(self, version: int) -> None:
        self.version = version
        super().__init__(f"Invalid RTP version: {version} (expected 2)")


class RtpPaddingError(RtpError):
    """The padding byte is invalid (zero or exceeds available space).

    Attributes:
        padding_value: The last-byte padding count found.
        available:     Bytes available for payload + padding.
    """

    def __init__(self, padding_value: int, available: int) -> None:
        self.padding_value = padding_value
        self.available = available
        super().__init__(
            f"Invalid padding: last byte says {padding_value}, but only {available} bytes available after header"
        )


class RtpExtensionError(RtpError):
    """The header extension is malformed or truncated.

    Attributes:
        detail: Human-readable description of the problem.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"RTP extension error: {detail}")


class RtpBuildError(RtpError):
    """A builder was given an out-of-range or otherwise invalid field value.

    Attributes:
        field:  Name of the offending field.
        detail: Human-readable description of the problem.
    """

    def __init__(self, field: str, detail: str) -> None:
        self.field = field
        self.detail = detail
        super().__init__(f"Invalid value for '{field}': {detail}")


class RtcpError(RtpError):
    """Base class for all RTCP parsing errors."""


class RtcpBufferTooShort(RtcpError):
    """The supplied buffer is too short to contain an RTCP packet header.

    Attributes:
        required: Minimum number of bytes expected.
        actual:   Number of bytes actually available.
    """

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"RTCP buffer too short: need at least {required} bytes, got {actual}")


class RtcpInvalidVersion(RtcpError):
    """An RTCP packet's version field is not 2.

    Attributes:
        version: The version value found in the packet.
    """

    def __init__(self, version: int) -> None:
        self.version = version
        super().__init__(f"Invalid RTCP version: {version} (expected 2)")


class RtcpLengthMismatch(RtcpError):
    """An RTCP packet's declared length exceeds the available buffer.

    Attributes:
        declared:  Packet length in bytes, as declared by the header.
        available: Bytes actually available from the packet's start.
    """

    def __init__(self, declared: int, available: int) -> None:
        self.declared = declared
        self.available = available
        super().__init__(f"RTCP packet declares {declared} bytes, but only {available} available")


class RtcpMalformedPacket(RtcpError):
    """An RTCP packet's type-specific body is malformed, truncated, or unrecognised.

    Attributes:
        detail: Human-readable description of the problem.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Malformed RTCP packet: {detail}")


class CaptureError(RtpError):
    """Base class for all pcap/pcapng capture-file reading and writing errors."""


class PcapWriteError(CaptureError):
    """A packet sequence can't be serialized as a valid classic pcap file.

    Attributes:
        detail: Human-readable description of the problem.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Cannot write pcap: {detail}")


class PcapBufferTooShort(CaptureError):
    """The supplied buffer is too short for a pcap global or record header.

    Attributes:
        required: Minimum number of bytes expected.
        actual:   Number of bytes actually available.
    """

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"pcap buffer too short: need at least {required} bytes, got {actual}")


class PcapInvalidMagic(CaptureError):
    """The pcap global header's magic number is not recognised.

    Attributes:
        magic: The 4 raw magic bytes found.
    """

    def __init__(self, magic: bytes) -> None:
        self.magic = magic
        super().__init__(f"Unrecognised pcap magic number: {magic!r}")


class PcapTruncatedRecord(CaptureError):
    """A pcap record declares more captured bytes than are available.

    Attributes:
        declared:  Captured length in bytes, as declared by the record header.
        available: Bytes actually available after the record header.
    """

    def __init__(self, declared: int, available: int) -> None:
        self.declared = declared
        self.available = available
        super().__init__(f"pcap record declares {declared} captured bytes, but only {available} available")


class PcapngBufferTooShort(CaptureError):
    """The supplied buffer is too short to contain a pcapng block header.

    Attributes:
        required: Minimum number of bytes expected.
        actual:   Number of bytes actually available.
    """

    def __init__(self, required: int, actual: int) -> None:
        self.required = required
        self.actual = actual
        super().__init__(f"pcapng buffer too short: need at least {required} bytes, got {actual}")


class PcapngInvalidByteOrderMagic(CaptureError):
    """A Section Header Block's byte-order magic is not recognised.

    Attributes:
        magic: The 4 raw magic bytes found.
    """

    def __init__(self, magic: bytes) -> None:
        self.magic = magic
        super().__init__(f"Unrecognised pcapng byte-order magic: {magic!r}")


class PcapngMalformedBlock(CaptureError):
    """A pcapng block is malformed, truncated, or appears before any Section Header Block.

    Attributes:
        detail: Human-readable description of the problem.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Malformed pcapng block: {detail}")


class EncapsulationError(RtpError):
    """A UDP payload can't be wrapped into a valid link/IP/UDP frame.

    Attributes:
        detail: Human-readable description of the problem.
    """

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(f"Cannot encapsulate UDP payload: {detail}")
