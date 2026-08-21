"""RTP header extension model and element parser (RFC 3550 / RFC 8285)."""

from __future__ import annotations

import enum
from collections.abc import Sequence
from dataclasses import dataclass

from .errors import RtpBuildError

__all__ = [
    "HeaderExtension",
    "ExtensionElement",
    "ExtensionProfile",
    "parse_extension_elements",
    "build_header_extension",
]

_ONE_BYTE_MAGIC: int = 0xBEDE
_TWO_BYTE_MASK: int = 0xFFF0
_TWO_BYTE_VALUE: int = 0x1000


class ExtensionProfile(enum.Enum):
    """Recognised header-extension profile families."""

    UNKNOWN = "unknown"
    ONE_BYTE = "one_byte"
    TWO_BYTE = "two_byte"


def classify_profile(profile: int) -> ExtensionProfile:
    """Return the :class:`ExtensionProfile` for a 16-bit profile value."""
    if profile == _ONE_BYTE_MAGIC:
        return ExtensionProfile.ONE_BYTE
    if (profile & _TWO_BYTE_MASK) == _TWO_BYTE_VALUE:
        return ExtensionProfile.TWO_BYTE
    return ExtensionProfile.UNKNOWN


@dataclass(frozen=True, slots=True)
class HeaderExtension:
    """Generic RFC 3550 header extension.

    Attributes:
        profile: 16-bit *defined by profile* identifier.
        length:  Number of 32-bit words in the extension body.
        data:    Raw extension bytes (``length * 4`` bytes, zero-copy view).
    """

    profile: int
    length: int
    data: memoryview

    def classify(self) -> ExtensionProfile:
        """Return which profile family this extension belongs to."""
        return classify_profile(self.profile)


@dataclass(frozen=True, slots=True)
class ExtensionElement:
    """Single element inside an RFC 8285 one-byte or two-byte extension.

    Attributes:
        id:   Element identifier (4-bit for one-byte, 8-bit for two-byte).
        data: Element payload bytes (zero-copy view).
    """

    id: int
    data: memoryview


def parse_extension_elements(
    ext: HeaderExtension,
) -> tuple[ExtensionElement, ...]:
    """Parse individual elements from an RFC 8285 header extension.

    For one-byte header format (profile ``0xBEDE``):
    * 4-bit ID (1-14) + 4-bit length (value + 1 == byte count).
    * ID 0 is padding, ID 15 is reserved (terminates parsing).

    For two-byte header format (profile ``0x100X``):
    * 8-bit ID (1-255) + 8-bit length (byte count, 0 allowed).
    * ID 0 is padding.

    Returns an empty tuple for unrecognised profiles.
    """
    kind = ext.classify()
    if kind is ExtensionProfile.UNKNOWN:
        return ()
    if kind is ExtensionProfile.ONE_BYTE:
        return _parse_one_byte(ext.data)
    return _parse_two_byte(ext.data)


def _parse_one_byte(data: memoryview) -> tuple[ExtensionElement, ...]:
    elements: list[ExtensionElement] = []
    pos = 0
    length = len(data)

    while pos < length:
        byte = data[pos]

        if byte == 0:  # padding
            pos += 1
            continue

        elem_id = (byte >> 4) & 0x0F
        if elem_id == 15:  # reserved, stop
            break

        elem_len = (byte & 0x0F) + 1
        pos += 1

        if pos + elem_len > length:
            break

        elements.append(ExtensionElement(id=elem_id, data=data[pos : pos + elem_len]))
        pos += elem_len

    return tuple(elements)


def build_header_extension(
    elements: Sequence[ExtensionElement],
    profile: ExtensionProfile = ExtensionProfile.ONE_BYTE,
) -> HeaderExtension:
    """Serialize elements into a :class:`HeaderExtension` (inverse of :func:`parse_extension_elements`).

    Uses ``0xBEDE`` for :attr:`ExtensionProfile.ONE_BYTE` and ``0x1000`` for
    :attr:`ExtensionProfile.TWO_BYTE`, then pads the body to a 4-byte boundary.
    """
    if profile is ExtensionProfile.ONE_BYTE:
        profile_value = _ONE_BYTE_MAGIC
        body = _build_one_byte(elements)
    elif profile is ExtensionProfile.TWO_BYTE:
        profile_value = _TWO_BYTE_VALUE
        body = _build_two_byte(elements)
    else:
        raise RtpBuildError("profile", f"cannot build an extension for profile {profile}")

    body += b"\x00" * ((-len(body)) % 4)
    return HeaderExtension(profile=profile_value, length=len(body) // 4, data=memoryview(body))


def _build_one_byte(elements: Sequence[ExtensionElement]) -> bytes:
    parts: list[bytes] = []
    for elem in elements:
        if not 1 <= elem.id <= 14:
            raise RtpBuildError("id", f"must be 1-14 for one-byte format, got {elem.id}")
        data = bytes(elem.data)
        if not 1 <= len(data) <= 16:
            raise RtpBuildError("data", f"must be 1-16 bytes for one-byte format, got {len(data)}")
        parts.append(bytes([(elem.id << 4) | (len(data) - 1)]))
        parts.append(data)
    return b"".join(parts)


def _build_two_byte(elements: Sequence[ExtensionElement]) -> bytes:
    parts: list[bytes] = []
    for elem in elements:
        if not 1 <= elem.id <= 255:
            raise RtpBuildError("id", f"must be 1-255 for two-byte format, got {elem.id}")
        data = bytes(elem.data)
        if len(data) > 255:
            raise RtpBuildError("data", f"must be at most 255 bytes for two-byte format, got {len(data)}")
        parts.append(bytes([elem.id, len(data)]))
        parts.append(data)
    return b"".join(parts)


def _parse_two_byte(data: memoryview) -> tuple[ExtensionElement, ...]:
    elements: list[ExtensionElement] = []
    pos = 0
    length = len(data)

    while pos < length:
        byte = data[pos]

        if byte == 0:  # padding
            pos += 1
            continue

        elem_id = byte
        pos += 1

        if pos >= length:
            break

        elem_len = data[pos]
        pos += 1

        if pos + elem_len > length:
            break

        elements.append(ExtensionElement(id=elem_id, data=data[pos : pos + elem_len]))
        pos += elem_len

    return tuple(elements)
