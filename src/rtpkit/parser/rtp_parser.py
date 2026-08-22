"""RTP packet parser — strict and lenient modes.

This module provides two entry points:

* :func:`parse_rtp` — strict parser that raises on any protocol violation.
* :func:`parse_rtp_lenient` — best-effort parser that tolerates
  non-critical problems and logs warnings instead of raising.

Both functions accept ``bytes``, ``bytearray``, or ``memoryview`` and
return an immutable :class:`~rtpkit.model.packet.RtpPacket` without
copying the underlying buffer.
"""

from __future__ import annotations

import logging
import struct

from ..model.errors import (
    RtpBufferTooShort,
    RtpExtensionError,
    RtpInvalidVersion,
    RtpPaddingError,
)
from ..model.extension import HeaderExtension
from ..model.packet import RtpPacket

__all__ = ["parse_rtp", "parse_rtp_lenient"]

logger = logging.getLogger("rtpkit.parser")

_FIXED_HEADER_SIZE = 12


def parse_rtp(data: bytes | bytearray | memoryview) -> RtpPacket:
    """Parse an RTP packet in strict mode.

    Raises :class:`~rtpkit.model.errors.RtpError` (or a subclass) on any
    protocol violation, including wrong version, truncated buffers,
    invalid padding, and malformed extensions.

    The returned :class:`RtpPacket` holds zero-copy ``memoryview``
    references into *data*.  Callers must keep *data* alive for as long
    as the packet is used.
    """
    return _parse(data, strict=True)


def parse_rtp_lenient(data: bytes | bytearray | memoryview) -> RtpPacket:
    """Parse an RTP packet in lenient (best-effort) mode.

    Only raises :class:`~rtpkit.model.errors.RtpBufferTooShort` when the
    buffer is physically too short to contain even the fixed header.
    All other problems (wrong version, broken extension, padding
    overflow) are logged as warnings and handled gracefully.
    """
    return _parse(data, strict=False)


def _parse(data: bytes | bytearray | memoryview, *, strict: bool) -> RtpPacket:
    """Core parsing logic shared by strict and lenient modes."""
    if not isinstance(data, memoryview):
        data = memoryview(data)

    buf_len = len(data)

    # Fixed header: 12 bytes minimum
    if buf_len < _FIXED_HEADER_SIZE:
        raise RtpBufferTooShort(required=_FIXED_HEADER_SIZE, actual=buf_len)

    first_byte: int = data[0]
    version = (first_byte >> 6) & 0x03
    padding_flag = bool((first_byte >> 5) & 0x01)
    extension_flag = bool((first_byte >> 4) & 0x01)
    cc = first_byte & 0x0F

    second_byte: int = data[1]
    marker = bool((second_byte >> 7) & 0x01)
    payload_type = second_byte & 0x7F

    (seq, timestamp, ssrc) = struct.unpack_from("!HII", data, 2)

    # Version check
    if version != 2:
        if strict:
            raise RtpInvalidVersion(version)
        logger.warning("RTP version %d (expected 2) — continuing in lenient mode", version)

    # CSRC list
    csrc_end = _FIXED_HEADER_SIZE + cc * 4
    if csrc_end > buf_len:
        if strict:
            raise RtpBufferTooShort(required=csrc_end, actual=buf_len)
        cc = (buf_len - _FIXED_HEADER_SIZE) // 4
        csrc_end = _FIXED_HEADER_SIZE + cc * 4
        logger.warning("CSRC count truncated to %d in lenient mode", cc)

    if cc:
        csrc = struct.unpack_from(f"!{cc}I", data, _FIXED_HEADER_SIZE)
    else:
        csrc = ()

    offset = csrc_end

    # Header extension
    header_ext: HeaderExtension | None = None

    if extension_flag:
        ext_header_end = offset + 4
        if ext_header_end > buf_len:
            if strict:
                raise RtpExtensionError(f"Need {ext_header_end} bytes for extension header, got {buf_len}")
            logger.warning("Extension header truncated — skipping extension")
        else:
            (ext_profile, ext_word_len) = struct.unpack_from("!HH", data, offset)
            ext_data_len = ext_word_len * 4
            ext_data_end = ext_header_end + ext_data_len

            if ext_data_end > buf_len:
                if strict:
                    raise RtpExtensionError(
                        f"Extension declares {ext_data_len} bytes of data, "
                        f"but only {buf_len - ext_header_end} available"
                    )
                logger.warning(
                    "Extension data truncated (%d declared, %d available) — skipping",
                    ext_data_len,
                    buf_len - ext_header_end,
                )
            else:
                header_ext = HeaderExtension(
                    profile=ext_profile,
                    length=ext_word_len,
                    data=data[ext_header_end:ext_data_end],
                )
                offset = ext_data_end

    # Padding
    padding_size = 0
    payload_end = buf_len

    if padding_flag:
        available = buf_len - offset
        if available < 1:
            if strict:
                raise RtpPaddingError(padding_value=0, available=available)
            logger.warning("Padding flag set but no bytes after header — ignoring")
        else:
            pad_count: int = data[buf_len - 1]

            if pad_count == 0:
                if strict:
                    raise RtpPaddingError(padding_value=0, available=available)
                logger.warning("Padding last byte is 0 — ignoring padding")
            elif pad_count > available:
                if strict:
                    raise RtpPaddingError(padding_value=pad_count, available=available)
                logger.warning(
                    "Padding count %d exceeds available %d — ignoring padding",
                    pad_count,
                    available,
                )
            else:
                padding_size = pad_count
                payload_end = buf_len - pad_count

    # Payload
    payload = data[offset:payload_end]

    return RtpPacket(
        version=version,
        padding=padding_flag,
        extension=extension_flag,
        marker=marker,
        payload_type=payload_type,
        sequence_number=seq,
        timestamp=timestamp,
        ssrc=ssrc,
        csrc=csrc,
        header_extension=header_ext,
        payload=payload,
        padding_size=padding_size,
        _raw=data,
    )
