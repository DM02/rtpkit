"""Immutable RTP packet model."""

from __future__ import annotations

from dataclasses import dataclass

from .extension import HeaderExtension

__all__ = ["RtpPacket"]


@dataclass(frozen=True, slots=True)
class RtpPacket:
    """Immutable representation of a parsed RTP packet.

    All byte-level fields are stored as zero-copy :class:`memoryview`
    references into the original buffer.

    Attributes:
        version:          RTP version (should be 2).
        padding:          True if the padding bit is set.
        extension:        True if the extension bit is set.
        marker:           True if the marker bit is set.
        payload_type:     7-bit payload type identifier (0–127).
        sequence_number:  16-bit sequence number.
        timestamp:        32-bit timestamp.
        ssrc:             32-bit synchronisation source identifier.
        csrc:             Tuple of contributing source identifiers (0–15).
        header_extension: Parsed header extension, or ``None``.
        payload:          Zero-copy view of the payload bytes.
        padding_size:     Number of padding bytes (0 when P=0).
        _raw:             Zero-copy view of the entire original packet.
    """

    version: int
    padding: bool
    extension: bool
    marker: bool
    payload_type: int
    sequence_number: int
    timestamp: int
    ssrc: int
    csrc: tuple[int, ...]
    header_extension: HeaderExtension | None
    payload: memoryview
    padding_size: int
    _raw: memoryview

    # -- derived properties --------------------------------------------------

    @property
    def cc(self) -> int:
        """CSRC count (0–15)."""
        return len(self.csrc)

    @property
    def header_size(self) -> int:
        """Total header size in bytes (fixed + CSRC + extension)."""
        size = 12 + len(self.csrc) * 4
        ext = self.header_extension
        if ext is not None:
            size += 4 + ext.length * 4
        return size

    @property
    def total_size(self) -> int:
        """Total packet size in bytes."""
        return len(self._raw)
