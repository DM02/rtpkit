"""A single captured packet read from a pcap or pcapng file."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["PcapPacket"]


@dataclass(frozen=True, slots=True)
class PcapPacket:
    """One record from a capture file.

    Attributes:
        timestamp:         Capture time as seconds since the Unix epoch.
        captured_length:   Number of bytes actually present in ``data``.
        original_length:   Length of the packet on the wire (may exceed
                            ``captured_length`` if the capture used a snaplen).
        link_type:         Link-layer type (pcap LINKTYPE_* / DLT_* value).
        data:              Zero-copy view of the captured link-layer frame.
    """

    timestamp: float
    captured_length: int
    original_length: int
    link_type: int
    data: memoryview
