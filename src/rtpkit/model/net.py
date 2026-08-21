"""Result of stripping link/IP/UDP layers off a captured frame."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["DecapsulatedUdp"]


@dataclass(frozen=True, slots=True)
class DecapsulatedUdp:
    """A UDP datagram recovered from a link-layer frame.

    Attributes:
        src_ip:   Source IP address, in canonical text form (v4 or v6).
        dst_ip:   Destination IP address, in canonical text form.
        src_port: UDP source port.
        dst_port: UDP destination port.
        payload:  Zero-copy view of the UDP payload — the RTP/RTCP candidate.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload: memoryview
