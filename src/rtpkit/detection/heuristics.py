"""Single-packet structural plausibility checks for RTP/RTCP.

Neither function is a certainty — a handful of bytes can pass an RTP-shaped
check by coincidence. For a trustworthy signal, accumulate evidence across a
whole flow with :class:`~rtpkit.detection.RtpFlowClassifier` instead.
"""

from __future__ import annotations

from ..model.errors import RtcpError, RtpError
from ..model.rtcp import ReceiverReport, SenderReport
from ..parser.rtcp_parser import parse_rtcp
from ..parser.rtp_parser import parse_rtp

__all__ = ["looks_like_rtp", "looks_like_rtcp"]

# RFC 3551 section 6 reserves these payload types to avoid colliding with RTCP's 200-204 packet types.
RTCP_COLLISION_RANGE = range(72, 77)


def looks_like_rtp(data: bytes | bytearray | memoryview) -> bool:
    """Does *data* parse as a structurally valid RTP packet, outside the RTCP-collision PT range?"""
    try:
        packet = parse_rtp(data)
    except RtpError:
        return False
    return packet.payload_type not in RTCP_COLLISION_RANGE


def looks_like_rtcp(data: bytes | bytearray | memoryview) -> bool:
    """Does *data* parse as a compound RTCP packet starting with SR or RR, per RFC 3550?"""
    try:
        packets = parse_rtcp(data)
    except RtcpError:
        return False
    return bool(packets) and isinstance(packets[0], (SenderReport, ReceiverReport))
