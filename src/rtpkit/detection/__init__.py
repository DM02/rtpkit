"""rtpkit.detection — Spot RTP/RTCP in traffic without SDP context."""

from .flow import FlowClassification, RtpFlowClassifier
from .heuristics import RTCP_COLLISION_RANGE, looks_like_rtcp, looks_like_rtp

__all__ = ["looks_like_rtp", "looks_like_rtcp", "RTCP_COLLISION_RANGE", "RtpFlowClassifier", "FlowClassification"]
