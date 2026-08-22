"""Multi-packet RTP flow classification.

A single packet can look RTP-shaped by coincidence; a whole flow of them
sharing one SSRC with plausible sequence-number deltas essentially can't.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..model.errors import RtpError
from ..parser.rtp_parser import parse_rtp
from .heuristics import RTCP_COLLISION_RANGE

__all__ = ["FlowClassification", "RtpFlowClassifier"]

_DEFAULT_MIN_PACKETS = 4
_DEFAULT_SEQ_JUMP_THRESHOLD = 1000
_SEQ_MOD = 1 << 16
_SEQ_MOD_HALF = 1 << 15


@dataclass(frozen=True, slots=True)
class FlowClassification:
    """Result of :meth:`RtpFlowClassifier.classify`.

    Attributes:
        packets_observed:   Total calls to :meth:`~RtpFlowClassifier.observe`.
        packets_parsed:     Of those, how many parsed as structurally valid RTP.
        ssrc_consistent:    Whether every parsed packet shared one SSRC.
        sequence_plausible: Whether consecutive sequence-number deltas stayed small.
        is_likely_rtp:      True iff enough packets parsed and both signals held.
    """

    packets_observed: int
    packets_parsed: int
    ssrc_consistent: bool
    sequence_plausible: bool
    is_likely_rtp: bool


def _wrapped_delta(a: int, b: int) -> int:
    delta = (b - a) % _SEQ_MOD
    if delta > _SEQ_MOD_HALF:
        delta -= _SEQ_MOD
    return delta


class RtpFlowClassifier:
    """Accumulates evidence across successive UDP payloads from one presumed flow.

    Feed candidate packets in arrival order via :meth:`observe`, then call
    :meth:`classify`. A packet only counts as evidence once it parses under
    strict RTP rules and falls outside the RFC 3551 RTCP-collision payload
    type range (see :data:`~rtpkit.detection.heuristics.RTCP_COLLISION_RANGE`).
    """

    def __init__(
        self,
        min_packets: int = _DEFAULT_MIN_PACKETS,
        seq_jump_threshold: int = _DEFAULT_SEQ_JUMP_THRESHOLD,
    ) -> None:
        self._min_packets = min_packets
        self._seq_jump_threshold = seq_jump_threshold
        self._packets_observed = 0
        self._packets_parsed = 0
        self._ssrc: int | None = None
        self._ssrc_consistent = True
        self._last_seq: int | None = None
        self._sequence_plausible = True

    def observe(self, data: bytes | bytearray | memoryview) -> None:
        self._packets_observed += 1
        try:
            packet = parse_rtp(data)
        except RtpError:
            return
        if packet.payload_type in RTCP_COLLISION_RANGE:
            return
        self._packets_parsed += 1

        if self._ssrc is None:
            self._ssrc = packet.ssrc
        elif packet.ssrc != self._ssrc:
            self._ssrc_consistent = False

        if self._last_seq is not None:
            if abs(_wrapped_delta(self._last_seq, packet.sequence_number)) > self._seq_jump_threshold:
                self._sequence_plausible = False
        self._last_seq = packet.sequence_number

    def classify(self) -> FlowClassification:
        is_likely_rtp = self._packets_parsed >= self._min_packets and self._ssrc_consistent and self._sequence_plausible
        return FlowClassification(
            packets_observed=self._packets_observed,
            packets_parsed=self._packets_parsed,
            ssrc_consistent=self._ssrc_consistent,
            sequence_plausible=self._sequence_plausible,
            is_likely_rtp=is_likely_rtp,
        )
