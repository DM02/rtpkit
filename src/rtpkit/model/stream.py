"""Per-SSRC RTP stream statistics."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["RtpStreamStats"]


@dataclass(frozen=True, slots=True)
class RtpStreamStats:
    """A snapshot of one SSRC's stream state, as tracked by :class:`~rtpkit.stream.RtpStreamTracker`.

    Attributes:
        ssrc:                     Synchronisation source identifier.
        payload_type:             Payload type of the most recently observed packet.
        packet_count:             Total packets observed, including duplicates.
        expected_count:           Packets expected, from the sequence number range covered.
        lost_count:               ``max(0, expected_count - unique packets received)``.
        out_of_order_count:       Packets whose extended sequence number was below the
                                   highest one already observed.
        duplicate_count:          Packets whose extended sequence number repeats one
                                   already observed.
        first_extended_sequence:  Extended (unwrapped) sequence number of the first packet.
        highest_extended_sequence: Highest extended sequence number observed.
        jitter:                   RFC 3550 interarrival jitter estimate, in RTP timestamp
                                   units (divide by the codec's clock rate for seconds).
    """

    ssrc: int
    payload_type: int
    packet_count: int
    expected_count: int
    lost_count: int
    out_of_order_count: int
    duplicate_count: int
    first_extended_sequence: int
    highest_extended_sequence: int
    jitter: float

    @property
    def fraction_lost(self) -> float:
        """Loss ratio in ``[0.0, 1.0]``, or ``0.0`` if nothing was expected yet."""
        return self.lost_count / self.expected_count if self.expected_count > 0 else 0.0
