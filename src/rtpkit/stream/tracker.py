"""Group RTP packets by SSRC and track sequence/loss/jitter state per stream.

Unlike the parsers and builder, there's no strict/lenient split here: the
input is already-validated :class:`RtpPacket` instances, not raw bytes, so
there's nothing to reject — every packet is simply folded into its SSRC's
running state.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..model.packet import RtpPacket
from ..model.stream import RtpStreamStats

__all__ = ["RtpStreamTracker"]

_SEQ_MOD = 1 << 16
_SEQ_MOD_HALF = 1 << 15


@dataclass
class _StreamState:
    payload_type: int
    packet_count: int = 0
    duplicate_count: int = 0
    out_of_order_count: int = 0
    first_ext_seq: int | None = None
    highest_ext_seq: int | None = None
    jitter: float = 0.0
    _prev_transit: float | None = field(default=None, repr=False)
    _seen_ext_seqs: set[int] = field(default_factory=set, repr=False)
    _packets: dict[int, RtpPacket] = field(default_factory=dict, repr=False)

    def observe(self, packet: RtpPacket, arrival_time: float, clock_rate: int) -> None:
        self.packet_count += 1
        self.payload_type = packet.payload_type

        ext_seq = self._extend(packet.sequence_number)
        if self.first_ext_seq is None:
            self.first_ext_seq = ext_seq

        if ext_seq in self._seen_ext_seqs:
            self.duplicate_count += 1
        else:
            self._seen_ext_seqs.add(ext_seq)
            self._packets[ext_seq] = packet
            if self.highest_ext_seq is not None and ext_seq < self.highest_ext_seq:
                self.out_of_order_count += 1

        if self.highest_ext_seq is None or ext_seq > self.highest_ext_seq:
            self.highest_ext_seq = ext_seq

        self._update_jitter(packet.timestamp, arrival_time, clock_rate)

    def _extend(self, seq: int) -> int:
        if self.highest_ext_seq is None:
            return seq
        prev_seq = self.highest_ext_seq & 0xFFFF
        prev_cycle = self.highest_ext_seq & ~0xFFFF
        delta = seq - prev_seq
        if delta > _SEQ_MOD_HALF:
            delta -= _SEQ_MOD
        elif delta < -_SEQ_MOD_HALF:
            delta += _SEQ_MOD
        return prev_cycle + prev_seq + delta

    def _update_jitter(self, rtp_timestamp: int, arrival_time: float, clock_rate: int) -> None:
        transit = arrival_time * clock_rate - rtp_timestamp
        if self._prev_transit is not None:
            self.jitter += (abs(transit - self._prev_transit) - self.jitter) / 16
        self._prev_transit = transit

    def snapshot(self, ssrc: int) -> RtpStreamStats:
        assert self.first_ext_seq is not None and self.highest_ext_seq is not None
        expected = self.highest_ext_seq - self.first_ext_seq + 1
        received = self.packet_count - self.duplicate_count
        return RtpStreamStats(
            ssrc=ssrc,
            payload_type=self.payload_type,
            packet_count=self.packet_count,
            expected_count=expected,
            lost_count=max(0, expected - received),
            out_of_order_count=self.out_of_order_count,
            duplicate_count=self.duplicate_count,
            first_extended_sequence=self.first_ext_seq,
            highest_extended_sequence=self.highest_ext_seq,
            jitter=self.jitter,
        )

    def ordered_packets(self) -> tuple[RtpPacket, ...]:
        return tuple(self._packets[seq] for seq in sorted(self._packets))


class RtpStreamTracker:
    """Groups RTP packets by SSRC, tracking loss/jitter/reordering per stream.

    Feed already-parsed packets in arrival order via :meth:`observe`; retrieve
    per-SSRC statistics with :meth:`stats`/:meth:`all_stats`, or the packets
    themselves back in sequence-number order with :meth:`ordered_packets`.

    Sequence numbers are unwrapped (RFC 3550-style, 16-bit rollover handled)
    relative to the highest one already seen for that SSRC. This resolves
    ambiguity for reordered packets within half the sequence space (32768) of
    the current high point; a stream that goes silent long enough for the
    counter to wrap more than that between packets will be misread — not a
    concern for the continuous traffic this is meant to analyse.

    All observed packets are retained in memory (for :meth:`ordered_packets`),
    so memory use grows with packet count — fine for call-length captures, not
    for indefinite live monitoring.
    """

    def __init__(self) -> None:
        self._states: dict[int, _StreamState] = {}

    def observe(self, packet: RtpPacket, arrival_time: float, clock_rate: int = 8000) -> None:
        """Fold one packet into its SSRC's running state.

        *arrival_time* is wall-clock seconds (e.g. from :class:`~rtpkit.model.pcap.PcapPacket.timestamp`).
        *clock_rate* is the codec's RTP clock rate in Hz (default 8000, e.g. G.711);
        pass the actual negotiated rate for a meaningful jitter estimate.
        """
        state = self._states.get(packet.ssrc)
        if state is None:
            state = _StreamState(payload_type=packet.payload_type)
            self._states[packet.ssrc] = state
        state.observe(packet, arrival_time, clock_rate)

    def ssrcs(self) -> tuple[int, ...]:
        """SSRCs observed so far, in first-seen order."""
        return tuple(self._states)

    def stats(self, ssrc: int) -> RtpStreamStats | None:
        """Current statistics for *ssrc*, or ``None`` if it hasn't been observed."""
        state = self._states.get(ssrc)
        return state.snapshot(ssrc) if state is not None else None

    def all_stats(self) -> dict[int, RtpStreamStats]:
        """Current statistics for every SSRC observed so far."""
        return {ssrc: state.snapshot(ssrc) for ssrc, state in self._states.items()}

    def ordered_packets(self, ssrc: int) -> tuple[RtpPacket, ...]:
        """Unique packets for *ssrc*, sorted by extended sequence number."""
        state = self._states.get(ssrc)
        return state.ordered_packets() if state is not None else ()
