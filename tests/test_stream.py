"""Tests for RtpStreamTracker."""

from __future__ import annotations

import pytest

from rtpkit import RtpBuilder, RtpStreamTracker


def _packet(seq: int, ssrc: int = 1, ts: int = 0, pt: int = 8):
    return RtpBuilder().with_sequence_number(seq).with_ssrc(ssrc).with_timestamp(ts).with_payload_type(pt).build_packet()


class TestBasicTracking:
    def test_unknown_ssrc_returns_none_and_empty(self) -> None:
        tracker = RtpStreamTracker()
        assert tracker.stats(999) is None
        assert tracker.ordered_packets(999) == ()
        assert tracker.ssrcs() == ()
        assert tracker.all_stats() == {}

    def test_single_packet(self) -> None:
        tracker = RtpStreamTracker()
        tracker.observe(_packet(seq=100), arrival_time=0.0)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.ssrc == 1
        assert stats.packet_count == 1
        assert stats.expected_count == 1
        assert stats.lost_count == 0
        assert stats.out_of_order_count == 0
        assert stats.duplicate_count == 0
        assert stats.first_extended_sequence == 100
        assert stats.highest_extended_sequence == 100
        assert stats.jitter == 0.0
        assert stats.fraction_lost == 0.0

    def test_sequential_packets_no_loss(self) -> None:
        tracker = RtpStreamTracker()
        for seq in range(10):
            tracker.observe(_packet(seq=seq), arrival_time=seq * 0.02)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.packet_count == 10
        assert stats.expected_count == 10
        assert stats.lost_count == 0
        assert stats.out_of_order_count == 0

    def test_gap_is_counted_as_loss(self) -> None:
        tracker = RtpStreamTracker()
        for seq in (0, 1, 2, 5, 6):
            tracker.observe(_packet(seq=seq), arrival_time=seq * 0.02)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.expected_count == 7  # seqs 0..6
        assert stats.packet_count == 5
        assert stats.lost_count == 2
        assert stats.fraction_lost == pytest.approx(2 / 7)

    def test_out_of_order_arrival(self) -> None:
        tracker = RtpStreamTracker()
        for seq in (0, 1, 3, 2, 4):
            tracker.observe(_packet(seq=seq), arrival_time=0.0)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.out_of_order_count == 1
        assert stats.highest_extended_sequence == 4
        assert stats.lost_count == 0

    def test_duplicate_packet(self) -> None:
        tracker = RtpStreamTracker()
        for seq in (0, 1, 1, 2):
            tracker.observe(_packet(seq=seq), arrival_time=0.0)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.packet_count == 4
        assert stats.duplicate_count == 1
        assert stats.expected_count == 3
        assert stats.lost_count == 0

    def test_large_forward_delta_is_treated_as_an_old_packet(self) -> None:
        # a raw seq far ahead of the current high point is nearer (mod 2**16) to
        # being just before it than actually 65530 packets ahead
        tracker = RtpStreamTracker()
        tracker.observe(_packet(seq=0), arrival_time=0.0)
        tracker.observe(_packet(seq=65530), arrival_time=0.0)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.out_of_order_count == 1
        assert stats.highest_extended_sequence == 0

    def test_sequence_number_wraparound(self) -> None:
        tracker = RtpStreamTracker()
        for seq in (65534, 65535, 0, 1):
            tracker.observe(_packet(seq=seq), arrival_time=0.0)

        stats = tracker.stats(1)
        assert stats is not None
        assert stats.first_extended_sequence == 65534
        assert stats.highest_extended_sequence == 65537
        assert stats.out_of_order_count == 0
        assert stats.lost_count == 0

    def test_ordered_packets_recovers_arrival_order(self) -> None:
        tracker = RtpStreamTracker()
        for seq in (2, 0, 3, 1):
            tracker.observe(_packet(seq=seq), arrival_time=0.0)

        ordered = tracker.ordered_packets(1)
        assert [p.sequence_number for p in ordered] == [0, 1, 2, 3]

    def test_multiple_ssrcs_tracked_independently(self) -> None:
        tracker = RtpStreamTracker()
        tracker.observe(_packet(seq=0, ssrc=1), arrival_time=0.0)
        tracker.observe(_packet(seq=0, ssrc=2), arrival_time=0.0)
        tracker.observe(_packet(seq=1, ssrc=1), arrival_time=0.02)

        assert set(tracker.ssrcs()) == {1, 2}
        assert tracker.stats(1) is not None and tracker.stats(1).packet_count == 2
        assert tracker.stats(2) is not None and tracker.stats(2).packet_count == 1
        assert set(tracker.all_stats()) == {1, 2}

    def test_payload_type_reflects_latest_packet(self) -> None:
        tracker = RtpStreamTracker()
        tracker.observe(_packet(seq=0, pt=8), arrival_time=0.0)
        tracker.observe(_packet(seq=1, pt=13), arrival_time=0.02)  # e.g. comfort noise
        stats = tracker.stats(1)
        assert stats is not None
        assert stats.payload_type == 13


class TestJitter:
    def test_matches_rfc3550_formula(self) -> None:
        tracker = RtpStreamTracker()
        clock_rate = 8000

        tracker.observe(_packet(seq=0, ts=0), arrival_time=0.0, clock_rate=clock_rate)
        assert tracker.stats(1).jitter == pytest.approx(0.0)  # type: ignore[union-attr]

        tracker.observe(_packet(seq=1, ts=160), arrival_time=0.02, clock_rate=clock_rate)
        assert tracker.stats(1).jitter == pytest.approx(0.0)  # type: ignore[union-attr]

        tracker.observe(_packet(seq=2, ts=320), arrival_time=0.045, clock_rate=clock_rate)
        assert tracker.stats(1).jitter == pytest.approx(2.5)  # type: ignore[union-attr]

        tracker.observe(_packet(seq=3, ts=480), arrival_time=0.065, clock_rate=clock_rate)
        assert tracker.stats(1).jitter == pytest.approx(2.34375)  # type: ignore[union-attr]
