"""Tests for looks_like_rtp(), looks_like_rtcp(), and RtpFlowClassifier."""

from __future__ import annotations

from rtpkit import RtpBuilder, RtpFlowClassifier, looks_like_rtcp, looks_like_rtp

from .conftest import build_rr, build_sr


class TestLooksLikeRtp:
    def test_valid_rtp_packet(self) -> None:
        raw = RtpBuilder().with_payload_type(8).with_sequence_number(1).build()
        assert looks_like_rtp(raw) is True

    def test_garbage_too_short(self) -> None:
        assert looks_like_rtp(b"\x00" * 4) is False

    def test_wrong_version(self) -> None:
        raw = bytearray(RtpBuilder().build())
        raw[0] = 0xC0  # version 3
        assert looks_like_rtp(bytes(raw)) is False

    def test_rtcp_collision_payload_type_rejected(self) -> None:
        raw = RtpBuilder().with_payload_type(72).build()
        assert looks_like_rtp(raw) is False

    def test_rtcp_packet_is_not_rtp(self) -> None:
        raw = build_sr(ssrc=1)
        assert looks_like_rtp(raw) is False


class TestLooksLikeRtcp:
    def test_valid_sr(self) -> None:
        assert looks_like_rtcp(build_sr(ssrc=1)) is True

    def test_valid_rr(self) -> None:
        assert looks_like_rtcp(build_rr(ssrc=1)) is True

    def test_garbage_too_short(self) -> None:
        assert looks_like_rtcp(b"\x00\x00") is False

    def test_rtp_packet_is_not_rtcp(self) -> None:
        raw = RtpBuilder().with_payload_type(8).build()
        assert looks_like_rtcp(raw) is False


class TestRtpFlowClassifier:
    def test_consistent_flow_is_classified_as_rtp(self) -> None:
        classifier = RtpFlowClassifier(min_packets=4)
        for seq in range(6):
            raw = RtpBuilder().with_ssrc(0xAABBCCDD).with_sequence_number(seq).build()
            classifier.observe(raw)

        result = classifier.classify()
        assert result.packets_observed == 6
        assert result.packets_parsed == 6
        assert result.ssrc_consistent is True
        assert result.sequence_plausible is True
        assert result.is_likely_rtp is True

    def test_too_few_packets_not_classified_as_rtp(self) -> None:
        classifier = RtpFlowClassifier(min_packets=4)
        for seq in range(2):
            raw = RtpBuilder().with_ssrc(1).with_sequence_number(seq).build()
            classifier.observe(raw)

        result = classifier.classify()
        assert result.packets_parsed == 2
        assert result.is_likely_rtp is False

    def test_inconsistent_ssrc_rejected(self) -> None:
        classifier = RtpFlowClassifier(min_packets=2)
        classifier.observe(RtpBuilder().with_ssrc(1).with_sequence_number(0).build())
        classifier.observe(RtpBuilder().with_ssrc(2).with_sequence_number(1).build())

        result = classifier.classify()
        assert result.ssrc_consistent is False
        assert result.is_likely_rtp is False

    def test_large_sequence_jump_rejected(self) -> None:
        classifier = RtpFlowClassifier(min_packets=2, seq_jump_threshold=100)
        classifier.observe(RtpBuilder().with_ssrc(1).with_sequence_number(0).build())
        classifier.observe(RtpBuilder().with_ssrc(1).with_sequence_number(40000).build())

        result = classifier.classify()
        assert result.sequence_plausible is False
        assert result.is_likely_rtp is False

    def test_non_rtp_garbage_does_not_count_as_parsed(self) -> None:
        classifier = RtpFlowClassifier(min_packets=1)
        classifier.observe(b"\x00\x00")

        result = classifier.classify()
        assert result.packets_observed == 1
        assert result.packets_parsed == 0
        assert result.is_likely_rtp is False

    def test_rtcp_collision_payload_type_excluded_from_evidence(self) -> None:
        classifier = RtpFlowClassifier(min_packets=1)
        classifier.observe(RtpBuilder().with_payload_type(74).build())

        result = classifier.classify()
        assert result.packets_observed == 1
        assert result.packets_parsed == 0

    def test_sequence_wraparound_is_plausible(self) -> None:
        classifier = RtpFlowClassifier(min_packets=2)
        classifier.observe(RtpBuilder().with_ssrc(1).with_sequence_number(65534).build())
        classifier.observe(RtpBuilder().with_ssrc(1).with_sequence_number(0).build())

        result = classifier.classify()
        assert result.sequence_plausible is True
