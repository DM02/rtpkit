"""Tests for lookup_payload_type() and the RFC 3551 static table."""

from __future__ import annotations

import pytest

from rtpkit import DYNAMIC_PAYLOAD_TYPE_RANGE, MediaType, lookup_payload_type


@pytest.mark.parametrize(
    ("pt", "name", "media_type", "clock_rate", "channels"),
    [
        (0, "PCMU", MediaType.AUDIO, 8000, 1),
        (8, "PCMA", MediaType.AUDIO, 8000, 1),
        (9, "G722", MediaType.AUDIO, 8000, 1),
        (18, "G729", MediaType.AUDIO, 8000, 1),
        (10, "L16", MediaType.AUDIO, 44100, 2),
        (31, "H261", MediaType.VIDEO, 90000, None),
        (33, "MP2T", MediaType.AUDIO_VIDEO, 90000, None),
    ],
)
def test_known_static_entries(
    pt: int, name: str, media_type: MediaType, clock_rate: int, channels: int | None
) -> None:
    info = lookup_payload_type(pt)
    assert info is not None
    assert info.name == name
    assert info.media_type == media_type
    assert info.clock_rate == clock_rate
    assert info.channels == channels


def test_dynamic_range_has_no_static_entry() -> None:
    for pt in (96, 111, 127):
        assert pt in DYNAMIC_PAYLOAD_TYPE_RANGE
        assert lookup_payload_type(pt) is None


def test_unassigned_returns_none() -> None:
    assert lookup_payload_type(35) is None


def test_out_of_range_returns_none() -> None:
    assert lookup_payload_type(200) is None
    assert lookup_payload_type(-1) is None
