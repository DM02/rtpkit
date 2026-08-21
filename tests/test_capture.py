"""Tests for read_capture() / read_capture_lenient() format auto-detection."""

from __future__ import annotations

import pytest

from rtpkit import CaptureError, read_capture, read_capture_lenient
from .conftest import build_epb, build_idb, build_pcap_global_header, build_pcap_record, build_shb


def test_detects_classic_pcap() -> None:
    raw = build_pcap_global_header(link_type=1) + build_pcap_record(1, 0, b"\x01")
    (pkt,) = list(read_capture(raw))
    assert bytes(pkt.data) == b"\x01"


def test_detects_pcapng() -> None:
    raw = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x02")
    (pkt,) = list(read_capture(raw))
    assert bytes(pkt.data) == b"\x02"


def test_lenient_detects_pcapng() -> None:
    raw = build_shb() + build_idb(link_type=1) + build_epb(0, 0, b"\x03")
    (pkt,) = list(read_capture_lenient(raw))
    assert bytes(pkt.data) == b"\x03"


def test_unrecognised_data_raises() -> None:
    with pytest.raises(CaptureError):
        list(read_capture(b"not a capture file"))
