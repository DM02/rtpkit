"""RTCP packet models (RFC 3550 section 6): SR, RR, SDES, BYE, APP."""

from __future__ import annotations

import enum
from dataclasses import dataclass

__all__ = [
    "RtcpPacketType",
    "SdesItemType",
    "SenderInfo",
    "ReportBlock",
    "SdesItem",
    "SdesChunk",
    "SenderReport",
    "ReceiverReport",
    "SourceDescription",
    "Goodbye",
    "ApplicationDefined",
    "RtcpPacket",
]


class RtcpPacketType(enum.IntEnum):
    """RTCP packet type identifiers (RFC 3550 section 12.2)."""

    SR = 200
    RR = 201
    SDES = 202
    BYE = 203
    APP = 204


class SdesItemType(enum.IntEnum):
    """SDES item type identifiers (RFC 3550 section 6.5)."""

    CNAME = 1
    NAME = 2
    EMAIL = 3
    PHONE = 4
    LOC = 5
    TOOL = 6
    NOTE = 7
    PRIV = 8


@dataclass(frozen=True, slots=True)
class SenderInfo:
    """Sender info block of a Sender Report (RFC 3550 section 6.4.1)."""

    ntp_seconds: int
    ntp_fraction: int
    rtp_timestamp: int
    packet_count: int
    octet_count: int

    @property
    def ntp_timestamp(self) -> float:
        """NTP timestamp as seconds since the NTP epoch (1900-01-01)."""
        return self.ntp_seconds + self.ntp_fraction / 2**32


@dataclass(frozen=True, slots=True)
class ReportBlock:
    """A single reception report block, present in both SR and RR (RFC 3550 section 6.4.1)."""

    ssrc: int
    fraction_lost: int
    cumulative_lost: int
    extended_highest_sequence: int
    jitter: int
    last_sr: int
    delay_since_last_sr: int


@dataclass(frozen=True, slots=True)
class SdesItem:
    """A single SDES item within a chunk."""

    type: int
    text: memoryview


@dataclass(frozen=True, slots=True)
class SdesChunk:
    """One SSRC/CSRC's items within an SDES packet."""

    ssrc: int
    items: tuple[SdesItem, ...]


@dataclass(frozen=True, slots=True)
class SenderReport:
    """RTCP Sender Report (PT=200)."""

    ssrc: int
    sender_info: SenderInfo
    report_blocks: tuple[ReportBlock, ...]
    padding_size: int


@dataclass(frozen=True, slots=True)
class ReceiverReport:
    """RTCP Receiver Report (PT=201)."""

    ssrc: int
    report_blocks: tuple[ReportBlock, ...]
    padding_size: int


@dataclass(frozen=True, slots=True)
class SourceDescription:
    """RTCP Source Description (PT=202)."""

    chunks: tuple[SdesChunk, ...]
    padding_size: int


@dataclass(frozen=True, slots=True)
class Goodbye:
    """RTCP Goodbye (PT=203)."""

    sources: tuple[int, ...]
    reason: memoryview | None
    padding_size: int


@dataclass(frozen=True, slots=True)
class ApplicationDefined:
    """RTCP Application-Defined packet (PT=204)."""

    subtype: int
    ssrc: int
    name: str
    data: memoryview
    padding_size: int


RtcpPacket = SenderReport | ReceiverReport | SourceDescription | Goodbye | ApplicationDefined
