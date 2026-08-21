"""Static RTP payload type registry (RFC 3551 section 6)."""

from __future__ import annotations

import enum
from dataclasses import dataclass

__all__ = ["MediaType", "PayloadTypeInfo", "lookup_payload_type", "DYNAMIC_PAYLOAD_TYPE_RANGE"]


class MediaType(enum.Enum):
    AUDIO = "audio"
    VIDEO = "video"
    AUDIO_VIDEO = "audio/video"


@dataclass(frozen=True, slots=True)
class PayloadTypeInfo:
    """One row of the RFC 3551 static payload type table.

    Attributes:
        name:        Encoding name (e.g. ``"PCMU"``).
        media_type:  Audio, video, or both (MP2T multiplexes both).
        clock_rate:  RTP timestamp clock rate in Hz.
        channels:    Audio channel count, or ``None`` where not applicable (video/AV).
    """

    name: str
    media_type: MediaType
    clock_rate: int
    channels: int | None


DYNAMIC_PAYLOAD_TYPE_RANGE = range(96, 128)

_STATIC_PAYLOAD_TYPES: dict[int, PayloadTypeInfo] = {
    0: PayloadTypeInfo("PCMU", MediaType.AUDIO, 8000, 1),
    3: PayloadTypeInfo("GSM", MediaType.AUDIO, 8000, 1),
    4: PayloadTypeInfo("G723", MediaType.AUDIO, 8000, 1),
    5: PayloadTypeInfo("DVI4", MediaType.AUDIO, 8000, 1),
    6: PayloadTypeInfo("DVI4", MediaType.AUDIO, 16000, 1),
    7: PayloadTypeInfo("LPC", MediaType.AUDIO, 8000, 1),
    8: PayloadTypeInfo("PCMA", MediaType.AUDIO, 8000, 1),
    # G.722 actually samples at 16 kHz; RFC 3551 fixes its RTP clock at 8000 for historical reasons.
    9: PayloadTypeInfo("G722", MediaType.AUDIO, 8000, 1),
    10: PayloadTypeInfo("L16", MediaType.AUDIO, 44100, 2),
    11: PayloadTypeInfo("L16", MediaType.AUDIO, 44100, 1),
    12: PayloadTypeInfo("QCELP", MediaType.AUDIO, 8000, 1),
    13: PayloadTypeInfo("CN", MediaType.AUDIO, 8000, 1),
    14: PayloadTypeInfo("MPA", MediaType.AUDIO, 90000, None),
    15: PayloadTypeInfo("G728", MediaType.AUDIO, 8000, 1),
    16: PayloadTypeInfo("DVI4", MediaType.AUDIO, 11025, 1),
    17: PayloadTypeInfo("DVI4", MediaType.AUDIO, 22050, 1),
    18: PayloadTypeInfo("G729", MediaType.AUDIO, 8000, 1),
    25: PayloadTypeInfo("CelB", MediaType.VIDEO, 90000, None),
    26: PayloadTypeInfo("JPEG", MediaType.VIDEO, 90000, None),
    28: PayloadTypeInfo("nv", MediaType.VIDEO, 90000, None),
    31: PayloadTypeInfo("H261", MediaType.VIDEO, 90000, None),
    32: PayloadTypeInfo("MPV", MediaType.VIDEO, 90000, None),
    33: PayloadTypeInfo("MP2T", MediaType.AUDIO_VIDEO, 90000, None),
    34: PayloadTypeInfo("H263", MediaType.VIDEO, 90000, None),
}


def lookup_payload_type(payload_type: int) -> PayloadTypeInfo | None:
    """Look up a static RFC 3551 payload type.

    Returns ``None`` for dynamic types (96-127, see :data:`DYNAMIC_PAYLOAD_TYPE_RANGE`)
    and for reserved/unassigned static numbers — both simply have no fixed meaning.
    """
    return _STATIC_PAYLOAD_TYPES.get(payload_type)
