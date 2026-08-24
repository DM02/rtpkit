"""rtpkit — RTP packet parsing, analysis and reconstruction.

Quick start::

    from rtpkit import parse_rtp

    pkt = parse_rtp(raw_bytes)
    print(pkt.payload_type, pkt.sequence_number)
"""

from __future__ import annotations

import logging
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("rtpkit")
except PackageNotFoundError:  # running from source without an installed distribution
    __version__ = "0.0.0+unknown"

from .builder.rtp_builder import RtpBuilder
from .codec.g711 import decode_pcma, decode_pcmu, encode_pcma, encode_pcmu
from .detection.flow import FlowClassification, RtpFlowClassifier
from .detection.heuristics import RTCP_COLLISION_RANGE, looks_like_rtcp, looks_like_rtp
from .fuzz.mutate import bit_flip, fuzz_cases, random_bytes, splice_random_bytes, truncate
from .fuzz.runner import FuzzCrash, FuzzResult, fuzz_parser
from .io.capture import read_capture, read_capture_lenient
from .io.decap import decapsulate_udp
from .io.encap import encapsulate_udp
from .io.pcap_reader import read_pcap, read_pcap_lenient
from .io.pcap_writer import write_pcap
from .io.pcapng_reader import read_pcapng, read_pcapng_lenient
from .io.pcapng_writer import write_pcapng
from .model.errors import (
    CaptureError,
    EncapsulationError,
    PcapBufferTooShort,
    PcapInvalidMagic,
    PcapngBufferTooShort,
    PcapngInvalidByteOrderMagic,
    PcapngMalformedBlock,
    PcapTruncatedRecord,
    PcapWriteError,
    RtcpBufferTooShort,
    RtcpError,
    RtcpInvalidVersion,
    RtcpLengthMismatch,
    RtcpMalformedPacket,
    RtpBufferTooShort,
    RtpBuildError,
    RtpError,
    RtpExtensionError,
    RtpInvalidVersion,
    RtpPaddingError,
)
from .model.extension import (
    ExtensionElement,
    ExtensionProfile,
    HeaderExtension,
    build_header_extension,
    parse_extension_elements,
)
from .model.net import DecapsulatedUdp
from .model.packet import RtpPacket
from .model.payload_types import DYNAMIC_PAYLOAD_TYPE_RANGE, MediaType, PayloadTypeInfo, lookup_payload_type
from .model.pcap import PcapPacket
from .model.rtcp import (
    ApplicationDefined,
    Goodbye,
    ReceiverReport,
    ReportBlock,
    RtcpPacket,
    RtcpPacketType,
    SdesChunk,
    SdesItem,
    SdesItemType,
    SenderInfo,
    SenderReport,
    SourceDescription,
)
from .model.stream import RtpStreamStats
from .parser.rtcp_parser import parse_rtcp, parse_rtcp_lenient
from .parser.rtp_parser import parse_rtp, parse_rtp_lenient
from .stream.tracker import RtpStreamTracker

__all__ = [
    "__version__",
    # Core
    "parse_rtp",
    "parse_rtp_lenient",
    "RtpPacket",
    # Builder
    "RtpBuilder",
    # Extension
    "HeaderExtension",
    "ExtensionElement",
    "ExtensionProfile",
    "parse_extension_elements",
    "build_header_extension",
    # RTCP
    "parse_rtcp",
    "parse_rtcp_lenient",
    "RtcpPacket",
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
    # IO — captures and decapsulation
    "read_pcap",
    "read_pcap_lenient",
    "write_pcap",
    "read_pcapng",
    "read_pcapng_lenient",
    "write_pcapng",
    "read_capture",
    "read_capture_lenient",
    "decapsulate_udp",
    "encapsulate_udp",
    "PcapPacket",
    "DecapsulatedUdp",
    # Stream
    "RtpStreamTracker",
    "RtpStreamStats",
    # Payload types
    "MediaType",
    "PayloadTypeInfo",
    "lookup_payload_type",
    "DYNAMIC_PAYLOAD_TYPE_RANGE",
    # Detection
    "looks_like_rtp",
    "looks_like_rtcp",
    "RTCP_COLLISION_RANGE",
    "RtpFlowClassifier",
    "FlowClassification",
    # Codec
    "decode_pcmu",
    "encode_pcmu",
    "decode_pcma",
    "encode_pcma",
    # Fuzz
    "bit_flip",
    "truncate",
    "splice_random_bytes",
    "random_bytes",
    "fuzz_cases",
    "FuzzCrash",
    "FuzzResult",
    "fuzz_parser",
    # Errors
    "RtpError",
    "RtpBufferTooShort",
    "RtpInvalidVersion",
    "RtpPaddingError",
    "RtpExtensionError",
    "RtpBuildError",
    "RtcpError",
    "RtcpBufferTooShort",
    "RtcpInvalidVersion",
    "RtcpLengthMismatch",
    "RtcpMalformedPacket",
    "CaptureError",
    "PcapWriteError",
    "PcapBufferTooShort",
    "PcapInvalidMagic",
    "PcapTruncatedRecord",
    "PcapngBufferTooShort",
    "PcapngInvalidByteOrderMagic",
    "PcapngMalformedBlock",
    "EncapsulationError",
]

# Library-level NullHandler — no output unless the consumer configures logging.
logging.getLogger("rtpkit").addHandler(logging.NullHandler())
