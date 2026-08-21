"""Format-agnostic capture reader — dispatches to pcap or pcapng by magic bytes."""

from __future__ import annotations

from collections.abc import Iterator

from ..model.pcap import PcapPacket
from .pcap_reader import read_pcap, read_pcap_lenient
from .pcapng_reader import read_pcapng, read_pcapng_lenient

__all__ = ["read_capture", "read_capture_lenient"]

_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def read_capture(data: bytes | bytearray | memoryview) -> Iterator[PcapPacket]:
    """Read a .pcap or .pcapng file in strict mode, detected from its magic bytes."""
    yield from (read_pcapng if _is_pcapng(data) else read_pcap)(data)


def read_capture_lenient(data: bytes | bytearray | memoryview) -> Iterator[PcapPacket]:
    """Read a .pcap or .pcapng file in lenient mode, detected from its magic bytes."""
    yield from (read_pcapng_lenient if _is_pcapng(data) else read_pcap_lenient)(data)


def _is_pcapng(data: bytes | bytearray | memoryview) -> bool:
    return bytes(data[0:4]) == _PCAPNG_MAGIC
