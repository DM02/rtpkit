# rtpkit

[![CI](https://github.com/dm02/rtpkit/actions/workflows/ci.yml/badge.svg)](https://github.com/dm02/rtpkit/actions/workflows/ci.yml)

Parse, build, analyse and (eventually) reconstruct RTP/RTCP traffic — a from-scratch, zero-dependency Python
library for VoIP and media tooling.

**New here?** Jump to [Getting started](#getting-started) for the fastest path from `pip install` to pulling RTP
out of a real capture file.

- [Why](#why)
- [Status](#status)
- [Install](#install)
- [Getting started](#getting-started)
- [More examples](#more-examples)
- [Roadmap](#roadmap)
- [Changelog](#changelog)
- [License](#license)

## Why

Python has plenty of general-purpose packet sniffers (scapy, dpkt) but no well-maintained library dedicated to RTP
semantics — typed packets, strict/lenient parsing, zero-copy payload access, RFC 8285 header extensions. rtpkit
exists to fill that gap so downstream VoIP tools (pcap analysis, stream extraction, QoS/security tooling) don't have
to hand-roll `struct.unpack` calls.

## Status

Alpha. Implemented so far:

- RTP header parsing (RFC 3550) — strict and lenient modes
- RFC 8285 header extensions (one-byte and two-byte formats)
- RTP packet building (inverse of parsing)
- RTCP compound-packet parsing and building (SR, RR, SDES, BYE, APP) — strict and lenient parsing modes
- pcap and pcapng file reading and writing, zero-dependency
- Ethernet / Linux cooked capture / raw-IP → IPv4 / IPv6 → UDP decapsulation (and the inverse — building a synthetic frame from a UDP payload)
- RTP stream reconstruction: per-SSRC grouping, sequence-number reordering, loss/jitter statistics (RFC 3550)
- RTP/RTCP detection heuristics for traffic without SDP context, plus the RFC 3551 static payload type table
- A mutation-based fuzzing harness — protocol-agnostic, usable against rtpkit's own parsers or your own code
- G.711 (PCMU/PCMA) audio codec — decode RTP payloads to 16-bit PCM (and back), zero-dependency

Planned — see [Roadmap](#roadmap).

## Install

```bash
pip install rtpkit
```

Development setup:

```bash
git clone https://github.com/dm02/rtpkit
cd rtpkit
python -m venv venv
./venv/Scripts/pip install -e ".[dev]"
```

## Getting started

Two starting points cover most of what people reach for rtpkit to do: parsing an RTP packet you already have
in hand, and pulling RTP out of a capture file you didn't produce yourself.

### 1. Parse a packet

```python
from rtpkit import parse_rtp

pkt = parse_rtp(raw_bytes)
print(pkt.payload_type, pkt.sequence_number, hex(pkt.ssrc))
print(bytes(pkt.payload))  # memoryview — zero-copy view into raw_bytes
```

`parse_rtp` is strict: malformed input raises a typed `RtpError` subclass. For real-world/untrusted captures,
where a few oddball packets are normal, use `parse_rtp_lenient` instead — it logs a warning and does its best
rather than raising:

```python
from rtpkit import parse_rtp, parse_rtp_lenient

parse_rtp(malformed_bytes)  # raises
parse_rtp_lenient(malformed_bytes)  # warns, returns a best-effort RtpPacket
```

### 2. Pull RTP out of a capture file

This is the more common real-world entry point — a `.pcap`/`.pcapng` file with all kinds of traffic mixed
together, and you want just the RTP:

```python
from rtpkit import read_capture, decapsulate_udp, parse_rtp_lenient

with open("call.pcapng", "rb") as f:
    data = f.read()

for pkt in read_capture(data):  # auto-detects .pcap vs .pcapng
    udp = decapsulate_udp(pkt.link_type, pkt.data)
    if udp is None:
        continue  # not Ethernet/SLL/raw-IP -> IPv4/IPv6 -> UDP
    rtp = parse_rtp_lenient(udp.payload)
    print(udp.src_ip, udp.dst_ip, rtp.ssrc, rtp.sequence_number)
```

See [examples/demo.py](examples/demo.py) for a longer walkthrough of the same two entry points — CSRC lists,
header extensions, padding, error handling, and the zero-copy guarantee.

## More examples

### Build a packet

```python
from rtpkit import RtpBuilder

pkt = (
    RtpBuilder()
    .with_payload_type(8)
    .with_sequence_number(1000)
    .with_timestamp(160_000)
    .with_ssrc(0xDEADBEEF)
    .with_payload(b"\x80" * 160)
    .build_packet()
)
```

RTCP has no fluent builder — five distinct packet shapes, not one packet with many options, so `build_rtcp` just serializes the model dataclasses you already have:

```python
from rtpkit import SenderReport, SenderInfo, build_rtcp

sr = SenderReport(
    ssrc=0xDEADBEEF,
    sender_info=SenderInfo(ntp_seconds=0, ntp_fraction=0, rtp_timestamp=160_000, packet_count=100, octet_count=16_000),
    report_blocks=(),
    padding_size=0,
)
raw = build_rtcp([sr])  # pass more packets for one compound buffer
```

### Edit a capture

Read, filter down to one RTP flow, write back out:

```python
from rtpkit import read_capture, decapsulate_udp, write_pcap

with open("call.pcap", "rb") as f:
    data = f.read()

rtp_only = [
    pkt
    for pkt in read_capture(data)
    if (udp := decapsulate_udp(pkt.link_type, pkt.data)) is not None and udp.dst_port == 6730
]

with open("rtp_only.pcap", "wb") as f:
    f.write(write_pcap(rtp_only))
```

### Track a stream's loss/jitter

```python
from rtpkit import RtpStreamTracker

tracker = RtpStreamTracker()
for pkt in rtp_packets_in_arrival_order:
    tracker.observe(pkt, arrival_time=..., clock_rate=8000)

stats = tracker.stats(ssrc)
print(stats.packet_count, stats.lost_count, stats.fraction_lost, stats.jitter)
ordered = tracker.ordered_packets(ssrc)  # back in sequence-number order
```

### Fuzz a parser

Works against rtpkit's own parsers, or your own code:

```python
from rtpkit import RtpBuilder, RtpError, fuzz_cases, fuzz_parser, parse_rtp
import random

seeds = [RtpBuilder().with_payload(b"\xaa" * 160).build()]
cases = list(fuzz_cases(random.Random(0), 1000, seeds=seeds))
result = fuzz_parser(parse_rtp, cases, allowed_exceptions=RtpError)
assert result.ok, result.crashes  # anything raised outside RtpError is a real bug
```

### Decode G.711 audio to a WAV file

```python
import wave
from rtpkit.codec.g711 import decode_pcma  # PCMU is decode_pcmu; same shape

pcm = b"".join(decode_pcma(bytes(pkt.payload)) for pkt in ordered_pcma_packets)
with wave.open("call.wav", "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(8000)
    w.writeframes(pcm)
```

### Build a synthetic capture from scratch

The inverse of decapsulation — wrap an RTP packet in a real link/IP/UDP frame (correct checksums included)
and write it out, without ever touching a real network:

```python
from rtpkit import RtpBuilder, encapsulate_udp, PcapPacket, write_pcap

rtp = RtpBuilder().with_payload_type(8).with_sequence_number(0).with_payload(b"\xd5" * 160).build()
frame = encapsulate_udp(1, "192.168.1.10", "192.168.1.20", 6730, 6730, rtp)  # 1 = Ethernet

pkt = PcapPacket(timestamp=0.0, captured_length=len(frame), original_length=len(frame), link_type=1, data=frame)
with open("synthetic.pcap", "wb") as f:
    f.write(write_pcap([pkt]))
```

## Roadmap

- [x] RTP header parsing (RFC 3550), strict + lenient modes
- [x] RFC 8285 header extensions (one-byte / two-byte)
- [x] RTP packet building
- [x] RTCP (SR / RR / SDES / BYE / APP)
- [x] pcap/pcapng ingestion + Ethernet/IP/UDP decapsulation (and encapsulation)
- [x] pcap/pcapng writing
- [x] G.711 (PCMU/PCMA) codec
- [x] RTP stream reconstruction (SSRC grouping, reorder, jitter/loss stats)
- [x] RTP/RTCP flow detection heuristics
- [x] Fuzzing harness

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
