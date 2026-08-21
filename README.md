# rtpkit

Parse, build, analyse and (eventually) reconstruct RTP/RTCP traffic — a from-scratch, zero-dependency Python
library for VoIP and media tooling.

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
- RTCP compound-packet parsing (SR, RR, SDES, BYE, APP) — strict and lenient modes
- pcap and pcapng file reading, zero-dependency
- Ethernet / Linux cooked capture / raw-IP → IPv4 / IPv6 → UDP decapsulation, to pull RTP/RTCP candidates out of a capture
- RTP stream reconstruction: per-SSRC grouping, sequence-number reordering, loss/jitter statistics (RFC 3550)
- RTP/RTCP detection heuristics for traffic without SDP context, plus the RFC 3551 static payload type table
- A mutation-based fuzzing harness — protocol-agnostic, usable against rtpkit's own parsers or your own code

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

## Quick start

Parsing:

```python
from rtpkit import parse_rtp

pkt = parse_rtp(raw_bytes)
print(pkt.payload_type, pkt.sequence_number, hex(pkt.ssrc))
print(bytes(pkt.payload))  # memoryview — zero-copy view into raw_bytes
```

Building:

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

Strict vs. lenient parsing:

```python
from rtpkit import parse_rtp, parse_rtp_lenient

parse_rtp(malformed_bytes)          # raises a typed RtpError subclass
parse_rtp_lenient(malformed_bytes)  # logs a warning, returns a best-effort RtpPacket
```

Reading a capture and pulling out RTP candidates:

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

Tracking a stream's loss/jitter as you go:

```python
from rtpkit import RtpStreamTracker

tracker = RtpStreamTracker()
for pkt in rtp_packets_in_arrival_order:
    tracker.observe(pkt, arrival_time=..., clock_rate=8000)

stats = tracker.stats(ssrc)
print(stats.packet_count, stats.lost_count, stats.fraction_lost, stats.jitter)
ordered = tracker.ordered_packets(ssrc)  # back in sequence-number order
```

Fuzzing a parser (rtpkit's own, or your own code):

```python
from rtpkit import RtpBuilder, RtpError, fuzz_cases, fuzz_parser, parse_rtp
import random

seeds = [RtpBuilder().with_payload(b"\xaa" * 160).build()]
cases = list(fuzz_cases(random.Random(0), 1000, seeds=seeds))
result = fuzz_parser(parse_rtp, cases, allowed_exceptions=RtpError)
assert result.ok, result.crashes  # anything raised outside RtpError is a real bug
```

See [examples/demo.py](examples/demo.py) for a complete walkthrough, including CSRC lists, header extensions,
padding, error handling, and the zero-copy guarantee.

## Roadmap

- [x] RTP header parsing (RFC 3550), strict + lenient modes
- [x] RFC 8285 header extensions (one-byte / two-byte)
- [x] RTP packet building
- [x] RTCP (SR / RR / SDES / BYE / APP)
- [x] pcap/pcapng ingestion + Ethernet/IP/UDP decapsulation
- [x] RTP stream reconstruction (SSRC grouping, reorder, jitter/loss stats)
- [x] RTP/RTCP flow detection heuristics
- [x] Fuzzing harness

## License

MIT — see [LICENSE](LICENSE).
