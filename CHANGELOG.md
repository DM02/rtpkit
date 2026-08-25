# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

## [0.3.0] - 2026-08-25

### Added
- `build_rtcp` — the inverse of `parse_rtcp`: serializes SR/RR/SDES/BYE/APP model dataclasses into a compound
  RTCP buffer, completing the parse/build round trip for RTCP the same way `RtpBuilder` does for RTP

## [0.2.0] - 2026-08-24

### Added
- CI (GitHub Actions): lint, format check, type check, and the test suite across Python 3.11-3.13 on Linux and Windows
- `ruff` for linting and formatting, wired into CI
- `write_pcap` / `write_pcapng` — pcap/pcapng writers, completing the read/edit/write round trip
- `rtpkit.codec.g711` — pure-Python G.711 (PCMU/PCMA) decode/encode, verified bit-exact against CPython's
  `audioop` reference for decoding, and provably optimal (nearest-neighbour against that same table) for encoding
- `rtpkit.__version__`
- `encapsulate_udp` — the inverse of `decapsulate_udp`: wraps a UDP payload in a link/IP/UDP frame (Ethernet/Linux
  cooked capture/raw IP, IPv4/IPv6, correct checksums), for building synthetic capture files from scratch

### Fixed
- `RtpFlowClassifier` false positive on non-RTP traffic with a frozen SSRC/sequence number (found by testing
  against a real mixed SIP/RTP capture)
