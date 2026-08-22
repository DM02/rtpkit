# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added
- CI (GitHub Actions): lint, format check, type check, and the test suite across Python 3.11-3.13 on Linux and Windows
- `ruff` for linting and formatting, wired into CI
- `write_pcap` / `write_pcapng` — pcap/pcapng writers, completing the read/edit/write round trip
- `rtpkit.codec.g711` — pure-Python G.711 (PCMU/PCMA) decode/encode, verified bit-exact against CPython's
  `audioop` reference for decoding, and provably optimal (nearest-neighbour against that same table) for encoding
- `rtpkit.__version__`

### Fixed
- `RtpFlowClassifier` false positive on non-RTP traffic with a frozen SSRC/sequence number (found by testing
  against a real mixed SIP/RTP capture)
