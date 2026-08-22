"""rtpkit.codec — Decode/encode simple RTP audio payload codecs."""

from .g711 import decode_pcma, decode_pcmu, encode_pcma, encode_pcmu

__all__ = ["decode_pcmu", "encode_pcmu", "decode_pcma", "encode_pcma"]
