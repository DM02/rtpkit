"""
rtpkit -- demo: co potrafi biblioteka i jak tego uzyc.

Odpal:
    cd c:/biblioteka/rtpkit
    .\\venv\\Scripts\\python.exe examples/demo.py
"""

import logging
import struct

from rtpkit import (
    RtpBufferTooShort,
    RtpInvalidVersion,
    RtpPaddingError,
    parse_extension_elements,
    parse_rtp,
    parse_rtp_lenient,
)


def separator(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


# 1. Reczne budowanie pakietu RTP z surowych bajtow

separator("1. Budujemy pakiet RTP recznie z bajtow")

header = struct.pack(
    "!BBHII",
    0x80,  # V=2, P=0, X=0, CC=0
    0x08,  # M=0, PT=8
    1000,  # sequence number
    160_000,  # timestamp
    0xDEADBEEF,  # SSRC
)

payload = bytes([0x55, 0xAA] * 10)

raw_packet = header + payload
print(f"Surowy pakiet: {raw_packet.hex()}")
print(f"Rozmiar: {len(raw_packet)} bajtow")


# 2. Parsowanie tego pakietu

separator("2. Parsujemy pakiet")

pkt = parse_rtp(raw_packet)

print(f"version:         {pkt.version}")
print(f"padding:         {pkt.padding}")
print(f"extension:       {pkt.extension}")
print(f"marker:          {pkt.marker}")
print(f"payload_type:    {pkt.payload_type}  (8 = G.711 A-law)")
print(f"sequence_number: {pkt.sequence_number}")
print(f"timestamp:       {pkt.timestamp}")
print(f"ssrc:            0x{pkt.ssrc:08X}")
print(f"csrc count (cc): {pkt.cc}")
print(f"header_size:     {pkt.header_size} bajtow")
print(f"payload size:    {len(pkt.payload)} bajtow")
print(f"payload (hex):   {bytes(pkt.payload).hex()}")
print(f"total_size:      {pkt.total_size} bajtow")


# 3. Pakiet z CSRC (contributing sources)

separator("3. Pakiet z CSRC (konferencja)")

header_with_csrc = struct.pack(
    "!BBHII II",
    0x82,  # V=2, P=0, X=0, CC=2
    0x08,  # M=0, PT=8
    1001,
    160_160,
    0xCAFEBABE,  # SSRC (mikser)
    0x11111111,  # CSRC 1
    0x22222222,  # CSRC 2
)
raw2 = header_with_csrc + b"\x00" * 10

pkt2 = parse_rtp(raw2)
print(f"SSRC (mikser):    0x{pkt2.ssrc:08X}")
print(f"Ilosc zrodel:     {pkt2.cc}")
for i, csrc in enumerate(pkt2.csrc):
    print(f"  CSRC[{i}]:        0x{csrc:08X}")


# 4. Pakiet z Extension (WebRTC one-byte)

separator("4. Pakiet z rozszerzeniem naglowka (0xBEDE)")

ext_header = struct.pack("!HH", 0xBEDE, 1)
ext_data = bytes(
    [
        0x11,  # ID=1, length=1 -> 2 bajty
        0x05,
        0x0A,  # dane elementu (np. audio level)
        0x00,  # padding do 4 bajtow
    ]
)

header_ext = struct.pack(
    "!BBHII",
    0x90,  # V=2, P=0, X=1, CC=0
    111,  # M=0, PT=111 (Opus)
    5000,
    480_000,
    0xABCD1234,
)
raw3 = header_ext + ext_header + ext_data + b"\x80" * 20

pkt3 = parse_rtp(raw3)
print(f"Ma extension:     {pkt3.extension}")
print(f"Extension profil: 0x{pkt3.header_extension.profile:04X}")
print(f"Extension words:  {pkt3.header_extension.length}")
print(f"Extension raw:    {bytes(pkt3.header_extension.data).hex()}")

elements = parse_extension_elements(pkt3.header_extension)
print(f"Ilosc elementow:  {len(elements)}")
for elem in elements:
    print(f"  Element ID={elem.id}, dane={bytes(elem.data).hex()}")


# 5. Pakiet z paddingiem

separator("5. Pakiet z paddingiem")

header_pad = struct.pack(
    "!BBHII",
    0xA0,  # V=2, P=1, X=0, CC=0
    0x08,
    2000,
    320_000,
    0x99887766,
)
audio = b"\xaa" * 16
padding = b"\x00\x00\x00\x04"  # 4 bajty paddingu

raw4 = header_pad + audio + padding

pkt4 = parse_rtp(raw4)
print(f"Padding flag:     {pkt4.padding}")
print(f"Padding size:     {pkt4.padding_size} bajtow")
print(f"Payload size:     {len(pkt4.payload)} bajtow (bez paddingu!)")
print(f"Total size:       {pkt4.total_size} bajtow")
print(f"Payload (hex):    {bytes(pkt4.payload).hex()}")


# 6. Obsluga bledow (strict mode)

separator("6. Obsluga bledow (strict mode)")

print("-> Za krotki bufor (5 bajtow):")
try:
    parse_rtp(b"\x80\x08\x00\x01\x00")
except RtpBufferTooShort as e:
    print(f"  BLAD: {e}")
    print(f"  Potrzeba: {e.required}, mam: {e.actual}")

print("\n-> Wersja RTP = 3 (powinno byc 2):")
bad_version = bytearray(raw_packet)
bad_version[0] = 0xC0  # V=3
try:
    parse_rtp(bytes(bad_version))
except RtpInvalidVersion as e:
    print(f"  BLAD: {e}")
    print(f"  Znaleziona wersja: {e.version}")

print("\n-> Padding = 0 (nielegalne):")
bad_pad = bytearray(raw4)
bad_pad[-1] = 0
try:
    parse_rtp(bytes(bad_pad))
except RtpPaddingError as e:
    print(f"  BLAD: {e}")


# 7. Lenient mode

separator("7. Lenient mode - parsuj mimo bledow")

logging.basicConfig(level=logging.WARNING, format="  [!] %(message)s")

print("-> Parsujemy pakiet z version=3 (lenient):")
pkt_lenient = parse_rtp_lenient(bytes(bad_version))
print(f"  Wersja:  {pkt_lenient.version} (nie 2, ale biblioteka kontynuowala)")
print(f"  Payload: {len(pkt_lenient.payload)} bajtow")
print(f"  PT:      {pkt_lenient.payload_type}")

print("\n-> Parsujemy pakiet z zlym paddingiem (lenient):")
pkt_bad_pad = parse_rtp_lenient(bytes(bad_pad))
print(f"  Padding flag:  {pkt_bad_pad.padding}")
print(f"  Padding size:  {pkt_bad_pad.padding_size} (zignorowany!)")


# 8. Zero-copy

separator("8. Zero-copy - payload wskazuje na oryginalny bufor")

buf = bytearray(raw_packet)
pkt_zc = parse_rtp(buf)

print(f"Payload[0] przed:  0x{pkt_zc.payload[0]:02X}")
buf[12] = 0xFF
print(f"Payload[0] po:     0x{pkt_zc.payload[0]:02X}  <- zmiana widoczna!")
print("-> Nie bylo zadnego kopiowania - payload to widok na ten sam bufor")


# Podsumowanie

separator("KONIEC DEMO")
print("Biblioteka potrafi:")
print("  [+] Parsowac surowe bajty RTP -> immutable RtpPacket")
print("  [+] Rozpakowywac CSRC (contributing sources)")
print("  [+] Parsowac rozszerzenia naglowka (RFC 8285 one/two-byte)")
print("  [+] Obslugiwac padding")
print("  [+] Strict mode - rzuca wyjatki na wszelkie problemy")
print("  [+] Lenient mode - kontynuuje mimo bledow, loguje ostrzezenia")
print("  [+] Zero-copy - memoryview, brak kopiowania danych")
print()
print("Czego jeszcze NIE potrafi:")
print("  [-] Otwierac plikow pcap/pcapng")
print("  [-] Rozpakowywac Ethernet/IP/UDP -> RTP")
print("  [-] Skladac strumieni (grupowanie po SSRC, reorder)")
print("  [-] Budowac pakietow RTP (builder - przyszly etap)")
