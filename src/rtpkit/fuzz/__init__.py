"""rtpkit.fuzz — Mutation-based fuzzing harness for byte-buffer parsers."""

from .mutate import bit_flip, fuzz_cases, random_bytes, splice_random_bytes, truncate
from .runner import FuzzCrash, FuzzResult, fuzz_parser

__all__ = [
    "bit_flip",
    "truncate",
    "splice_random_bytes",
    "random_bytes",
    "fuzz_cases",
    "FuzzCrash",
    "FuzzResult",
    "fuzz_parser",
]
