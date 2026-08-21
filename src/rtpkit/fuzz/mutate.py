"""Byte-buffer mutation primitives for building fuzz corpora.

Protocol-agnostic on purpose: these work on any parser's input, not just
RTP/RTCP — pair them with your own seed buffers via :func:`fuzz_cases`.
"""

from __future__ import annotations

import random
from collections.abc import Iterator, Sequence

__all__ = ["bit_flip", "truncate", "splice_random_bytes", "random_bytes", "fuzz_cases"]


def bit_flip(data: bytes, rng: random.Random, *, count: int = 1) -> bytes:
    """Flip *count* random bits in *data*."""
    if not data:
        return data
    buf = bytearray(data)
    for _ in range(count):
        pos = rng.randrange(len(buf))
        buf[pos] ^= 1 << rng.randrange(8)
    return bytes(buf)


def truncate(data: bytes, rng: random.Random) -> bytes:
    """Cut *data* to a random shorter length (possibly empty)."""
    if not data:
        return data
    return data[: rng.randrange(len(data))]


def splice_random_bytes(data: bytes, rng: random.Random, *, max_insert: int = 8) -> bytes:
    """Insert a short run of random bytes at a random position in *data*."""
    pos = rng.randrange(len(data) + 1)
    run = bytes(rng.randrange(256) for _ in range(rng.randrange(1, max_insert + 1)))
    return data[:pos] + run + data[pos:]


def random_bytes(rng: random.Random, length: int) -> bytes:
    """A buffer of *length* uniformly random bytes."""
    return bytes(rng.randrange(256) for _ in range(length))


_MUTATORS = (bit_flip, truncate, splice_random_bytes)


def fuzz_cases(
    rng: random.Random,
    count: int,
    seeds: Sequence[bytes] = (),
    *,
    max_random_length: int = 64,
) -> Iterator[bytes]:
    """Yield *count* fuzz inputs: mutated seeds interleaved with pure random noise.

    With no seeds, every case is pure random noise. With seeds, most cases
    (80%) mutate a randomly chosen seed; the rest stay pure noise, so the
    corpus keeps probing completely unstructured input too.
    """
    for _ in range(count):
        if seeds and rng.random() < 0.8:
            seed = rng.choice(seeds)
            mutator = rng.choice(_MUTATORS)
            yield mutator(seed, rng)
        else:
            yield random_bytes(rng, rng.randrange(max_random_length + 1))
