"""Run a parser against a corpus of fuzz inputs and record what breaks it."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

__all__ = ["FuzzCrash", "FuzzResult", "fuzz_parser"]


@dataclass(frozen=True, slots=True)
class FuzzCrash:
    """One input that raised an exception outside the parser's declared contract."""

    input: bytes
    exception_type: str
    message: str


@dataclass(frozen=True, slots=True)
class FuzzResult:
    """Outcome of running :func:`fuzz_parser` over a corpus."""

    cases_run: int
    crashes: tuple[FuzzCrash, ...]

    @property
    def ok(self) -> bool:
        return not self.crashes


def fuzz_parser(
    parse: Callable[[bytes], object],
    cases: Iterable[bytes],
    *,
    allowed_exceptions: type[BaseException] | tuple[type[BaseException], ...] = (),
) -> FuzzResult:
    """Call ``parse(case)`` for every case, recording anything outside *allowed_exceptions* as a crash.

    *parse* should fully consume its result — wrap a generator-returning
    function (e.g. ``read_pcap``) as ``lambda data: list(read_pcap(data))``
    so exceptions raised lazily during iteration still surface here.
    """
    crashes: list[FuzzCrash] = []
    cases_run = 0
    for case in cases:
        cases_run += 1
        try:
            parse(case)
        except allowed_exceptions:
            pass
        except Exception as exc:  # noqa: BLE001 -- this *is* the crash detector
            crashes.append(FuzzCrash(input=bytes(case), exception_type=type(exc).__name__, message=str(exc)))
    return FuzzResult(cases_run=cases_run, crashes=tuple(crashes))
