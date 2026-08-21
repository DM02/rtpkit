"""Direct unit tests for rtpkit.fuzz's own mechanics (not run against rtpkit's parsers)."""

from __future__ import annotations

import random

from rtpkit import bit_flip, fuzz_cases, fuzz_parser, random_bytes, splice_random_bytes, truncate
from rtpkit.fuzz import FuzzCrash, FuzzResult


class TestMutators:
    def test_bit_flip_empty_data_is_unchanged(self) -> None:
        assert bit_flip(b"", random.Random(1)) == b""

    def test_bit_flip_changes_exactly_one_bit(self) -> None:
        original = bytes([0b00000000] * 4)
        mutated = bit_flip(original, random.Random(42))
        diff_bits = sum(bin(o ^ m).count("1") for o, m in zip(original, mutated))
        assert diff_bits == 1

    def test_bit_flip_count_flips_multiple_bits(self) -> None:
        original = bytes(16)
        mutated = bit_flip(original, random.Random(1), count=5)
        assert mutated != original

    def test_truncate_empty_data_is_unchanged(self) -> None:
        assert truncate(b"", random.Random(1)) == b""

    def test_truncate_always_shortens(self) -> None:
        rng = random.Random(7)
        original = b"\xaa" * 20
        for _ in range(20):
            result = truncate(original, rng)
            assert len(result) < len(original)
            assert original.startswith(result)

    def test_splice_random_bytes_grows_the_buffer(self) -> None:
        rng = random.Random(3)
        original = b"\x01\x02\x03"
        result = splice_random_bytes(original, rng)
        assert len(result) > len(original)

    def test_random_bytes_has_requested_length(self) -> None:
        rng = random.Random(5)
        data = random_bytes(rng, 32)
        assert len(data) == 32
        assert all(0 <= b <= 255 for b in data)

    def test_random_bytes_zero_length(self) -> None:
        assert random_bytes(random.Random(1), 0) == b""


class TestFuzzCases:
    def test_yields_requested_count(self) -> None:
        cases = list(fuzz_cases(random.Random(1), 50))
        assert len(cases) == 50

    def test_without_seeds_is_pure_random_noise(self) -> None:
        cases = list(fuzz_cases(random.Random(1), 20, seeds=()))
        assert all(isinstance(c, bytes) for c in cases)

    def test_with_seeds_produces_seed_derived_and_random_cases(self) -> None:
        seeds = [b"\x01\x02\x03\x04"]
        cases = list(fuzz_cases(random.Random(2), 100, seeds=seeds))
        assert len(cases) == 100
        # at least one case should differ from every seed (pure-random branch) ...
        assert any(c not in seeds for c in cases)


class TestFuzzParser:
    def test_no_crashes_reports_ok(self) -> None:
        result = fuzz_parser(lambda data: len(data), [b"\x01", b"\x02\x03"])
        assert result.ok is True
        assert result.cases_run == 2
        assert result.crashes == ()

    def test_records_unexpected_exceptions_as_crashes(self) -> None:
        def always_fails(data: bytes) -> None:
            raise ValueError(f"boom on {data!r}")

        result = fuzz_parser(always_fails, [b"\x01", b"\x02"])
        assert result.ok is False
        assert len(result.crashes) == 2
        crash = result.crashes[0]
        assert isinstance(crash, FuzzCrash)
        assert crash.exception_type == "ValueError"
        assert crash.input == b"\x01"
        assert "boom" in crash.message

    def test_allowed_exceptions_are_not_crashes(self) -> None:
        def raises_key_error(data: bytes) -> None:
            raise KeyError("expected")

        result = fuzz_parser(raises_key_error, [b"\x01"], allowed_exceptions=KeyError)
        assert result.ok is True
        assert result.cases_run == 1

    def test_allowed_exceptions_tuple(self) -> None:
        def raises_type_error(data: bytes) -> None:
            raise TypeError("expected")

        result = fuzz_parser(raises_type_error, [b"\x01"], allowed_exceptions=(KeyError, TypeError))
        assert result.ok is True

    def test_unlisted_exception_type_still_crashes(self) -> None:
        def raises_index_error(data: bytes) -> None:
            raise IndexError("nope")

        result = fuzz_parser(raises_index_error, [b"\x01"], allowed_exceptions=KeyError)
        assert result.ok is False
        assert result.crashes[0].exception_type == "IndexError"

    def test_empty_case_iterable(self) -> None:
        result = fuzz_parser(lambda data: data, [])
        assert result.cases_run == 0
        assert result.ok is True

    def test_result_is_a_dataclass_instance(self) -> None:
        result = fuzz_parser(lambda data: data, [b"\x00"])
        assert isinstance(result, FuzzResult)
