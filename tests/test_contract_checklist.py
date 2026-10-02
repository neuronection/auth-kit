"""Checklist ↔ tests binding (F9): `CONTRACT_CASES` cannot drift from
the suite that proves it — in either direction.

Forward: every row's proving modules (the kit-side `CONTRACT_CASE_TESTS`
map) exist under `tests/` and actually contain tests. Reverse: every
test module carrying the family contract marker proves at least one
checklist row. A new row without tests, a renamed proving module, or a
new contract-marked test module without a row fails here loudly — the
checklist only helps a product copying it while the kit can prove it.
"""

from __future__ import annotations

import re
from pathlib import Path

from nx_auth.testing import CONTRACT_CASE_TESTS, CONTRACT_CASES

TESTS_DIR = Path(__file__).resolve().parent

# The family contract marker, assembled from fragments so this meta-test
# can scan module sources without matching its own pattern literal.
_CONTRACT_MARK = re.compile(re.escape("mark" + ".contract"))


def _case_number(row: str) -> str:
    return row.split(" ", 1)[0]


def _read(name: str) -> str:
    return (TESTS_DIR / f"{name}.py").read_text(encoding="utf-8")


def test_case_numbers_are_contiguous() -> None:
    numbers = [_case_number(row) for row in CONTRACT_CASES]
    assert numbers == [str(index) for index in range(1, len(CONTRACT_CASES) + 1)]


def test_every_case_number_has_a_proving_module_map() -> None:
    assert set(CONTRACT_CASE_TESTS) == set(map(_case_number, CONTRACT_CASES))


def test_every_case_references_existing_test_modules() -> None:
    missing = {
        case: [name for name in names if not (TESTS_DIR / f"{name}.py").is_file()]
        for case, names in CONTRACT_CASE_TESTS.items()
    }
    assert {case: names for case, names in missing.items() if names} == {}


def test_every_referenced_module_defines_tests() -> None:
    empty = {
        case: [name for name in names if "def test_" not in _read(name)]
        for case, names in CONTRACT_CASE_TESTS.items()
    }
    assert {case: names for case, names in empty.items() if names} == {}


def test_contract_marked_modules_prove_a_row() -> None:
    referenced = {name for names in CONTRACT_CASE_TESTS.values() for name in names}
    unreferenced = sorted(
        path.stem
        for path in TESTS_DIR.glob("test_*.py")
        if _CONTRACT_MARK.search(path.read_text(encoding="utf-8"))
        and path.stem not in referenced
    )
    assert unreferenced == []
