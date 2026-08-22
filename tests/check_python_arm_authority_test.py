# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `compare()`, the diff logic of the weekly Python-arm sentinel.

`measure()` is what actually runs the suite under coverage, module by
module -- exactly what this repository collects no coverage from, the
reason `.github/scripts` sits outside `tool.coverage.run`'s `source` in
the first place. `compare()` takes none of that: a
`dict[str, frozenset[str]]` in, the three-way STALE/UNDERSTATED/NEW
AUTHORITY diff against `_AUTHORITY` and `_WITHOUT_AN_AUTHORITY` out, no
subprocess or coverage run needed to exercise it. `_AUTHORITY` and
`_WITHOUT_AN_AUTHORITY` are monkeypatched to small synthetic tables here
rather than read from `tests/python_arm_authority_test.py`, so a change
to the real table cannot make this test pass or fail by accident.

Loaded by path, the same reason and the same shape as
`tests/check_vendored_vectors_test.py`.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_SCRIPT = (
    Path(__file__).parents[1] / ".github" / "scripts" / "check_python_arm_authority.py"
)


@pytest.fixture
def checker(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Return the script, imported by path, registered before it runs."""
    spec = importlib.util.spec_from_file_location("check_python_arm_authority", _SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "check_python_arm_authority", module)
    spec.loader.exec_module(module)
    return module


def test_compare_finds_nothing_when_every_arm_matches(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A measurement equal to `_AUTHORITY` reports no mismatch at all."""
    monkeypatch.setattr(checker, "_AUTHORITY", {"an.arm": ("a.json",)})
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset())

    assert checker.compare({"an.arm": frozenset({"a.json"})}) == []


def test_compare_reports_stale_understated_and_new_authority(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One line per direction `compare()` can report, sorted by arm name."""
    monkeypatch.setattr(
        checker,
        "_AUTHORITY",
        {
            "match.arm": ("b.json",),
            "new.arm": (),
            "stale.arm": ("a.json",),
            "understated.arm": ("c.json",),
        },
    )
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset({"new.arm"}))

    mismatches = checker.compare(
        {
            "match.arm": frozenset({"b.json"}),
            "new.arm": frozenset({"e.json"}),
            "stale.arm": frozenset(),
            "understated.arm": frozenset({"c.json", "d.json"}),
        }
    )

    assert mismatches == [
        "NEW AUTHORITY: new.arm is reached by ['e.json'], not named in its entry",
        "STALE: stale.arm claims ['a.json'], whose run no longer reaches it",
        "UNDERSTATED: understated.arm is reached by ['d.json'], not named in its entry",
    ]


def test_compare_treats_an_arm_missing_from_the_measurement_as_empty(
    checker: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An arm `_AUTHORITY` claims, and the measurement never mentions: STALE."""
    monkeypatch.setattr(checker, "_AUTHORITY", {"an.arm": ("a.json",)})
    monkeypatch.setattr(checker, "_WITHOUT_AN_AUTHORITY", frozenset())

    assert checker.compare({}) == [
        "STALE: an.arm claims ['a.json'], whose run no longer reaches it"
    ]
