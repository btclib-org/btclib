# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every fuzz harness's `fuzz_target` runs on every seed of its corpus.

A harness imports atheris at module level, and atheris is CI-only. Each
harness is therefore imported here with an empty stand-in `atheris` in
`sys.modules`. Importing runs no atheris call: those are in `main()`,
under `if __name__ == "__main__":`. The stand-in is empty so that a
harness reaching for atheris at import time fails with an
`AttributeError` instead of being silently served.

What the suite then runs is the harness's own body, asserts included:
a wrong assert, a vanished name or a round trip that cannot hold fails
here, on a pull request, rather than in the weekly ClusterFuzzLite run.

`fuzz_corpus_test.py` is the other half: it reads the harnesses with
`ast` and checks the seeds against the entry points they declare.

This module reads `fuzz/`, which an unpacked sdist does not carry, so
`[tool.uv.build-backend] source-exclude` names it.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path

import pytest

_FUZZ = Path(__file__).parent.parent / "fuzz"
_HARNESSES = tuple(sorted(_FUZZ.glob("fuzz_*.py")))
_SEEDS = tuple(
    (path, seed)
    for path in _HARNESSES
    for seed in sorted((_FUZZ / "corpus" / path.stem).glob("*.bin"))
)


def _fuzz_target(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[[bytes], None]:
    """Import the harness with a stand-in atheris; return its fuzz_target."""
    stand_in = types.ModuleType("atheris")
    monkeypatch.setitem(sys.modules, "atheris", stand_in)
    spec = importlib.util.spec_from_file_location(f"_harness_{path.stem}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.atheris is stand_in, f"{path.name} did not import the stand-in"
    target: Callable[[bytes], None] = module.fuzz_target
    return target


def test_there_are_harnesses_and_seeds() -> None:
    """The parametrized tests below quantify over both."""
    assert _HARNESSES, f"{_FUZZ} holds no fuzz_*.py"
    assert _SEEDS, f"{_FUZZ / 'corpus'} holds no seed"


@pytest.mark.parametrize(
    "path, seed",
    _SEEDS,
    ids=[str(seed.relative_to(_FUZZ / "corpus")) for _, seed in _SEEDS],
)
def test_fuzz_target_runs_on_its_seed(
    path: Path, seed: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A seed is an input the harness's own body must survive."""
    _fuzz_target(path, monkeypatch)(seed.read_bytes())
