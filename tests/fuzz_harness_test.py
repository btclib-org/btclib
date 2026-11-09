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

import ast
import importlib.util
import sys
import types
from collections.abc import Callable
from pathlib import Path

import pytest
from typing_extensions import override

from btclib import var_int
from btclib.p2p.inventory import Headers

_FUZZ = Path(__file__).parent.parent / "fuzz"
_HARNESSES = tuple(sorted(_FUZZ.glob("fuzz_*.py")))
_SEEDS = tuple(
    (path, seed)
    for path in _HARNESSES
    for seed in sorted((_FUZZ / "corpus" / path.stem).glob("*.bin"))
)


def _requires(path: Path) -> tuple[str, ...]:
    """Return the harness's `REQUIRES`, read without importing it."""
    return next(
        (
            tuple(ast.literal_eval(node.value))
            for node in ast.parse(path.read_text(encoding="utf-8")).body
            if isinstance(node, ast.Assign)
            and [ast.unparse(target) for target in node.targets] == ["REQUIRES"]
        ),
        (),
    )


def _fuzz_target(
    path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[[bytes], None]:
    """Import the harness with a stand-in atheris; return its fuzz_target.

    Skip where a module its `REQUIRES` names is not installed.
    """
    for name in _requires(path):
        pytest.importorskip(name)
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


class _Forgetful(Headers):
    """A `Headers` that writes the empty message, whatever it holds."""

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        return Headers().serialize(check_validity=check_validity)


class _Padded(Headers):
    """A `Headers` that writes a three-octet count of 253 after each header.

    `Headers.parse` reads that count and ignores it, so what this writes
    parses back to the same headers, and is longer than a zero would be.
    """

    @override
    def serialize(self, *, check_validity: bool = True) -> bytes:
        out = var_int.serialize(len(self.headers))
        for header in self.headers:
            out += header.serialize(check_validity=check_validity)
            out += var_int.serialize(253)
        return out


@pytest.mark.parametrize(
    "lossy, check",
    [(_Forgetful, "parse back"), (_Padded, "never longer")],
    ids=["parse-back", "never-longer"],
)
def test_the_inventory_harness_holds_headers_to_both_checks(
    lossy: type[Headers], check: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `headers` that fails either check of the harness is a finding.

    The harness cannot ask `Headers.parse` to reproduce a seed carrying a
    transaction count, so it asks that the octets written parse back to
    the same headers and are never longer than the seed. `_Forgetful`
    writes shorter octets that are other headers, and `_Padded` writes the
    same headers in longer octets: each fails one check and passes the
    other.
    """
    target = _fuzz_target(_FUZZ / "fuzz_inventory.py", monkeypatch)
    monkeypatch.setitem(target.__globals__, "Headers", lossy)
    seed = (_FUZZ / "corpus" / "fuzz_inventory" / "headers-tx-count.bin").read_bytes()
    parsed = lossy.parse(seed)
    written = parsed.serialize()
    settles = lossy.parse(written) == parsed
    no_longer = len(written) <= len(seed)
    assert (settles, no_longer) == (check == "never longer", check == "parse back")
    with pytest.raises(AssertionError):
        target(seed)
