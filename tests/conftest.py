# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the whole suite shares: hypothesis profiles, and one fixture.

Registered once here rather than passed to each `@given`: a settings
profile is process-wide, and a decorator repeating it on every property
test is one more place to forget it.
"""

import difflib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings

# The deadline is a per-example time limit, measured on a run whose cost
# the interpreter and the runner decide: pypy meets these tests with a
# cold JIT, and the matrix runs them on emulated arm64 as well as on
# native x86. A timing flake in one of 54 jobs is a red build nobody can
# reproduce locally, and none of these tests is a benchmark -- what they
# assert is the answer, not how long it took to reach it.
#
# 500 examples against the hypothesis default of 100: measured at 1.4
# seconds for the whole suite over the default, which is worth five
# times the input on a run that happens at every commit. It is not the
# number that finds a latent defect, though -- the empty block of
# test_block_without_transactions took 2000 to turn up, and once turned
# up it belongs in a vector test rather than in a search that may or may
# not repeat it. Deep exploration is what the profile below is for.
settings.register_profile("btclib", deadline=None, max_examples=500)

# What to run when a parser is being changed, rather than at every
# commit: HYPOTHESIS_PROFILE=thorough uv run pytest
settings.register_profile("thorough", deadline=None, max_examples=2_000)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "btclib"))


@pytest.fixture
def generated_files_dir(request: pytest.FixtureRequest) -> Path:
    """Locate the `_generated_files` directory beside the asking module.

    Stated once here rather than once per module: spelling
    `path.join(path.dirname(__file__), "_generated_files")` in each test
    restates the directory layout eleven times, in terms of `__file__`,
    so it moves with the test rather than with the data. `request.path`
    is the asking module's file.
    """
    return Path(request.path).parent / "_generated_files"


# What the json_golden fixture hands a test: named here so that the eleven
# modules taking it can annotate the parameter without restating the type
JsonGolden = Callable[[str, Any], None]

# the escape hatch, and the only thing that writes into the source tree
REGENERATE = "BTCLIB_REGENERATE_GOLDEN"


@pytest.fixture
def json_golden(
    request: pytest.FixtureRequest, generated_files_dir: Path
) -> JsonGolden:
    """Compare a `to_dict()` against the json committed beside the module.

    The point of keeping these files in the repository is to notice when
    what `to_dict` writes changes: they are the output of eleven dataclasses
    over fixed input, so a diff to one of them is a change to a serialized
    form somebody may be storing.

    The comparison reads and never writes: the file is read, and a
    difference fails the test. Writing the file on every run and leaving
    `git status` to report the difference would not be hermetic (a
    read-only checkout, an installed sdist), and it would depend on a
    human running the suite and then remembering to look -- no workflow
    inspects the working tree after pytest, so in CI the drift would be
    invisible exactly where it matters. To update a golden on purpose,
    when a change to `to_dict` is the intended change:

        BTCLIB_REGENERATE_GOLDEN=1 uv run pytest

    then read the diff, which is the review the change is meant to get.

    There is no on-disk round trip -- dump, load, compare to the dict just
    dumped -- because it could only fail if json.dump and json.load were
    not each other's inverse, which is a test of the standard library.
    What these tests assert about btclib is `from_dict(to_dict()) == obj`,
    in memory, beside every golden check.
    """

    def check(name: str, value: Any) -> None:
        check_golden(generated_files_dir / name, name, value, request.path.name)

    return check


def check_golden(path: Path, name: str, value: Any, module: str) -> None:
    """Compare `value` against the json at `path`, or rewrite it.

    The body of the fixture above, a module-level function rather than a
    closure: a closure over `request` cannot be called without a test to
    build it from, so the regenerate, missing-file and mismatch paths --
    the three that matter and the two that are failures -- would be the
    only lines of `tests/` a passing suite never runs. Taking a path and
    a module name lets `tests/conftest_test.py` exercise all three
    against a tmp_path, hermetically and without writing into the source
    tree.
    """
    # what the writes produced, byte for byte, so that regenerating
    # leaves no diff of its own
    text = json.dumps(value, indent=4) + "\n"

    if os.environ.get(REGENERATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="ascii")
        return

    if not path.exists():
        pytest.fail(
            f"missing golden file {path}\nrun: {REGENERATE}=1 uv run pytest {module}"
        )

    committed = path.read_text(encoding="ascii")
    if committed != text:
        diff = "".join(
            difflib.unified_diff(
                committed.splitlines(keepends=True),
                text.splitlines(keepends=True),
                fromfile=f"{name} (committed)",
                tofile=f"{name} (this run)",
            )
        )
        pytest.fail(
            f"{name} does not match what to_dict() produces now.\n"
            f"If the change is intended, regenerate and review the diff:\n"
            f"  {REGENERATE}=1 uv run pytest {module}\n\n"
            f"{diff}"
        )
