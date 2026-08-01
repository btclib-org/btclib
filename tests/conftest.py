#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
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
    """The `_generated_files` directory beside the test module asking.

    Each of the modules using it used to open the test with the same line,
    `path.join(path.dirname(__file__), "_generated_files")`, which is a
    directory layout restated eleven times -- and restated in terms of
    `__file__`, so it moved with the test rather than with the data. Here
    it is stated once, and `request.path` is the same module's file.
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

    Eleven modules used to get that by *writing* the file on every run and
    leaving `git status` to report the difference. Three things were wrong
    with it. The suite was not hermetic, so it failed on a read-only
    checkout or when run from an installed sdist. The check depended on a
    human running the suite and then remembering to look, and CI never
    looks: no workflow inspects the working tree after pytest, so in CI the
    file was rewritten and thrown away, and the drift it exists to catch was
    invisible exactly where it matters. And each of those writes ended in
    `file_.write("\\n")  # end-of-file-fixer`, a test shaped to placate a
    lint hook.

    So the comparison runs the other way round now: the file is read, the
    difference fails the test, and nothing is written. To update a golden on
    purpose, when a change to `to_dict` is the intended change:

        BTCLIB_REGENERATE_GOLDEN=1 uv run pytest

    then read the diff, which is the review this was always meant to get.

    The round trip these tests used to do on disk -- dump, load, compare to
    the dict just dumped -- is not kept: it could only fail if json.dump and
    json.load were not each other's inverse, which is a test of the standard
    library. What they assert about btclib is `from_dict(to_dict()) == obj`,
    in memory, which every one of them already did beside it.
    """

    def check(name: str, value: Any) -> None:
        check_golden(generated_files_dir / name, name, value, request.path.name)

    return check


def check_golden(path: Path, name: str, value: Any, module: str) -> None:
    """Compare `value` against the json at `path`, or rewrite it.

    The body of the fixture above, lifted out of the closure it used to
    be: a closure over `request` cannot be called without a test to
    build it from, so the regenerate, missing-file and mismatch paths --
    the three that matter and the two that are failures -- were the only
    lines of `tests/` a passing suite never ran. Here they take a path
    and a module name, so `tests/conftest_test.py` exercises all three
    against a tmp_path, hermetically and without writing into the source
    tree, which is what this fixture exists to have stopped doing.
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
