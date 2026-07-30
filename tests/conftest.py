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

import os
from pathlib import Path

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

    Eleven modules serialize a dataclass to json on disk and read it back,
    and the file is committed rather than discarded: a change to what
    `to_dict` writes then shows up as a diff to review, which is the point
    of writing it to the repository instead of to `tmp_path`.

    Each of those modules used to open the test with the same line,
    `path.join(path.dirname(__file__), "_generated_files")`, which is a
    directory layout restated eleven times -- and restated in terms of
    `__file__`, so it moved with the test rather than with the data. Here
    it is stated once, and `request.path` is the same module's file.
    """
    return Path(request.path).parent / "_generated_files"
