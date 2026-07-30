#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Hypothesis profiles for the whole suite.

Registered once here rather than passed to each `@given`: a settings
profile is process-wide, and a decorator repeating it on every property
test is one more place to forget it.
"""

import os

from hypothesis import settings

# The deadline is a per-example time limit, measured on a run whose cost
# the interpreter and the runner decide: pypy meets these tests with a
# cold JIT, and the matrix runs them on emulated arm64 as well as on
# native x86. A timing flake in one of 54 jobs is a red build nobody can
# reproduce locally, and none of these tests is a benchmark -- what they
# assert is the answer, not how long it took to reach it.
# The example count is left at the hypothesis default of 100: the suite
# runs on every commit of a six-interpreter matrix, and the parsers are
# cheap enough that 100 inputs each cost about a second in total.
settings.register_profile("btclib", deadline=None)

# What to run when a parser is being changed, rather than on every
# commit: HYPOTHESIS_PROFILE=thorough uv run pytest
settings.register_profile("thorough", deadline=None, max_examples=2_000)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "btclib"))
