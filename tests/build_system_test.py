# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Nothing but setuptools runs while a distribution is built.

`docs/source/package-content-policy.md` states what may be in the wheel
and the sdist, and `.github/scripts/verify_dist_contents.py` refuses a
build that carries anything else -- an installed wheel therefore executes
nothing at install time, there being no member left that could. What no
list of members can see is the *build*: `[build-system] requires` is
resolved into an isolated environment and every package named there runs
code while the archives are made, so that one line is the whole of what a
release trusts, and a diff is the only thing that reads it.

Which is what this is: the line is one requirement long, and a test
saying so is what a second one would have to go past.

Not an assertion on the exact string. The floor is declared in
pyproject.toml with the reason for it, and a copy of it here would be a
second declaration to keep in step, failing on the day it moves for a
reason that has nothing to do with what runs. The shape is what matters
and what is checked: one requirement, named setuptools, bounded from
below and nothing else -- which is also how a direct reference to a url,
an extra and an environment marker are refused, each of them a way to
name a package that resolves to somebody else's code.
"""

from __future__ import annotations

import re
from pathlib import Path

import tomllib

_PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"

# a name, `>=` and a release: no `@ <url>`, no `[extra]`, no `; marker`
_LOWER_BOUND = re.compile(r"setuptools>=[0-9]+(?:\.[0-9]+)*")

# the table pip and uv build with, read at import: the file is the
# project's own and a test module that cannot read it has nothing to say
_BUILD_SYSTEM = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["build-system"]


def test_the_build_requires_setuptools_and_nothing_else() -> None:
    """One requirement, and a lower bound is the whole of what it says."""
    (requirement,) = _BUILD_SYSTEM["requires"]

    assert _LOWER_BOUND.fullmatch(requirement)


def test_the_backend_is_the_declarative_one() -> None:
    """`setuptools.build_meta`, and not the `:__legacy__` beside it.

    That one is the backend for a project configured by `setup.py`: it
    imports the file and runs it, which is the install-time hook the
    package-content policy is about, one stage earlier and in the build.
    """
    assert _BUILD_SYSTEM["build-backend"] == "setuptools.build_meta"
