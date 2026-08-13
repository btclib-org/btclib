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

Regex rather than `tomllib` for the two keys wanted out of
pyproject.toml: the floor here is 3.10, and `tomllib` is 3.11, so a test
module importing it fails to collect on the oldest interpreter the
matrix runs, with every other cell green. `tests/copyright_test.py` reads
the same file the same way and for the same reason; once 3.10 is dropped,
both can parse it. What the regex costs is that it reads text and not a
table, so it is anchored on the `[build-system]` header and stops at the
next one: a `requires` belonging to some `[tool.*]` below is a different
key, and a second build requirement is what has to be seen.
"""

from __future__ import annotations

import re
from pathlib import Path

_PYPROJECT = Path(__file__).parents[1] / "pyproject.toml"

# a name, `>=` and a release: no `@ <url>`, no `[extra]`, no `; marker`
_LOWER_BOUND = re.compile(r"setuptools>=[0-9]+(?:\.[0-9]+)*")

# the table pip and uv build with, up to whichever table follows it
_TABLE = re.compile(r"^\[build-system\]$(.*?)(?=^\[)", re.MULTILINE | re.DOTALL)
_REQUIRES = re.compile(r"^requires\s*=\s*\[(.*?)\]", re.MULTILINE | re.DOTALL)
_BACKEND = re.compile(r'^build-backend\s*=\s*"(.*?)"', re.MULTILINE)
_QUOTED = re.compile(r'"(.*?)"')


def _build_system() -> str:
    """Return the text of pyproject.toml's `[build-system]` table.

    Called at import: the file is the project's own and a test module
    that cannot read it has nothing to say.
    """
    text = _PYPROJECT.read_text(encoding="utf-8")
    match = _TABLE.search(text)
    assert match, "pyproject.toml has no [build-system] table"
    return match.group(1)


_BUILD_SYSTEM = _build_system()


def test_the_build_requires_setuptools_and_nothing_else() -> None:
    """One requirement, and a lower bound is the whole of what it says."""
    match = _REQUIRES.search(_BUILD_SYSTEM)
    assert match, "[build-system] declares no requires"
    (requirement,) = _QUOTED.findall(match.group(1))

    assert _LOWER_BOUND.fullmatch(requirement)


def test_the_backend_is_the_declarative_one() -> None:
    """`setuptools.build_meta`, and not the `:__legacy__` beside it.

    That one is the backend for a project configured by `setup.py`: it
    imports the file and runs it, which is the install-time hook the
    package-content policy is about, one stage earlier and in the build.
    """
    match = _BACKEND.search(_BUILD_SYSTEM)
    assert match, "[build-system] declares no build-backend"

    assert match.group(1) == "setuptools.build_meta"
