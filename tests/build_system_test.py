# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Nothing but the uv build backend runs while a distribution is built.

`docs/source/package-content-policy.md` states what may be in the wheel
and the sdist, and `.github/scripts/verify_dist_contents.py` refuses a
build that carries anything else -- an installed wheel therefore executes
nothing at install time, there being no member left that could. What no
list of members can see is the *build*: `[build-system] requires` is what
a build resolves, from an index or from the copy uv carries, and every
package named there runs code while the archives are made, so that one
line is the whole of what a release trusts, and a diff is the only thing
that reads it.

Which is what this is: the line is one requirement long, and a test
saying so is what a second one would have to go past.

Not an assertion on the exact string. The bounds are declared in
pyproject.toml with the reason for them, and a copy of them here would be
a second declaration to keep in step, failing on the day they move for a
reason that has nothing to do with what runs. The shape is what matters
and what is checked: one requirement, named uv_build, bounded below and
above and nothing else -- which is also how a direct reference to a url,
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

# a name and two releases: no `@ <url>`, no `[extra]`, no `; marker`
_RELEASE = r"[0-9]+(?:\.[0-9]+)*"
_BOUNDS = re.compile(rf"uv_build>={_RELEASE},<{_RELEASE}")

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


def test_the_build_requires_the_uv_backend_and_nothing_else() -> None:
    """One requirement, and a pair of bounds is the whole of what it says."""
    match = _REQUIRES.search(_BUILD_SYSTEM)
    assert match, "[build-system] declares no requires"
    (requirement,) = _QUOTED.findall(match.group(1))

    assert _BOUNDS.fullmatch(requirement)


def test_the_backend_is_the_one_the_tooling_reads() -> None:
    """`uv_build`, the string two other tools key on.

    uv matches it to use the backend bundled in its own binary rather
    than resolving the package, and check-sdist matches it to read
    `source-exclude` when it decides what the sdist is allowed to omit.
    Either would fall back to a default that is neither, and the fall
    back is silent.
    """
    match = _BACKEND.search(_BUILD_SYSTEM)
    assert match, "[build-system] declares no build-backend"

    assert match.group(1) == "uv_build"


# the same requirement declared twice on purpose, and the two spellings:
# `[project.optional-dependencies]` is what a consumer of the wheel asks
# for, `[dependency-groups]` what this repository resolves for itself.
# uv has no default extra, so a group is what keeps `uv sync` and every
# `--group` command of CONTRIBUTING.md on the delegated configuration
_EXTRA = re.compile(r"^secp256k1 = \[(.*?)^\]", re.MULTILINE | re.DOTALL)
_GROUP = re.compile(r"^bindings = \[(.*?)\]", re.MULTILINE | re.DOTALL)


def _bindings_requirements() -> tuple[list[str], list[str]]:
    """Return the bindings requirement, as the extra and as the group."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    extra = _EXTRA.search(text)
    group = _GROUP.search(text)
    assert extra is not None, "no secp256k1 extra in pyproject.toml"
    assert group is not None, "no bindings dependency group in pyproject.toml"
    return _QUOTED.findall(extra.group(1)), _QUOTED.findall(group.group(1))


def test_the_bindings_extra_and_group_ask_for_the_same_thing() -> None:
    """One floor, written twice, and this is what keeps them equal.

    The extra is the published fact -- `pip install btclib[secp256k1]` --
    and the group is how this repository puts the bindings in its own
    environment, uv having no way to make an extra the default. Two
    declarations of one requirement drift, and the direction that drifts
    silently is the dangerous one: a group left behind resolves the suite
    against a bindings older than the extra promises, so every comparison
    the suite makes is made against the wrong authority.

    The requirement itself is not spelled here, for the reason the build
    system above is not: the floor moves with the features btclib calls,
    and its reason is written beside it in pyproject.toml.
    """
    extra, group = _bindings_requirements()
    assert extra == group, f"the extra asks {extra}, the group asks {group}"
    assert len(extra) == 1, f"the extra names more than the bindings: {extra}"
    assert extra[0].startswith("btclib-secp256k1"), extra[0]
