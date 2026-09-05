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

import ast
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


# `[tool.uv.build-backend] source-exclude` carries its own reasoning in
# pyproject.toml for why a test loading `.github` or `fuzz/` off disk
# belongs in it: each such test is unrunnable from an unpacked sdist,
# neither directory being shipped. What no comment there can show is
# that the list still names the tests of the shape below -- ISS 1509
# found one it did not, and nothing failed
_SOURCE_EXCLUDE = re.compile(
    r"^source-exclude\s*=\s*\[(.*?)^\]", re.MULTILINE | re.DOTALL
)
_TESTS = Path(__file__).parent


def _source_exclude() -> list[str]:
    """Return `[tool.uv.build-backend] source-exclude`'s own entries."""
    text = _PYPROJECT.read_text(encoding="utf-8")
    match = _SOURCE_EXCLUDE.search(text)
    assert match, "no source-exclude array in pyproject.toml"
    return _QUOTED.findall(match.group(1))


def _reaches_outside_the_sdist(tree: ast.Module) -> bool:
    """Whether a module reads `.github`, `fuzz`, or `.git` off the tree.

    Two shapes. The first is the convention `Path(__file__).parents[1] /
    ".github" / "scripts" / "<name>.py"` and `Path(__file__).parent.parent
    / "fuzz"` follow -- a `/` join with one side the literal directory
    name -- walked rather than matched on the formatted text, so a reflow
    of the expression across lines is still seen.

    The second is `tests/changelog_immutability_test.py`'s own: it reads
    a release's own tag with `subprocess.run([_GIT, ...])` rather than a
    `Path` join, `.git` not being a directory any test builds a path
    through. `_GIT` -- `shutil.which("git") or "git"`, resolved once, the
    convention `generate_sbom.py` and its own test already use -- is a
    bare name and not the string "git" itself, ruff's own
    start-process-with-partial-path check being what a literal there
    would trip; matching that name is what the shape actually looks like
    now, a call whose first argument is a list or tuple literal opening
    with a bare name called `_GIT`, regardless of which attribute is
    called (`run`, `check_output`, ...) or what object the call is made
    through (issue #1512).
    """
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.BinOp)
            and isinstance(node.op, ast.Div)
            and isinstance(node.right, ast.Constant)
            and node.right.value in (".github", "fuzz")
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.args
            and isinstance(node.args[0], (ast.List, ast.Tuple))
            and node.args[0].elts
            and isinstance(node.args[0].elts[0], ast.Name)
            and node.args[0].elts[0].id == "_GIT"
        ):
            return True
    return False


def test_every_test_reaching_outside_the_sdist_is_source_excluded() -> None:
    """A `tests/*.py` the reader above recognizes is named in the list.

    Not the other direction: `source-exclude` also names entries no test
    file could match -- `docs/build`, the linter caches -- so only this
    direction closes what ISS 1509 found open.

    And not every test that reaches outside the sdist: what the reader
    sees of a directory is a `/` join on its own name, so a path with
    the whole of it in one literal -- `_ROOT / ".github/workflows"` --
    is outside its reach and outside this assertion's, which is issue
    #1736. Widening the sentence here without widening the reader is
    what would put the guarantee ISS 1509 asked for on a green run that
    does not give it.
    """
    excluded = set(_source_exclude())
    missing = [
        f"/tests/{path.name}"
        for path in sorted(_TESTS.glob("*.py"))
        if _reaches_outside_the_sdist(
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        )
        and f"/tests/{path.name}" not in excluded
    ]
    assert not missing, f"reaches outside the sdist, not in source-exclude: {missing}"
