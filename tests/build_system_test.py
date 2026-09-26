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

`tomllib` for every value read out of pyproject.toml: stdlib from 3.11,
which requires-python's own floor now is too, so the module collects on
every interpreter the matrix runs. Parsed rather than matched, because
the file this module finds beside `tests/` in an unpacked sdist is the
build backend's normalized copy -- its comments gone and its arrays laid
out anew -- and a pattern written against the committed file's layout
finds nothing there, or the wrong array (issue #2252).
`tests/copyright_test.py` reads pyproject.toml with `tomllib` too.
"""

from __future__ import annotations

import ast
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

_PYPROJECT = tomllib.loads(
    (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
)

# a name and two releases: no `@ <url>`, no `[extra]`, no `; marker`
_RELEASE = r"[0-9]+(?:\.[0-9]+)*"
_BOUNDS = re.compile(rf"uv_build>={_RELEASE},<{_RELEASE}")


def _build_system() -> dict[str, Any]:
    """Return pyproject.toml's `[build-system]` table, parsed.

    Called at import: the file is the project's own and a test module
    that cannot read it has nothing to say.
    """
    table = _PYPROJECT.get("build-system")
    assert isinstance(table, dict), "pyproject.toml has no [build-system] table"
    return table


_BUILD_SYSTEM = _build_system()


def test_the_build_requires_the_uv_backend_and_nothing_else() -> None:
    """One requirement, and a pair of bounds is the whole of what it says."""
    requires = _BUILD_SYSTEM.get("requires")
    assert isinstance(requires, list), "[build-system] declares no requires"
    # the one-element unpack turns a second, unexpected entry into a raise
    # rather than a silent pass -- the second risk this reader has
    (requirement,) = requires

    assert _BOUNDS.fullmatch(requirement)


def test_the_backend_is_the_one_the_tooling_reads() -> None:
    """`uv_build`, the string two other tools key on.

    uv matches it to use the backend bundled in its own binary rather
    than resolving the package, and check-sdist matches it to read
    `source-exclude` when it decides what the sdist is allowed to omit.
    Either would fall back to a default that is neither, and the fall
    back is silent.
    """
    assert _BUILD_SYSTEM.get("build-backend") == "uv_build"


# the same requirement declared twice on purpose, and the two spellings:
# `[project.optional-dependencies]` is what a consumer of the wheel asks
# for, `[dependency-groups]` what this repository resolves for itself.
# uv has no default extra, so a group is what keeps `uv sync` and every
# `--group` command of CONTRIBUTING.md on the delegated configuration
def _bindings_requirements() -> tuple[list[Any], list[Any]]:
    """Return the bindings requirement, as the extra and as the group."""
    extra = _PYPROJECT.get("project", {}).get("optional-dependencies", {})
    group = _PYPROJECT.get("dependency-groups", {}).get("bindings")
    assert "secp256k1" in extra, "no secp256k1 extra in pyproject.toml"
    assert group is not None, "no bindings dependency group in pyproject.toml"
    return extra["secp256k1"], group


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
    # the bindings, and ellipticcurves' own extra for them, which is what
    # puts them behind that package's delegations as well as btclib's
    names = sorted(requirement.split(">=")[0] for requirement in extra)
    assert names == ["btclib-secp256k1", "ellipticcurves[secp256k1]"], extra


# `[tool.uv.build-backend] source-exclude` carries its own reasoning in
# pyproject.toml for why a test loading `.github` or `fuzz/` off disk
# belongs in it: each such test is unrunnable from an unpacked sdist,
# neither directory being shipped. What no comment there can show is
# that the list still names the tests of the shape below -- ISS 1509
# found one it did not, and nothing failed
_TESTS = Path(__file__).parent


def _source_exclude() -> list[str]:
    """Return `[tool.uv.build-backend] source-exclude`'s own entries.

    Parsed, so a `#` comment in the array quoting a path or a shape --
    `.github`, `fuzz` and `.*` among them -- is never read as an entry
    (ISS 2152).
    """
    backend = _PYPROJECT.get("tool", {}).get("uv", {}).get("build-backend", {})
    entries = backend.get("source-exclude")
    assert isinstance(entries, list), "no source-exclude array in pyproject.toml"
    return entries


def _reaches_outside_the_sdist(tree: ast.Module) -> bool:
    """Whether a module reads `.github`, `fuzz`, or `.git` off the tree.

    Two shapes. The first is any string literal that is the directory
    name or opens with it and a slash -- split on the slash rather than
    matched as a substring, so a name merely starting with the same
    letters (".githubbookmark") is not mistaken for the directory.
    Walked rather than matched on the formatted text, so a reflow across
    lines is still seen, and wherever in the module the literal sits: a
    `/` join's own right side, the way `Path(__file__).parents[1] /
    ".github" / "scripts" / "<name>.py"` and `_ROOT /
    ".github/workflows"` hold it, or a dict key read out by name and
    joined once a comprehension binds it, the way
    `tests/docs_commands_test.py` reaches ".github/workflows/test.yml".

    Exempted is a literal that never leaves a closed membership test --
    an element of the tuple, list or set an `in` or `not in` comparison
    reads its answer from, this function's own `(".github", "fuzz")`
    included. Comparing a value against a fixed set of names reads
    nothing off the tree; joining a path or keying a dict on the name
    does, whichever of the two shapes above carries it there. The
    exemption is why this module reports nothing about its own two
    literals.

    The second shape is `tests/changelog_immutability_test.py`'s own: it
    reads a release's own tag with `subprocess.run([_GIT, ...])` rather
    than a `Path` join, `.git` not being a directory any test builds a
    path through. `_GIT` -- `shutil.which("git") or "git"`, resolved
    once, the convention `generate_sbom.py` and its own test already
    use -- is a bare name and not the string "git" itself, ruff's own
    start-process-with-partial-path check being what a literal there
    would trip; matching that name is what the shape actually looks like
    now, a call whose first argument is a list or tuple literal opening
    with a bare name called `_GIT`, regardless of which attribute is
    called (`run`, `check_output`, ...) or what object the call is made
    through (issue #1512).
    """
    exempt = {
        id(elt)
        for node in ast.walk(tree)
        if isinstance(node, ast.Compare)
        for op, comparator in zip(node.ops, node.comparators, strict=True)
        if isinstance(op, (ast.In, ast.NotIn))  # codespell:ignore notin
        and isinstance(comparator, (ast.Tuple, ast.List, ast.Set))
        for elt in comparator.elts
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and node.value.split("/", 1)[0] in (".github", "fuzz")
            and id(node) not in exempt
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


def _missing_source_excludes(tests_dir: Path, excluded: Iterable[str]) -> list[str]:
    """Every `*.py` under `tests_dir`, recursively, unlisted in `excluded`.

    Recursive, `tests/ecc/`, `tests/script/` and the rest of the package's
    own subdirectories being as reachable from an installed test as the
    top level is -- a module there naming `.github` or `fuzz` would be
    just as unrunnable from an unpacked sdist. `source-exclude`'s own
    entries are full paths from the project root, not bare filenames, so
    a subdirectory member is named by its path relative to `tests_dir`
    and not by its `name` alone.
    """
    excluded = set(excluded)
    return [
        f"/tests/{path.relative_to(tests_dir).as_posix()}"
        for path in sorted(tests_dir.rglob("*.py"))
        if _reaches_outside_the_sdist(
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        )
        and f"/tests/{path.relative_to(tests_dir).as_posix()}" not in excluded
    ]


def test_every_test_reaching_outside_the_sdist_is_source_excluded() -> None:
    """A `tests/**/*.py` the reader above recognizes is named in the list.

    Not the other direction: `source-exclude` also names entries no test
    file could match -- `docs/build`, the linter caches -- so only this
    direction closes what ISS 1509 found open.
    """
    missing = _missing_source_excludes(_TESTS, _source_exclude())
    assert not missing, f"reaches outside the sdist, not in source-exclude: {missing}"


def test_a_subdirectory_module_is_reached_and_named_by_its_relative_path(
    tmp_path: Path,
) -> None:
    """`_missing_source_excludes` opens a subdirectory, not only the top.

    A synthetic `sub/offender_test.py`, planted under a directory this
    test builds rather than the real `tests/`, is what proves the reader
    descends into it -- `_TESTS.glob("*.py")`, the shape this replaced,
    never opened a subdirectory at all, so a module there naming
    `.github` would have passed unseen whatever `source-exclude` said.
    """
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "offender_test.py").write_text('URL = ".github/x.yml"\n', encoding="utf-8")

    assert _missing_source_excludes(tmp_path, []) == ["/tests/sub/offender_test.py"]


def test_a_subprocess_call_to_git_is_reached(tmp_path: Path) -> None:
    """The second shape is recognized on a module planted for it.

    Every module of `tests/` carrying the shape is in `source-exclude`,
    so an unpacked sdist holds none of them, and a reader tested only
    against the real `tests/` would leave this arm unreached there
    (issue #2252).
    """
    (tmp_path / "tagged_test.py").write_text(
        'subprocess.run([_GIT, "show", "v1:CHANGELOG.md"], check=True)\n',
        encoding="utf-8",
    )

    assert _missing_source_excludes(tmp_path, []) == ["/tests/tagged_test.py"]
