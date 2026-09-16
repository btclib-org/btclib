# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A tracked dotted path under a shipped tree is one source-exclude names.

`[tool.uv.build-backend] source-exclude` takes a tool's cache out of the
sdist by the property every such cache has -- a dot-prefixed basename --
rather than by the name of the tool that wrote it. The two ways of
writing that exclusion fail in opposite directions: a list of names is
silently incomplete, and a property is silently over-broad. Both are
silent for one reason, which is `check-sdist`'s: it compares an archive
against the tree it was built from, so it refuses only a cache that is
on disk when it runs, and there is none in CI (btclib-org/.github#1070).

This module is the gate for the over-broad direction. A
`tests/_data/<name>/.gitkeep` carrying an empty directory, or a
`tests/.gitignore` scoping ignores to the suite, is an ordinary thing to
add with no reason to think about packaging, and what it costs is a
release missing a file rather than anything red. Named in
`source-exclude` the drop is a decision; unnamed it is a side effect,
and this is what tells the two apart.

`git ls-files` rather than a walk of the directory, the distinction
being exactly tracked against untracked: a contributor who ran `pytest`
from inside `tests/` has a `.hypothesis` there, and that one is what the
exclusion exists for. The roots come out of the exclusion patterns
themselves, so a tree brought under the shape is a tree this walks
without a second edit.
"""

import re
import shutil
import subprocess
from collections.abc import Iterable
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PYPROJECT = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")

# resolved once, for the reason `declared_version_test.py`'s own `_GIT`
# is: a bare "git" in a subprocess list is a partial executable path
_GIT = shutil.which("git") or "git"

# regex rather than `tomllib`, which is stdlib from 3.11 where this
# tree's floor is 3.10 -- the reason `build_system_test.py` gives for
# reading the same file the same way
_SOURCE_EXCLUDE = re.compile(
    r"^source-exclude\s*=\s*\[(.*?)^\]", re.MULTILINE | re.DOTALL
)
# an entry and not a comment: the array's comments carry quoted names of
# their own, and a sentence about a path standing in for the exclusion
# of it is the failure this pattern's leading quote refuses
_ENTRY = re.compile(r'^\s*"([^"]*)",', re.MULTILINE)
# a shape entry, whose anchor names a tree the archive carries whole
_SHAPE = re.compile(r"/(.+)/\*\*/\.\*")


def _source_exclude() -> tuple[str, ...]:
    """Return `[tool.uv.build-backend] source-exclude`'s own entries."""
    match = _SOURCE_EXCLUDE.search(_PYPROJECT)
    assert match is not None, "no source-exclude array in pyproject.toml"
    return tuple(_ENTRY.findall(match.group(1)))


def _shipped_roots(entries: Iterable[str]) -> tuple[str, ...]:
    """Return the tree each shape entry anchors on, in the list's order."""
    roots = tuple(
        match.group(1) for entry in entries if (match := _SHAPE.fullmatch(entry))
    )
    assert roots, "source-exclude carries no dot-prefixed shape entry"
    return roots


def _tracked(roots: Iterable[str]) -> tuple[str, ...]:
    """Return every path this repository tracks under `roots`."""
    listed = subprocess.run(  # noqa: S603
        [_GIT, "ls-files", "--", *roots],
        cwd=_ROOT,
        capture_output=True,
        encoding="utf-8",
        check=True,
    )
    return tuple(listed.stdout.splitlines())


def _unnamed(paths: Iterable[str], entries: Iterable[str]) -> list[str]:
    """Return the paths carrying a dotted component no entry names.

    Every component and not the basename alone: a tracked
    `tests/.config/tool.ini` is dropped by the same pattern, its
    directory being what the pattern matches and the file going with it.
    An entry is compared as the bare name it is, which is how the
    backend reads one that does not open with a slash -- a match at any
    depth, everything below it going too.
    """
    named = set(entries)
    return sorted(
        {
            path
            for path in paths
            for part in path.split("/")
            if part.startswith(".") and part not in named
        }
    )


def test_a_dotted_path_no_entry_names_is_reported() -> None:
    """The reader has teeth: a planted `.gitkeep` is what it must catch."""
    planted = "tests/_data/vectors/.gitkeep"

    assert _unnamed([planted], _source_exclude()) == [planted]


def test_every_tracked_dotted_path_under_a_shipped_tree_is_named() -> None:
    """Nothing the shape drops is a file this tree meant to ship.

    The census is what makes the drop visible while it is still a diff:
    unmeasured, a dotted path added under one of these trees leaves the
    suite green, the lint gate green, and the file out of the next
    release.
    """
    entries = _source_exclude()
    tracked = _tracked(_shipped_roots(entries))
    assert tracked, "the shape entries' anchors reach no tracked file"

    unnamed = _unnamed(tracked, entries)
    assert not unnamed, f"dotted and not named in source-exclude: {unnamed}"
