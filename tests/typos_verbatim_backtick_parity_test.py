# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""Every file `[tool.typos.type.verbatim]` covers has an even backtick count.

That section's `extend-ignore-re` (a backtick, no backtick, then a
backtick, applied with `--write-changes`) is what keeps `typos` from
correcting a misspelling `CHANGELOG.md` quotes on purpose instead of
using. `typos-cli` (pinned in `.pre-commit-config.yaml`) applies it with
`Ignores::new`, in `crates/typos-cli/src/file.rs`: `ignore.find_iter`
runs once over the whole file read into one string, pairing backticks
two at a time from the start, not per line and not per code span. A file
with an odd number of raw backtick characters has one left over, and
every pairing after the line it sits on shifts by one -- a quotation
many lines below, already backticked and previously matched, stops
being one, and `typos` offers to correct it again.

Issue #1302 is where that happened: a `CHANGELOG.md` draft quoted a
literal triple-backtick fence marker inside a single-backtick span,
five backticks on one line, and two of the file's own already-quoted
misspellings, both untouched and lines away, started failing. Regex
cannot assert "an even count" on its own -- `regex::Regex`,
the crate `typos` compiles `extend-ignore-re` with, has no counting or
backreferences -- so the correction is in the files this reads, once,
rather than in that pattern.
"""

import fnmatch
import os
import tomllib
from pathlib import Path

_ROOT = Path(__file__).parents[1]
# parsed rather than matched, so that the sdist's `pyproject.toml` -- the
# build backend's normalized copy, its comments gone and its arrays laid
# out anew -- names the same files the committed one does (issue #2252)
_PYPROJECT = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def _named(pattern: str) -> list[Path]:
    """Return the files under the root whose name `pattern` matches.

    typos matches a type's glob against a file's name alone. A directory
    whose name starts with a dot is not walked: none holds what the glob
    is for, and `.venv` holds files of every name.
    """
    found: list[Path] = []
    for top, dirs, files in os.walk(_ROOT):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        found.extend(
            Path(top) / name for name in files if fnmatch.fnmatchcase(name, pattern)
        )
    return sorted(found)


def _verbatim_names() -> list[str]:
    """Return `[tool.typos.type.verbatim]`'s `extend-glob`, as written."""
    table = _PYPROJECT.get("tool", {}).get("typos", {}).get("type", {})
    names = table.get("verbatim", {}).get("extend-glob")
    assert isinstance(names, list), (
        "pyproject.toml's [tool.typos.type.verbatim] table or its"
        " extend-glob key was not found"
    )
    return names


def _verbatim_files() -> tuple[Path, ...]:
    """Return the paths `[tool.typos.type.verbatim]`'s `extend-glob` names.

    A name with a glob character is every file of that name; any other
    name is a path from the root.
    """
    paths: list[Path] = []
    for name in _verbatim_names():
        paths.extend(_named(name) if any(c in name for c in "*?[") else [_ROOT / name])
    return tuple(paths)


def test_the_section_was_found() -> None:
    """The table names at least one file, so the check below runs.

    A renamed key fails the assertion in `_verbatim_files()`; an emptied
    list would pass it and leave the check below vacuously true.
    """
    assert _verbatim_files(), "[tool.typos.type.verbatim]'s extend-glob names no file"


def test_the_section_reaches_every_changelog_entry() -> None:
    """Each entry under `changelog/next/` is among the files it names.

    An entry quotes what it is about as a release's section does, and
    typos with `--write-changes` would otherwise rewrite the quotation.
    The first assertion still checks something when `changelog/next/`
    holds no entry, where the second would check nothing.
    """
    assert any(fnmatch.fnmatchcase("pr1-iss2.md", n) for n in _verbatim_names()), (
        "[tool.typos.type.verbatim] matches no entry name such as pr1-iss2.md"
    )
    entries = set((_ROOT / "changelog" / "next").glob("*.md"))
    assert entries <= set(_verbatim_files()), (
        f"[tool.typos.type.verbatim] does not reach {sorted(entries)}"
    )


def test_every_verbatim_file_has_an_even_backtick_count() -> None:
    r"""A raw backtick left unpaired desyncs every pairing after it.

    Not a claim that every backtick in these files delimits a code span,
    only that the total stays a multiple of two, which is what keeps
    `find_iter`'s left-to-right pairing from drifting past where a human
    reader would still see two matched code spans.
    """
    odd = {
        path.name: count
        for path in _verbatim_files()
        if (count := path.read_text(encoding="utf-8").count("`")) % 2
    }
    assert not odd, (
        f"an odd backtick count desyncs typos' pairing for the rest of the file: {odd}"
    )
