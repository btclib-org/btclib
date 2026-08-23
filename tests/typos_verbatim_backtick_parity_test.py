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
misspellings, both untouched and lines away, started failing.
`.pre-commit-config.yaml` had the same defect independently:
`local-link-prefix`'s lookbehind matched one raw backtick byte in a
character class, the only backtick in the file outside a matched pair,
and writing it `\x60` instead is what turned the file's count back to
even. Regex cannot assert "an even count" on its own -- `regex::Regex`,
the crate `typos` compiles `extend-ignore-re` with, has no counting or
backreferences -- so the correction is in the files this reads, once,
rather than in that pattern.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_PYPROJECT = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")

# scoped to the section rather than matched anywhere in the file, so a
# later `extend-glob` under a different `[tool.typos...]` table --
# `[tool.typos.type.mixed-case-vectors]` already has one -- is not read
# as this one's list
_SECTION = re.compile(
    r"^\[tool\.typos\.type\.verbatim\]\n"
    r"(?:^(?:#.*)?\n)*"
    r'^extend-glob = \[(?P<files>(?:"[^"]*", ?)*"[^"]*")\]$',
    re.MULTILINE,
)


def _verbatim_files() -> tuple[Path, ...]:
    """Return the paths `[tool.typos.type.verbatim]`'s `extend-glob` names."""
    section = _SECTION.search(_PYPROJECT)
    assert section, (
        "pyproject.toml's [tool.typos.type.verbatim] table or its"
        " extend-glob key was not found where this test expects it"
    )
    names = re.findall(r'"([^"]*)"', section["files"])
    return tuple(_ROOT / name for name in names)


def test_the_section_was_found() -> None:
    """The regex above found a non-empty list, so the check below runs.

    A renamed key or a reindented table would leave `_verbatim_files()`
    empty and the check below vacuously true.
    """
    assert _verbatim_files(), "[tool.typos.type.verbatim]'s extend-glob names no file"


def test_every_verbatim_file_has_an_even_backtick_count() -> None:
    r"""A raw backtick left unpaired desyncs every pairing after it.

    Not a claim that every backtick in these files delimits a code span
    -- `.pre-commit-config.yaml` quotes one as a regex character, escaped
    as `\\x60` rather than written literally for exactly this reason --
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
