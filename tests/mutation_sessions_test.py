# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What `.github/workflows/mutation.yml`'s `profiles` is held to.

Two correspondences, and each of them breaks in silence.

`.github/mutation/` states what a scope mutates and what judges it, and
`profiles` is what spends a budget on it. Neither file names what the
other holds. A configuration no session names enumerates nothing,
measures nothing and reports nothing, while the workflow stays green: a
job that does not exist cannot fail. A session naming a configuration
that is gone is a red `Check the baselines` step in a weekly run of a
workflow that gates nothing, so it waits for whoever opens the Actions
tab.

The dispatch dropdown and a profile's own `slug` are the second pair,
and the callee's `SELECTED` is what joins them: it compares the
`selected` this workflow forwards with `matrix.slug`, so an option no
slug answers leaves that expression false in every job. Each takes a
runner and gives it back in seconds, and the run is green having
measured nothing, which is a failure with nothing red in it. A slug no
option offers is the quieter half: the schedule runs that profile
whatever the dropdown holds, so nothing says the button is short of one.

A third thing is only checkable because the matrix is JSON: whether the
forge can read it at all. `fromJSON` runs in the callee, at the moment
the matrix is expanded, so a comma dropped out of `profiles` is a
weekly run that fails before any profile starts and says so to nobody.
`json.loads` here is that failure moved into the suite, and the same
parse is what makes the two censuses below exact rather than regular
expressions over yaml.

The workflow is still read as text rather than parsed as yaml, the
suite's own environment carrying no yaml parser: pyyaml reaches this
tree through `myst-parser` and `pre-commit`, which are the `docs` and
`lint` groups, and the suite runs under `--group harness` and under
`--group test`, which is that group and the bindings. A module importing
one collects on a contributor's own `uv sync`, which installs every
group, and fails to collect in CI -- issue #1538's shape, and the reason
`tests/copyright_test.py` reads a line of `docs/source/conf.py` rather
than executing it. `json` is the standard library and adds no group.
What is read without a parser is narrow enough to defend: the lines a
key indents under it, one at a time, and for `profiles` the fold a `>-`
scalar performs on them, which is a join on one space.

Every census is asserted non-empty before anything is subtracted from
it, a set subtracted from an empty one being empty whatever the other
holds, and each reader is driven over a literal workflow of its own -- a
key reworded past what a reader matches would otherwise make every
assertion below pass for free.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "mutation.yml"
_PROFILES = _ROOT / ".github" / "mutation"

# a session as the callee's own steps read one: the configuration under
# `.github/mutation/`, and the budget `timeout --signal=INT` is given.
# The budget is matched and not captured -- what it has to do here is
# tell a session from a line that is something else, so what it matches
# is `timeout`'s own duration -- a number with an optional `s`, `m`, `h`
# or `d` -- rather than the minutes every budget happens to be spelled
# in today. Held to minutes, a legitimate `2h` would be reported as no
# session at all and turn the census red on the spelling of a budget
# this module does not otherwise read
_SESSION = re.compile(r"(\S+\.toml) \d+(?:\.\d+)?[smhd]?")

# an entry of the dispatch dropdown: a sequence item and nothing else on
# the line. Held to the whole of it, so that a key indented into the
# list is reported rather than read as an option
_OPTION = re.compile(r"- (\S+)")

# the one entry of the dropdown that is no profile: a `selected` of
# `all` is a branch of the callee's `SELECTED` rather than a matrix
# entry, so it is subtracted from the dropdown's side instead of being
# looked for on the matrix's
_EVERY_PROFILE = "all"

# what a cell owes. `profile` names the job, `slug` selects it and names
# its artifact, `ceiling` is its `timeout-minutes` and `sessions` the
# loop's own input: a cell short of one of them reaches the callee as an
# empty expression rather than as an error, and `timeout-minutes:` with
# nothing after it is the one that fails the job on syntax
_CELL_KEYS = frozenset({"profile", "slug", "ceiling", "sessions"})


def _block(text: str, key: str) -> list[str]:
    """Return the stripped lines each `key` line indents under it.

    A block runs to the first line indented no deeper than the key that
    opened it, blank lines belonging to the block rather than closing
    it. That is the whole of the yaml either reader below needs:
    `profiles: >-` opens a folded scalar whose value is the JSON the
    callee hands `fromJSON`, and `options:` a sequence the forge draws
    as a dropdown.
    """
    lines: list[str] = []
    depth: int | None = None
    for line in text.split("\n"):
        stripped = line.strip()
        if depth is not None:
            if not stripped:
                continue
            if len(line) - len(line.lstrip(" ")) > depth:
                lines.append(stripped)
                continue
            depth = None
        if stripped == key:
            depth = len(line) - len(line.lstrip(" "))
    return lines


def _profiles(text: str) -> list[dict[str, Any]]:
    """Return the cells `profiles` carries, folding the scalar first.

    A `>-` scalar folds its lines into one space each, which is what the
    join below reproduces: every line of the block is written at one
    indentation, so none of them is the more-indented kind yaml keeps a
    newline for. The parse is then the forge's own -- what `fromJSON`
    is handed is this string -- so a blob this cannot read is one the
    weekly run cannot either.
    """
    folded = " ".join(_block(text, "profiles: >-"))
    if not folded:
        return []
    read = json.loads(folded)
    assert isinstance(read, list), f"`profiles` is no array: {type(read).__name__}"
    return read


def _entries(lines: list[str], entry: re.Pattern[str]) -> tuple[list[str], list[str]]:
    """Return what `entry` captured line by line, and what it did not match.

    The second list is what keeps a line from leaving a census in
    silence: one the reader cannot parse is reported rather than
    dropped, which is the difference between a census that is wrong and
    one that is empty.
    """
    read: list[str] = []
    unparsed: list[str] = []
    for line in lines:
        found = entry.fullmatch(line)
        if found is None:
            unparsed.append(line)
        else:
            read.append(found.group(1))
    return read, unparsed


def _sessions(cells: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    """Return the configurations the profiles run, and what is no session."""
    lines = [
        line
        for cell in cells
        for line in str(cell.get("sessions", "")).split("\n")
        if line
    ]
    return _entries(lines, _SESSION)


def _options(text: str) -> tuple[list[str], list[str]]:
    """Return what the dropdown offers, and what is no option.

    A comment is dropped here where the reader above reports a line it
    cannot parse, and the asymmetry is the yaml: under `options:` a `#`
    line is a comment, while inside the folded scalar the same line is
    literal text that would make the JSON unreadable.
    """
    lines = [line for line in _block(text, "options:") if not line.startswith("#")]
    return _entries(lines, _OPTION)


_TEXT = _WORKFLOW.read_text(encoding="utf-8")
_CONFIGURATIONS = frozenset(path.name for path in _PROFILES.glob("*.toml"))
_CELLS = _profiles(_TEXT)
_RUN, _UNPARSED = _sessions(_CELLS)
_OFFERED, _UNOFFERED = _options(_TEXT)
_SLUGS: list[str] = [str(cell["slug"]) for cell in _CELLS if "slug" in cell]


def test_both_sides_of_the_census_were_read() -> None:
    """A comparison over a side that came up empty is true of nothing.

    The assertions below subtract one set from the other, and each of
    them passes for free on an empty one. The workflow's side is read by
    the functions above, which answer empty for a key spelled some other
    way; the directory's side is a glob, which answers empty for a
    directory renamed or emptied out, which is the same drift this
    module is about arriving where it cannot be seen.

    A configuration named twice is the third way the comparison holds
    while the matrix does not: the callee derives the session file from
    the configuration's own name, so a second session of one
    configuration in the same job re-initializes over the first's
    verdicts, and in two jobs it pays twice for one answer.
    """
    assert _CONFIGURATIONS, "no configuration under .github/mutation at all"
    assert _CELLS, "no profile was read out of mutation.yml at all"
    assert _RUN, "no session was read out of mutation.yml at all"
    assert not _UNPARSED, f"a line of `sessions` is no session: {_UNPARSED}"
    assert len(set(_RUN)) == len(_RUN), (
        f"a configuration is given more than one session: {sorted(_RUN)}"
    )


def test_every_cell_carries_what_the_callee_reads() -> None:
    """A key missing from a cell is an empty expression, not an error.

    `fromJSON` is happy with an object short of a key, and what the
    callee does with the absence is quiet in three of the four cases: a
    job named `Mutate `, an artifact named `mutation--sessions`, or a
    `SELECTED` no dropdown entry can answer. Only a missing `ceiling`
    is loud, `timeout-minutes:` with nothing after it failing the job.
    """
    short = [cell for cell in _CELLS if _CELL_KEYS - set(cell)]
    assert not short, f"a profile is short of a key the callee reads: {short}"


def test_every_configuration_has_a_session() -> None:
    """A configuration no profile names is a scope nothing mutates."""
    missing = sorted(_CONFIGURATIONS - set(_RUN))
    assert not missing, f"no session in mutation.yml for: {missing}"


def test_every_session_names_a_configuration() -> None:
    """The other direction, where a renamed configuration lands.

    `cosmic-ray baseline` is what refuses it, in the step that runs
    before any mutant, and the job it fails is one nothing gates on.
    """
    unaccounted = sorted(set(_RUN) - _CONFIGURATIONS)
    assert not unaccounted, (
        f"a session names no file under .github/mutation: {unaccounted}"
    )


def test_both_sides_of_the_dispatch_census_were_read() -> None:
    """The same guard for the dropdown, and two the matrix needs beside it.

    `all` is subtracted from the dropdown below, and subtracting a
    member that is not there removes nothing: the equality would then
    hold for a dropdown that had lost the entry its own `default:`
    names.

    A repeated name is what an equality of sets cannot see either, and
    it costs on both sides: two profiles sharing a slug answer one
    option and name one artifact between them, which the callee's own
    upload step calls an error, and an option offered twice is a
    dropdown drawn with a duplicate in it.
    """
    assert _OFFERED, "no dispatch option was read out of mutation.yml at all"
    assert _SLUGS, "no profile slug was read out of mutation.yml at all"
    assert not _UNOFFERED, f"a line under `options:` is no option: {_UNOFFERED}"
    assert _EVERY_PROFILE in _OFFERED, (
        f"the dropdown does not offer `{_EVERY_PROFILE}`, its own default"
    )
    assert len(set(_OFFERED)) == len(_OFFERED), (
        f"the dropdown offers one profile twice: {sorted(_OFFERED)}"
    )
    assert len(set(_SLUGS)) == len(_SLUGS), (
        f"two profiles share a slug: {sorted(_SLUGS)}"
    )


def test_every_option_names_a_profile() -> None:
    """An option no slug answers asks for a run that measures nothing.

    The callee's `SELECTED` is false in every job of the matrix, each of
    them takes a runner and gives it back in seconds, and the run is
    green.
    """
    unmatched = sorted(set(_OFFERED) - {_EVERY_PROFILE} - set(_SLUGS))
    assert not unmatched, f"the dropdown offers what no profile runs: {unmatched}"


def test_every_profile_is_offered_by_the_dropdown() -> None:
    """The other direction: a profile the button cannot ask for.

    The schedule runs it whatever the dropdown holds, so what is lost is
    the escape hatch alone, and a scope reachable once a week is exactly
    the one somebody wants to re-measure by hand.
    """
    unoffered = sorted(set(_SLUGS) - set(_OFFERED))
    assert not unoffered, f"the dropdown cannot ask for: {unoffered}"


def test_the_reader_folds_the_scalar_the_way_yaml_does() -> None:
    """The guard above passes for free if the reader answers empty.

    The shapes mutation.yml puts around the folded scalar: a comment
    above the key, a value broken across lines mid-object and mid-string
    -- the fold joining either on one space -- and the dedent to the
    next key of the same mapping, which must not be read as more of the
    block.
    """
    cells = _profiles(
        "    with:\n"
        "      # the reasoning, which the scalar below cannot carry\n"
        "      profiles: >-\n"
        '        [{"profile": "one", "slug": "a", "ceiling": 20,\n'
        '        "sessions": "a.toml 10m"},\n'
        '        {"profile": "two", "slug": "b", "ceiling": 30, "sessions":\n'
        '        "b.toml 5m\\nc.toml 20m"}]\n'
        "      selected: ${{ inputs.profile }}\n"
    )

    assert [cell["slug"] for cell in cells] == ["a", "b"]
    assert cells[1]["sessions"] == "b.toml 5m\nc.toml 20m"
    assert _sessions(cells) == (["a.toml", "b.toml", "c.toml"], [])
    # the key spelled some other way, which is what the guard above
    # exists for: empty rather than an exception, so that the censuses
    # report a reader that found nothing instead of failing to collect
    assert _profiles("      profiles: |\n        []\n") == []


def test_a_profiles_value_that_is_no_json_is_reported() -> None:
    """A blob the forge cannot read fails here instead of in the run.

    `fromJSON` is evaluated when the matrix is expanded, so the cost of
    finding this in the weekly run is every profile of it.
    """
    with pytest.raises(json.JSONDecodeError):
        _profiles(
            "      profiles: >-\n"
            '        [{"profile": "one", "slug": "a", "ceiling": 20,\n'
            '        "sessions": "a.toml 10m"},]\n'
        )


def test_a_line_that_is_no_session_is_reported() -> None:
    """A line the reader cannot parse is named rather than skipped.

    Skipping it is how a session leaves the census while the profile
    goes on spending its budget: the configuration would then read as
    one no job runs, and the census would be red about the wrong thing.
    """
    configurations, unparsed = _sessions(
        [{"sessions": "a.toml 90m\nb.toml\nc.txt 30m"}]
    )

    assert configurations == ["a.toml"]
    assert unparsed == ["b.toml", "c.txt 30m"]


def test_the_reader_finds_the_dropdown_and_only_it() -> None:
    """The same guard for the other reader, over the same file's shapes.

    The keys of the input above the list, a comment between two entries,
    the dedent to the next top-level key, and a sequence below it that
    is indented under a key of another name and is not the dropdown.
    """
    offered, unparsed = _options(
        "on:\n"
        "  workflow_dispatch:\n"
        "    inputs:\n"
        "      profile:\n"
        "        default: all\n"
        "        type: choice\n"
        "        options:\n"
        "          - all\n"
        "          # the escape hatch this file argues for\n"
        "          - consensus\n"
        "\n"
        "permissions:\n"
        "  contents: read\n"
        "        include:\n"
        "          - profile: one\n"
    )

    assert offered == ["all", "consensus"]
    assert not unparsed


def test_a_line_that_is_no_option_is_reported() -> None:
    """A key indented into the list is named rather than read as an entry.

    Dropping it instead is how the census goes quiet about the drift it
    is here for: the dropdown would read as holding less than it does,
    and the comparison would be against a set that is simply wrong.
    """
    offered, unparsed = _options(
        "        options:\n"
        "          - all\n"
        "          - two words\n"
        "          type: choice\n"
    )

    assert offered == ["all"]
    assert unparsed == ["- two words", "type: choice"]
