# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every mutation profile has a session, and every session a profile.

`.github/mutation/` states what a scope mutates and what judges it, and
`.github/workflows/mutation.yml`'s matrix is what spends a budget on it.
Neither file names what the other holds, and both directions of the drift
are quiet. A configuration no session names enumerates nothing, measures
nothing and reports nothing, while the workflow stays green: a job that
does not exist cannot fail. A session naming a configuration that is gone
is a red `Check the baselines` step in a weekly run of a workflow that
gates nothing, so it waits for whoever opens the Actions tab.

The workflow is read as text rather than parsed as yaml, the suite's own
environment carrying no yaml parser: pyyaml reaches this tree through
`myst-parser` and `pre-commit`, which are the `docs` and `lint` groups,
and the suite runs under `--group harness` and under `--group test`,
which is that group and the bindings. A module importing one
collects on a contributor's own `uv sync`, which installs every group,
and fails to collect in CI -- issue #1538's shape, and the reason
`tests/copyright_test.py` reads a line of `docs/source/conf.py` rather
than executing it. What is read here is narrow enough to defend without a
parser: the block scalars introduced by `sessions:`, each line of which
is a configuration and the budget `timeout` is given.

Both censuses are asserted non-empty before either is compared, a set
subtracted from an empty one being empty whatever it holds, and the
reader is driven over a literal workflow of its own -- a `sessions:`
reworded past what it matches would otherwise make every assertion below
pass for free.
"""

from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]
_WORKFLOW = _ROOT / ".github" / "workflows" / "mutation.yml"
_PROFILES = _ROOT / ".github" / "mutation"

# a session as the workflow's own steps read one: the configuration
# under `.github/mutation/`, and the budget `timeout --signal=INT` is
# given. The budget is matched and not captured -- what it has to do
# here is tell a session from a line that is something else, so what
# it matches is `timeout`'s own duration -- a number with an optional
# `s`, `m`, `h` or `d` -- rather than the minutes every budget happens
# to be spelled in today. Held to minutes, a legitimate `2h` would be
# reported as no session at all and turn the census red on the spelling
# of a budget this module does not otherwise read
_SESSION = re.compile(r"(\S+\.toml) \d+(?:\.\d+)?[smhd]?")


def _sessions(text: str) -> tuple[list[str], list[str]]:
    """Return the configurations the matrix runs, and what is no session.

    A `sessions:` block scalar runs to the first line indented no deeper
    than the key that opened it, blank lines belonging to the scalar
    rather than closing it. That is the whole of the yaml this needs, the
    value being literal text the `while read -r config budget` loops of
    the workflow split on whitespace.

    The second list is what keeps a line from leaving the census in
    silence: one the reader cannot parse is reported rather than dropped,
    which is the difference between a census that is wrong and one that
    is empty.
    """
    configurations: list[str] = []
    unparsed: list[str] = []
    depth: int | None = None
    for line in text.split("\n"):
        stripped = line.strip()
        if depth is not None:
            if not stripped:
                continue
            if len(line) - len(line.lstrip(" ")) > depth:
                session = _SESSION.fullmatch(stripped)
                if session is None:
                    unparsed.append(stripped)
                else:
                    configurations.append(session.group(1))
                continue
            depth = None
        if stripped == "sessions: |":
            depth = len(line) - len(line.lstrip(" "))
    return configurations, unparsed


_CONFIGURATIONS = frozenset(path.name for path in _PROFILES.glob("*.toml"))
_RUN, _UNPARSED = _sessions(_WORKFLOW.read_text(encoding="utf-8"))


def test_both_sides_of_the_census_were_read() -> None:
    """A comparison over a side that came up empty is true of nothing.

    The assertions below subtract one set from the other, and each of
    them passes for free on an empty one. The workflow's side is read by
    the function above, which answers empty for a key spelled some other
    way; the directory's side is a glob, which answers empty for a
    directory renamed or emptied out, which is the same drift this module
    is about arriving where it cannot be seen.

    A configuration named twice is the third way the comparison holds
    while the matrix does not: `run_session` derives the session file
    from the configuration's own name, so a second session of one
    configuration in the same job re-initializes over the first's
    verdicts, and in two jobs it pays twice for one answer.
    """
    assert _CONFIGURATIONS, "no configuration under .github/mutation at all"
    assert _RUN, "no session was read out of mutation.yml at all"
    assert not _UNPARSED, f"a line under `sessions:` is no session: {_UNPARSED}"
    assert len(set(_RUN)) == len(_RUN), (
        f"a configuration is given more than one session: {sorted(_RUN)}"
    )


def test_every_configuration_has_a_session() -> None:
    """A profile the matrix does not name is a scope nothing mutates."""
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


def test_the_reader_finds_the_sessions_and_only_those() -> None:
    """The guard above passes for free if the reader answers empty.

    The shapes mutation.yml puts around a block scalar: a second entry's
    key at the same depth, a blank line inside a block, the dedent to the
    job's own keys, and the environment key that carries the same value
    under a spelling this must not read as a block of its own.
    """
    configurations, unparsed = _sessions(
        "    strategy:\n"
        "      matrix:\n"
        "        include:\n"
        "          - profile: one\n"
        "            sessions: |\n"
        "              a.toml 90m\n"
        "\n"
        "              b.toml 30m\n"
        "          - profile: two\n"
        "            sessions: |\n"
        "              c.toml 5m\n"
        "    steps:\n"
        "      - env:\n"
        "          SESSIONS: ${{ matrix.sessions }}\n"
    )

    assert configurations == ["a.toml", "b.toml", "c.toml"]
    assert not unparsed


def test_a_line_that_is_no_session_is_reported() -> None:
    """A line the reader cannot parse is named rather than skipped.

    Skipping it is how a session leaves the census while the matrix goes
    on spending its budget: the configuration would then read as one no
    job runs, and the census would be red about the wrong thing.
    """
    configurations, unparsed = _sessions(
        "            sessions: |\n"
        "              a.toml 90m\n"
        "              b.toml\n"
        "              c.txt 30m\n"
    )

    assert configurations == ["a.toml"]
    assert unparsed == ["b.toml", "c.txt 30m"]
