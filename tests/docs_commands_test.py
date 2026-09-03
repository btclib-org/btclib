# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The documentation job's commands are spelled one way each.

The build is written in `.github/workflows/docs.yml`, which is what the
merge gate runs; in `.readthedocs.yaml`, which is what the published site
is built with; in `CONTRIBUTING.md`, which is what a contributor is told
to run; and in `docs/README.rst`, which is where `RELEASING.md` sends a
release. The grep over the pages that build wrote is in the workflow and
in `CONTRIBUTING.md`.

Each of those files is separately valid, so only reading them together
says they have diverged, and a divergence is not reported by any run: a
contributor whose local build passes a flag the gate does not, or a
published site built by a command no merge ever ran, is a difference the
green everywhere hides.

Both commands are here because the failure is one -- a command spelled in
more than one place with nothing comparing the spellings -- and the
reading that finds either finds both.

`docs/Makefile` and `docs/make.bat` are not sites of the build.
`docs/README.rst` says they drive the same build "without the flags", and
`SPHINXOPTS` is empty in each, so they spell nothing there is to agree
about.

Read with a regex rather than parsed, for the reason
`interpreters_test.py` gives: no dependency group here carries a yaml
parser. What a regex has to cross is a broken line, and these files break
theirs two ways, one of which leaves no mark in the file at all, so a
line is offered to the pattern joined to the one above it as well as
alone -- and joined only where that one was no command itself, which is
what keeps a closing fence off the end of a command already read. A site
yielding anything other than one command is `test_every_site_was_read`'s
failure, which is what keeps the comparisons below from passing over a
file they could not read.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).parents[1]

# a POSIX line continuation, which is how the markdown and the rst break
# the build command. The two yaml files fold theirs instead, and folding
# leaves no marker, which is why `_commands` joins each line to the one
# above it rather than this pattern reaching that case too
_CONTINUATION = re.compile(r"\\\n[ \t]*")

# the build, from `uv run` to the end of the line it is written on. The
# match has to reach `sphinx-build` for the prefix to be compared as
# well: `--group docs` is what installs the toolchain, and a site that
# dropped it would build against a different environment
_BUILD = re.compile(r"uv run\b.*\bsphinx-build\b.*")
# the grep over the built pages, to the end of the command rather than of
# the line: the workflow wraps it in an `if ...; then`, and the `;` is
# where the command a reader is given stops
_GREP = re.compile(r"grep -r.*?(?=;|$)")

# where each site writes, which is the one argument that does not agree
# and must not: read the docs names its destination in an environment
# variable of its own. So the last word is read against the site that
# holds it rather than across the sites, and one that changes where it
# builds to is red here rather than agreeing with itself
_BUILD_SITES = {
    ".github/workflows/docs.yml": "docs/build/html",
    ".readthedocs.yaml": "$READTHEDOCS_OUTPUT/html",
    "CONTRIBUTING.md": "docs/build/html",
    "docs/README.rst": "docs/build/html",
}
_GREP_SITES = (".github/workflows/docs.yml", "CONTRIBUTING.md")


def _commands(path: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    """Return every distinct command `pattern` finds in `path`.

    Each line is offered to the pattern alone, and joined to the one
    above it where that one held no command of its own: a folded yaml
    scalar continues a line that is incomplete, which is what reads one
    without a parser, and the same condition keeps a closing markdown
    fence off the end of a command already read whole.
    """
    text = _CONTINUATION.sub(" ", (_ROOT / path).read_text(encoding="utf-8"))
    lines = text.splitlines()
    found = [pattern.search(line) for line in lines]
    folded = [
        f"{above} {below}"
        for above, below, matched in zip(lines, lines[1:], found, strict=False)
        if matched is None
    ]
    found += [pattern.search(line) for line in folded]
    return tuple(sorted({" ".join(m.group().split()) for m in found if m}))


def _one(found: tuple[str, ...]) -> str:
    """Return the command of a site that holds exactly one.

    Joined rather than indexed: a site holding none, or more than one, is
    `test_every_site_was_read`'s failure, and joining leaves the
    comparisons below a string that agrees with nothing rather than an
    `IndexError` that says which file was read and not which check was
    being made.
    """
    return " ".join(found)


_BUILDS = {path: _commands(path, _BUILD) for path in _BUILD_SITES}
_GREPS = {path: _commands(path, _GREP) for path in _GREP_SITES}


def test_every_site_was_read() -> None:
    """Each file yielded the one command it holds.

    A renamed workflow key, a reindented block, a fence rewritten as
    something else: each leaves an extraction empty, and a comparison
    over nothing is true.
    """
    builds = {path: len(found) for path, found in _BUILDS.items()}
    assert set(builds.values()) == {1}, (
        f"one documentation build command per site, and instead: {builds}"
    )
    greps = {path: len(found) for path, found in _GREPS.items()}
    assert set(greps.values()) == {1}, (
        f"one unresolved-link grep per site, and instead: {greps}"
    )


def test_every_site_spells_one_build_command() -> None:
    """What the gate runs is what publishes the site and what a reader gets."""
    spellings = {path: _one(found).rsplit(" ", 1)[0] for path, found in _BUILDS.items()}
    assert len(set(spellings.values())) == 1, (
        f"the documentation build is spelled more than one way: {spellings}"
    )


def test_every_site_names_its_own_output_directory() -> None:
    """The argument that differs differs by site, and by no other."""
    outdirs = {path: _one(found).rsplit(" ", 1)[-1] for path, found in _BUILDS.items()}
    assert outdirs == _BUILD_SITES, (
        f"the documentation build writes to {outdirs}, where the sites are"
        f" {_BUILD_SITES}"
    )


def test_the_documented_grep_is_the_one_the_job_runs() -> None:
    """A reader who runs it and sees nothing has run the job's question."""
    spellings = {path: _one(found) for path, found in _GREPS.items()}
    assert len(set(spellings.values())) == 1, (
        f"the unresolved-link grep is spelled more than one way: {spellings}"
    )
