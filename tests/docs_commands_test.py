# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A command CI runs is spelled one way wherever it is written down.

The documentation build is written in `btclib-org/.github`'s
`reusable-docs.yml`, which `.github/workflows/docs.yml` calls and which
this suite, reading only this tree, does not; in `.readthedocs.yaml`,
which is what the published site is built with; in `CONTRIBUTING.md`,
which is what a contributor is told to run; and in `docs/README.rst`,
which is where `RELEASING.md` sends a release. The grep over the pages
that build wrote moved with it, and is compared against nothing here now
(issue btclib-org/.github#35).

The lint command is written in `btclib-org/.github`'s `reusable-lint.yml`,
which `.github/workflows/lint.yml` calls and which this suite, reading
only this tree, does not; and in `CONTRIBUTING.md`, which is what a
contributor is told to run. Comparing `CONTRIBUTING.md` against the one
site left in this tree would compare it against itself, which passes
vacuously, so the comparison goes rather than staying as coverage that
cannot fail (issue btclib-org/.github#35).

`CONTRIBUTING.md`'s *Reproducing what CI runs* prints a command per job,
and the suite's own are read here as well: the cell of the platform
matrices, which `os-ubuntu.yml`, `os-macos.yml` and `os-windows.yml` each
run; the pair `test.yml`'s `coverage-union` job runs, which combines the
two coverage data files and reports their union; the names those data files
carry, which the section writes in front of the command that produces each;
the `coverage` job's `pytest`; the `no-bindings` job's
`pytest --cov-fail-under=0`; and the `python -c` assertion that job makes
before running it.

The union pair, the two `pytest` steps and the bindings assertion are each
compared with nothing set aside. The cell is not: the
workflows leave the interpreter to `astral-sh/setup-uv`, which takes it
from the matrix, where whoever reproduces a cell has to type `--python`, so
that argument is read against the site that holds it as the build's output
directory is -- named rather than normalised away. The data files are read
as values for the same kind of reason: `test.yml` sets `COVERAGE_FILE` as a
step's `env:` mapping where the section writes a shell assignment in front
of the command, so the assignment itself is what the two sites cannot
share. A name they disagree on leaves one of them combining a file nothing
wrote.

Each of those files is separately valid, so only reading them together
says they have diverged, and a divergence is not reported by any run: a
contributor whose local build passes a flag the gate does not, or a
published site built by a command no merge ever ran, is a difference the
green everywhere hides.

Everything read here is read because the failure is one -- a command, or
an argument it is given, spelled in more than one place with nothing
comparing the spellings -- and the reading that finds any of them finds
the rest.

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

The bindings assertion is the one construct a single join does not
reach: `test.yml` folds it over several lines and none of them, alone or
joined to its neighbour, reads as the command. It is read as a whole
file instead, `_CONTINUATION` collapsing the shell script's own
backslash breaks first and a single pattern spanning the rest, anchored
at both ends on text neither a shorter nor a longer command would carry
-- so what the pattern must skip in between is read along with it,
which is what lets a clause missing from one side and not the other
show up as a difference in the string rather than a match either way
agrees to.
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
# one cell of the platform matrices, from `uv run` to the end of the line
# it is written on. `--no-cov` is what tells it from the `coverage` job's
# own run of the same suite, which is typed with nothing after `pytest`
_CELL = re.compile(r"uv run\b.*\bpytest --no-cov\b.*")
# the interpreter a cell names, which the comparison sets aside before
# making it and reads on its own afterwards
_INTERPRETER = re.compile(r" --python (\S+)")
# the `coverage-union` job's two commands, each to the end of the line it
# is written on: `combine` names the data files it reads and `report` is
# typed with nothing after it, so neither ends before its line does
_COVERAGE = re.compile(r"uv run\b.*\bcoverage (?:combine|report)\b.*")
# the data file a coverage run writes, matched as the value alone: the
# separator in front of it is the half of the spelling the two sites
# cannot share
_DATA_FILE = re.compile(r"(?<=COVERAGE_FILE[=:])\s*\S+")
# the `coverage` job's bare `pytest`. `deps-latest.yml`'s own
# `suite-bindings-latest` job types the identical string in
# `CONTRIBUTING.md` too -- `uv run --locked --no-default-groups
# --group test pytest`, byte for byte, with nothing after `pytest`
# either -- so no pattern over the line's own text tells the two apart,
# only where each sits: this job's own line is the one carrying
# `COVERAGE_FILE=coverage-data-bindings`, which the `deps-latest`
# reproduction never does. `_job_pytest_doc` below reads `CONTRIBUTING.md`
# scoped to that line; `test.yml` needs no such scoping, that string
# occurring there once
_JOB_PYTEST = re.compile(
    r"uv run --locked --no-default-groups --group test\s+"
    r"pytest\b(?:\s+-\S+)*\s*$"
)
# the `no-bindings` job's `pytest --cov-fail-under=0`. In `test.yml` the
# line before it is that step's own `uv run --locked --no-default-groups
# --group harness`, which the fold above joins it to; in `CONTRIBUTING.md`,
# already one line after `_CONTINUATION` collapses its own backslash
# breaks, the line above that is the bindings assertion's closing
# `is_libsecp256k1_serving()"`. Neither is a command this pattern could
# be folded into by mistake, so the trailing `(?:\s+-\S+)*\s*$` is here
# for a flag appended on this line's own end, not to keep this pattern
# from reaching a neighbour
_HARNESS_PYTEST = re.compile(
    r"uv run --locked --no-default-groups --group harness\s+"
    r"pytest --cov-fail-under=0\b(?:\s+-\S+)*\s*$"
)
# the `python -c` that asserts the bindings are absent, anchored on the
# import `INSTALLED` is bound from and the call that closes the
# argument's quote: `test.yml` folds the four clauses in between over
# four lines with none of them, alone or joined to one neighbour, ending
# in a valid command -- `_spellings`'s one-line join never reaches a
# match, so this one is read whole-file instead, by
# `_whole_text_spellings` below
_BINDINGS_ASSERT = re.compile(
    r"uv run --locked --no-default-groups --group harness\s+"
    r'python -c "from btclib\._libsecp256k1 import INSTALLED;'
    r".*?is_libsecp256k1_serving\(\)\"",
    re.DOTALL,
)

# where each site writes, which is the one argument that does not agree
# and must not: read the docs names its destination in an environment
# variable of its own. So the last word is read against the site that
# holds it rather than across the sites, and one that changes where it
# builds to is red here rather than agreeing with itself
_BUILD_SITES = {
    ".readthedocs.yaml": "$READTHEDOCS_OUTPUT/html",
    "CONTRIBUTING.md": "docs/build/html",
    "docs/README.rst": "docs/build/html",
}

# the interpreter each site names, which is the other argument that does
# not agree and must not: a workflow takes it from `astral-sh/setup-uv`,
# one cell of the matrix per run, where whoever reproduces a cell locally
# has to say which one. So a workflow that started naming an interpreter
# of its own is red here, and so is a section that stopped naming one
_CELL_SITES = {
    ".github/workflows/os-ubuntu.yml": "",
    ".github/workflows/os-macos.yml": "",
    ".github/workflows/os-windows.yml": "",
    "CONTRIBUTING.md": "3.10",
}
# the union job and the section that tells a reader how to run it again,
# which are also the two sites of the data files that job combines
_COVERAGE_SITES = (".github/workflows/test.yml", "CONTRIBUTING.md")
# the two pytest steps, each against the section that tells a reader how
# to run it again
_HARNESS_PYTEST_SITES = (".github/workflows/test.yml", "CONTRIBUTING.md")
_BINDINGS_ASSERT_SITES = (".github/workflows/test.yml", "CONTRIBUTING.md")


def _spellings(path: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    """Return every distinct spelling `pattern` finds in `path`.

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


def _whole_text_spellings(path: str, pattern: re.Pattern[str]) -> tuple[str, ...]:
    """Return every distinct spelling `pattern` finds across the whole file.

    `_spellings` above offers the pattern one line, and at most one join,
    at a time, which is what the bindings assertion does not fit: none of
    its own lines in `test.yml` matches alone, and joining two of them
    still leaves two more outside the string. Matched against the
    continuation-collapsed text as a whole instead, with the same
    whitespace folding `_spellings` applies to what it finds, so a
    command spread over any number of lines reads the same as one written
    on a single line already.
    """
    text = _CONTINUATION.sub(" ", (_ROOT / path).read_text(encoding="utf-8"))
    return tuple(sorted({" ".join(m.group().split()) for m in pattern.finditer(text)}))


def _job_pytest_doc() -> tuple[str, ...]:
    """Return the coverage job's `pytest`, read out of its own line only.

    `CONTRIBUTING.md` also carries `_JOB_PYTEST`'s exact string for
    `deps-latest.yml`'s `suite-bindings-latest` job, so searching the
    whole file finds both. `COVERAGE_FILE=coverage-data-bindings` is the
    coverage job's own env assignment, and the only line of the file
    that carries it; searching that line alone is what the `deps-latest`
    job's line, carrying no such marker, cannot reach. A lookbehind on
    the marker cannot express this match: the source carries one literal
    space before the line's own backslash break, `_CONTINUATION`
    substitutes one more for the break itself, and Python's `re`
    lookbehind has to be a fixed width, which two spaces only sometimes
    is.
    """
    text = _CONTINUATION.sub(
        " ", (_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    )
    lines = [
        line
        for line in text.splitlines()
        if "COVERAGE_FILE=coverage-data-bindings" in line
    ]
    found = [_JOB_PYTEST.search(line) for line in lines]
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


_BUILDS = {path: _spellings(path, _BUILD) for path in _BUILD_SITES}
_CELLS = {path: _spellings(path, _CELL) for path in _CELL_SITES}
_COVERAGES = {path: _spellings(path, _COVERAGE) for path in _COVERAGE_SITES}
_DATA_FILES = {path: _spellings(path, _DATA_FILE) for path in _COVERAGE_SITES}
_JOB_PYTESTS = {
    ".github/workflows/test.yml": _spellings(".github/workflows/test.yml", _JOB_PYTEST),
    "CONTRIBUTING.md": _job_pytest_doc(),
}
_HARNESS_PYTESTS = {
    path: _spellings(path, _HARNESS_PYTEST) for path in _HARNESS_PYTEST_SITES
}
_BINDINGS_ASSERTS = {
    path: _whole_text_spellings(path, _BINDINGS_ASSERT)
    for path in _BINDINGS_ASSERT_SITES
}


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
    cells = {path: len(found) for path, found in _CELLS.items()}
    assert set(cells.values()) == {1}, (
        f"one matrix cell command per site, and instead: {cells}"
    )
    coverages = {path: len(found) for path, found in _COVERAGES.items()}
    assert set(coverages.values()) == {2}, (
        f"the combine and the report per site, and instead: {coverages}"
    )
    data_files = {path: len(found) for path, found in _DATA_FILES.items()}
    assert set(data_files.values()) == {2}, (
        f"a data file per coverage run per site, and instead: {data_files}"
    )
    job_pytests = {path: len(found) for path, found in _JOB_PYTESTS.items()}
    assert set(job_pytests.values()) == {1}, (
        f"one coverage-job pytest per site, and instead: {job_pytests}"
    )
    harness_pytests = {path: len(found) for path, found in _HARNESS_PYTESTS.items()}
    assert set(harness_pytests.values()) == {1}, (
        f"one no-bindings pytest per site, and instead: {harness_pytests}"
    )
    bindings_asserts = {path: len(found) for path, found in _BINDINGS_ASSERTS.items()}
    assert set(bindings_asserts.values()) == {1}, (
        f"one bindings assertion per site, and instead: {bindings_asserts}"
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


def test_every_site_spells_one_matrix_cell_command() -> None:
    """What a platform workflow runs is what a reader is told to run."""
    spellings = {
        path: _INTERPRETER.sub("", _one(found)) for path, found in _CELLS.items()
    }
    assert len(set(spellings.values())) == 1, (
        f"the matrix cell is spelled more than one way: {spellings}"
    )


def test_only_the_documented_cell_names_an_interpreter() -> None:
    """The argument that differs differs by site, and by no other."""
    interpreters = {
        path: "".join(_INTERPRETER.findall(_one(found)))
        for path, found in _CELLS.items()
    }
    assert interpreters == _CELL_SITES, (
        f"the matrix cell names the interpreters {interpreters}, where the"
        f" sites are {_CELL_SITES}"
    )


def test_the_documented_union_is_the_one_the_job_runs() -> None:
    """A reader who combines and reports gates what the job gates."""
    assert len(set(_COVERAGES.values())) == 1, (
        f"the coverage union is spelled more than one way: {_COVERAGES}"
    )


def test_the_documented_data_files_are_the_ones_the_jobs_write() -> None:
    """`COVERAGE_FILE` names there what `test.yml`'s own `env:` names."""
    assert len(set(_DATA_FILES.values())) == 1, (
        f"the coverage data files are named more than one way: {_DATA_FILES}"
    )


def test_the_documented_coverage_pytest_is_the_one_the_job_runs() -> None:
    """A reader reproducing the `coverage` job runs what it runs."""
    assert len(set(_JOB_PYTESTS.values())) == 1, (
        f"the coverage job's pytest is spelled more than one way: {_JOB_PYTESTS}"
    )


def test_the_documented_no_bindings_pytest_is_the_one_the_job_runs() -> None:
    """A reader reproducing the `no-bindings` job runs what it runs."""
    assert len(set(_HARNESS_PYTESTS.values())) == 1, (
        f"the no-bindings job's pytest is spelled more than one way: {_HARNESS_PYTESTS}"
    )


def test_the_documented_bindings_assertion_is_the_one_the_job_runs() -> None:
    """The assertion a reader is told to run is the one the job runs."""
    assert len(set(_BINDINGS_ASSERTS.values())) == 1, (
        f"the bindings assertion is spelled more than one way: {_BINDINGS_ASSERTS}"
    )
