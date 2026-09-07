# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the golden-file check and the coverage gate of conftest.

Eleven modules compare a `to_dict()` against a committed json through
`json_golden`, and the two paths that report a difference are the ones a
passing suite never takes: a golden that is missing and a golden that
does not match. They are the reason the fixture exists, so they are
tested here, against a tmp_path -- the source tree is what this check
stopped writing into, and a test of it must not put that back.

`coverage_fail_under` is the other one a passing suite cannot exercise
on its own: the run that reaches it with a subset selected is, by
construction, not the run that measures this file. The position of
`--cov` in addopts is here for the same reason -- it is a property of
the command line no run of that command line can report on.
"""

import re
from pathlib import Path

import pytest

from tests.conftest import REGENERATE, check_golden, coverage_fail_under

MODULE = "something_test.py"
_ROOT = Path(__file__).parents[1]
# what pyproject.toml's `testpaths` holds, passed in rather than read:
# the cases below are about what a command line means against a given
# `testpaths`, and reading the real one would make them a test of the
# configuration as well
_TESTPATHS = ["tests"]
# `deselect, ignore, ignore_glob, lf`, all unset: spliced into a call that
# is testing something else, so the four further triggers stay off
# without restating "None, None, None, False" at every one of them
_NO_FURTHER_SELECTION = (None, None, None, False)


@pytest.fixture(autouse=True)
def _regenerate_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Take REGENERATE out of the environment, for every test here.

    `BTCLIB_REGENERATE_GOLDEN=1 uv run pytest` is the command the failure
    message names and tests/_data/README.md documents, and running it
    turned three of the tests below red: with the variable set,
    `check_golden` takes the regenerate branch, so the missing and the
    mismatch paths rewrite the file instead of failing and the
    `pytest.raises` around them finds nothing to catch. The escape hatch
    made the tests of the escape hatch fail, and it is the whole suite
    that command is meant for, not the eleven golden modules alone.
    The two tests that want the variable set still set it themselves.
    """
    monkeypatch.delenv(REGENERATE, raising=False)


def test_a_matching_golden_passes(tmp_path: Path) -> None:
    """Verify a committed file equal to what the check writes passes."""
    path = tmp_path / "net.json"
    # four spaces of indent and a trailing newline: what the check writes
    # is what it then accepts, and nothing else is
    path.write_text('{\n    "a": 1\n}\n', encoding="ascii")
    check_golden(path, "net.json", {"a": 1}, MODULE)


def test_a_missing_golden_says_how_to_write_it(tmp_path: Path) -> None:
    """Verify a missing file fails and names the regenerate command."""
    path = tmp_path / "absent.json"
    with pytest.raises(pytest.fail.Exception, match="missing golden file"):
        check_golden(path, "absent.json", {"a": 1}, MODULE)
    # the message carries the command, that being the whole point of it
    with pytest.raises(pytest.fail.Exception, match=f"{REGENERATE}=1 uv run pytest"):
        check_golden(path, "absent.json", {"a": 1}, MODULE)


def test_a_mismatching_golden_fails_with_the_diff(tmp_path: Path) -> None:
    """Verify a mismatch reports a unified diff of the changed line."""
    path = tmp_path / "net.json"
    path.write_text('{\n    "a": 1\n}\n', encoding="ascii")

    with pytest.raises(pytest.fail.Exception) as excinfo:
        check_golden(path, "net.json", {"a": 2}, MODULE)

    message = str(excinfo.value)
    assert "net.json does not match what to_dict() produces now." in message
    # the diff is the review the check exists to ask for: both sides of
    # the changed line, and the file names that say which is which
    assert '-    "a": 1' in message
    assert '+    "a": 2' in message
    assert "net.json (committed)" in message
    assert "net.json (this run)" in message
    assert f"{REGENERATE}=1 uv run pytest {MODULE}" in message


def test_regenerating_creates_the_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`_generated_files` may not exist yet, for a new test module."""
    monkeypatch.setenv(REGENERATE, "1")
    path = tmp_path / "_generated_files" / "net.json"
    assert not path.parent.exists()

    check_golden(path, "net.json", {"a": 1}, MODULE)

    assert path.read_text(encoding="ascii") == '{\n    "a": 1\n}\n'


def test_regenerating_overwrites_a_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The escape hatch: what fails the check is what regenerating fixes."""
    path = tmp_path / "net.json"
    path.write_text('{\n    "a": 1\n}\n', encoding="ascii")
    with pytest.raises(pytest.fail.Exception, match="does not match"):
        check_golden(path, "net.json", {"a": 2}, MODULE)

    monkeypatch.setenv(REGENERATE, "1")
    check_golden(path, "net.json", {"a": 2}, MODULE)
    assert path.read_text(encoding="ascii") == '{\n    "a": 2\n}\n'

    # and the rewritten file is what the check then accepts, which is the
    # property that makes regenerating leave no diff of its own
    monkeypatch.delenv(REGENERATE)
    check_golden(path, "net.json", {"a": 2}, MODULE)


def test_a_whole_run_is_gated_at_what_pyproject_configured() -> None:
    """No selection: the ratchet applies, and it is not restated here.

    The number comes back as it was handed in, which is the property
    worth pinning: pyproject.toml is where 100 is decided, and a copy of
    it in this file would be a second place to change it.
    """
    assert (
        coverage_fail_under(
            None, 100.0, [], "", "", *_NO_FURTHER_SELECTION, _TESTPATHS, _ROOT
        )
        == 100.0
    )
    assert (
        coverage_fail_under(
            None, 42.0, [], "", "", *_NO_FURTHER_SELECTION, _TESTPATHS, _ROOT
        )
        == 42.0
    )


@pytest.mark.parametrize(
    "file_or_dir",
    [["tests"], ["./tests"], ["tests/"], ["."], [str(_ROOT)], None],
    ids=[
        "the suite",
        "./ before it",
        "trailing slash",
        "the cwd",
        "absolute",
        "--help",
    ],
)
def test_a_path_that_collects_the_suite_is_a_whole_run(
    file_or_dir: list[str] | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A path at or above `testpaths` is gated like the bare command.

    `pytest tests` is what somebody types who means the whole suite and
    says so, and every path here collects exactly what a bare run
    collects. Equality against `testpaths` would take in `tests` alone:
    `./tests` and `tests/` are that same directory spelled otherwise, and
    `.` and the rootdir are above it, which is why containment and not
    equality is what decides.

    `None` is the `--help` path, where the parse is abandoned before the
    positional is filled in; it reaches this function like any other run,
    and answering it wrongly would be a traceback rather than a threshold.

    The relative spellings are read against the working directory, which
    is what pytest does with them, so the run has to be standing in the
    rootdir for them to mean the suite.
    """
    monkeypatch.chdir(_ROOT)
    gate = coverage_fail_under(
        None, 100.0, file_or_dir, "", "", *_NO_FURTHER_SELECTION, _TESTPATHS, _ROOT
    )
    assert gate == 100.0


def test_a_symlinked_spelling_of_one_tree_is_still_the_whole_suite(
    tmp_path: Path,
) -> None:
    """Both sides are resolved, so one directory named twice is one path.

    A path on the command line and a `testpaths` entry joined onto the
    rootdir can each be spelled through a symlink -- `/tmp` is one on
    macOS, and a checkout under a linked home is another. pytest builds
    `rootpath` with `os.path.abspath`, which leaves the link in the path
    alone, so the two sides meet only once `Path.resolve` has followed
    it: unresolved on one side, `/tmp/...` neither equals
    `/private/tmp/...` nor is above it, and the run that collects
    everything is gated at nothing.

    One assertion per call, and neither stands in for the other: the
    first answers the ratchet with the `testpaths` side left unresolved,
    the second with the command line's side left unresolved.

    The link is made here rather than taken from the machine, so what
    the case is about is the comparison and not which directories an
    operating system happens to link. Creating one on Windows takes a
    privilege a runner need not hold, so a platform that refuses says so
    as a skip, which `-ra` reports.
    """
    base = tmp_path.resolve()
    real = base / "real"
    (real / "tests").mkdir(parents=True)
    link = base / "link"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError as refused:  # pragma: no cover -- Windows without the privilege
        pytest.skip(f"this platform will not create a symlink: {refused}")

    named_through_the_link = coverage_fail_under(
        None,
        100.0,
        [str(link / "tests")],
        "",
        "",
        *_NO_FURTHER_SELECTION,
        _TESTPATHS,
        real,
    )
    assert named_through_the_link == 100.0

    rootdir_through_the_link = coverage_fail_under(
        None,
        100.0,
        [str(real / "tests")],
        "",
        "",
        *_NO_FURTHER_SELECTION,
        _TESTPATHS,
        link,
    )
    assert rootdir_through_the_link == 100.0


def test_a_testpaths_entry_is_the_directory_its_parent_segment_reaches(
    tmp_path: Path,
) -> None:
    """`tests/../src` is `src`, which a command line naming `tests` misses.

    `pathlib` keeps a parent-directory segment where it collapses `.`
    and a trailing separator, so the unresolved join carries `..` into a
    path whose parents include the directory that segment left: `tests`
    then reads as above `tests/../src`, and a run collecting nothing of
    `src` is handed the whole suite's ratchet. Resolving the join makes
    the entry the directory it reaches, which `tests` is not above.

    That is the `testpaths` side's second reason, and it asks for no
    symlink and no privilege, so it holds where the case above can only
    skip. A `..` that re-enters the directory it left -- `tests/../tests`
    -- cannot see it: the unresolved target then has more parents and the
    command line's path is one of them, so containment answers the same
    with the call and without it.
    """
    base = tmp_path.resolve()
    gate = coverage_fail_under(
        None,
        100.0,
        [str(base / "tests")],
        "",
        "",
        *_NO_FURTHER_SELECTION,
        ["tests/../src"],
        base,
    )
    assert gate == 0


@pytest.mark.parametrize(
    "file_or_dir, keyword, markexpr",
    [
        (["tests/bip32/bip32_test.py"], "", ""),
        (["tests/bip32"], "", ""),
        ([], "derive", ""),
        ([], "", "integration"),
        (["tests/bip32"], "derive", "integration"),
        (["tests"], "derive", ""),
    ],
    ids=["one file", "one directory", "-k", "-m", "all three", "the suite, -k"],
)
def test_a_selected_subset_is_gated_at_nothing(
    file_or_dir: list[str], keyword: str, markexpr: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Any of the three selections drops the threshold to zero.

    Zero and not None: None is what pytest-cov reads the configured
    threshold into, so it would restore the very gate this removes.

    The last case is the whole suite named beside a `-k`: the path takes
    everything in and the expression then selects out of it, so what
    decides is the selection and not the path.
    """
    monkeypatch.chdir(_ROOT)
    gate = coverage_fail_under(
        None,
        100.0,
        file_or_dir,
        keyword,
        markexpr,
        *_NO_FURTHER_SELECTION,
        _TESTPATHS,
        _ROOT,
    )
    assert gate == 0


@pytest.mark.parametrize(
    "deselect, ignore, ignore_glob, lf",
    [
        (["tests/bip32/bip32_test.py::test_one"], None, None, False),
        (None, ["tests/bip32"], None, False),
        (None, None, ["tests/**/*_test.py"], False),
        (None, None, None, True),
    ],
    ids=["--deselect", "--ignore", "--ignore-glob", "--lf"],
)
def test_a_further_selection_is_gated_at_nothing(
    deselect: list[str] | None,
    ignore: list[str] | None,
    ignore_glob: list[str] | None,
    lf: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Section 8's four further triggers drop the threshold too.

    The path still collects the whole suite and neither `-k` nor `-m` is
    set, so each case here isolates the one flag it names -- the same
    property `test_a_selected_subset_is_gated_at_nothing` checks for a
    path, `-k` and `-m`.
    """
    monkeypatch.chdir(_ROOT)
    gate = coverage_fail_under(
        None,
        100.0,
        ["tests"],
        "",
        "",
        deselect,
        ignore,
        ignore_glob,
        lf,
        _TESTPATHS,
        _ROOT,
    )
    assert gate == 0


def test_without_testpaths_a_named_path_is_a_subset() -> None:
    """With nothing naming the suite, no path can be all of it.

    A bare run then collects the rootdir, so a path on the command line
    asks for less whatever it is. `all` over an empty `testpaths` would
    answer the opposite -- every run a whole one, and the floor never
    relaxed for the one-file run it exists for.
    """
    gate = coverage_fail_under(
        None, 100.0, ["tests"], "", "", *_NO_FURTHER_SELECTION, [], _ROOT
    )
    assert gate == 0


def test_cov_is_not_the_last_token_of_addopts() -> None:
    """`--cov` last in addopts eats the first argument of the command.

    It takes an optional value, so as the final token it is handed
    whatever the command line goes on to say: `pytest
    tests/ecc/dsa_test.py` became `--cov=tests/ecc/dsa_test.py`, leaving
    no path to select on. The whole suite then ran, measured a directory
    `omit` excludes, and reported 0.00% against a `fail_under` of 100 --
    which is how the regtest job, whose command is `pytest
    tests/integration`, went red on a branch that had touched none of it.

    `pytest -q tests/...` hides it, a token starting with `-` not being
    consumed, so the habitual spelling is green and the documented one is
    not. Nothing about a run reports its own addopts, which is why this
    reads the file: anywhere but last is safe, and the assertion is that
    weak on purpose -- the order of the rest is nobody's business here.
    """
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^addopts = "(.*)"$', text, re.MULTILINE)
    assert match, "pyproject.toml has no single-line 'addopts = \"...\"'"

    addopts = match.group(1).split()
    assert "--cov" in addopts, "the local coverage gate is --cov in addopts"
    assert addopts[-1] != "--cov", (
        "--cov is the last token of addopts, so it will swallow the first "
        "positional argument of any command line that has one"
    )


def test_an_explicit_threshold_survives_either_kind_of_run() -> None:
    """`--cov-fail-under` is the caller's, and outranks both branches."""
    subset = ["tests/bip32"]
    assert (
        coverage_fail_under(
            90.0, 100.0, subset, "", "", *_NO_FURTHER_SELECTION, _TESTPATHS, _ROOT
        )
        == 90.0
    )
    assert (
        coverage_fail_under(
            90.0, 100.0, [], "", "", *_NO_FURTHER_SELECTION, _TESTPATHS, _ROOT
        )
        == 90.0
    )
    # zero is a threshold somebody asked for, not a missing answer: it
    # has to survive the `is not None` test rather than be falsy
    assert (
        coverage_fail_under(
            0, 100.0, [], "", "", *_NO_FURTHER_SELECTION, _TESTPATHS, _ROOT
        )
        == 0
    )
