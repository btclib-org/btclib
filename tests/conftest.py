# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the whole suite shares: hypothesis profiles, a fixture, a gate.

Registered once here rather than passed to each `@given`: a settings
profile is process-wide, and a decorator repeating it on every property
test is one more place to forget it.
"""

import difflib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings

from btclib._libsecp256k1 import INSTALLED

# The deadline is a per-example time limit, measured on a run whose cost
# the interpreter and the runner decide: pypy meets these tests with a
# cold JIT, and the matrix runs them on emulated arm64 as well as on
# native x86. A timing flake in one of 54 jobs is a red build nobody can
# reproduce locally, and none of these tests is a benchmark -- what they
# assert is the answer, not how long it took to reach it.
#
# 500 examples against the hypothesis default of 100: measured at 1.4
# seconds for the whole suite over the default, which is worth five
# times the input on a run that happens at every commit. It is not the
# number that finds a latent defect, though -- the empty block of
# test_block_without_transactions took 2000 to turn up, and once turned
# up it belongs in a vector test rather than in a search that may or may
# not repeat it. Deep exploration is what the profile below is for.
settings.register_profile("btclib", deadline=None, max_examples=500)

# What to run when a parser is being changed, rather than at every
# commit: HYPOTHESIS_PROFILE=thorough uv run pytest
settings.register_profile("thorough", deadline=None, max_examples=2_000)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "btclib"))


def asks_for_everything(
    file_or_dir: list[str] | None, testpaths: list[str], rootpath: Path
) -> bool:
    """Whether the paths named on the command line take the suite in.

    No path at all narrows nothing and is the whole run. A path above one
    of them -- `pytest .`, or the rootdir spelled out -- collects it too,
    so what decides is containment and not equality. `tests` alone would
    match either way; `./tests` and `tests/` are the same directory under
    another name and need the paths resolved before they compare equal;
    and a path above `testpaths` is never equal to it, so only
    containment reads all four as the whole run they collect.

    `file_or_dir` is `None` rather than `[]` on the `--help` path, the
    parse having been abandoned rather than left unfinished: `--help` is
    bound to pytest's `HelpAction`, which raises `PrintHelp` to skip the
    rest of argument parsing, so the positional still carries argparse's
    default when `pytest_configure` fires. That is no path either, and
    folding it is what keeps `--help` from ending in a traceback whose
    last frame is this file.

    The two sides are relative to different directories: a path on the
    command line to where pytest was run from, a `testpaths` entry to the
    rootdir, which is what `testpaths` means. Both are then resolved, and
    the second needs it as much as the first -- pytest builds `rootpath`
    with `os.path.abspath`, which leaves a symlink in the path alone,
    while `Path.resolve` follows one, so a tree reached through `/tmp` on
    macOS would compare `/tmp/...` against `/private/tmp/...` and find no
    containment anywhere.
    """
    given = [Path(path).resolve() for path in file_or_dir or []]
    if not given:
        return True
    wanted = [(rootpath / path).resolve() for path in testpaths]
    if not wanted:
        # `all` over nothing is true, which would make every path named
        # here the whole suite. With `testpaths` unset there is nothing
        # to measure containment against, so this errs toward dropping
        # the floor rather than gating a run it cannot call whole
        return False
    return all(
        any(target == path or path in target.parents for path in given)
        for target in wanted
    )


def coverage_fail_under(
    asked: float | None,
    configured: float | None,
    file_or_dir: list[str] | None,
    keyword: str,
    markexpr: str,
    testpaths: list[str],
    rootpath: Path,
) -> float | None:
    """Return the coverage threshold this run's selection has to meet.

    `--cov` is in addopts, so the 100% ratchet is what a bare `uv run
    pytest` measures rather than something only the coverage job reaches:
    a gate that CI alone runs is one a change meets after it is pushed.
    What that costs is this function. `fail_under` applies to every
    report coverage writes, a partial one included, so `pytest
    tests/bip32/bip32_test.py` would end in `Required test coverage of
    100.0% not reached` -- true of that run and saying nothing about the
    tree. Running one file and one test are documented commands, and a
    gate that fails them is a gate read as noise.

    So a run that asked for a subset is gated at zero rather than having
    coverage switched off: the report still prints, which is what makes
    it worth measuring while iterating on one module. A whole run is
    handed back `configured`, the threshold pytest-cov has already read
    out of the coverage configuration, so pyproject.toml stays the one
    place the number lives.

    The two thresholds are two arguments because by the time any of this
    runs they no longer agree. pytest-cov fills `cov_fail_under` from the
    coverage configuration in `pytest_load_initial_conftests`, before
    `pytest_configure`, so "the option is set" has stopped meaning
    "somebody asked for it": what still means that is `config.option`,
    which carries only what the command line and addopts put there. An
    explicit `--cov-fail-under` is therefore `asked`, and is handed back
    untouched whichever kind of run it is -- the caller naming the
    threshold is the one thing this must not overrule.

    A subset is what pytest was *asked* for: a path that leaves part of
    the suite behind, `-k` or `-m`. Not every way a run can be short --
    `--lf`, `--deselect` and an `-x` that stops early are not read -- so
    those still meet the full threshold and report a shortfall the tree
    does not have. They are the flags of an iteration whose next run is
    the whole suite, and reading intent off all of them would make this a
    second definition of what a real run is.

    Section 8 of the organization standard has since taken the other
    side -- it counts `--deselect`, `--ignore`, `--ignore-glob` and
    `--lf` as selections too, and records the paragraph above as the
    reading it rejects. This tree agreeing with the wider set is
    btclib-org/.github#424, and is not what the containment rule here
    was about.

    Which paths leave nothing behind is `asks_for_everything` above, and
    it is the reason `testpaths` and the rootdir are arguments here.
    """
    if asked is not None:
        return asked
    if keyword or markexpr:
        return 0
    if not asks_for_everything(file_or_dir, testpaths, rootpath):
        return 0
    return configured


def pytest_configure(config: pytest.Config) -> None:
    """Gate a whole run at `fail_under`, and a partial one at nothing.

    The threshold is written to `known_args_namespace` and not to
    `config.option`: pytest builds the first by parsing the known
    arguments into a *copy* of the second, and pytest-cov holds on to
    that copy. Writing to `config.option` instead runs without error and
    changes nothing -- the plugin never reads it back, and the run still
    fails on the whole tree's coverage.
    """
    namespace = config.known_args_namespace
    namespace.cov_fail_under = coverage_fail_under(
        config.option.cov_fail_under,
        namespace.cov_fail_under,
        config.option.file_or_dir,
        config.option.keyword,
        config.option.markexpr,
        config.getini("testpaths"),
        config.rootpath,
    )


@pytest.fixture
def generated_files_dir(request: pytest.FixtureRequest) -> Path:
    """Locate the `_generated_files` directory beside the asking module.

    Stated once here rather than once per module: spelling
    `path.join(path.dirname(__file__), "_generated_files")` in each test
    restates the directory layout eleven times, in terms of `__file__`,
    so it moves with the test rather than with the data. `request.path`
    is the asking module's file.
    """
    return Path(request.path).parent / "_generated_files"


# What the json_golden fixture hands a test: named here so that the eleven
# modules taking it can annotate the parameter without restating the type
JsonGolden = Callable[[str, Any], None]

# the escape hatch, and the only thing that writes into the source tree
REGENERATE = "BTCLIB_REGENERATE_GOLDEN"


@pytest.fixture
def json_golden(
    request: pytest.FixtureRequest, generated_files_dir: Path
) -> JsonGolden:
    """Compare a `to_dict()` against the json committed beside the module.

    The point of keeping these files in the repository is to notice when
    what `to_dict` writes changes: they are the output of eleven dataclasses
    over fixed input, so a diff to one of them is a change to a serialized
    form somebody may be storing.

    The comparison reads and never writes: the file is read, and a
    difference fails the test. Writing the file on every run and leaving
    `git status` to report the difference would not be hermetic (a
    read-only checkout, an installed sdist), and it would depend on a
    human running the suite and then remembering to look -- no workflow
    inspects the working tree after pytest, so in CI the drift would be
    invisible exactly where it matters. To update a golden on purpose,
    when a change to `to_dict` is the intended change:

        BTCLIB_REGENERATE_GOLDEN=1 uv run pytest

    then read the diff, which is the review the change is meant to get.

    There is no on-disk round trip -- dump, load, compare to the dict just
    dumped -- because it could only fail if json.dump and json.load were
    not each other's inverse, which is a test of the standard library.
    What these tests assert about btclib is `from_dict(to_dict()) == obj`,
    in memory, beside every golden check.
    """

    def check(name: str, value: Any) -> None:
        check_golden(generated_files_dir / name, name, value, request.path.name)

    return check


def check_golden(path: Path, name: str, value: Any, module: str) -> None:
    """Compare `value` against the json at `path`, or rewrite it.

    The body of the fixture above, a module-level function rather than a
    closure: a closure over `request` cannot be called without a test to
    build it from, so the regenerate, missing-file and mismatch paths --
    the three that matter and the two that are failures -- would be the
    only lines of `tests/` a passing suite never runs. Taking a path and
    a module name lets `tests/conftest_test.py` exercise all three
    against a tmp_path, hermetically and without writing into the source
    tree.
    """
    # what the writes produced, byte for byte, so that regenerating
    # leaves no diff of its own
    text = json.dumps(value, indent=4) + "\n"

    if os.environ.get(REGENERATE):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="ascii")
        return

    if not path.exists():
        pytest.fail(
            f"missing golden file {path}\nrun: {REGENERATE}=1 uv run pytest {module}"
        )

    committed = path.read_text(encoding="ascii")
    if committed != text:
        diff = "".join(
            difflib.unified_diff(
                committed.splitlines(keepends=True),
                text.splitlines(keepends=True),
                fromfile=f"{name} (committed)",
                tofile=f"{name} (this run)",
            )
        )
        pytest.fail(
            f"{name} does not match what to_dict() produces now.\n"
            f"If the change is intended, regenerate and review the diff:\n"
            f"  {REGENERATE}=1 uv run pytest {module}\n\n"
            f"{diff}"
        )


def _skip_what_needs_the_bindings(items: list[pytest.Item]) -> None:  # pragma: no cover
    """Skip every test marked `bindings`, naming why once.

    Runs only where `btclib_secp256k1` is absent, `INSTALLED` being set
    once at import and not something a test can fake in-process. Issue
    #1002 asked whether that still leaves this unmeasured, given
    `test.yml`'s `coverage-union` job: it does not go unmeasured -- the
    no-bindings job's own `--cov` reaches this function and the combined
    report is 100% with the pragma removed -- but the pragma stays,
    because `coverage-union` gates beside the `coverage` job's report and
    not instead of it, and that job's own single run has the bindings
    installed, so `INSTALLED` is always True there and this function is
    never called. Removing the pragma would fail that gate, which this
    issue chose to leave exactly as it was.
    """
    skip = pytest.mark.skip(reason="btclib_secp256k1 is not installed")
    for item in items:
        # `iter_markers` and not `item.keywords`: keywords is what `-k`
        # matches, so it holds the module name, the test name and the
        # parametrize id as well -- and this tree has seventeen
        # parametrize decorators whose first id is `bindings`, whose
        # arms would then be skipped by the spelling of an id rather
        # than by a mark. Those arms do need skipping, so the suite
        # would stay green and the two names this marker exists to keep
        # equal would already differ; renaming one id is all it would
        # take to turn that into fourteen errors saying nothing
        if any(mark.name == "bindings" for mark in item.iter_markers()):
            item.add_marker(skip)


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Turn the `bindings` marker into a skip where there is nothing to compare.

    The marker is what `tests.needs_bindings` applies and what `pytest -m
    "not bindings"` selects on; this is what makes it a skip as well, so
    that one name does the selecting and the skipping and cannot drift
    into doing only one.
    """
    if not INSTALLED:
        _skip_what_needs_the_bindings(items)  # pragma: no cover
