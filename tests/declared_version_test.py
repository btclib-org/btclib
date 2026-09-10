# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""pyproject.toml never declares a release some other commit is.

The version is declared once, in pyproject.toml, and
`btclib.__version__` reads it back from the installed metadata -- so a
checkout declaring a version that has already been tagged reports itself
as that release, which is what a bug report quotes. RELEASING.md's last
step, *Open the next cycle's version*, is what keeps it from happening:
it sets a generic next version without the day, "so a checkout of `main`
reports itself as work in progress rather than as a release it is not".
Skipping it is what left `main` declaring `2026.9.3` while `v2026.9.3`
named an older commit, with nothing anywhere reporting it (issue #1927).

`version-check` is the other check that reads the version, and it cannot
be this one: `release.yml` triggers it on a `v*` tag push and on the
`workflow_dispatch` of a rehearsal, so it has no opinion between
releases, and the shape it refuses -- two components, a tag on the
placeholder -- is the shape that is *missing* in the state above. A
stale three-component version is exactly what it is built to accept.

What distinguishes a release commit from every commit after it is not
that the tag exists but that it points **at this commit**, which is the
whole of the rule here:

- the placeholder, month only, must name no tag. `version-check` already
  holds this opinion at tag time, for the reason RELEASING.md gives: a
  tag on `2026.8` publishes a version whose day cannot be told from the
  placeholder naming the same month
- a version carrying the day -- three components, four for a patch on
  one, which is `version-check`'s own reading of the scheme -- may name
  no tag, and does throughout a release pull request and up to `git tag
  -s`. `tests/changelog_immutability_test.py` carries the same transient
  as a skip of its own, `"{version!r} is being released and has no tag
  yet"`
- a version carrying the day whose tag *does* resolve must resolve to
  `HEAD`. That is the release commit; anything else is a release this
  commit is not

`git describe --exact-match HEAD` answers the last of those in one call
and is the wrong spelling: in a shallow or archived checkout it reports
no tag, which turns the third arm into the second and a failure into a
pass with nothing said. `refs/tags/v<version>` is resolved directly
instead, and an empty tag namespace is a skip naming its own reason
rather than agreement -- `actions/checkout`'s default is a tagless
clone, which is why test.yml's `coverage` and `no-bindings` jobs, the
two that run pytest and gate a merge, pass `fetch-tags: true`.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).parents[1]

# regex rather than `tomllib`, which is stdlib only from 3.11 where this
# package supports 3.10: `tests/copyright_test.py` reads `authors` out of
# the same file the same way and its docstring carries the reason
_VERSION = re.compile(r'(?m)^version = "([^"]+)"$')

# the two shapes RELEASING.md's *Which version string is which* gives
# pyproject.toml's own version over one cycle: the month alone between
# releases, and YYYY.M.D on release day, with a fourth number where a
# release day is patched
_PLACEHOLDER = re.compile(r"[0-9]+\.[0-9]+")
_RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?")

# resolved once, for the reason generate_sbom.py's own `_GIT` is: a bare
# "git" in a subprocess list is a partial executable path
_GIT = shutil.which("git") or "git"


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    """Run `git <args>` against this repository, never raising on its own."""
    return subprocess.run(  # noqa: S603
        [_GIT, *args],
        cwd=_ROOT,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def _declared_version() -> str:
    """Return pyproject.toml's own `version`, the one place it is declared."""
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = _VERSION.search(text)
    assert match, "pyproject.toml has no 'version = ...' line"
    return match.group(1)


def _commit(rev: str) -> str | None:
    """Return the commit `rev` names, or `None` where it does not resolve.

    The `^{commit}` suffix peels: `git tag -s` writes a tag object, so
    `refs/tags/v2026.9.3` names that object rather than a commit, while
    the releases cut before it are lightweight tags naming their commit
    already and the same suffix leaves them alone.
    """
    resolved = _git("rev-parse", "-q", "--verify", f"{rev}^{{commit}}")
    return resolved.stdout.strip() if resolved.returncode == 0 else None


def _verdict(version: str, tag: str | None, head: str | None) -> tuple[str, str] | None:
    """Judge one declared `version` against the commit `v<version>` names.

    Returns `None` where the declaration is one this tree is allowed to
    carry, and otherwise a `("fail", message)` pair. The two commits are
    arguments rather than reads, so a test can ask what this answers
    about a state no checkout of this repository is in.
    """
    if _PLACEHOLDER.fullmatch(version):
        if tag is None:
            return None
        return (
            "fail",
            (
                f"pyproject.toml declares {version!r}, the placeholder a cycle"
                f" is opened with, and v{version} resolves at {tag}: a tag on"
                " the placeholder publishes a version with no day in it"
            ),
        )
    if not _RELEASE.fullmatch(version):
        return (
            "fail",
            (
                f"pyproject.toml declares {version!r}, which is neither the"
                " placeholder a cycle is opened with nor the YYYY.M.D of a"
                " release; RELEASING.md's 'Which version string is which' has"
                " the scheme"
            ),
        )
    if tag is None:
        # the version is being released and has no tag yet, which is what
        # a release pull request declares and what the default branch
        # declares between that pull request landing and `git tag -s`
        return None
    if tag == head:
        return None
    return (
        "fail",
        (
            f"pyproject.toml declares {version!r} and v{version} resolves at"
            f" {tag}, which is not this commit: RELEASING.md's 'Open the next"
            " cycle's version' is the step that has not been taken"
        ),
    )


def _verify() -> tuple[str, str] | None:
    """Judge this checkout's own declared version.

    Returns `None` where it holds, and otherwise a `(kind, message)` pair
    naming what the caller does with it: "fail" for a declaration this
    tree may not carry, "skip" for a checkout whose tags cannot answer.
    """
    if not _git("tag", "-l", "v*").stdout.split():
        return (
            "skip",
            (
                "no v* tag resolves in this checkout, so a declared version"
                " cannot be told from a release it names -- test.yml's"
                " coverage and no-bindings jobs, the two that run pytest and"
                " gate a merge, fetch tags for exactly this reason, so a pull"
                " request does not take this skip"
            ),
        )
    version = _declared_version()
    return _verdict(version, _commit(f"refs/tags/v{version}"), _commit("HEAD"))


def _answer(verdict: tuple[str, str] | None) -> None:
    """Turn one `_verify` verdict into a pass, a skip or a failure."""
    if verdict is None:
        return
    kind, message = verdict
    if kind == "skip":
        pytest.skip(message)
    pytest.fail(message)


def test_the_declared_version_is_not_another_commits_release() -> None:
    """pyproject.toml's version names no release this commit is not."""
    _answer(_verify())


def test_the_placeholder_a_cycle_is_opened_with_names_no_tag() -> None:
    """The month alone, which is what a checkout between releases reads."""
    assert _verdict("2026.10", None, "a1b2c3d") is None


def test_a_tagged_placeholder_fails() -> None:
    """A release nobody meant: the opinion `version-check` holds at tag time."""
    assert _verdict("2026.10", "a1b2c3d", "a1b2c3d") == (
        "fail",
        (
            "pyproject.toml declares '2026.10', the placeholder a cycle is"
            " opened with, and v2026.10 resolves at a1b2c3d: a tag on the"
            " placeholder publishes a version with no day in it"
        ),
    )


def test_a_version_being_released_has_no_tag_yet() -> None:
    """What a release pull request declares, and what follows it to the tag."""
    assert _verdict("2026.9.10", None, "a1b2c3d") is None
    assert _verdict("2026.9.10.1", None, "a1b2c3d") is None


def test_the_tagged_release_commit_passes() -> None:
    """The tag points at this commit, which is the release itself."""
    assert _verdict("2026.9.10", "a1b2c3d", "a1b2c3d") is None


def test_a_release_tagged_elsewhere_fails() -> None:
    """The state issue #1927 was opened about, in the shape it reaches here."""
    assert _verdict("2026.9.3", "e0fbd112", "2796a5c3") == (
        "fail",
        (
            "pyproject.toml declares '2026.9.3' and v2026.9.3 resolves at"
            " e0fbd112, which is not this commit: RELEASING.md's 'Open the"
            " next cycle's version' is the step that has not been taken"
        ),
    )


def test_a_version_of_neither_shape_fails() -> None:
    """`version-check` refuses this at tag time and never runs before one."""
    assert _verdict("2026.9rc1", None, "a1b2c3d") == (
        "fail",
        (
            "pyproject.toml declares '2026.9rc1', which is neither the"
            " placeholder a cycle is opened with nor the YYYY.M.D of a"
            " release; RELEASING.md's 'Which version string is which' has the"
            " scheme"
        ),
    )
    # a day and a suffix: what tells `fullmatch` from `match`, which would
    # read the three components and stop before the `rc1` that makes it
    # the non-final version `version-check` refuses at tag time
    assert _verdict("2026.9.10rc1", None, "a1b2c3d") == (
        "fail",
        (
            "pyproject.toml declares '2026.9.10rc1', which is neither the"
            " placeholder a cycle is opened with nor the YYYY.M.D of a"
            " release; RELEASING.md's 'Which version string is which' has the"
            " scheme"
        ),
    )


def test_the_declared_version_is_the_one_line_pyproject_carries() -> None:
    """One `version = ` line at the left margin, and this reads it.

    `re.search` answers with the first match, so what makes it the
    `[project]` table's own is that the file opens no second one.
    """
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert _VERSION.findall(text) == [_declared_version()]


def test_a_ref_that_does_not_resolve_answers_none() -> None:
    """`None` and not the empty string, which a sha could never be.

    Only the refusal, and no assertion that `HEAD` resolves: a tree with
    no `.git` answers `None` to both, and this module's whole rule is
    that such a tree skips with a reason rather than failing.
    `test_a_tag_object_is_peeled_to_the_commit_it_names` is where the
    success branch is measured, off a stubbed `git`.
    """
    assert _commit("refs/tags/v0.0.0") is None


def test_a_tag_object_is_peeled_to_the_commit_it_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`git tag -s` writes a tag object, whose own sha is not a commit's.

    Comparing that sha against `HEAD` fails on the release commit
    itself, which is the one commit this check has to pass, so the
    suffix that peels is asserted rather than left to a state no
    checkout is in between releases.
    """
    seen: list[list[str]] = []

    def record(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="a1b2c3d\n")

    monkeypatch.setattr(subprocess, "run", record)
    assert _commit("refs/tags/v2026.9.3") == "a1b2c3d"
    assert seen[0][-1] == "refs/tags/v2026.9.3^{commit}"


def test_an_empty_tag_namespace_skips_rather_than_agreeing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tagless clone cannot tell the third arm from the second.

    `actions/checkout`'s own default is one, so the answer has to be a
    skip naming its reason rather than the pass a `git describe` would
    have handed back.
    """

    def no_tags(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert cmd[1] == "tag"
        return subprocess.CompletedProcess(cmd, 0, stdout="")

    monkeypatch.setattr(subprocess, "run", no_tags)
    verdict = _verify()
    assert verdict is not None
    assert verdict[0] == "skip"
    assert verdict[1].startswith("no v* tag resolves in this checkout")


def test_a_skip_verdict_skips_and_a_fail_verdict_fails() -> None:
    """The two outcomes no state of this repository's own tree reaches."""
    with pytest.raises(pytest.fail.Exception, match="planted"):
        _answer(("fail", "a planted failure"))
    with pytest.raises(pytest.skip.Exception, match="planted"):
        _answer(("skip", "a planted skip"))
