# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A released `## v<version>` section of CHANGELOG.md never moves again.

`merge=union` resolves a rebase's append-point conflict by keeping both
sides' added lines at the anchor they were written at (`.gitattributes`
puts CHANGELOG.md and RELEASE_NOTES.md under that driver). A branch cut
while a section still read "work in progress, not released yet" carries
its own entry at that anchor; where a release retitles the heading before
the branch rebases, the anchor is now the released heading, and the
driver puts the entry there without a conflict, a diff, or a `range-diff`
line showing it (issue #1512's own measurement, with
`git merge-file --union`).

So the one thing an already-released section can still be checked
against is not the working tree at all: it is the tag `git tag -s`
cut for that release, which is why this module shells out to `git`
rather than reading only what `Path.read_text` returns. For every
`## v<version>` heading in CHANGELOG.md and RELEASE_NOTES.md that is not
"work in progress", `git show <version>:<path>` is that section's own
authority, and the two must still agree byte for byte.

**Two ways for that comparison to be answered rather than performed,
and both are read as a name rather than as a verdict:**

- No `v*` tag resolves at all. `actions/checkout`'s own default is a
  shallow, tagless clone -- proven here by fetching one from this
  repository's own remote (`git init && git fetch --depth=1 origin
  main`): `git tag -l` printed nothing and `git show v2026.8.29:...`
  answered `fatal: invalid object name`. Erroring there would turn a
  pull request red for a checkout setting rather than for anything the
  branch touched; the module skips instead, and what keeps the skip from
  being pure decoration is that `coverage` and `no-bindings` in test.yml
  add `fetch-tags: true` to their checkout for exactly this test, so a
  real pull request never takes the skip. `test-passed`, the context the
  branch rule requires, waits on more jobs than those two; they are the
  ones that run pytest, so they are the ones this module needs. Adding
  the same to `git fetch` with no depth change still resolved every `v*`
  tag's own tree, measured the same way: history stayed one commit deep
  and `git show` still answered every release this module reads.
- The path did not carry its current name at that tag. RELEASE_NOTES.md
  was `HISTORY.md` before issue #1011's rename, and `CHANGES.md` before
  an earlier one still, so `git show v2026.8.9:RELEASE_NOTES.md` answers
  `fatal: path ... exists on disk, but not in 'v2026.8.9'` for a release
  that predates the file's current name. Chasing every rename back to
  `CHANGES.md` is not this gate's job; a heading whose tag cannot resolve
  the file under this name is skipped rather than treated as a match or
  a mismatch it was never able to compute.

**One exception, and its own repair narrowed it rather than closing
it.** Running this comparison against `origin/main` before this module
existed found CHANGELOG.md's `v2026.8.7`, `v2026.8.21` and `v2026.8.27`
already disagreeing with their own tag (issue #1512). `v2026.8.21` and
`v2026.8.27` had gained lines and lost none, misplaced bullets from
`afc1ca36` and `cbedc3b7` respectively, landed after that release's own
tag was already cut. `v2026.8.7` had both gained and lost lines: the
union driver only ever keeps both sides' *added* lines, so it cannot
rewrite or delete what a tag already holds, and two landed commits did,
deliberately and in review -- `13941fd1` de-linked `[HISTORY.md](...)`
inside that section, the file having been renamed and the link now
404ing, and `0744d3f4` rewrote a bullet's quoted misspellings in place.
The bullets `237c86d4` added under that section's own heading, with no
deletions, shared `afc1ca36`'s and `cbedc3b7`'s *misplacement* shape
instead.

None of the three landed under a subsection the open cycle would have
opened for it. Each was written under whichever heading, searching down
from the top of the file, was the first still carrying a subsection of
the matching name -- not "there was nowhere to put it", but that no
fresh subsection was opened under the still-open cycle for it.
`git show <commit>:CHANGELOG.md | grep -nE '^## |^### '` is what shows
this at each of the three: `237c86d4` wrote under `### Repository`,
which neither the open cycle nor `v2026.8.9`, immediately below it,
carried that day -- `v2026.8.7`, the next heading down, being the
first that did; `afc1ca36` wrote under `### Documentation and the
website`, which the open cycle's own subsections did not include that
day, `v2026.8.21` immediately below it being the first that did; and
`cbedc3b7` wrote under `### Repository`, again absent from the open
cycle's own subsections that day, `v2026.8.27` immediately below it
being the first that did. Issue #1458 points the right way without
being the whole story: it is the subsection, not only the cycle
heading, that a release now has to open for the next one.

issue #1524 is that repair, and its own measurement corrected the
obvious plan for the misplaced bullets: "move each to the release that
actually shipped it" reads as though some already-tagged release's own
snapshot shows it correctly filed, and none does. `git
merge-base --is-ancestor <commit> <tag>` says `237c86d4` first reaches
`v2026.8.21`, `afc1ca36` first reaches `v2026.8.27`, `cbedc3b7` first
reaches `v2026.8.29` -- but every one of those tags' *own* section for
that heading was checked directly and lacks the bullet too, because each
commit wrote it under an already-released heading as measured above,
and nothing has touched it since: the mistake was never a rebase
disturbing a settled tag, it is what that one commit itself wrote, and
every tag cut afterwards simply inherited it unchanged. So no already-
tagged heading can receive a bullet without gaining text its own sealed
tag never had, which is the identical failure this module exists to
catch, moved rather than fixed. The one heading with no tag to violate
is the currently open one, `## v2026.9 (work in progress, not released
yet)`, in the subsection each bullet already belonged to -- and once
that cycle is itself tagged, the bullet is part of its tag from day one,
unlike every prior placement. Each relocated bullet carries its own
trailing "(shipped in v<version>)", the tag `merge-base --is-ancestor`
found, so a reader can still tell it apart from what this cycle actually
added.

`v2026.8.7` keeps its exemption, now to `13941fd1` and `0744d3f4` alone:
`237c86d4`'s bullets, the section's only relocatable content, are gone
from it, and the two deliberate, already-reviewed edits that remain
rewrote their own text in place rather than adding a bullet, so there is
nothing left to relocate -- matching the tag again would mean undoing
two already-reviewed corrections instead.

`_KNOWN_DRIFT` below names the one remaining section and marks it
`xfail(strict=True)`: a further hand fix that makes it match its tag
again turns that case into an *unexpected* pass, which is a failure too,
so the exemption cannot quietly outlive the drift it names.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).parents[1]
_FILES = ("CHANGELOG.md", "RELEASE_NOTES.md")
_WIP = "work in progress, not released yet"
_HEADING = re.compile(r"^## (\S+)(.*)$", re.MULTILINE)

# resolved once, for the reason generate_sbom.py's own `_GIT` is: a bare
# "git" in a subprocess list is a partial executable path
_GIT = shutil.which("git") or "git"

# what emptied v2026.8.7 of relocatable content is issue #1524 moving
# out 237c86d4's own bullets, not the separate move of v2026.8.21's
# and v2026.8.27's. What remains, 13941fd1's and 0744d3f4's own
# deliberate edits, rewrote text already in that section rather than
# adding a bullet, so there is nothing to relocate -- matching the tag
# again would mean undoing two already-reviewed corrections
_KNOWN_DRIFT = frozenset(
    {
        ("CHANGELOG.md", "v2026.8.7"),
    }
)


def _sections(text: str) -> dict[str, str]:
    """Map each non-"work in progress" `## ` heading to its own block.

    A block runs from its own heading line up to (not including) the
    next `## ` heading or the end of the text, so the same heading in two
    different snapshots of a file is comparable block for block.
    """
    matches = list(_HEADING.finditer(text))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        version, rest = match.group(1), match.group(2)
        if _WIP in rest:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        blocks[version] = text[match.start() : end]
    return blocks


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    """Run `git <args>` against this repository, never raising on its own."""
    return subprocess.run(  # noqa: S603
        [_GIT, *args],
        cwd=_ROOT,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )


def _released_headings() -> list[tuple[str, str]]:
    """Every (path, version) naming an already-released heading on disk."""
    pairs: list[tuple[str, str]] = []
    for name in _FILES:
        text = (_ROOT / name).read_text(encoding="utf-8")
        pairs.extend((name, version) for version in _sections(text))
    return pairs


def _cases() -> list[Any]:
    """`_released_headings`, `_KNOWN_DRIFT` marked `xfail(strict=True)`."""
    cases: list[Any] = []
    for path, version in _released_headings():
        if (path, version) in _KNOWN_DRIFT:
            marks = pytest.mark.xfail(
                reason=(
                    f"deliberate, reviewed post-release edit: {path}'s"
                    f" {version!r} section carries 13941fd1's and"
                    " 0744d3f4's own text, rewritten in place rather than"
                    " added as a bullet, so there is nothing to relocate"
                    " (issue #1524); a further fix making this match its"
                    " tag again should turn this case into an unexpected"
                    " pass, which is what removes it from _KNOWN_DRIFT"
                ),
                strict=True,
            )
            cases.append(pytest.param(path, version, marks=marks))
        else:
            cases.append(pytest.param(path, version))
    return cases


_ANY_TAG = bool(_git("tag", "-l", "v*").stdout.split())

pytestmark = pytest.mark.skipif(
    not _ANY_TAG,
    reason=(
        "no v* tag resolves in this checkout -- a shallow, tagless clone"
        " cannot verify a release's own history. test.yml's coverage and"
        " no-bindings jobs, the two that gate a merge, fetch tags for"
        " exactly this reason, so a pull request does not take this skip"
    ),
)


def _newest_released(path: str) -> str | None:
    """`path`'s topmost heading that is not "work in progress"."""
    return next(iter(_sections((_ROOT / path).read_text(encoding="utf-8"))), None)


def _verify(path: str, version: str) -> tuple[str, str] | None:
    """Compare `path`'s own `version` section against its own tag.

    Returns `None` where they still agree, and otherwise a `(kind,
    message)` pair naming what the caller does with it: "fail" for a
    real disagreement or a tag this repository's own history never
    leaves unresolved, "skip" for a comparison this module cannot make
    at all. Kept apart from the test function below so a fixture can
    drive the two branches no released heading in this repository's own
    history reaches -- `test_a_released_section_still_matches_its_own_tag`
    only calls it, in the shape the 100% coverage floor asks of a
    defensive branch: not removed, moved where a test can trip it on
    purpose.
    """
    tag_exists = _git("rev-parse", "-q", "--verify", f"refs/tags/{version}")
    if tag_exists.returncode != 0:
        if version == _newest_released(path):
            # The release being cut. Its section is retitled in the pull
            # request and its tag is pushed from the commit that lands
            # that pull request, so between the two this one heading
            # names a tag that cannot exist yet -- a comparison not yet
            # possible, which is not the same answer as one that failed.
            # The window closes at the tag, and it reaches this heading
            # alone: every older one whose tag stops resolving still
            # falls through to the failure below.
            return "skip", f"{version!r} is being released and has no tag yet"
        # _ANY_TAG established some v* tag resolves; one specific release
        # heading whose own tag still does not is not the shallow-clone
        # case above, and is not waved through as though it were.
        return "fail", f"{version!r} does not resolve, though other v* tags do"

    tagged = _git("show", f"{version}:{path}")
    if tagged.returncode != 0:
        return "skip", f"{path!r} did not carry this name at {version} (a rename)"

    tagged_sections = _sections(tagged.stdout)
    if version not in tagged_sections:
        return "skip", f"{version}:{path} carries no {version!r} heading of its own"

    current = _sections((_ROOT / path).read_text(encoding="utf-8"))[version]
    if current != tagged_sections[version]:
        return (
            "fail",
            f"{path}'s {version!r} section no longer matches its own {version} tag",
        )
    return None


@pytest.mark.parametrize("path, version", _cases())
def test_a_released_section_still_matches_its_own_tag(path: str, version: str) -> None:
    """`<path>`'s `## <version>` section reads the same as at its own tag."""
    verdict = _verify(path, version)
    if verdict is None:
        return
    kind, message = verdict
    if kind == "skip":
        pytest.skip(message)
    else:
        pytest.fail(message)


# ---- _verify's own two branches, which no released heading in this
# repository's own history reaches: a tag genuinely missing among ones
# that resolve, and a tag whose file exists under its current name but
# not the heading being asked about


def test_verify_fails_when_one_specific_tag_does_not_resolve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Distinct from the module-wide skip.

    Some `v*` tag resolves, this one specifically does not, which is a
    checkout worth failing on rather than one this module declines to
    judge.
    """

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert cmd[1] == "rev-parse"
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _verify("CHANGELOG.md", "v0.0.0") == (
        "fail",
        "'v0.0.0' does not resolve, though other v* tags do",
    )


def test_verify_skips_the_release_being_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The newest heading names a tag that is pushed only after it lands.

    A release pull request retitles the "work in progress" section to
    the version being cut, and the tag is pushed from the commit that
    lands that pull request -- so in between, the newest heading
    resolves to no tag. The version is read back off the file rather
    than written here, so this asks about whatever release is open
    rather than needing an edit at each one.
    """

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert cmd[1] == "rev-parse"
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    newest = _newest_released("CHANGELOG.md")
    assert newest is not None
    assert _verify("CHANGELOG.md", newest) == (
        "skip",
        f"{newest!r} is being released and has no tag yet",
    )


def test_verify_skips_when_the_tags_own_snapshot_lacks_the_heading(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The file resolves at the tag and still carries no such heading.

    CHANGELOG.md's own history was reset once, so an old tag can predate
    every heading the current file still opens with, and this is read as
    nothing to compare against, not as a mismatch.
    """

    def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if cmd[1] == "rev-parse":
            return subprocess.CompletedProcess(cmd, 0)
        assert cmd[1] == "show"
        return subprocess.CompletedProcess(cmd, 0, stdout="## v0.0.1\n\nsomething\n")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _verify("CHANGELOG.md", "v0.0.0") == (
        "skip",
        "v0.0.0:CHANGELOG.md carries no 'v0.0.0' heading of its own",
    )
