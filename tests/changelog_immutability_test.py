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
every tag cut afterwards simply inherited it unchanged. So no already-tagged
heading can receive a bullet without gaining text its own sealed
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

`_KNOWN_DRIFT` below is where that exemption is written, and what an
entry pins is the text its section reads at rather than the section
itself: the digest, and beside it that entry's own reason for the text
being what it is. A section digesting to what its entry pins is the text
somebody reviewed; one matching its own tag again leaves the entry
exempting nothing, which is what takes the entry out; and one matching
neither has taken a line nobody read -- the union driver lands an entry
wherever its branch wrote it, anywhere inside the section rather than at
the edit an exemption was registered for, so an exemption reaching the
whole section would swallow exactly what is described above.

An entry is evaluated only where its key is among `_released_headings()`,
which is what the parametrized cases are generated from. A key naming
anything else -- a mistyped version, a heading since retitled or removed,
one written against the still-open cycle `_sections` skips -- reaches no
case at all, so the table is held to those headings as well: an exemption
the comparison never applies is a claim about this tree that nothing
would otherwise check (issue #1905).

A case of its own is still not a comparison, and `_verify`'s own skips
are where the two part. A key whose tag cannot resolve the file under
this name, and one whose tag's own snapshot carries no such heading, are
answered before `_verdict` reads either text, so the digest such an
entry pins is held against nothing; a tag is what it is, so neither
answer changes afterwards. The window between a release's retitling
commit and its own tag is the one skip that closes, and it reaches the
heading `_newest_released` names alone -- an exemption written there is
a statement every check here applies to from the tag onward, which is
why the table is held to that pair of cases rather than to
comparability alone (issue #1911).
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest

_ROOT = Path(__file__).parents[1]
_FILES = ("CHANGELOG.md", "RELEASE_NOTES.md")
_WIP = "work in progress, not released yet"
_HEADING = re.compile(r"^## (\S+)(.*)$", re.MULTILINE)

# resolved once, for the reason generate_sbom.py's own `_GIT` is: a bare
# "git" in a subprocess list is a partial executable path
_GIT = shutil.which("git") or "git"


class _Drift(NamedTuple):
    """One exempt section: the digest it reads at, and why it reads so."""

    digest: str
    reason: str


# a digest rather than the section's own bytes: CHANGELOG.md is where
# that text lives, and a copy of a released section inside a test module
# is a second place for it to be edited. What a digest gives up is
# showing what the drift is, which is what the reason beside it says,
# and the failing message prints the digest a section reads at, so a
# reviewed edit costs its entry one line
_KNOWN_DRIFT: dict[tuple[str, str], _Drift] = {
    ("CHANGELOG.md", "v2026.8.7"): _Drift(
        digest="8cb4a0458fc3da3484fe493b28ee28b103fbc9d7f76bd7245cb4464664ff0884",
        reason=(
            "13941fd1 de-linked [HISTORY.md](...) inside it, the file"
            " having been renamed, and 0744d3f4 rewrote a bullet's quoted"
            " misspellings; each rewrote text already there rather than"
            " adding a bullet, so there is nothing to relocate (issue"
            " #1524)"
        ),
    ),
}


def _digest(section: str) -> str:
    """Return a section's own sha256, which is what a `_Drift` pins."""
    return hashlib.sha256(section.encode("utf-8")).hexdigest()


def _read(path: str) -> str:
    """`path`'s own text, as this checkout holds it."""
    return (_ROOT / path).read_text(encoding="utf-8")


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
        pairs.extend((name, version) for version in _sections(_read(name)))
    return pairs


def _exemptions_naming_no_released_heading(
    drift: dict[tuple[str, str], _Drift],
) -> list[tuple[str, str]]:
    """Which of `drift`'s keys name no released heading on disk.

    Each such key reaches none of the cases
    `test_a_released_section_still_matches_its_own_tag` is generated
    from, which is where an exemption is applied to the section it
    names. The table is an argument rather than a read, for the reason
    `_verdict`'s texts are: a test can plant an entry and ask what this
    answers about it.
    """
    released = set(_released_headings())
    return [key for key in drift if key not in released]


def _comparable_exemptions(
    drift: dict[tuple[str, str], _Drift],
) -> list[tuple[tuple[str, str], _Drift, str, str]]:
    """Each entry of `drift` whose section and its tag's can both be read.

    The two tests that drive `_verdict` from a real exempt section index
    `_sections` on both sides, and an entry's position does not say
    whether they can: a key naming no released heading has no section on
    disk, and one whose tag predates the file's current name has none at
    the tag, which is the pair `_verify` skips. Taking the first entry
    instead answers `KeyError` about that entry rather than anything
    about `_verdict`.
    """
    usable: list[tuple[tuple[str, str], _Drift, str, str]] = []
    for (path, version), entry in drift.items():
        tagged = _git("show", f"{version}:{path}")
        at_tag = _sections(tagged.stdout) if tagged.returncode == 0 else {}
        current = _sections(_read(path))
        if version in at_tag and version in current:
            usable.append(((path, version), entry, current[version], at_tag[version]))
    return usable


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
    return next(iter(_sections(_read(path))), None)


def _tag_resolves(version: str) -> bool:
    """Whether `refs/tags/<version>` is in this checkout's own ref store.

    The one test that tells the release being cut from a release the
    file has outlived, and `_verify` and the table check below read it
    the same way rather than each spelling out a `git` call of its own.
    """
    return _git("rev-parse", "-q", "--verify", f"refs/tags/{version}").returncode == 0


def _exemptions_no_verdict_can_reach(
    drift: dict[tuple[str, str], _Drift],
) -> list[tuple[str, str]]:
    """Which of `drift`'s keys `_verify` answers before `_verdict` sees them.

    `_comparable_exemptions` is where an entry's digest and its section
    meet; a key outside it is one of `_verify`'s skips, and the release
    window is the skip that closes. That heading is
    `_newest_released(path)` and its tag is pushed as the pull request
    lands, so an exemption written for it is evaluated from there on. A
    rename and a tag whose snapshot opens no such heading are permanent
    instead, and an exemption on either excuses a comparison nothing
    performs. Where a key names one of `_FILES`, having no section on
    disk leaves it neither comparable nor `_newest_released(path)`, so
    what `_exemptions_naming_no_released_heading` names is a subset of
    this and its own message is the narrower reading of it. A key naming
    any other path has nothing for `_read` to open, and
    `_comparable_exemptions` raises there rather than answering. The
    table is an argument, as it is above.
    """
    comparable = {key for key, _, _, _ in _comparable_exemptions(drift)}
    unreachable: list[tuple[str, str]] = []
    for path, version in drift:
        if (path, version) in comparable:
            continue
        if version == _newest_released(path) and not _tag_resolves(version):
            continue
        unreachable.append((path, version))
    return unreachable


def _verdict(
    path: str, version: str, current: str, tagged: str
) -> tuple[str, str] | None:
    """Judge one section's own text against its tag and its exemption.

    Returns `None` where the section reads as it should -- its own tag's
    text, or, where `_KNOWN_DRIFT` names it, the text that entry pins --
    and otherwise a `("fail", message)` pair. The two texts are
    arguments rather than reads, so a test can plant a line in a real
    section and ask what this answers about it.
    """
    drift = _KNOWN_DRIFT.get((path, version))
    if drift is None:
        if current != tagged:
            return (
                "fail",
                f"{path}'s {version!r} section no longer matches its own {version} tag",
            )
        return None
    if current == tagged:
        return (
            "fail",
            (
                f"{path}'s {version!r} section matches its own {version} tag"
                f" again, so its _KNOWN_DRIFT entry exempts nothing:"
                f" {drift.reason}"
            ),
        )
    digest = _digest(current)
    if digest != drift.digest:
        return (
            "fail",
            (
                f"{path}'s {version!r} section is neither its own {version}"
                f" tag's text nor what _KNOWN_DRIFT pins for it"
                f" ({drift.reason}); a reviewed edit is what puts {digest} in"
                f" that entry"
            ),
        )
    return None


def _verify(path: str, version: str) -> tuple[str, str] | None:
    """Compare `path`'s own `version` section against its own tag.

    Returns `None` where they still agree, and otherwise a `(kind,
    message)` pair naming what the caller does with it: "fail" for a
    real disagreement or a tag this repository's own history never
    leaves unresolved, "skip" for a comparison this module cannot make
    at all. Kept apart from the test function below so a test can drive
    the branches no released heading in this repository's own history
    reaches -- `test_a_released_section_still_matches_its_own_tag`
    only calls it, in the shape the 100% coverage floor asks of a
    defensive branch: not removed, moved where a test can trip it on
    purpose.
    """
    if not _tag_resolves(version):
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

    current = _sections(_read(path))[version]
    return _verdict(path, version, current, tagged_sections[version])


def _answer(verdict: tuple[str, str] | None) -> None:
    """Turn one `_verify` verdict into a pass, a skip or a failure."""
    if verdict is None:
        return
    kind, message = verdict
    if kind == "skip":
        pytest.skip(message)
    pytest.fail(message)


@pytest.mark.parametrize("path, version", _released_headings())
def test_a_released_section_still_matches_its_own_tag(path: str, version: str) -> None:
    """`<path>`'s `## <version>` section reads the same as at its own tag."""
    _answer(_verify(path, version))


def test_every_exemption_names_a_released_heading_on_disk() -> None:
    """`_KNOWN_DRIFT` exempts a released heading a case is generated for.

    An entry keyed on anything else is never evaluated, and a table read
    for which sections are excused and why is where that costs most. The
    planted key is the still-open cycle, which `_sections` skips, and it
    carries a live entry's own value: the key is then the only thing
    that differs, so an implementation answering about a digest or a
    reason instead does not pass this.
    """
    assert _KNOWN_DRIFT, "no exemption to ask about"
    dead = _exemptions_naming_no_released_heading(_KNOWN_DRIFT)
    assert not dead, (
        f"_KNOWN_DRIFT exempts {dead}, naming no released heading on disk,"
        " so no case is generated for it and the comparison never applies it"
    )

    bogus = ("CHANGELOG.md", "v2026.9")
    assert bogus not in _KNOWN_DRIFT
    planted = {**_KNOWN_DRIFT, bogus: next(iter(_KNOWN_DRIFT.values()))}
    assert _exemptions_naming_no_released_heading(planted) == [bogus]


def test_every_exemption_is_compared_or_names_the_release_being_cut() -> None:
    """`_KNOWN_DRIFT` exempts comparisons that reach a verdict.

    A key naming a released heading on disk still buys nothing where the
    comparison for it is skipped: `git show <version>:<path>` fails for
    a release predating the file's current name, and `_verify` answers
    that before `_verdict` reads either text, so the digest the entry
    pins is held against nothing. The planted key is
    `RELEASE_NOTES.md`'s `v2020.4.7`, whose tag resolves and whose file
    did not carry this name there, and it carries a live entry's own
    value: the key is the only thing that differs.
    """
    assert _KNOWN_DRIFT, "no exemption to ask about"
    unreachable = _exemptions_no_verdict_can_reach(_KNOWN_DRIFT)
    assert not unreachable, (
        f"_KNOWN_DRIFT exempts {unreachable}, a comparison this module skips"
        " rather than answers, so nothing is ever held to the digest it pins"
    )

    renamed = ("RELEASE_NOTES.md", "v2020.4.7")
    assert renamed not in _KNOWN_DRIFT
    planted = {**_KNOWN_DRIFT, renamed: next(iter(_KNOWN_DRIFT.values()))}
    assert _exemptions_no_verdict_can_reach(planted) == [renamed]


def test_an_exemption_may_name_the_release_being_cut(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_exemptions_no_verdict_can_reach` leaves the release window alone.

    A release pull request retitles the "work in progress" section and
    the tag is pushed from the commit that lands it, so in between the
    newest heading is on disk with no tag to read it at. An exemption
    written there is evaluated from the tag onward, and the check the
    table is held to is the one that says so. No tag resolves under the
    first stub, which is what makes the window; the heading below the
    newest is the control, named under that same stub, so what the
    newest one answers is the window rather than the stub.

    What excuses that heading is the tag it has yet to name and not its
    position, and a permanent skip can sit on it: at `13941fd1` the
    newest released heading of `RELEASE_NOTES.md` is `v2026.8.9`, whose
    tag resolves while `git show v2026.8.9:RELEASE_NOTES.md` does not,
    the file having carried another name at that release. The second
    stub is that pair, and the newest heading is named under it.
    """

    def no_tag_yet(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        assert cmd[1] in {"rev-parse", "show"}
        return subprocess.CompletedProcess(cmd, 1)

    def tag_pushed(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        if cmd[1] == "rev-parse":
            return subprocess.CompletedProcess(cmd, 0)
        assert cmd[1] == "show"
        return subprocess.CompletedProcess(cmd, 1)

    released = list(_sections(_read("CHANGELOG.md")))
    entry = next(iter(_KNOWN_DRIFT.values()))
    window = ("CHANGELOG.md", released[0])
    older = ("CHANGELOG.md", released[1])

    monkeypatch.setattr(subprocess, "run", no_tag_yet)
    assert _exemptions_no_verdict_can_reach({window: entry}) == []
    assert _exemptions_no_verdict_can_reach({older: entry}) == [older]

    monkeypatch.setattr(subprocess, "run", tag_pushed)
    assert _exemptions_no_verdict_can_reach({window: entry}) == [window]


def test_a_comparable_exemption_is_picked_by_readability_not_position() -> None:
    """An entry neither test below can read is passed over wherever it sits.

    `RELEASE_NOTES.md`'s `v2020.4.7` heading is on disk, so
    `test_every_exemption_names_a_released_heading_on_disk` has nothing
    to say about it, and `git show
    v2020.4.7:RELEASE_NOTES.md` exits non-zero all the same, that
    release predating the file's current name. Planted first, it is what
    picking by position hands the two tests below.
    """
    comparable = _comparable_exemptions(_KNOWN_DRIFT)
    assert comparable, "no exemption whose section and its tag's can both be read"
    entry = comparable[0][1]

    unreadable = ("RELEASE_NOTES.md", "v2020.4.7")
    assert unreadable in _released_headings()
    assert _exemptions_naming_no_released_heading({unreadable: entry}) == []
    assert _comparable_exemptions({unreadable: entry, **_KNOWN_DRIFT}) == comparable


# ---- what `_verify`, `_verdict` and `_answer` answer where no
# released heading of this repository's own history reaches them


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


def test_a_line_planted_inside_an_exempt_section_fails() -> None:
    """An exemption reaches the text it pins and not the section.

    The union driver lands a rebased branch's entry at the anchor that
    branch wrote it at, which is anywhere inside a section a release has
    since sealed rather than where the exemption was registered. The
    unplanted section is the control: the same call passes on it, so
    what the planted call answers is the line and not the exemption.
    """
    comparable = _comparable_exemptions(_KNOWN_DRIFT)
    assert comparable, "no exemption whose section and its tag's can both be read"
    (path, version), drift, current, tagged = comparable[0]
    assert _verdict(path, version, current, tagged) is None

    lines = current.splitlines(keepends=True)
    middle = len(lines) // 2
    planted = "".join([*lines[:middle], "- a rebase put this here\n", *lines[middle:]])
    assert planted != current
    assert _verdict(path, version, planted, tagged) == (
        "fail",
        (
            f"{path}'s {version!r} section is neither its own {version}"
            f" tag's text nor what _KNOWN_DRIFT pins for it ({drift.reason});"
            f" a reviewed edit is what puts {_digest(planted)} in that entry"
        ),
    )


def test_an_exemption_for_a_section_matching_its_tag_fails() -> None:
    """An exemption cannot outlive the drift it names.

    A hand fix putting an exempt section back to its own tag leaves its
    entry pinning text nothing holds any more, and the entry is what
    goes.
    """
    comparable = _comparable_exemptions(_KNOWN_DRIFT)
    assert comparable, "no exemption whose section and its tag's can both be read"
    (path, version), drift, _, tagged = comparable[0]
    assert _verdict(path, version, tagged, tagged) == (
        "fail",
        (
            f"{path}'s {version!r} section matches its own {version} tag"
            f" again, so its _KNOWN_DRIFT entry exempts nothing: {drift.reason}"
        ),
    )


def test_a_section_no_entry_names_is_held_to_its_own_tag() -> None:
    """The comparison itself, on a heading no exemption names."""
    assert ("CHANGELOG.md", "v0.0.0") not in _KNOWN_DRIFT
    assert _verdict(
        "CHANGELOG.md", "v0.0.0", "## v0.0.0\n\ndrift\n", "## v0.0.0\n"
    ) == (
        "fail",
        "CHANGELOG.md's 'v0.0.0' section no longer matches its own v0.0.0 tag",
    )


def test_a_disagreement_is_a_failure_and_not_a_skip() -> None:
    """The outcome a section drifting past its entry is reported as.

    Every released heading of this repository's own history answers
    `None` or "skip", so the branch that carries a real disagreement to
    the report is driven from here.
    """
    with pytest.raises(pytest.fail.Exception, match="planted"):
        _answer(("fail", "a planted line"))
