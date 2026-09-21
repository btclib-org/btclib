# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Every citation a markdown file makes of this tree resolves.

A citation is what a reader follows to check a claim, so one resolving to
nothing sends whoever follows it looking for a file that is not there, or
for a section the file it reaches does not have. The path is one half and
the `#fragment` on it the other. A backticked span carrying a directory is
a path and is resolved as one; a link's own target is both halves, and each
of them is resolved.
The population is every tracked `*.md`, citing being what these files do
rather than a property of any one of them: `tests/_data/README.md` and
`CHANGELOG.md` name the module a verdict's values sit in, `CONTRIBUTING.md`
and `REVIEWING.md` the file a rule lives in, and `CLAUDE.md` the module a
layer is drawn at.

Whose a cited path is, the tree decides. A list of the paths other
projects own is a list to keep, and the day a vendored file arrives
without an entry the red lands on a correct citation. So a cited path
this tree does not have, whose file name it does have, under a directory
it does have, is one of this tree's own files cited where it is not, and
another project's path fails one half or the other. Dropping either half
reddens citations that are correct:

- without the directory half a path written relative to `src/` or to
  `src/btclib/` is left to a file name this tree does have, which is
  `CLAUDE.md`'s `curves/curve_group.py` and `RELEASE_NOTES.md`'s
  `btclib/b58.py`;
- without the file name half another project's tests are left to
  `tests/`, the directory everyone puts them in, which is `REVIEWING.md`'s
  `tests/verbatim_test.py` -- named in that sentence as the organization
  standard's own module -- and `tests/_data/README.md`'s spesmilo/electrum
  vector sources.

A citation broken across the eighty-column wrap is not read at all: the
character class stops at the newline, so `tests/` ending one line and
`descriptors_test.py` opening the next is no match, and the sweep's
silence about such a path is not a verdict on it. Folding the wrap away
before matching is not the repair, the two foldings being exactly
complementary: joining the halves with nothing does see a wrapped path,
and also fuses a *command* wrapped at a space, which `CHANGELOG.md`
carries -- `pytest` and `tests/ecc/dsa_test.py` on either side of a break
become one path -- while joining them with a space fuses neither and sees
neither, a path having no space to be broken at. What keeps that fused
path from reddening a correct citation today is the directory half alone,
this tree having no `pytesttests/ecc`, which is luck and not the rule
(issue #1969). The rule is blind by construction in one more way, and
that one is deliberate: a cited path whose file name this tree does not
have anywhere is another project's as far as this reads, whether or not
it is. A `./` in front of one of this tree's own files is blind the same
way and for the same reason -- `.` is a directory no `git ls-files` path
carries, so the directory half excuses `` `./SECURITY.md` ``, which
CONTRIBUTING.md cites -- and a rename would go unflagged in that
spelling.

Both halves accept a path another repository owns whose file name *and*
whose directory this tree also has, and which this tree does not itself
have -- that last is what `cited - tracked` asks first, so one of our own
paths cited as somebody else's is not this class. REVIEWING.md cites the
organization standard's `tests/verbatim_test.py` one file name short of
it: `tests` is a directory here, so the day this tree gains a
`verbatim_test.py` anywhere but at `tests/verbatim_test.py` itself, that
landed citation begins to read as one of ours cited where it is not.
Landing at that path instead makes it disappear from the sweep rather than
reddening it, `cited - tracked` being asked first -- silence, and not this
class. `_EXEMPT` is where such a path goes, keyed on the path with what
makes it somebody else's beside it. A released `## v<version>` section of
`CHANGELOG.md` is the other way in: `changelog_immutability_test.py`
compares it byte for byte against its own tag, so a path renamed after an
entry cited it cannot be corrected where it is cited, and the exemption is
the only place that decision can be written down.

A file stating the convention its own citations are written to can be
held to more than this, and this rule does not stand in for that:
`security_citations_test.py` reads each of `SECURITY.md`'s `path:line`
citations against the dotted name or the quotation written in front of
it, which is available to it because that file says which of the two a
citation carries and what each claims.

A link's own target is the other spelling, and its path is resolved against
`git ls-files` itself rather than through the file name and the directory a
backticked span is held to. A local target is written with a `./` or a `../`
in front of it, which `.pre-commit-config.yaml`'s `local-link-prefix` hook is
what keeps true, so it names a path of this tree and there is no other
project's path to tell it from; that prefix is also what tells a local
destination from a url and from a fragment standing alone. A backticked span
is taken out of the text before a target is read, run of backticks against
run of backticks, so that prose can quote the shape of a link rather than
write one: `CHANGELOG.md` illustrates a badge as `[![alt](./src)](./href)`,
and the same distinction is the lookbehind that hook carries; a run
of backticks left unpaired takes what follows it into the span, which is
the shape `_anchors` has where an opening fence marker is not told from a
closing one. `git ls-files` answers for files, so a target naming a
directory reads as unreachable, this tree linking to files. The
reference-definition form, `[label]: destination`, is a link this does not
read, and so is a target carrying a title: the pattern wants the `)` against
the path, so a title leaves no match rather than a shortened one.

A cited `#fragment` is resolved against the headings of the file the
citation reaches, and that is a different question from the path: a heading
moves on a schedule where a path moves when somebody moves a file. A
release renames the open cycle's heading to its own version, so
`CHANGELOG.md` and `RELEASE_NOTES.md` each carry one heading a release
takes away, where a released section's headings are held byte for byte
against its own tag by `changelog_immutability_test.py`.

The fragment is read off a link's own target and not off a backticked span,
a link being what a reader clicks where a backticked `path#anchor` is prose
about the shape of one: `CHANGELOG.md` writes `./page.md#anchor` for a link
planted in a documentation build and `href="#README.md#build"` for the
rendered HTML a grep of that build passes over. A target this tree does not
track is left alone, a file this tree does not have carrying no headings to
read, and that is what keeps an `https://` url out as well, no tracked path
being spelled with a scheme. A fragment written alone,
`](#code-scanning)` as REPOSITORY.md writes it, names a heading of the
citing file. A heading named in prose rather than in a link target is not
read at all, which is the shape issue #2052 was: CONTRIBUTING.md names
`v2026.8.7`'s breaking-changes list by version, and a version in backticks
is not mechanically a citation of a heading -- RELEASING.md writes
`v2026.7` to illustrate how `git tag` sorts, and no heading of either file
answers to that.

The documentation build answers the same question over part of the same
population. `docs/source/conf.py` sets `myst_heading_anchors`, and its
`RootFileLinks` hands the fragment to myst for the root files the
`*_link.md` shims include: a fragment myst cannot find there is a
`myst.xref_missing` warning, which the `-n -W` build fails on -- measured
by planting `./CONTRIBUTING.md#no-such-heading-at-all` in README.md. Every
other link it rewrites into a `BLOB` url with the fragment appended
verbatim, and REPOSITORY.md is no page of that build at all, so a fragment
naming a heading of a file the build does not render reaches no resolver
in it. Nor is myst's own slugifier what this reads: `myst-parser` is in
the `docs` group, which no workflow's own pytest step installs, so
importing it here would be a test that only reproduces where the
documentation is built (issue #1538).

The path half falls to that same resolver: `RootFileLinks` rewrites a target
that is a file of the tree and leaves one that is not to myst, whose warning
the `-n -W` build fails on -- measured by planting `./CONTRIBUTNG.md` in
README.md's link to CONTRIBUTING.md. It asks the filesystem where this asks
the index, and it reaches the rendered root files alone, so a link target
written in `REPOSITORY.md` or in `RELEASING.md` reaches no resolver in it.

What the slug does is lowercase the heading, drop every character that is
neither a word character nor a hyphen nor a space, and hyphenate the spaces,
which is how `## Plan-gated settings` answers to `plan-gated-settings` and how
a backticked span in a heading keeps its text while the backticks go. The
second and later heading sharing a slug takes GitHub's `-1`, `-2` suffix, which
is how a fragment naming one of `RELEASE_NOTES.md`'s repeated `### Breaking
changes` resolves. What is not implemented: whatever GitHub does with a
character outside that class -- an emoji, a footnote marker -- a heading
holding a markdown link, whose target GitHub drops and this keeps, and a
literal slug colliding with another heading's numbered one, which GitHub
numbers again and this does not. A heading of any of those shapes is what
widens this. A heading is read as ATX, `.markdownlint.jsonc`'s `MD003` being
what makes that the only spelling here, and a heading-shaped line inside a
fenced block is a comment rather than a heading, REPOSITORY.md's shell fences
being full of them: a line opening a fence toggles whether what follows it is
read, and an opening marker is not told from a closing one, so an odd number of
markers nested in a longer fence inverts that state for the rest of the file.
That skipping is the target's side only. On the citing side a fence is read
unevenly: a backticked citation inside one is still read, where a link inside
one is not, the span strip matching a fence's opening run of backticks against
its closing one and taking the block whole. The convention here is a backticked
span for an illustrative citation.

The module asks `git ls-files` which paths this repository has, so
`source-exclude` keeps it out of the sdist: a tree stripped to its tracked
files has no index to ask.

A test rather than a hook, for the reasons `docs_test.py` gives: no
environment the suite does not already have, every interpreter of the
matrix rather than one runner, and `tests-passed` gates it without a line
in any `needs` list.
"""

import posixpath
import re
import shutil
import subprocess
from collections import Counter
from collections.abc import Mapping
from pathlib import Path

_ROOT = Path(__file__).parents[1]

# resolved once, for the reason `declared_version_test.py`'s own `_GIT`
# is: a bare "git" in a subprocess list is a partial executable path
_GIT = shutil.which("git") or "git"

# a backticked span of path characters, with a directory in it and a
# suffix on the name. What the character class leaves out is what makes
# the span a citation rather than something shaped like one:
# `bitcoin/bitcoin#15437` is an issue, `api/tx/<txid>` an endpoint, and
# `tests/tx/_data/*.bin` a set of files rather than one, so none of the
# three is a path `git ls-files` could answer for
_CITED_PATH = re.compile(r"`([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.[A-Za-z0-9]+)`")

# a path both halves of the rule accept and this tree does not own, with
# what makes it somebody else's beside it. Empty, the tree having no such
# path: an entry here records a decision about one citation, where
# widening the rule to excuse it would excuse the next real defect with it
_EXEMPT: dict[str, str] = {}

# a link's own target, which is a path, a `#fragment` on one, or a
# fragment standing alone. It holds neither a bracket nor a space, a link
# target ending at the first of either
_LINK_TARGET = re.compile(r"]\(([^()\s]+)\)")

# a backticked span, closed by the run of backticks that opened it
_CODE_SPAN = re.compile(r"(`+).*?\1", re.DOTALL)

# an ATX heading, and the text a fragment is made of
_HEADING = re.compile(r"^#{1,6} +(.+?)\s*$")

# a fenced block's marker, in either spelling and at either end
_FENCE = re.compile(r"^ {0,3}(?:`{3,}|~{3,})")


def _cited_paths(text: str) -> set[str]:
    """Every path `text` cites in backticks."""
    return {match.group(1) for match in _CITED_PATH.finditer(text)}


def _link_targets(text: str) -> set[str]:
    """Every target a link of `text` is written with.

    A target quoted inside a backticked span is prose about the shape of a
    link, so the spans go before the targets are read.
    """
    return set(_LINK_TARGET.findall(_CODE_SPAN.sub("", text)))


def _slug(heading: str) -> str:
    """Return the fragment GitHub answers `heading` to."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(text: str) -> set[str]:
    """Every fragment the headings of `text` answer to."""
    anchors: set[str] = set()
    taken: Counter[str] = Counter()
    fenced = False
    for line in text.splitlines():
        if _FENCE.match(line):
            fenced = not fenced
        elif not fenced and (heading := _HEADING.match(line)):
            slug = _slug(heading.group(1))
            taken[slug] += 1
            repeat = taken[slug] - 1
            anchors.add(f"{slug}-{repeat}" if repeat else slug)
    return anchors


def _resolved(markdown: str, written: str) -> str:
    """Return the file a link of `markdown` written as `written` reaches.

    A link target is written from the directory of the file carrying it,
    and an empty one names that file itself.
    """
    if not written:
        return markdown
    directory = posixpath.dirname(markdown)
    return posixpath.normpath(posixpath.join(directory, written))


def _cited_fragments(markdown: str, text: str) -> set[tuple[str, str]]:
    """Every heading `text` cites, as the file holding it and the fragment."""
    return {
        (_resolved(markdown, written), fragment)
        for written, _, fragment in (
            target.partition("#") for target in _link_targets(text)
        )
        if fragment
    }


def _cited_files(markdown: str, text: str) -> set[str]:
    """Every file of this tree a link of `text` reaches.

    The `./` or `../` a local destination carries is what tells one from a
    url and from a fragment naming a heading of the citing file itself.
    """
    return {
        _resolved(markdown, written)
        for target in _link_targets(text)
        if (written := target.partition("#")[0]).startswith(("./", "../"))
    }


def _unreachable(texts: Mapping[str, str], tracked: set[str]) -> dict[str, list[str]]:
    """Return what each file of `texts` links to and this tree has not.

    Keyed on the citing file for the reason `_offenders` is: the link is
    corrected in the paragraph carrying it.
    """
    return {
        markdown: dead
        for markdown, text in texts.items()
        if (dead := sorted(_cited_files(markdown, text) - tracked))
    }


def _unresolved(texts: Mapping[str, str]) -> dict[str, list[str]]:
    """Return what each file of `texts` cites and its target does not have.

    Keyed on the citing file for the reason `_offenders` is: the link is
    corrected in the paragraph carrying it.
    """
    anchors = {markdown: _anchors(text) for markdown, text in texts.items()}
    return {
        markdown: unresolved
        for markdown, text in texts.items()
        if (
            unresolved := sorted(
                f"{target}#{fragment}"
                for target, fragment in _cited_fragments(markdown, text)
                if target in anchors and fragment not in anchors[target]
            )
        )
    }


def _tracked() -> set[str]:
    """Every path this repository tracks."""
    listed = subprocess.run(  # noqa: S603
        [_GIT, "ls-files"],
        cwd=_ROOT,
        capture_output=True,
        encoding="utf-8",
        check=False,
    )
    return set(listed.stdout.splitlines())


def _misresolved(
    cited: set[str], tracked: set[str], exempt: Mapping[str, str]
) -> list[str]:
    """Return the cited paths naming a file `tracked` holds elsewhere.

    Both halves of a path are read, and each answers one of the two ways
    another project's path reads like one of ours. A vendored file keeps
    the name upstream publishes it under, so upstream's own path for it
    carries our file name and only the directory tells the two apart; and
    another project's tests sit under `tests/` as ours do, so there only
    the name does.
    """
    names = {path.rsplit("/", 1)[-1] for path in tracked}
    directories = {path.rsplit("/", 1)[0] for path in tracked if "/" in path}
    return sorted(
        path
        for path in cited - tracked - set(exempt)
        if path.rsplit("/", 1)[-1] in names and path.rsplit("/", 1)[0] in directories
    )


def _offenders(
    texts: Mapping[str, str], tracked: set[str], exempt: Mapping[str, str]
) -> dict[str, list[str]]:
    """Return what each markdown file of `texts` cites of this tree elsewhere.

    Keyed on the file, a path being followed from the paragraph carrying
    it: the same wrong path in two files is two corrections.
    """
    return {
        markdown: misresolved
        for markdown, text in texts.items()
        if (misresolved := _misresolved(_cited_paths(text), tracked, exempt))
    }


def _markdown(tracked: set[str]) -> dict[str, str]:
    """Every tracked markdown file of this tree, keyed on its path."""
    return {
        path: (_ROOT / path).read_text(encoding="utf-8")
        for path in sorted(tracked)
        if path.endswith(".md")
    }


def test_every_path_a_markdown_file_cites_of_this_tree_is_one_this_tree_has() -> None:
    """A citation is what a reader follows to check a claim.

    A verdict is checked by opening the module holding the values, a rule
    by opening the file stating it, so a path resolving to nothing leaves
    the claim standing on nothing a reader can reach.
    """
    tracked = _tracked()
    texts = _markdown(tracked)
    # what a sweep answering zero has to be held to: `git ls-files` gives
    # an empty set where git is missing, and the pattern can stop matching
    # without anything else here changing
    assert "pyproject.toml" in tracked
    assert {path for text in texts.values() for path in _cited_paths(text)} & tracked

    offenders = _offenders(texts, tracked, _EXEMPT)
    assert not offenders, (
        "a markdown file cites a path this tree does not have, under a file"
        f" name and a directory it does have: {offenders!r}"
    )

    # an exemption outlives the citation it was written for, and a dead one
    # excuses nothing while reading as though it did. Set arithmetic rather
    # than a loop over `_EXEMPT`, which is empty: a loop body no run enters
    # is uncovered, and the floor is 100%
    unexempted = {
        path
        for text in texts.values()
        for path in _misresolved(_cited_paths(text), tracked, {})
    }
    stale = sorted(set(_EXEMPT) - unexempted)
    assert not stale, f"_EXEMPT names a path the rule would not flag: {stale}"


def test_a_citation_broken_across_the_wrap_is_not_read() -> None:
    """The limit above, executable rather than stated.

    A fold that made this answer with the path would also fuse the
    command `CHANGELOG.md` wraps at a space, so a change here is a
    decision about that trade and not a widening (issue #1969).
    """
    assert _cited_paths("the module is `tests/\ndescriptors_test.py`.") == set()
    assert _cited_paths("the module is `tests/descriptors_test.py`.") == {
        "tests/descriptors_test.py"
    }


def test_a_path_of_this_tree_is_told_from_a_path_of_another_project() -> None:
    """The sweep above passes for free if it cannot tell the two apart.

    One synthetic tracked set, and a citation for each arm the rule has:
    `tests/descriptors_test.py` is this tree's own module at a path this
    tree does not have and is caught; the same module at its own path is
    not; Core's `src/test/data/script_tests.json` carries the file name
    our vendored copy keeps and is left to its directory, which this tree
    does not have; and electrum's `tests/test_mnemonic.py` sits in a
    directory this tree does have and is left to its name.

    Two of those arms turn on `tests` being a directory the set has, so
    the set holds a file directly under it and says so before the sweep
    runs: without that the caught arm is excused for the wrong reason and
    the electrum arm proves nothing, neither of which an expectation of an
    empty list would show. The cited set is read back for the same reason,
    a pattern that stopped matching leaving nothing for the rule to
    disagree about.
    """
    tracked = {
        "tests/markdown_citations_test.py",
        "tests/descriptors/descriptors_test.py",
        "tests/script_engine/_data/script_tests.json",
    }
    assert "tests" in {path.rsplit("/", 1)[0] for path in tracked}
    cited = _cited_paths(
        "`tests/descriptors_test.py`, `tests/descriptors/descriptors_test.py`,"
        " Core's `src/test/data/script_tests.json` and electrum's"
        " `tests/test_mnemonic.py`."
    )
    assert cited == {
        "tests/descriptors_test.py",
        "tests/descriptors/descriptors_test.py",
        "src/test/data/script_tests.json",
        "tests/test_mnemonic.py",
    }

    assert _misresolved(cited, tracked, {}) == ["tests/descriptors_test.py"]


def test_an_exempt_path_is_excused_and_the_rule_is_left_as_it_is() -> None:
    """What the guard does with the path both halves accept.

    The tree carries no such path, so this is what says the exemption
    works on the day one arrives, and it is measured against the same
    citation unexempted rather than against an empty list, which an
    exemption that suppressed everything would also answer with.
    """
    tracked = {
        "tests/markdown_citations_test.py",
        "tests/descriptors/descriptors_test.py",
    }
    cited = {"tests/descriptors_test.py", "tests/script_engine/_data/script_tests.json"}

    assert _misresolved(cited, tracked, {}) == ["tests/descriptors_test.py"]
    assert _misresolved(cited, tracked, {"tests/descriptors_test.py": "why"}) == []


def test_a_misresolved_citation_is_reported_under_the_file_citing_it() -> None:
    """Which paragraph to correct is the file, not the path alone."""
    tracked = {
        "tests/markdown_citations_test.py",
        "tests/descriptors/descriptors_test.py",
    }
    texts = {
        "CONTRIBUTING.md": "the module is `tests/descriptors_test.py`.",
        "README.md": "the module is `tests/descriptors/descriptors_test.py`.",
    }

    assert _offenders(texts, tracked, {}) == {
        "CONTRIBUTING.md": ["tests/descriptors_test.py"]
    }


def test_every_file_a_markdown_link_reaches_is_one_this_tree_has() -> None:
    """A link is the citation form a reader clicks rather than retypes.

    The documentation build resolves the same target for the root files its
    shims render and fails an `-n -W` build on one naming no file; a link
    written in a file no page of that build renders reaches nothing else.
    """
    tracked = _tracked()
    texts = _markdown(tracked)
    # what a sweep answering zero has to be held to: the pattern can stop
    # matching, and `git ls-files` gives an empty set where git is missing
    assert {
        target
        for markdown, text in texts.items()
        for target in _cited_files(markdown, text)
    } & tracked

    unreachable = _unreachable(texts, tracked)
    assert not unreachable, (
        f"a markdown file links to a path this tree has not: {unreachable!r}"
    )


def test_a_link_target_is_resolved_against_the_paths_this_tree_tracks() -> None:
    """One text per citing file, and a citation for each arm the rule has.

    The target naming a file the tracked set has resolves and the one a typo
    takes off it is caught, each read past the fragment on it; a url and a
    fragment standing alone carry no `./`, so neither is a path to resolve;
    the badge quoted in a backticked span is prose about a link rather than
    one; and a `../` is resolved from the directory of the file writing it.
    """
    tracked = {"README.md", "CONTRIBUTING.md"}
    texts = {
        "README.md": (
            "[here](./CONTRIBUTING.md#a-heading), [gone](./CONTRIBUTNG.md#a-heading),"
            " [away](https://example.org/page.md), [own](#a-heading-here) and"
            " `[![alt](./src)](./href)`, which is the shape of a badge.\n"
        ),
        "docs/source/package-content-policy.md": "[up](../../README.md).",
    }

    assert _unreachable(texts, tracked) == {"README.md": ["CONTRIBUTNG.md"]}


def test_every_heading_a_markdown_file_cites_is_one_its_target_has() -> None:
    """A citation's heading goes stale on the release schedule.

    A release renames the open cycle's heading of `CHANGELOG.md` and of
    `RELEASE_NOTES.md`, so a citation naming that heading stops resolving
    with nothing in the file carrying the citation having changed.
    """
    texts = _markdown(_tracked())
    # what a sweep answering zero has to be held to: a fragment resolving
    # to a file of this tree is what the rule reads, and the pattern can
    # stop matching, or every resolution land outside `texts`, without
    # anything else here changing
    assert {
        target
        for markdown, text in texts.items()
        for target, _ in _cited_fragments(markdown, text)
        if target in texts
    }

    unresolved = _unresolved(texts)
    assert not unresolved, (
        f"a markdown file cites a heading its target has not: {unresolved!r}"
    )


def test_a_cited_heading_is_resolved_against_the_file_the_link_names() -> None:
    """One text, and a citation for each arm the rule has.

    The heading `REVIEWING.md` has resolves and the one it has not is
    caught; a fragment alone is resolved against the citing file; a target
    outside this tree has no headings to read, so the url is left alone;
    and the link quoted in a backticked span is prose about the shape of
    one, so the heading it names joins neither the verdict nor this tree.
    """
    texts = {
        "README.md": (
            "[here](./REVIEWING.md#the-gates-are-the-evidence) and"
            " [gone](./REVIEWING.md#the-gates), [own](#a-heading-of-its-own)"
            " and [away](https://example.org/page.md#anchor), which"
            " `[quoted](./REVIEWING.md#quoted-away)` does not join.\n"
            "\n"
            "## A heading of its own\n"
        ),
        "REVIEWING.md": "## The gates are the evidence\n",
    }

    assert _unresolved(texts) == {"README.md": ["REVIEWING.md#the-gates"]}


def test_a_repeated_heading_answers_to_the_numbered_fragment() -> None:
    """`RELEASE_NOTES.md` repeats `### Breaking changes` under releases.

    Measured against the fragment past the last such heading, which
    nothing answers to: an implementation numbering none of them would
    answer the bare fragment and fail the numbered one, and one numbering
    from the first heading rather than the second would answer the
    numbered fragments and fail the bare one.
    """
    texts = {
        "RELEASE_NOTES.md": (
            "[a](#breaking-changes), [b](#breaking-changes-1) and"
            " [c](#breaking-changes-2).\n"
            "\n"
            "### Breaking changes\n"
            "\n"
            "### Breaking changes\n"
        )
    }

    assert _unresolved(texts) == {
        "RELEASE_NOTES.md": ["RELEASE_NOTES.md#breaking-changes-2"]
    }


def test_a_heading_shaped_line_inside_a_fence_is_a_comment() -> None:
    """REPOSITORY.md's shell fences are full of them.

    Read as headings they would answer fragments no reader can follow, a
    comment being no place a link lands.
    """
    fenced = "```shell\n# grep -n x\n```\n\n## A heading\n"

    assert _anchors(fenced) == {"a-heading"}


def test_the_slug_keeps_a_word_character_a_hyphen_and_a_space() -> None:
    """What is dropped is everything else, backticks with it.

    `## Plan-gated settings` is the hyphen, and a backticked span in a
    heading is what keeps its text while the backticks go.
    """
    heading = "## `mult`, and Plan-gated (x)\n"

    assert _anchors(heading) == {"mult-and-plan-gated-x"}
