# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Refuse an open `CHANGELOG.md` section a `merge=union` rebase can break.

`.gitattributes` gives `CHANGELOG.md` `merge=union` so that two branches
appending an entry at the same anchor do not conflict; btclib-org/.github#21
prices what that costs and rules that the driver stays and a gate is
added, and btclib-org/.github#760 is the second way the driver pays for
it. This is that gate, run once over the file's own open section -- the
first `## ` heading's, up to the line before the second, or to the end
of the file where there is no second, section 9 of README.md giving the
boundary the same way.

Three checks, all of them shapes a `merge=union` rebase produces and a
`git rebase` exit code does not report:

- a `### ` heading repeated within the section -- measured against real
  rebases under `merge=union`, not assumed from the driver's name. Two
  branches each adding their *own* new heading, worded exactly alike,
  at the section's one shared anchor is *not* this shape: union folds
  the two into a single entry, one heading and both sides' bullets,
  with nothing for this check to find -- which is not a fix landing
  quietly, it is the shape the next check's own blind spot leans on.
  A heading repeats instead where the matching text does not end up
  adjacent once the merge is done -- one side's own further entry
  landing between the two closes the gap that would otherwise let them
  fold -- or where a single branch's new heading, no second branch or
  merge required, repeats one already in the section at its own base.
  `markdownlint-cli2` already refuses a same-level heading repeated
  anywhere in the file as MD024, `.markdownlint.jsonc` leaving that
  rule at its own default rather than the `siblings_only`
  bitcoin-core-rpc's, btclib's and btclib-secp256k1's `CHANGELOG.md`
  each set for their own, deliberate, per-release repeat; unlike MD022
  below, MD024 is not autofixable, so a run this check would also catch
  already fails on it. What this check adds is the line number scoped
  to the open section and a message naming `merge=union` rather than
  markdownlint's own generic one;
- two entries in the section that each `(closes #N)` the same number --
  btclib-org/btclib#1168 and btclib-org/btclib#1170 is the pair
  btclib-org/.github#21 opens with, each entry closing the same defect
  under a number of its own. Scoped to `closes` and not `issue`: an
  issue this tree's own section 9 lets a branch advance without closing
  is cited `(issue #N)` by design, and a long-lived issue this
  repository never rotates out of its one open section is cited that
  way by several unrelated entries over as many weeks -- measured
  against this file's own history, which carries that repeat with
  nothing wrong in it. Closing the same issue twice has no such reading:
  `closes` names the entry that
  answers an issue for good, and an issue answered twice is what the
  driver produces when two branches each believe they are first. A
  cross-repository citation, `(closes owner/repo#N)`, compares against
  another written exactly the same rather than against the number
  alone, since two different trackers numbering their own issues alike
  name two different issues;
- a `### ` heading with no blank line above it, which is the byte
  `merge=union` eats at the seam where two sides' added lines abut
  (btclib-org/.github#760). `markdownlint-cli2` already reports this as
  MD022, but only as an autofix note -- "files were modified by this
  hook" is what a developer's terminal shows, the same sentence it
  prints for a stray trailing space, naming neither `merge=union` nor
  the rebase that ate the line. This check is the one thing in the
  gate that knows the difference and says so.

**What this cannot see.** Two entries citing *different* issue numbers
that are themselves duplicates of one another -- which is the actual
shape of #1168/#1170, one of the pair having been filed against an
issue the other already covered -- needs each number resolved and
compared through the tracker's own state, `closingIssuesReferences` or
an issue's `NOT_PLANNED` closure. That is one API call per citation, and
a `pre-commit` hook that reaches the network is the wrong place to put
one; btclib-org/.github#21's own ruling says so. Nor does this compare a
section against its branch's own base to catch a misplacement or a
revived, previously-refuted paragraph -- reconstruction against the
base is a discipline for the rebase itself
(CONTRIBUTING.md's *Committing and rebasing*), not a property of the
file its tip leaves behind, which is all a `pre-commit` hook ever reads.
Nor, for the reason the second check gives, does it see two entries that
merely *advance* the same issue without either closing it -- a tree that
never releases lives with that shape by design, and refusing it would
refuse the very entries section 9's *A live claim* asks for.

Three more gaps, none of them the network one above, and none named
until this file's own review found them:

- the fold the first check leaves alone -- two branches' own
  identically-worded new headings, described above, united by the
  driver into one entry -- is exactly what hides a real double-close
  from the second check too. A citation repeated across one entry's own
  bullets is not reported by design, and a folded entry reads the same
  way: two different branches each closing the same issue under the one
  heading their merge united is indistinguishable, to this script, from
  one author citing an issue twice in one entry;
- a section with no `### ` heading at all -- portanode's open section
  is one, prose bullets straight under the release heading with nothing
  this file's `_ENTRY_HEADING` matches -- leaves every check here
  vacuous rather than failing: nothing to repeat, nothing to split into
  entries, nothing to find a blank line above;
- two bullets from different entries that a rebase's seam leaves
  touching, with no blank line between them and no heading in sight.
  Valid CommonMark reads them as one list either way, so neither
  `markdownlint-cli2`'s MD022/MD032 nor this file's third check, both
  keyed on a heading's own blank line, has a line to object to.

A tree with no release carries one open section for the whole file, this
repository's own `CHANGELOG.md` among them; a tree that releases keeps
everything from the first `## ` heading to the line before the second as
open, and does not ask this script about anything a release has already
closed over.

    python3 .github/scripts/check_changelog.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_CHANGELOG = _ROOT / "CHANGELOG.md"

_RELEASE_HEADING = re.compile(r"^## .*$", re.MULTILINE)
_ENTRY_HEADING = re.compile(r"^### (?P<title>.*)$", re.MULTILINE)
# a parenthetical naming an issue is not always spelled the same way
# twice in one entry -- "closes #593, issue #571", "issues #327, #339
# and #342" -- so this reads the whole group once either keyword is
# found in it, and two more patterns read the keywords and the tokens
# out of that group separately, a token taking whichever keyword sits
# nearest before it rather than the group's first
_CITATION_GROUP = re.compile(
    r"\((?P<body>[^()]*?\b(?:closes?|issues?)\b[^()]*?)\)",
    re.IGNORECASE | re.DOTALL,
)
_KEYWORD = re.compile(r"\b(closes?|issues?)\b", re.IGNORECASE)
_CITATION_TOKEN = re.compile(r"(?:[\w.-]+/[\w.-]+)?#\d+")
# a code span quotes a citation's own shape as an example of prose --
# this file explains the standard's citation rules -- rather than citing
# anything itself; stripped before either pattern above ever sees it.
# Single backticks, not crossing a blank line: this house style's own
# code spans do not
_CODE_SPAN = re.compile(r"`[^`\n]*`")

_BLANK_LINE = "\n\n"
"""Two newlines: the empty line above a heading, read as a literal pair."""


def open_section(text: str) -> tuple[str, int]:
    """Return the file's open section, and the offset it starts at.

    :param text: the whole file.
    :returns: the text from the first `## ` heading's line to the line
        before the second, or to the end where there is no second; and
        the offset into `text` that text begins at.
    """
    headings = list(_RELEASE_HEADING.finditer(text))
    if not headings:
        return text, 0
    start = headings[0].end()
    end = headings[1].start() if len(headings) > 1 else len(text)
    return text[start:end], start


def line_at(text: str, offset: int) -> int:
    """Return the 1-based line of `text` that `offset` falls on.

    :param text: the whole file the offset is into.
    :param offset: a character offset into `text`.
    :returns: the line number.
    """
    return text.count("\n", 0, offset) + 1


def closing_tokens(body: str) -> set[str]:
    """Return every issue token a `closes`/`closed` citation names.

    Scoped to that keyword and not to `issue`: section 9 of README.md
    lets a branch advance an issue under `(issue #N)` without closing
    it, so the same number recurs wherever a long-lived issue this
    tree's own open section never rotates out of is answered across
    several entries over as many weeks -- normal, by that section's own
    *A live claim* rule, and not what this asks about. A token takes
    whichever keyword sits nearest before it in its own parenthetical,
    so `(closes #593, issue #571)` reads only the first as closed. A
    code span is stripped first, so an entry quoting a citation's shape
    as an example -- this file explains what one looks like -- is not
    read as making one of its own.

    :param body: the text to search -- an entry's heading and body both.
    :returns: each closed token, as written: `#N` or `owner/repo#N`.
    """
    body = _CODE_SPAN.sub("", body)
    tokens: set[str] = set()
    for group in _CITATION_GROUP.finditer(body):
        text = group.group("body")
        keywords = list(_KEYWORD.finditer(text))
        for token in _CITATION_TOKEN.finditer(text):
            before = [k for k in keywords if k.start() < token.start()]
            if before and before[-1].group(1).lower().startswith("close"):
                tokens.add(token.group(0))
    return tokens


def entries(section: str) -> list[tuple[str | None, str, int]]:
    """Split the open section into its entries.

    A `### ` heading names one entry, section 9 of README.md's own rule,
    so a heading and everything under it -- up to the next heading or
    the section's end -- is one entry. Content above the first heading
    is a tree whose convention has no `### `, or an open section that
    has not taken its first entry yet; it is read as a single entry
    with no title, there being nothing in a heading-less section to say
    where one such entry ends and the next begins.

    :param section: the open section's own text.
    :returns: each entry's heading text (`None` where it has none), its
        own span -- heading line included, where it has one -- and the
        offset that span starts at within `section`.
    """
    headings = list(_ENTRY_HEADING.finditer(section))
    out: list[tuple[str | None, str, int]] = []
    preamble_end = headings[0].start() if headings else len(section)
    preamble = section[:preamble_end]
    if preamble.strip():
        out.append((None, preamble, 0))
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(section)
        out.append(
            (
                heading.group("title").strip(),
                section[heading.start() : end],
                heading.start(),
            ),
        )
    return out


def repeated_headings(text: str, section: str, base: int) -> list[str]:
    """Report a `### ` heading that repeats one already seen.

    :param text: the whole file, for the line numbers reported.
    :param section: the open section's own text.
    :param base: the offset `section` starts at within `text`.
    :returns: one message per repeat.
    """
    seen: dict[str, int] = {}
    problems = []
    for heading in _ENTRY_HEADING.finditer(section):
        title = heading.group("title").strip()
        line = line_at(text, base + heading.start())
        if title in seen:
            problems.append(
                f"line {line}: heading {title!r} repeats the heading at"
                f" line {seen[title]}",
            )
        else:
            seen[title] = line
    return problems


def duplicate_closes(text: str, section: str, base: int) -> list[str]:
    """Report two entries of the open section closing the same issue.

    A citation repeated across the bullets of *one* entry is not
    reported: section 9 of README.md lets a list body make several
    related claims about the issue its heading answers, each bullet
    citing it again. What this asks is whether two different entries --
    two different `### ` headings, or the one heading-less entry
    against a headed one -- each `(closes #N)` the same issue, which
    `merge=union` keeping both sides of an append is what produces.

    :param text: the whole file, for the line numbers reported.
    :param section: the open section's own text.
    :param base: the offset `section` starts at within `text`.
    :returns: one message per repeat.
    """
    first_seen: dict[str, tuple[str, int]] = {}
    problems = []
    for title, body, offset in entries(section):
        line = line_at(text, base + offset)
        label = f"heading {title!r}" if title is not None else "the heading-less entry"
        for token in sorted(closing_tokens(body)):
            if token in first_seen:
                other_label, other_line = first_seen[token]
                problems.append(
                    f"line {line}: {label} closes {token}, already closed by"
                    f" {other_label} at line {other_line}",
                )
            else:
                first_seen[token] = (label, line)
    return problems


def unblanked_headings(text: str, section: str, base: int) -> list[str]:
    """Report a `### ` heading with no blank line directly above it.

    :param text: the whole file, for the line numbers reported.
    :param section: the open section's own text.
    :param base: the offset `section` starts at within `text`.
    :returns: one message per heading found glued to the line above it.
    """
    problems = []
    for heading in _ENTRY_HEADING.finditer(section):
        pos = heading.start()
        above = section[max(pos - len(_BLANK_LINE), 0) : pos]
        if above != _BLANK_LINE:
            line = line_at(text, base + pos)
            title = heading.group("title").strip()
            problems.append(
                f"line {line}: heading {title!r} has no blank line above"
                " it -- the seam a merge=union rebase eats",
            )
    return problems


def problems(text: str) -> list[str]:
    """Return every way the open section fails the three checks.

    :param text: the whole file.
    :returns: one message per finding, in the order the checks run.
    """
    section, base = open_section(text)
    return [
        *repeated_headings(text, section, base),
        *duplicate_closes(text, section, base),
        *unblanked_headings(text, section, base),
    ]


def main() -> int:
    """Report every problem the open section of `CHANGELOG.md` has.

    :returns: 1 where a problem was found, 0 where the section is clean.
    """
    found = problems(_CHANGELOG.read_text(encoding="utf-8"))
    for problem in found:
        print(f"{_CHANGELOG}: {problem}")
    if not found:
        print(
            f"{_CHANGELOG}: the open section repeats no heading, no two"
            " entries close the same issue, and no heading has lost its"
            " blank line.",
        )
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
