# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""Re-check a pin ledger against upstream, weekly.

A ledger pins each entry to a repository, a path and a commit, and
carries a documented manual procedure to re-check one pin. This
automates that procedure and reports drift, rather than fixing it: what
to do about a pin that has moved is a decision this script does not get
to make, so what it opens is an issue, never a commit.

The ledger and the issue title are both the caller's, because the
ledgers this repository passes go stale in different ways and are acted
on differently: tests/_data/README.md pins the revision a file here was
copied from, so a moved commit says the copy is behind, and TF2.md pins
the revision a verdict was read at, so a moved commit says the verdict
is a claim about a file that has moved. One title over both would name
one issue for the pair, each run rewriting what the other wrote.

btclib-secp256k1 carries a copy under this same name, over its own
tests/README.md, whose entries are each pinned to a commit under a
heading owning one fenced block. What the two copies share is owed to
the other in the same campaign: the parsing, the `gh` calls, a field's
spelling, the arguments this takes. What answers to one ledger's own
shape is not, and the collapsing of identical skip lines below is
that -- a heading owning several blocks being a shape that README does
not carry.

Scope is narrower than the ledger: only entries whose `behind` already
reads 0 -- the ones a human last confirmed were exactly at upstream's
tip. An entry documented as behind is a decision already made, and
re-reporting the same gap every week would just be noise; if a *new*
commit moves it further, `behind`'s own count in the ledger goes stale
in a way this script cannot see either, which is the reason it never
tries to judge relevance, only tip-vs-pinned identity.

A path upstream has renamed or deleted is reported rather than raising:
it has no commit to name as a tip, and a pin standing on a file that is
not there any more is the one drift nobody would otherwise notice.

Shapes a ledger can carry that this script does not attempt: an entry
with no `commit` at all (chain data self-identified by hash, files
this project composed itself), a path carrying a `<name>` placeholder
-- one pin standing in for several real paths under a directory, which
the "commits touching a path" call above cannot be asked about in one
request; a heading with no fenced block under it at all, which is
either a group heading the pins below it supersede or a pin whose
block an edit broke; a block carrying no `behind` line at all, which
is neither a documented gap nor a tip a human confirmed and is named
on its own rather than folded into either; and a `behind` line
present but empty, closer to that same broken block than to a
decision anybody made, and named apart from both.

No current entry uses the placeholder shape: BIP327's eight files and
BIP324's two were themselves written that way once, each pin citing
one commit as the tip of every path it stood in for. Splitting them
into one pin per real path is what brought them into this script's
scope, and also corrected BIP327's, whose shared commit was the tip of
only one of the eight. `tests/_data/descriptor_checksums.json` carries
no `behind` line: it pins the document revision its checksums were
checked against, not a copy this repository re-derives. Every heading
the ledger carries but this script did not check is listed in its own
report, so nothing silently reads as "checked and clean" that was not
checked at all.

    python .github/scripts/check_vendored_vectors.py \
        tests/_data/README.md "Vendored vectors behind upstream"
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

# resolved once: S607 is what a bare "gh" in a subprocess list would be,
# a partial executable path relying on PATH's own search order rather
# than naming what actually runs
_GH = shutil.which("gh") or "gh"

# a ledger entry's own ### heading, so a drift report -- and the
# skipped-entry list -- can name the entry rather than only its upstream
# path
_HEADING = re.compile(r"^### (.+)$", re.MULTILINE)

# a fenced block's key/value lines; a value's own continuation onto a
# further, unindented-marker line (BIP327's "behind" wraps) is not
# captured, and is not needed -- every check below reads only the first
# line of a field
_FIELD = re.compile(r"^(repo|path|commit|blob|pulled|behind)\s+(.*)$", re.MULTILINE)


@dataclass(frozen=True)
class Entry:
    """One pin this script can re-check: a single blob, a live commit."""

    heading: str
    repo: str
    path: str
    commit: str


@dataclass(frozen=True)
class Drift:
    """A pin whose commit is no longer the tip of its own path."""

    entry: Entry
    latest_commit: str
    latest_date: str

    @property
    def path_is_gone(self) -> bool:
        """True where upstream has no commit touching the pinned path.

        The empty `latest_commit` is what says so: there is no tip to
        name, `_latest_commit` having answered None. Reading it through
        a name keeps that encoding in one place.
        """
        return not self.latest_commit


def _entries_at_tip(ledger: str) -> tuple[list[Entry], list[str]]:
    """Return the checkable entries, and the headings this skips.

    A heading is skippable for several reasons: no fenced block of its
    own, no repo/path/commit triple, a path carrying a `<name>`
    placeholder, a `behind` already other than 0 -- a gap a human
    already decided not to close -- no `behind` line at all, which is
    distinct from that gap and is named as its own reason rather than
    folded into it, or a `behind` line present but empty, closer to a
    broken block than to either decision and named apart from both.

    The first is the one the loop below cannot see, walking blocks as it
    does: a heading owning none never enters it. A group heading a finer
    one supersedes has that shape, and so does a pin whose block an edit
    broke -- a fence indented into the prose, a `text` marker cut to a
    bare one. Telling those two apart is not this script's to do; naming
    the heading is.

    One heading contributes one line per reason rather than one per
    block: blocks skipped for the same reason under one heading repeat a
    line carrying nothing to tell them apart, so a reader gets the same
    sentence several times where one line carries all of it.
    """
    entries: list[Entry] = []
    skipped: list[str] = []
    owned: set[str] = set()
    heading = ""
    pos = 0
    for match in re.finditer(r"```text\n(.*?)\n```", ledger, re.DOTALL):
        headings_before = _HEADING.findall(ledger[pos : match.start()])
        if headings_before:
            heading = headings_before[-1]
        pos = match.end()
        owned.add(heading)

        fields = dict(_FIELD.findall(match.group(1)))
        repo, path, commit = (
            fields.get("repo"),
            fields.get("path"),
            fields.get("commit"),
        )
        if not (repo and path and commit):
            skipped.append(f"{heading} (no commit to check against)")
            continue
        if "<" in path:
            skipped.append(f"{heading} (one pin serves several files)")
            continue
        behind = fields.get("behind")
        if behind is None:
            skipped.append(f"{heading} (no behind line at all)")
            continue
        if not behind.strip():
            skipped.append(f"{heading} (behind line present but empty)")
            continue
        if not behind.startswith("0"):
            skipped.append(f"{heading} (already documented as behind)")
            continue
        entries.append(Entry(heading, repo, path.strip(), commit.split()[0]))
    skipped.extend(
        f"{unowned} (no fenced block)"
        for unowned in _HEADING.findall(ledger)
        if unowned not in owned
    )
    # dict.fromkeys keeps the first of each identical line, in the
    # order the walk and the pass after it appended them
    return entries, list(dict.fromkeys(skipped))


def _latest_commit(repo: str, path: str) -> tuple[str, str] | None:
    """Return the sha and date of the most recent commit touching path.

    None where upstream has no commit touching it at all, which means the
    path has been renamed or deleted: the sharpest drift there is, a pin
    naming a file that is not there any more. Answering None rather than
    unpacking one commit out of an empty list is what lets `report` see
    it as drift with no tip to name, instead of the run going red on a
    bare `ValueError` and no issue ever opening -- the one kind of drift
    nobody would otherwise notice, which is what this workflow exists
    for.
    """
    result = subprocess.run(  # noqa: S603
        [
            _GH,
            "api",
            "--method",
            "GET",
            f"repos/{repo}/commits",
            "-f",
            f"path={path}",
            "-f",
            "per_page=1",
        ],
        capture_output=True,
        check=True,
        encoding="utf-8",
    )
    commits = json.loads(result.stdout)
    if not commits:
        return None
    commit = commits[0]
    date: str = commit["commit"]["committer"]["date"][:10]
    sha: str = commit["sha"]
    return sha, date


def find_drift(ledger_path: Path) -> tuple[list[Drift], list[str]]:
    """Return every pin no longer at upstream's tip, and what was skipped."""
    entries, skipped = _entries_at_tip(ledger_path.read_text(encoding="utf-8"))
    drifted = []
    for entry in entries:
        latest = _latest_commit(entry.repo, entry.path)
        if latest is None:
            # a path upstream no longer has: drift with no tip to name
            drifted.append(Drift(entry, "", ""))
        elif latest[0] != entry.commit:
            drifted.append(Drift(entry, *latest))
    return drifted, skipped


def _issue_body(ledger_path: Path, drifted: list[Drift], skipped: list[str]) -> str:
    lines = [
        f"`{ledger_path}` pins below are no longer at upstream's tip.",
        "Refreshing is a decision, not a chore -- this issue only reports it.",
        "",
    ]
    for drift in drifted:
        if drift.path_is_gone:
            lines.append(
                f"- **{drift.entry.heading}**: pinned to"
                f" `{drift.entry.commit[:12]}`, and `{drift.entry.repo}` has no"
                f" commit touching `{drift.entry.path}` any more -- renamed,"
                " moved or deleted upstream"
            )
            continue
        lines.append(
            f"- **{drift.entry.heading}**: pinned to `{drift.entry.commit[:12]}`,"
            f" upstream's tip of `{drift.entry.path}` is now"
            f" `{drift.latest_commit[:12]}` ({drift.latest_date}),"
            f" `{drift.entry.repo}`"
        )
    if skipped:
        lines.extend(("", "Not checked by this run, for the reason named:"))
        lines.extend(f"- {heading}" for heading in skipped)
    return "\n".join(lines)


def _open_issue_number(title: str) -> str | None:
    result = subprocess.run(  # noqa: S603
        [
            _GH,
            "issue",
            "list",
            "--state",
            "open",
            "--search",
            f'"{title}" in:title',
            "--json",
            "number",
        ],
        capture_output=True,
        check=True,
        encoding="utf-8",
    )
    issues = json.loads(result.stdout)
    return str(issues[0]["number"]) if issues else None


def report(
    ledger_path: Path, title: str, drifted: list[Drift], skipped: list[str]
) -> None:
    """Open, update, or close this ledger's tracking issue, whichever applies.

    The title is what tells one ledger's issue from another's: it is the
    search term that finds an issue already open as well as the title a
    new one is created under, so a caller passing a title of its own
    gets an issue of its own.
    """
    number = _open_issue_number(title)
    if not drifted:
        if number is not None:
            subprocess.run(  # noqa: S603
                [
                    _GH,
                    "issue",
                    "close",
                    number,
                    "--comment",
                    "Re-checked: every pin with behind: 0 is still at upstream's tip.",
                ],
                check=True,
            )
        return
    body = _issue_body(ledger_path, drifted, skipped)
    if number is None:
        subprocess.run(  # noqa: S603
            [_GH, "issue", "create", "--title", title, "--body", body],
            check=True,
        )
    else:
        subprocess.run(  # noqa: S603
            [_GH, "issue", "edit", number, "--body", body], check=True
        )


def main() -> int:
    """Check the ledger named on argv, report drift, and say so on stdout.

    The title names the issue this run opens, updates or closes. It is
    required, which is what makes it a positional beside the path: a
    default would file one ledger's drift onto whichever issue the
    default happened to name. The one option here is a boolean, so what
    reads it is the filter below rather than a parser.

    --dry-run skips opening, updating or closing the issue: what the
    pull_request trigger of vendored-vectors.yml passes, so a change to
    this script or to a ledger is exercised without the run editing
    whatever tracking issue happens to be open at the time.
    """
    args = [a for a in sys.argv[1:] if a != "--dry-run"]
    dry_run = len(args) != len(sys.argv) - 1
    if len(args) != 2:
        # a human running this by hand is the only way here, the workflow
        # passing both every time: without this check, the indexing below
        # would answer with an IndexError naming a list instead
        print(
            f"usage: {Path(sys.argv[0]).name} <ledger path> <issue title> [--dry-run]",
            file=sys.stderr,
        )
        return 2
    ledger_path, title = Path(args[0]), args[1]
    drifted, skipped = find_drift(ledger_path)
    for drift in drifted:
        if drift.path_is_gone:
            print(
                f"GONE: {drift.entry.heading} pinned to"
                f" {drift.entry.commit[:12]}, and {drift.entry.repo} has no"
                f" commit touching {drift.entry.path} any more"
            )
            continue
        print(
            f"BEHIND: {drift.entry.heading} pinned to {drift.entry.commit[:12]},"
            f" tip is {drift.latest_commit[:12]} ({drift.latest_date})"
        )
    for heading in skipped:
        print(f"SKIPPED: {heading}")
    if not drifted:
        print("Every checked pin is still at upstream's tip.")
    if not dry_run:
        report(ledger_path, title, drifted, skipped)
    return 0


if __name__ == "__main__":
    sys.exit(main())
