# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""Re-check a pin ledger against upstream, weekly.

A ledger pins each entry to a repository, a path and a commit, and
carries a documented manual procedure to re-check one pin. This
automates that procedure and reports drift, rather than fixing it: what
to do about a pin that has moved is a decision this script does not get
to make, so what it opens is an issue, never a commit.

The ledger and the issue title are both the caller's, because a ledger
goes stale in its own way and is acted on in its own way:
tests/_data/README.md pins the revision a file here was copied from, so
a moved commit says the copy is behind. A caller passing two ledgers
under one title would open one issue for the pair, each run rewriting
what the other wrote.

btclib-secp256k1 carries a copy under this same name, over its own
tests/README.md, whose entries are each pinned to a commit under a
heading owning one fenced block, and bitcoin-node-tests another, over
its TF2.md. What the copies share is owed to the others in the same
campaign: the parsing, the `gh` calls, a field's spelling, the
arguments this takes. What answers to one ledger's own shape is not,
and the collapsing of identical skip lines below is that -- a heading
owning several blocks being a shape that README does not carry.

Scope is narrower than the ledger: only entries whose `behind` already
reads 0 -- the ones a human last confirmed were exactly at upstream's
tip. An entry documented as behind is a decision already made, and
re-reporting the same gap every week would just be noise; if a *new*
commit moves it further, `behind`'s own count in the ledger goes stale
in a way this script cannot see either, which is the reason it never
tries to judge relevance, only tip-vs-pinned identity.

A path upstream deleted or renamed away reaches this script as ordinary
drift: the "commits touching a path" call answers with the commit that
removed it, which is not the pin. Whether a commit changed the file or
removed it is a reading of that commit this script does not make, so
its report says the latest commit may have done either. The call
answers an empty list only for a path the branch it walks never held,
and that is reported rather than raising, with no tip to name.

An entry pinned to a fork's own pull-request branch rather than to a
repository's default one names that branch in a `ref` field, which
`_latest_commit` passes on as the "commits touching a path" call's own
`sha` parameter -- GitHub's name for it, a branch or a tag as much as a
commit despite the name. Without it the call resolves against the
default branch alone and answers an empty list for a path that lives
only on the named one, which is reported as a path the default branch
never held regardless of whether the pin is current (ISS 2160). A `ref`
line is what lets such a pin be checked at its own branch's tip rather
than carried as `behind` for want of one.

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
only one of the eight. Every heading
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

# a fenced block's key/value lines; a value's own continuation onto a further,
# unindented-marker line (BIP327's "behind" wraps) is not captured, and is not
# needed -- every check below reads only the first line of a field. The
# separator is `[ \t]+` rather than `\s+`: `\s` also matches the newline ending
# a bare key's own line, so a key written with no value and no trailing
# whitespace, and not last in its block, would let the separator cross into the
# following line and capture that whole line as its own value -- leaving the
# field the next line actually names unmatched. Confining the separator to the
# line answers a bare key with no match at all, which is what the checks below
# already treat as that field being absent.
_FIELD = re.compile(
    r"^(repo|path|ref|commit|blob|pulled|behind)[ \t]+(.*)$", re.MULTILINE
)


@dataclass(frozen=True)
class Entry:
    """One pin this script can re-check: a single blob, a live commit.

    `ref` is the branch (or tag, or sha) GitHub's "commits touching a
    path" API should walk instead of the repository's own default
    branch -- absent for every pin standing on a default branch, which
    is most of them, and present for one standing on a fork's own
    pull-request branch, which the API cannot otherwise find at all
    (ISS 2160): asking it with no `ref` answers an empty list for that
    path regardless of whether the pin is current, which is reported as
    a path the default branch never held.
    """

    heading: str
    repo: str
    path: str
    commit: str
    ref: str | None = None


@dataclass(frozen=True)
class Drift:
    """A pin whose commit is no longer the tip of its own path."""

    entry: Entry
    latest_commit: str
    latest_date: str

    @property
    def has_no_tip(self) -> bool:
        """True where no commit on the branch walked touches the pinned path.

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
        ref = fields.get("ref")
        entries.append(
            Entry(
                heading,
                repo,
                path.strip(),
                commit.split()[0],
                ref.strip() if ref else None,
            )
        )
    skipped.extend(
        f"{unowned} (no fenced block)"
        for unowned in _HEADING.findall(ledger)
        if unowned not in owned
    )
    # dict.fromkeys keeps the first of each identical line, in the
    # order the walk and the pass after it appended them
    return entries, list(dict.fromkeys(skipped))


def _latest_commit(
    repo: str, path: str, ref: str | None = None
) -> tuple[str, str] | None:
    """Return the sha and date of the most recent commit touching path.

    None where no commit on the branch walked touches the path at all,
    which is a path that branch never held: one deleted or renamed away
    answers with the commit that removed it instead, and comes back
    from here as an ordinary tip. Answering None rather than unpacking
    one commit out of an empty list is what lets `report` name the pin
    as drift with no tip, instead of the run going red on a bare
    `ValueError` and no issue ever opening.

    `ref` is GitHub's own `sha` parameter on this endpoint -- a branch,
    a tag or a commit to start walking history from, despite the name --
    left off where an `Entry` carries none, which is every pin standing
    on its repository's default branch: the parameter's own default
    matches it without this function naming the branch.
    """
    args = [
        _GH,
        "api",
        "--method",
        "GET",
        f"repos/{repo}/commits",
        "-f",
        f"path={path}",
        "-f",
        "per_page=1",
    ]
    if ref is not None:
        args.extend(("-f", f"sha={ref}"))
    result = subprocess.run(  # noqa: S603
        args,
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
        latest = _latest_commit(entry.repo, entry.path, entry.ref)
        if latest is None:
            # a path the branch walked never held: drift with no tip to name
            drifted.append(Drift(entry, "", ""))
        elif latest[0] != entry.commit:
            drifted.append(Drift(entry, *latest))
    return drifted, skipped


def _branch(entry: Entry) -> str:
    """Name the branch, tag or commit `_latest_commit` walked for an entry."""
    return f"`{entry.ref}`" if entry.ref else "the default branch"


def _issue_body(ledger_path: Path, drifted: list[Drift], skipped: list[str]) -> str:
    lines = [
        f"`{ledger_path}` pins below are no longer at upstream's tip.",
        "Refreshing is a decision, not a chore -- this issue only reports it.",
        "",
    ]
    for drift in drifted:
        if drift.has_no_tip:
            lines.append(
                f"- **{drift.entry.heading}**: pinned to"
                f" `{drift.entry.commit}`, and no commit on {_branch(drift.entry)}"
                f" of `{drift.entry.repo}` touches `{drift.entry.path}` --"
                " a path that branch never held"
            )
            continue
        lines.append(
            f"- **{drift.entry.heading}**: pinned to `{drift.entry.commit}`,"
            f" the latest commit touching `{drift.entry.path}` is now"
            f" `{drift.latest_commit}` ({drift.latest_date}),"
            f" `{drift.entry.repo}` -- which may have deleted or renamed"
            " the file rather than changed it"
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

    --dry-run skips opening, updating or closing the issue: what
    reusable-vendored-vectors.yml passes for every trigger but the
    weekly schedule, so a change to this script or to a ledger is
    exercised without the run editing whatever tracking issue happens
    to be open at the time.
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
        if drift.has_no_tip:
            print(
                f"NO COMMIT: {drift.entry.heading} pinned to"
                f" {drift.entry.commit}, and no commit on"
                f" {_branch(drift.entry)} of {drift.entry.repo} touches"
                f" {drift.entry.path}"
            )
            continue
        print(
            f"BEHIND: {drift.entry.heading} pinned to {drift.entry.commit},"
            f" latest commit touching it is {drift.latest_commit}"
            f" ({drift.latest_date}), which may have deleted or renamed it"
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
