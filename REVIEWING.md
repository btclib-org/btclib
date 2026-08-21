# Reviewing a btclib pull request

The standard a review of this repository is written against: what a
review has to establish before it can be given, how a finding is stated,
and what becomes of everything a reviewer notices that the diff under
review is not about.

This is the reviewer's half of [CONTRIBUTING.md](./CONTRIBUTING.md),
which is the author's. It does not restate the rules a review cites —
those are in that file, in REPOSITORY.md and in CLAUDE.md, and a finding
names the line that states them rather than a copy kept here.

It is for whoever reviews: a contributor reading somebody else's pull
request, the maintainer, an agent session that starts with the pull
request and no memory of how the last review went. Read the other way
round, before a pull request is opened, it is what that pull request
will be answered against.

A review produces comments on a pull request and issues filed against
the repository. **A reviewer writes nothing to the branch**: no push, no
amend, no merge. The one commit a review can lead to is the author's own
click on a suggestion, below, which is theirs to make and theirs to
decline.

## The standard an ack is given against

**A diff is acked when it leaves the tree better than it found it**, not
when it is the diff the reviewer would have written. Perfection is not
the bar and is not reachable; the question is whether `main` with this
change is in better shape than `main` without it. The formulation, and
the reasoning under it, is Google's
[standard of code review](https://google.github.io/eng-practices/review/reviewer/standard.html).

Two things follow, and they are what reviews get wrong in opposite
directions:

- **A matter of taste is not a finding.** Where the author's choice and
  the reviewer's are both defensible, the author's stands. Say it once
  as a nit, if it is worth saying at all.
- **Work the diff never set out to do is not a finding either.** It is
  an issue; the section below is the whole of what to do with it.

## What is under review

1. **A sha, never a branch.** `gh pr view <N> --json
   url,headRefOid,baseRefName` — `headRefOid` is what is reviewed, and
   a branch name moves under a review that names it.
1. **The issues it closes**, all of them: one pull request may answer
   more than one, and answering one of two is a finding.
1. **The diff against the pull request's base**, not against `main`:
   `git diff <baseRefName>...<headRefOid>`, three dots, the base being
   the parent branch where this one is stacked. A finding that belongs
   to the parent goes on the parent's pull request — repeated on the
   child, the author answers it twice and resolves it once.
1. **The tree at that sha**, checked out and gated. `gh pr checkout <N>`
   and `uv sync --locked`; `CLAUDE.md` has where a checkout may be made
   and where it may not.

Read the whole diff before writing the first comment. A comment on line
5 that line 60 answers costs the author a reply and the reviewer their
credit for the rest of the review.

## What to look for

In priority order, stopping at what this diff can be wrong about:

- **Does it answer its issues?** The whole of them, and nothing beside.
  A diff carrying an unrelated fix cannot be acked for either question.
- **Is it correct?** Reason about the code as it will run, not as it
  reads. Where a claim can be checked, check it rather than believing
  it — and where what the diff adds is what does the deciding, checking
  it means running it, below.
- **Does it break a rule this repository states?** Not a rule the
  reviewer would have written — one the repository's own documents
  state, cited by the line that states it. This is the class of finding
  a review exists for: the author has the diff in view and the document
  out of view.
- **Is what it adds tested and documented the way this repository tests
  and documents things?** Its `CHANGELOG.md` entry included.
- **Is it simpler than it needs to be?** As a non-blocking finding, and
  never as a rewrite.

**Never review what a hook already gates.** Formatting, import order,
line length and the rest are decided by `.pre-commit-config.yaml`, and a
comment about one of them is either wrong or a bug in the hook.

## Every collateral finding becomes an issue

A review notices more than its subject: a defect the diff did not cause,
a document that has gone stale, a rule the tree quietly stopped
following. **None of it is a review comment, and every one of it is an
issue.** File it, and go back to the diff.

The reason is the author's round trip. A finding they cannot address
without leaving the subject is a round of review spent on something the
pull request was not for, and asking for it anyway is how a branch stops
converging. Filing costs the reviewer one command and loses nothing: the
defect is recorded, with its evidence, where the next person to touch
that code will find it.

What is *not* collateral, and stays in the review, is what this diff
introduces or breaks, and what was already wrong and this diff makes
materially worse. The test is not whether the code sits on a changed
line; it is whether this change is what put it there or made it worse.

Look for the issue already open before filing another:

```shell
gh issue list --state open --search "<the thing, in a word or two>"
```

The issue stands on its own, read by somebody who never sees this pull
request: what is wrong, where — `file:line` —, how it is known, and why
it matters. No fix, and no reference to the pull request as a blocker,
because it is not one.

```shell
gh issue create --title "<the finding, as a claim>" \
  --body "<what was noticed and where, how it is known, why it matters>"
```

Name the issues filed at the foot of the summary comment, under a line
saying they are **not** findings against this pull request. Without that
line the list reads as more things to fix before merging, which is the
opposite of what filing them was for.

## What a finding says

- **Where**: `file:line`, as an inline comment wherever a line is the
  subject.
- **What is wrong**, in a sentence.
- **How it is known**: the command and what it printed, or the concrete
  path through the code that produces the wrong result.
- **What kind it is**, said explicitly and never left to be inferred:

    - **blocking** — wrong, misleading or unmaintainable on `main`
    - **non-blocking** — worth doing, does not hold the ack
    - **nit** — taste; said once and never repeated
    - **question** — something not reproduced, asked as a question
      rather than asserted as a defect

Labelling every comment is
[conventional comments](https://conventionalcomments.org/)' idea and its
whole value: an unlabelled remark makes the author guess whether it
holds the merge, and they guess conservatively, which turns a nit into a
round of review.

No speculation dressed as a defect, no "consider maybe", no restating
what the diff plainly does. A review of five real findings beats twenty
of which three are real.

The subject is the code and never its author: "this returns the wrong
sign for a negative scalar", not "you forgot the sign".

## A fix small enough to read at a glance is proposed, not described

Where the correction is a line or a few, put it in the comment rather
than around it. A review comment anchored to a diff line can carry a
`suggestion` block, and the author accepts it from the pull request page
in the browser — no checkout, no editor, one click:

````text
```suggestion
    return p - y if y % 2 != odd else y
```
````

*Add suggestion to batch* takes several of them into one commit, which
is what to use when a review leaves more than one.
`CONTRIBUTING.md` states the same thing from the author's side, as
something they may apply directly through the interface.

Two properties make this the right shape here and not merely a
convenience: the commit GitHub writes is signed with its web-flow key,
and `main` requires a valid signature rather than one particular
signer; and it lands as a commit of its own on top of the branch,
which is the shape `CONTRIBUTING.md` asks a correction to take, so the
shas the review is attached to survive it.

Two properties decide when not to:

- **It is committed verbatim, and nothing local sees it.** The author's
  `pre-commit` does not run on a commit made in the browser, so the
  block has to be already written the way the hooks would write it —
  indentation, quoting, line length, trailing comma. A suggestion that
  fails a gate is worse than a sentence describing the fix, because it
  is accepted with one click and the failure arrives after.
- **Do not suggest a decision.** A one-click accept invites acceptance
  without thought, so the block is for a fix whose correctness is
  visible inside it: a wrong constant, an inverted condition, a missing
  guard, a sentence in a docstring. Anything spanning files, wanting a
  test beside it, or having a defensible alternative is stated in prose
  and left to the author.

A suggestion carries the severity of the finding it belongs to. Offering
one does not make a blocking finding a nit, and accepting one is what
closes the thread.

## What a diff decides with is run, not read

A diff that adds a regex, a grep, a pattern in a hook, a script or a
query adds something that decides an outcome by matching or computing.
**Run it.** Reading it again is not a second check: the author read it
and believed it, and a reviewer who only reads reproduces that reading
rather than testing it. Running it is what makes the verdict something
the author's own reading did not already decide.

The cases to run are not the reviewer's to invent:

- **The shapes the diff's own prose claims to cover** — the example in
  the hook's comment, in the `CHANGELOG.md` entry, in the pull request
  body. A motivating case the pattern does not in fact handle is the
  finding, and the diff named that case itself.
- **The shapes the tree actually holds.** `git grep` for the construct
  the pattern is about and run it against those lines, rather than
  against an example composed to be matched.

A claim the prose makes *about the tree* takes the same treatment.
"Every link here is already `./`-prefixed", "nothing calls this any
more": each is one command's worth of evidence, and each is the reason
the change is offered as safe. Settle it. Where it is false, the finding
is not the code but the reason given for it.

What this is not:

- **A run of the gates.** They run what the rest of the tree already
  exercises; what this diff adds has been run against nothing, and the
  review is the first thing to run it. A review told to leave the gates
  to the workflows running beside it on the same sha is told about the
  gates, and this is not one of them.
- **A test suite written inside a review.** It is a handful of one-line
  runs, and their output is the "how it is known" that a finding carries
  anyway.
- **A hand trace wearing a run's authority.** Where what is at hand
  cannot run the thing — a script or a query wanting an interpreter,
  where a pattern against the tree needs only a grep and is the usual
  case — say so in the summary, in those words: it was not run. A trace
  is the author's reading performed a second time, which is what running
  it is meant to replace; it can carry a finding, and it cannot carry an
  ack.

## The gates are the evidence

Run them on that sha, and read **exit codes, not filtered output** — a
pipe into `grep -v Passed` hides the failure it was meant to find. What
the gates are, and the two ways a run of them lies, is `CLAUDE.md`: a
suite run over a subset is not the coverage gate, and `pre-commit`
passing is not the lint gate, sphinx being a job of its own.

A gate that fails locally is the strongest finding available. A gate
that passes is not evidence that the diff is right.

**CI is not the reviewer's concern.** Do not wait for a workflow run, do
not read one, do not report a check as a finding, do not withhold a
review because something is pending or red. A run is cancelled by the
next push to the same branch, so a red or missing check is as likely to
be the concurrency group as the diff; whether CI is green is the
author's problem at landing time, and the local run is the evidence
either way.

## What a review of this tree checks that a generic one would not

Each of these is a question, and the document that answers it is named
because that document, and not this one, is where the rule lives.

- A change under `curves/` or `ecc/`: does it keep **both arithmetic
  paths** right, and is the condition selecting them tested on both
  sides? Which calls the bindings and which the Python arithmetic is
  `CLAUDE.md`'s "Architecture", and the suite validates the second
  against the first.
- Does the diff **state a count** of anything — of vectors, of entries,
  of findings, of seconds? `CONTRIBUTING.md` says why it must not, and
  only some of those are caught by a test.
- If the branch was rebased: do `CHANGELOG.md` and `RELEASE_NOTES.md` say
  what the branch meant them to say? They are `merge=union`, so they never
  conflict and a rebase can put back a line the branch had removed.
- A new or changed workflow: the conventions in `CLAUDE.md`, and
  `REPOSITORY.md` before any rule or setting is touched. A renamed job
  is a required check renamed out of existence.
- A new file in the repository root: `_config.yml` decides whether it
  becomes a page on btclib.org, and its default is that it does.

## The verdict

Inline comments for the line-anchored findings, then exactly one summary
comment whose last line is one of two forms:

```text
CHANGES REQUESTED <sha>
```

```text
ACK <sha>
```

Nothing else is an ack — not "looks good", and not a forge approval,
which `CONTRIBUTING.md` records GitHub as refusing to the author of the
pull request. That refusal is why the record of a review here is a
comment at all. It names the sha because an ack belongs to a tree and
not to a branch.

The summary says, in a few lines, what was reviewed — the sha, the gates
and their exit codes —, lists the blocking findings, and names the
issues filed. No blocking findings and no ack is a contradiction: either
the finding is blocking or the ack is due.

Post it the moment it is written, and where several pull requests are
waiting, finish and post one before opening the next: a batch of reviews
arrives as one wall of comments, and the first of them waited for the
last to be written. Take a re-review before a first review, a parent
before its child, and otherwise the oldest.

## Re-review

The delta is `git diff <old-sha>..<new-sha>`, and there is one to read
because `CONTRIBUTING.md` has corrections added as commits rather than
amended in: the shas the review was attached to are still there.

- **Resolve every thread the author addressed, and only those.** A
  thread they declined stays open only if it is still blocking; where
  their reason is sound, resolve it and say so. A finding declined as
  out of scope and filed as an issue is addressed.
- Do not re-open settled ground, and do not introduce a preference late.
  A new blocking finding at round three is legitimate only if the new
  commits introduced it, or if leaving it would be wrong on `main`.
- Where the author declined something still considered blocking, say so
  once, with the argument. If they hold their position, do not spend a
  fourth round: withhold the ack and put both positions to a human.
  Escalating is a result; a stalemate repeated in silence is not.
- A handoff may be a **rebase rather than new work** — the parent landed
  and the child was retargeted, or a base was amended. Then the delta is
  the rebase, and what to check is that it carried nothing back: a child
  moved without naming its old base re-adds the parent's old text as
  additions, and every gate passes in both worlds.

    ```shell
    git diff origin/main...<new-sha>
    git merge-base --is-ancestor origin/main <new-sha>
    ```

- An acked pull request comes back for one more round when a rebase onto
  `main` **resolved a conflict**. That is correct of the author, and the
  delta is the resolution and nothing else: a conflict resolved by one
  hand is the change that passes every gate and is still wrong.

Ack when every blocking finding is closed, the gates passed locally on
that sha, and the diff answers its issues. Non-blocking findings and
nits do not hold an ack — say that they are left to the author.
