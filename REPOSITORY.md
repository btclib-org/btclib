# Repository configuration

Read this before changing a workflow, a branch rule or a repository
setting; writing code does not need it. `CLAUDE.md` points here rather
than carrying it, so that a session fixing a bug in `ecc/` does not hold
it in context.

The branch rules and the repository settings live *outside* the
repository, and this file is where those answers are written down. What
is recorded is the settings
[the standard](https://github.com/btclib-org/.github/blob/main/README.md)
asks about — the ones
[section 16's checklist](https://github.com/btclib-org/.github/blob/main/README.md#16-checklists)
sets on a new repository, the ones a section of the standard states a
rule for, and the ones a behaviour it describes rests on — together with
whatever a call quoted for one of those answers alongside it. That is
this file's scope, and *What this file passes over*, at the foot, says
what falls outside it.

*Code quality* is recorded past that edge: no section of the standard
states a rule about that setting, and it is here because turning off the
code scanning default setup — which section 11 does ask for — leaves the
quality analysis running, so stopping it is a decision of this
repository's.

Where an answer has a copy in the tree, the section recording it says so:
`pyproject.toml` carries the topics as `keywords` and the documentation
site as `[project.urls] homepage`.

## Required checks on main

**Never name matrix contexts in the branch rule.** The rule lives outside
the repository, so a context that stops being produced blocks every merge
with nothing in the tree to explain why. `test: every job passed` is an
aggregate job at the end of `test.yml` that `needs` every other job in
it; a new job in `test.yml` belongs in that job's `needs`, or it gates
nothing. Its name carries the workflow because a context is keyed by name
alone: two workflows with a job named the same thing produce one
ambiguous check.

That aggregate skips, rather than fails, when the run itself was
cancelled by the concurrency group superseding it -- a skip satisfies a
required check, the same as this very job's own draft/closed condition
already relies on. A `changes` job gates `coverage`, `no-bindings`,
`dist` and `coverage-union` on whether a pull request touched anything
those jobs read, so `skipped` from any one of them is legitimate too, on
purpose, whenever the diff is prose alone
(issue #1044) -- not only the whole-run-cancelled case. The aggregate
fails hard on anything else a dependency reports, `success` or
`skipped` and nothing besides, checked by name in a shell loop that
always runs rather than a boolean expression a skipped step could
leave unevaluated. (Issues #1025, #1001 and #1044.) Read the cells,
not the aggregate, when a run's own conclusion and this check
disagree: `gh api repos/btclib-org/btclib/actions/runs/<id>/jobs`.

`main` requires these checks, and no others — `gh api
repos/btclib-org/btclib/branches/main/protection --jq
'.required_status_checks.checks'` reads the rule back live:

| Check | Produced by |
| --- | --- |
| `test: every job passed` | `test.yml`, aggregate over its own jobs |
| `Lint and type-check` | `lint.yml`, its only job |
| `Build the documentation` | `docs.yml`, its only job |
| `Regtest against Bitcoin Core` | `integration-bitcoind.yml`, its regtest job |

A workflow needs an aggregate when every one of its jobs has to gate:
`test.yml` is the one with several, and a context naming any one of them
would leave the rest outside the rule. Where a single job is what gates,
that job *is* the context, which is why most of the checks above are job
names.
`integration-bitcoind.yml` holds only the regtest job: the HWI jobs — `HWI
against a Trezor emulator` and `HWI against a Ledger emulator` — live in
`integration-hwi.yml`, a workflow with no `pull_request` trigger at all, so a
firmware release or a Ledger screen that changed wording produces no
pull-request check to ignore, required or not — a job merely skipped on a pull
request still lists there, a workflow that never triggers on one does not. What
a job added back to `integration-bitcoind.yml` would still cost is a rename: a
workflow whose *whole* answer becomes required needs an aggregate, and this
table with it.

`Build the documentation` is named on its own on purpose: a rule naming
`Lint and type-check` alone would leave a red docs build outside the
required checks entirely. It moved from `lint.yml` to a workflow of its own
without the rule changing, which is worth knowing before renaming anything:
a context is matched by name, not by the workflow that reported it, so
moving a job is free and renaming one is not — the pull request that renames
a required check stops producing the old name and never produces one the
rule is waiting for.

`Regtest against Bitcoin Core` is the newest of the four, and it is here
because its cost was measured rather than assumed: 36 seconds of work for a
disposable regtest node, which is less than the gate it runs beside. It answers
the one claim the recorded vectors cannot make. `integration-bitcoind.yml`
therefore carries no `paths` filter: a required check that never runs blocks a
merge, where a skipped one satisfies it.

The plan puts a ceiling on how many jobs the organization runs at once,
and *Plan-gated settings* below is where that figure lives, beside the
command that re-derives it. Measured over a working afternoon while a
commit here asked for thirty-nine jobs, this repository sat at the
ceiling or one job below it for 1375 of 2100 seconds — so a pull
request's wall clock was the wait for a slot and not the work. That is
the measurement the gate and the weekly sweeps are arranged around.

`codeql.yml` carries no required check at all. It runs on `main`, on its
schedule and on every pull request now — the OpenSSF Scorecard's `SAST`
check is why, and `codeql.yml`'s own `on:` block comment carries that
story — but neither cell of its `analyze` job's matrix can be named in
the branch rule on its own, the bullet above being why, and the workflow
has no aggregate job that could be. The Code scanning section below
states that in its own terms, at the point where default setup's own
`CodeQL` context is dropped from the rule instead.

What still reads a branch before it merges, `codeql.yml` itself included
now, is the workflow half of the same question: `zizmor` is a pre-commit
hook, so `lint.yml` audits these very files for an injected expression on
every pull request, and that check is required.

Renaming or dropping a required check is the one change that cannot be made
in a pull request: the workflow in the branch stops producing the name while
the rule outside still waits for it, so nothing merges. The rule moves
first, against the branch, and the pull request follows:

```shell
branch=repos/btclib-org/btclib/branches/main
gh api -X PATCH "$branch"/protection/required_status_checks --input - <<'JSON'
{
  "strict": true,
  "checks": [
    {"context": "test: every job passed", "app_id": 15368},
    {"context": "Lint and type-check", "app_id": 15368},
    {"context": "Build the documentation", "app_id": 15368},
    {"context": "Regtest against Bitcoin Core", "app_id": 15368}
  ]
}
JSON
```

**`checks` and not `contexts`, and that is not a style.** All four are
bound to the app that produces them — 15368, Actions — so nothing else
reporting one of those names can satisfy it. `contexts` has no field for
an app, so a `PATCH` sending it replaces the bound list with an unbound
one: the rule keeps working, silently accepting any app's check of that
name, and nothing in a run says so. Read it back rather than assume:

```shell
gh api repos/btclib-org/btclib/branches/main/protection \
  --jq '.required_status_checks.checks'
```

**A JSON body on stdin is what `app_id` takes**: `-f` sends every value as
a string and the endpoint answers `422 Invalid request. For
'properties/app_id', "15368" is not a null or integer`. A shell variable
holds the path for the same reason the JSON is not on one line, which is
80 columns.

**PATCH that sub-endpoint, never PUT the whole protection object**: a
partial PUT drops the reviews, the signatures and the rest. Repeat
`strict: true` in the body, which replaces the object rather than merging
into it.

## Code scanning

The analysis runs from `codeql.yml`, and default setup — the repository
setting that used to hold it — is off:

```shell
gh api repos/btclib-org/btclib/code-scanning/default-setup
# {"state":"not-configured", ...}
```

**The two cannot both be on**, and what that costs is not a workflow that
declines to run. The workflow runs, the analysis completes, the SARIF
uploads, and processing answers:

```text
Code Scanning could not process the submitted SARIF file:
CodeQL analyses from advanced configurations cannot be processed when the
default setup is enabled
```

So while the setting is on, the analysing jobs are red rather than
absent — which is why the exchange has an order. These four steps are
the order that never leaves `main` unmergeable, and 1 and 2 are a token
rather than a pull request, so only a human can perform them:

1. patch the rule to drop the `CodeQL` context, every other one staying;
1. disable default setup;
1. re-run the pull request's checks: the upload that was refused is
   accepted now, so `Analyze actions` and `Analyze python` go green;
1. merge.

There is no fifth step adding a `codeql.yml` check to the rule: neither
matrix cell is required, and this workflow carries no aggregate that
could be either.

Step 2 is what makes the setting let go of the analysis. It is not the
command that enabled default setup and there is no need to keep that one:
what a browser switched on, this switches off, and the tree is where the
configuration lives afterwards.

Two things survive step 2, and neither is explained by the endpoint this
section tells you to read. A generated
`dynamic/github-code-scanning/codeql` workflow stays `active` and keeps
running `Analyze (ruby)` and `Analyze (python)`, but it uploads *code
quality* results now — `ruby.quality.sarif` in its log, where the security
analysis produced `python.sarif` and `actions.sarif`. Code quality is a
separate setting with an endpoint of its own, the section below, and
`code-scanning/default-setup` reports nothing about it:

```shell
gh api repos/btclib-org/btclib/actions/workflows \
  --jq '.workflows[] | select(.path | startswith("dynamic/"))
        | {name, path, state}'
```

And the `CodeQL` context itself does not stop: it still reports on a pull
request's head, `neutral` where it was `success`, summarised
`1 configuration not found`. Whether a rule naming it would be satisfied by
that is untested, and testing it means deadlocking `main` to find out —
which is an argument for the order above rather than against it.

```shell
gh api -X PATCH \
  repos/btclib-org/btclib/code-scanning/default-setup \
  -F state=not-configured
```

Step 1 patches the `checks` array rather than `contexts`, so that the
bindings the rule already has survive the edit, and **a JSON body on stdin
is what that takes**: `-f` sends every value as a string and the endpoint
answers 422 for a string `app_id`. Its body is the four-check one the
section above carries, every entry naming its app because every one of these
is an Actions check — the `CodeQL` it drops was the exception, the app
producing it not being Actions.

## Code quality

The analysis the section above leaves behind, and it is off. Its setting
is not `code-scanning/default-setup`, and the Actions API refuses to be
the way in — `actions/workflows/<id>/disable` answers 422, `Unable to
disable this workflow`, a generated workflow not being one this repository
owns. The endpoint that reports it is the one that sets it:

```shell
gh api repos/btclib-org/btclib/code-quality/setup
# {"state":"not-configured","languages":["python"], ...}

gh api -X PATCH repos/btclib-org/btclib/code-quality/setup \
  -F state=not-configured
```

What decided it is the concurrency ceiling measured above, not the
queries: the check set a pull request here already asks for is large on
purpose, and `Analyze (python)` and `Analyze (ruby)` were two more on
every pull request and every push to `main` — `Code Quality: PR #N` in
the run list, 80 seconds and 32.

How large is read off a pull request rather than written down here,
because it is not one number.

```shell
head=$(gh pr view <an open pull request> --json headRefOid --jq .headRefOid)
gh api "repos/btclib-org/btclib/commits/$head/check-runs" --jq '.total_count'
# 14 and 15, the two open when this was written
```

**An open one.** Every workflow here that triggers on a pull request
takes `closed` in its `types:`, `claude-review.yml` excepted, so that a
landing cancels the run its own group is still holding. A merged head
therefore carries a second set of runs on top of the first, skipped
entire, for all but that one. PR 1546's merged head answers 23 to the
call above, of which one run succeeded and the other 22 were cancelled or
skipped. A figure taken there measures what the forge recorded, not what
a pull request asks a runner for.

What they produced in exchange cannot be read from here at all. There is
no `code-quality/alerts` and no `code-quality/analyses`, both 404, and a
quality upload appears in neither of the endpoints that do answer: the
alert list is empty, and every analysis is `codeql.yml`'s own, by
category.

```shell
gh api "repos/btclib-org/btclib/code-scanning/alerts?per_page=100" \
  --jq length
gh api "repos/btclib-org/btclib/code-scanning/analyses?per_page=100" \
  --jq '[.[] | .category] | unique'
```

So the repository's Code quality tab is the only place the python quality
queries have ever spoken — the run log lists them one by one as they
evaluate — and nothing outside a browser can say what they said, which is
most of the reason nobody read them.

`Analyze (ruby)` is the plainest half of it: there is no Ruby in this
library. A `Gemfile` sat beside the package for as long as this
repository served a Jekyll site from `main`'s root, and autodetection
read a Ruby project from it — which the endpoint above now says in
its own voice, `ruby` having left that list when the `Gemfile` did. The
control is the tree that took the site: the same call against
`btclib-org/btclib-org.github.io`, which holds a `Gemfile` and no
Python, answers `["ruby"]`. `codeql.yml`'s `matrix.language` names
`actions` and `python` and nothing else — an absence rather than an
exclusion, there being no Ruby for either configuration to analyse —
and that workflow's own header carries the measurement.

`state=configured` is the way back, and the argument for it is that these
queries are a class of finding nothing else here makes: ruff, mypy and the
two spell checkers are the cover, and they are not the same questions. The
trade against them is above, and it is the ceiling, so a fleet that is not
waiting for slots is what would change it.

## Branch protection

`main` is the repository's default branch and its only one:

```shell
gh api repos/btclib-org/btclib --jq '.default_branch'
# main
```

Everything reaches it through a pull request: the four checks above with
`strict`, one approving review, `dismiss_stale_reviews`, **required
signatures**, linear history, no force pushes, no deletions,
`required_conversation_resolution`, and `enforce_admins` *off* — an
administrator can bypass all of it.

That last one is what carries the review. CONTRIBUTING.md states why a
review cannot be satisfied by its author; the consequence here is that on
a solo-maintainer repository the rule as written stops every pull request
the maintainer opens, and the bypass is what lets one merge at all. The
trade is the review's other half: it is there for a contributor's pull
request, where there *is* somebody else to ask.

Required signatures cost the maintainer nothing when a pull request is
what lands on `main`: the only thing writing to it is a merge GitHub
performs itself, and GitHub signs those with its web-flow key — true of
a merge commit and a squash, and worse for a rebase, which GitHub
disables on a branch requiring signed commits because it has no access
to the original signer's key to re-sign what it recreates.

Dependabot, its security updates and pre-commit.ci all open pull requests
here, none of them naming a target branch: what they get is the default
branch, and it is the only branch there is. Issue #158 was the other
arrangement — two bots pushing through an integration branch that carried
no protection at all — and one branch is what closed it.

### The rulesets beside the classic rule

`enforce_admins` off is one switch that exempts an administrator from
every rule above at once — there is no way, inside the classic rule
alone, to relax the review requirement for a solo merge while keeping
signatures and linear history unconditional. `main-integrity` and
`main-self-merge` carry that split, additive to the classic rule rather
than replacing it: rules aggregate across rulesets and classic
protection, taking the most restrictive combination wherever they
overlap. `tag-integrity` targets tags rather than `main`, for an
unrelated reason: `release.yml` publishes to PyPI on `push: tags:
["v*"]`, and that tag was the one unattested link in an otherwise
fully-signed chain (issue #1022).

- `main-integrity`: required signatures, required linear history, no
  force pushes, no deletions. No bypass actor, for anyone, ever.
- `main-self-merge`: require a pull request — one approving review,
  dismiss stale reviews, conversation resolution — and `squash` as the
  only merge method it will accept. Bypass: the maintainer, in
  **`pull_request` mode**.
- `tag-integrity`, `target: tag`, `refs/tags/v*`: required signatures,
  and nothing else. No `deletion` or `non_fast_forward` rule, on
  purpose — RELEASING.md's own recovery path deletes and re-tags a
  release that failed before `publish-pypi`, and either rule would
  block exactly that. No bypass actor, for anyone, ever: RELEASING.md's
  tagging step already produces a signed tag by default, so there is no
  case that needs one.

**The bypass mode is the whole of the design.** `pull_request` excuses
its holder from the rule *while merging a pull request* and at no other
time, so it answers the one thing a solo-maintainer repository cannot
do — produce an approving review from somebody else — and answers
nothing further. A direct push to `main` is refused for everyone, the
holder included: outside a pull request there is no bypass to apply, and
the rule says changes must come through one.

The other mode, `always`, permits a direct push as well, and it is not
used here. What it would buy is a landing that keeps the maintainer's
own signature on the commit; what it costs is a `main` any local mistake
can reach. The first half is worth nothing once the branch rule is read
as asking for a valid signature rather than for a particular signer,
which makes GitHub's web-flow key as good as the maintainer's — and the
second half is not hypothetical: a `git merge` run in the wrong working
tree is enough to advance `main` locally, and under `always` the push
that follows would be accepted.

Read the three back rather than trusting any one:

```shell
gh api repos/btclib-org/btclib/rulesets --jq '.[].id' \
  | xargs -I{} gh api repos/btclib-org/btclib/rulesets/{} \
    --jq '{name, rules: [.rules[].type],
           bypass: [.bypass_actors[] | .bypass_mode]}'
```

`main-integrity` and `tag-integrity` both answer with an empty bypass
list, and it is what makes an unsigned commit or a rewritten history
unlandable, and an unsigned `v*` tag unpushable, by anyone, admin or
not, through a pull request or otherwise.

**Two settings hold the door, not one.** The classic protection still
carries `required_pull_request_reviews`, and what clears it for the
maintainer is `enforce_admins` being `false` together with holding
`admin` — the ruleset bypass alone would not be enough. Turning
`enforce_admins` on would therefore deadlock every solo merge, the
classic review requirement having no bypass list to be named in.

**Every landing is now a pull request GitHub merges**, which is what
retires the question this section used to answer at length: whether the
object arriving on `main` is the one the pull request names. It always
is. GitHub marks the pull request **Merged**, the `Closes #N` in its
description closes the issue, and `delete_branch_on_merge` takes the
head branch a second later — with nothing left to close by hand, and no
case where a commit lands that no pull request knows about.

## Merge methods

**Squash is the only *button* enabled, and it is how a pull request
lands here** — auto-merge presses it once the review and the checks are
in, so the default landing is one GitHub performs and signs with its
web-flow key. That signature satisfies `main-integrity` exactly as the
maintainer's own would: what the rule requires is a valid signature, not
a particular signer.

```shell
gh api repos/btclib-org/btclib \
  --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge,
         allow_auto_merge, squash_merge_commit_title,
         squash_merge_commit_message}'
# {"allow_auto_merge":true,"allow_merge_commit":false,
#  "allow_rebase_merge":false,"allow_squash_merge":true,
#  "squash_merge_commit_message":"COMMIT_MESSAGES",
#  "squash_merge_commit_title":"COMMIT_OR_PR_TITLE"}
```

`allow_auto_merge` is what makes "auto-merge presses it" above a setting
this file reads back rather than a fact about a workflow: turned off,
every landing here would wait for somebody to press *Squash and merge* by
hand at the moment the last check goes green, and nothing would turn red
to say so.

**There is no second path**, the section above having the bypass mode
that closes it and the ruleset entry that names `squash` as the only
merge method the rule will accept.

What a pull request as the only way in costs is a stacked pull
request: once the parent lands, the
child's base is an object no longer on `main` — a button recreates
rather than moves, GitHub's documentation saying rebase-and-merge
"always updates the committer information and creates new commit SHAs"
— so the child is rebased and pays a fresh run of the gate. That is
the price of having no way to write to `main` by hand, and it is the
one worth paying: the afternoon this rule was written, a `git merge` run
in the wrong working tree advanced `main` locally, and only the absence
of a push kept it off the remote.

The merge commit was refused by the required linear history above already,
so turning it off takes away a button that could not have worked. The
rebase merge could have, and that is the one this removes: it replays a
branch's commits onto `main`, where one change is one commit and the steps
of a review belong to the pull request that carries them.

What a single method buys is not the button on a pull request somebody is
looking at. GitHub preselects whichever method was used last, and the
dialog that switches auto-merge on carries the same dropdown — so the
answer can be given hours before anything merges, by whoever switched it
on, with nothing asking again. One method is one entry: there is no wrong
one to preselect, and nothing to read before pressing.

What the commit a squash writes then says is
`squash_merge_commit_title` and `squash_merge_commit_message`, the last
two fields above; CONTRIBUTING.md explains the pair where a contributor
meets it.

## Head branches after a merge

`delete_branch_on_merge` is on, since 7 August 2026:

```shell
gh api repos/btclib-org/btclib --jq '.delete_branch_on_merge'
```

GitHub deletes the head branch of a pull request when it is merged, which
is what keeps the branch list a list of live work rather than a history of
every change ever made. It was turned on after a sweep that removed nine
merged head branches from here, none of which anybody could tell from live
work without comparing each against the trunk commit by commit.

Two cases it does not cover, both deliberate. A protected branch is never
deleted, protection winning over this setting, which is why `main` cannot
be removed by anything — including a pull request that somehow had it as a
head. And a pull request **closed without merging** keeps its head branch:
GitHub cannot know whether that work was abandoned or is waiting, so those
are the ones still worth looking at now and then.

The setting hangs on the merge GitHub records, and every landing here is
one it records, so nothing is left to delete by hand. Measured in
btclib-secp256k1, whose configuration is this one: a pull request marked
Merged at 12:39:19 had `head_ref_deleted` at 12:39:20, with nobody
asking.

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more must declare it. Most of those declarations are in
`release.yml`: `contents: write` on `github-release`, `id-token: write` on
`publish-pypi` and `publish-testpypi`, `id-token: write` with
`attestations: write` on
`attest`, and `contents: read` with `pull-requests: read` on `test` — that
last one there because `test` calls `test.yml`, and a caller's
`permissions:` block replaces the callee's default outright rather than
adding to it, so it has to grant what `test.yml`'s own jobs declare, not
only what `release.yml` itself needs. `test.yml` has one such declaration
of its own, on `changes`: `pull-requests: read`, to list a pull request's
files. And `codeql.yml`'s `analyze` has one: `security-events: write` is
what uploading a SARIF to code scanning takes, with `actions: read` beside
it — redundant while this repository is public, and written down so that
the file does not quietly stop working the day it is not. Every
workflow's aggregate job needs none of that and declares none of it: one
elevation per job is the shape to keep — the job that writes releases holds
no OIDC token, and the job that signs writes no release.
`vendored-vectors.yml`'s `vectors` job has one such declaration of its
own: `issues: write`, for the `gh issue create`/`edit`/`close` calls its
script makes on the tracking issue it maintains.
The workflow-level `permissions: contents: read` is belt and braces; keep
it, it is what makes the intent readable in the file.

```shell
git grep -n "permissions:$" -- .github/workflows/*.yml
```

re-derives the current list, whenever it's wanted, rather than a count
here going stale the next time a job's own needs change.

### Whether that default is pinned here is untested

```shell
gh api repos/btclib-org/btclib/actions/permissions/workflow
# {"default_workflow_permissions":"read",
#  "can_approve_pull_request_reviews":false}
```

`read`, and a false `can_approve_pull_request_reviews` beside it. What
the call cannot say is whether either value is this repository's own or
the organization's, no endpoint reporting an override and none clearing
one: [the standard's tokens
section](https://github.com/btclib-org/.github/blob/main/README.md#tokens-publishing-scanning)
is where that is argued, and the answer this file adds is which of the
two states this repository is in.

It is **untested**, and that is what the date makes it: this repository
already held `read` when the organization default moved there on
21 August 2026, so it was not among the ones that could be *seen*
following the move, and an override set before that day reads back
exactly like an inheritance does. Nobody has recorded setting one here,
which is weaker than knowing there is none — `bitcoin-core-rpc` is the
repository where one was found, by that survey, and its `REPOSITORY.md`
records it as pinned.

So whoever moves the organization default reads this repository back
afterwards rather than assuming it followed, and moves it by hand where
it did not:

```shell
gh api -X PUT repos/btclib-org/btclib/actions/permissions/workflow \
  -f default_workflow_permissions=read \
  -F can_approve_pull_request_reviews=false
```

## Publishing

**Publishing waits for an approval**: the `pypi` and `testpypi`
environments both require a review, and `pypi` is restricted to `v*`
tags. `RELEASING.md` records the reasoning, including why self-review
stays allowed.

```shell
gh api repos/btclib-org/btclib/environments \
  --jq '.environments[] | select(.name == "pypi" or .name == "testpypi") |
        {name, protection_rules: [.protection_rules[]?.type]}'
# {"name":"pypi","protection_rules":["required_reviewers","branch_policy"]}
# {"name":"testpypi","protection_rules":["required_reviewers"]}
```

`pypi`'s `branch_policy` is the `v*` tag restriction stated above:

```shell
gh api repos/btclib-org/btclib/environments/pypi/deployment-branch-policies \
  --jq '.branch_policies[] | {name, type}'
# {"name":"v*","type":"tag"}
```

`testpypi` carries `required_reviewers` with no `branch_policy` beside
it — the same call against `testpypi` 404s, where it answers for `pypi`
— so a publish to TestPyPI accepts any branch or tag once approved;
`release.yml`'s own `workflow_dispatch` trigger is what narrows it
further.

## Pages, which this repository does not use

**There is no site here, and the endpoint that would describe one
answers with its absence.** It has no body worth reading, so what is
asked for is the status alone, the way `vulnerability-alerts` is asked
below:

```shell
gh api -i repos/btclib-org/btclib/pages 2>/dev/null | head -1
# HTTP/2.0 404 Not Found
```

`--jq` is the wrong tool for it and quietly so: on an error response `gh`
bypasses the filter and prints the whole body, which carries no trailing
newline, so a `2>&1 | tail -1` returns that body with the error line
glued to its end rather than the error line on its own.

This repository served `btclib.org` from `main`'s root with the classic
Jekyll builder, and btclib-org/.github#530 is the decision that moved
the organization's domain above any one tree: it is
`btclib-org/btclib-org.github.io` that serves it now, from a homepage
derived from the organization's own `profile/README.md`. What that
leaves here is nothing to configure — no `_config.yml` deciding which
root files become URLs, no `Gemfile` pinning a builder, no `website.yml`
asking whether the site still renders, and no `CNAME`.

**What a reader is sent to instead is the documentation**, which is the
*Read the Docs* section below and is what `[project.urls] homepage`
names. The two were never the same thing, and only one of them was ever
built from the library.

Turning Pages back on is a settings change and not a pull request, and
it would republish `main`'s root as whatever Jekyll makes of a tree that
now has no site sources — `README.md` as a themeless homepage, and every
root file beside it a URL, `exclude:` being the list that is gone.

## Read the Docs, which is btclib.readthedocs.io

**The published documentation is a project on Read the Docs**, `btclib` on
<https://app.readthedocs.org/projects/btclib/>. `.readthedocs.yaml` says
how a build runs; *which* versions run it is settings there, and nothing
in the tree records them:

```shell
curl -s https://app.readthedocs.org/api/v3/projects/btclib/ \
  | python3 -c 'import json, sys; p = json.load(sys.stdin); \
      print(p["default_branch"], p["default_version"])'
# main latest
```

- **`latest` follows the default branch, which is `main`.** That setting is
  Read the Docs' own and not GitHub's, so renaming the branch here leaves
  it pointing at one that no longer exists — and a push to a branch no
  version follows is *accepted* and builds nothing, which is a green
  delivery and a site frozen at its last build (issue #574). The
  `{"build_triggered": false, "versions": []}` body that used to be
  quoted here is the webhook era's; what carries a delivery now is the
  App below, and no call in this file reads what it answers.
- **`stable` is the highest semantic-version tag**, chosen by Read the Docs
  and moved by it on each release, pre-releases excluded. It takes no
  setting and no rule, and it is what `/en/stable/` serves.
- **An automation rule activates each new release tag**: Admin → Automation
  Rules, match `SemVer versions`, version type `Tag`, action `Activate
  version`. A tag is created inactive otherwise, which is a 404 on
  `/en/v<version>/`; with the rule each release keeps a URL that stays that
  release rather than becoming the next one. It applies to versions created
  after it, so a tag pushed before it stays inactive until activated by
  hand.
- **`default_version` is `latest`**, so the root of the site serves the
  development tip, declaring the placeholder version `pyproject.toml`
  carries between releases. `stable` is the alternative, and what the
  choice decides is which of the two a reader arriving with no version in
  mind is given.
- **The repository's `.homepage` names this same site**, read back from
  the endpoint rather than from `pyproject.toml`'s own copy of it:

  ```shell
  gh api repos/btclib-org/btclib --jq '.homepage'
  # https://btclib.readthedocs.io/
  ```

  `[project.urls] homepage` in `pyproject.toml` carries the identical
  string (issue btclib-org/.github#533): a releasing tree's home is its
  own documentation, and this is the only site this repository has, the
  *Pages* section above recording that it serves none.

Tags older than the rule are mostly not activatable rather than merely not
activated: a build needs `.readthedocs.yaml`, which reaches back to
`v2026.8.7` alone, so an older tag answers with a failed build instead of
with the documentation of 2023. None was backfilled, `v2026.8.9` — which
could have been — included, so `/en/v<version>/` starts at the first tag
pushed after the rule and there is nothing behind it. `/en/stable/` is the
last release either way, which is what makes the backfill skippable.

**What connects the project is the `read-the-docs-community` GitHub App**,
installed on the organization for every repository, so this repository
carries no webhook of its own and none to give a secret to:

```shell
gh api orgs/btclib-org/installations \
  --jq '.installations[] | select(.app_slug == "read-the-docs-community")
        | [.app_slug, .repository_selection]'
# ["read-the-docs-community","all"]
gh api repos/btclib-org/btclib/hooks --jq 'length'
# 0
gh api repos/octocat/Hello-World/hooks --jq 'length'
# gh: Not Found (HTTP 404)
# gh: This API operation needs the "admin:repo_hook" scope.
```

The third command is the control, and it is what makes the second an
answer about this repository rather than about the token: a call this
token may not make refuses out loud and exits non-zero rather than
answering an empty list, so the `0` above is a repository with no hook
and not a permission ceiling that reads like one. Every repository of the
organization answers `0`; the last per-repository webhook left anywhere
was bitcoin-core-rpc's, dead since the App arrived and deleted on
2026-08-28 (bitcoin-core-rpc#291).

## Security settings

All of these are repository settings and none of them is in the tree, so
this list is the whole of them:

```shell
gh api repos/btclib-org/btclib --jq '.security_and_analysis'
# the alerts themselves are not in that object: the endpoint that
# answers for them has no body, and says so with its status -- 204 for
# enabled, 404 for not
gh api -i repos/btclib-org/btclib/vulnerability-alerts | head -1
gh api repos/btclib-org/btclib/private-vulnerability-reporting
```

| Setting | State |
| --- | --- |
| Dependabot alerts | enabled |
| Dependabot security updates | enabled |
| Secret scanning | enabled |
| Secret scanning push protection | enabled |
| Secret scanning non-provider patterns | disabled |
| Secret scanning validity checks | disabled |
| Private vulnerability reporting | enabled |

The two that read `disabled` are not settings this repository declined:
[Plan-gated settings](#plan-gated-settings) below is where that belongs,
and reading their state as something to go and fix is the mistake that
section exists to prevent.

Code scanning default setup (CodeQL) is answered above, in [Code
scanning](#code-scanning), which is where the reason it is off belongs
rather than repeated here.

Private vulnerability reporting is what `SECURITY.md` sends a reporter
to, and the link in `.github/ISSUE_TEMPLATE/config.yml`'s "Security
vulnerability" form is the same door:
[GitHub's own documentation](https://docs.github.com/en/code-security/security-advisories/working-with-repository-security-advisories/configuring-private-vulnerability-reporting-for-a-repository)
is what says that form appears only where the setting above reads
`enabled`, so the setting and the two files go together. Whether the
form 404s where it is off was not checked here, and doing so means
turning it off.

## Plan-gated settings

Some settings cannot be enabled and fail silently: secret scanning's
non-provider patterns and validity checks need paid Secret Protection,
which is why they read `disabled` in the table above, and the API answers
a PATCH with 200 while leaving them so. Do not read that 200 as success.
The `detect-secrets` hook is the compensating control.

The other plan-gated number is not a setting at all, and it is the one
this repository's workflows are arranged around: how many jobs may run
at once. It is an attribute of the organization, shared by every
repository in it, and the plan is what sets it.

```shell
gh api orgs/btclib-org --jq .plan.name        # free
```

[GitHub's own table](https://docs.github.com/en/actions/reference/limits)
is the authority, and two of its numbers matter here — the standard
runner limit and the macOS-specific one, larger runners being a thing
nothing here asks for. On the free plan they are twenty concurrent jobs,
of which five may be macOS runners.

**Read the second number before spending anything on the first.** The
first is what *Required checks on main* above measures a wider gate
against, and a paid plan raises it well before it moves the second. The
five is the ceiling behind the macOS queueing `os-macos.yml`'s header
records, so taking the platform cells out of the merge gate is not a
workaround for a plan — below Enterprise no plan changes that arithmetic,
and Enterprise is not what is being asked about. What a paid plan would
buy is the rest: the Linux and Windows crowding, and the contention with
every other repository of the organization, which spends against this same
ceiling. Whether that is worth paying for is a question for whoever would
pay, and it is recorded here so that it is asked with the second number in
view.

## Features

```shell
gh api repos/btclib-org/btclib --jq '{visibility, has_issues}'
# {"has_issues":true,"visibility":"public"}
```

Section 10's `scorecard` sentinel rests on the first answer: public is
what it reads at all, so a flip to private leaves `scorecard.yml` and
`README.md`'s badge standing while the run stops producing a score, and
`.visibility` above is what puts that flip one command from being seen.

`has_issues` is what `CONTRIBUTING.md`'s *The issue tracker* rests on —
an issue about this tree alone stays here — and so does the
`.github/ISSUE_TEMPLATE/` section 16's checklist gives every repository.

## Topics

```shell
gh api repos/btclib-org/btclib --jq '.topics'
```

```json
["base58","bech32","bip32","bip340","bip39","bitcoin","cryptography",
 "ecdsa","electrum","elliptic-curves","hardware-wallet",
 "message-signing","musig2","output-descriptors","psbt","schnorr",
 "secp256k1","segwit","slip39","taproot"]
```

Twenty, GitHub's own ceiling on the field. `pyproject.toml`'s `keywords`
carries the same twenty plus five more past that ceiling — `rfc-6979`,
`mnemonic`, `merkle-proof`, `bip44`, `bitcoin-script` — which are
keywords for PyPI and not topics, a comment beside the list saying so.
Nothing in the tree holds the two lists together, so this is the command
that does: it prints the difference and exits nonzero on one, GitHub
returning its own alphabetical order rather than the relevance order
`pyproject.toml` declares:

```shell
diff <(gh api repos/btclib-org/btclib --jq '.topics[]' | sort) \
     <(awk '/^keywords = \[/,/Past the twenty topics/' pyproject.toml \
       | grep -oE '"[a-z0-9-]+"' | tr -d '"' | sort)
```

## What this file passes over

The scope at the top is a perimeter, and this is its other edge: what an
endpoint answers for and no section above reaches, each with the reason
it stays outside.

**What no call sets.** `gh api repos/btclib-org/btclib` answers with the
repository document, most of which is URLs, counts and state GitHub
derives from the tree; the switches among them this file records are the
ones a section above reads back with a call of its own, and the
paragraphs below are about switches it does not. `gh api
repos/btclib-org/btclib/pages` has the same shape: `custom_404` follows a
`404.html` in the root, and `status` and `https_certificate` report the
last build and the certificate issued for the domain.

**A field the standard states no rule about, and no call above answers
alongside one it does.** `allow_forking`, `allow_update_branch`,
`has_discussions`, `has_downloads`, `is_template` and
`web_commit_signoff_required` are in the repository document, in no
`--jq` object above, and in no rule of the standard:

```shell
std=$(gh api repos/btclib-org/.github/contents/README.md --jq .content \
  | base64 -d)
for f in allow_forking allow_update_branch has_discussions has_downloads \
         is_template web_commit_signoff_required; do
  printf '%s %s\n' "$f" "$(printf '%s' "$std" | grep -c "$f")"  # 0 each
done
printf '%s' "$std" | grep -c delete_branch_on_merge  # not 0, which is
                                                     # what makes those
                                                     # zeros absences
```

Recording a field on no rule grows this file with GitHub's API rather
than with the standard.

**The wiki and the projects board are outside the perimeter by section
11's own sentence**, which states no rule about either, so this file
neither reads `has_wiki` and `has_projects` back nor explains an answer
to them; that sentence is what the loop above would count, which is why
the pair is not in its list.

**A credential this repository does not hold.** `claude-review.yml`
spends `secrets.CLAUDE_CODE_OAUTH_TOKEN`, and section 11 of the standard
holds that token at the organization, in both stores, rather than in each
repository:

```shell
gh api repos/btclib-org/btclib/actions/secrets --jq '.total_count'     # 0
gh api repos/btclib-org/btclib/dependabot/secrets --jq '.total_count'  # 0
gh api orgs/btclib-org/actions/secrets \
  --jq '.secrets[] | "\(.name) \(.visibility)"'
# CLAUDE_CODE_OAUTH_TOKEN all
gh api orgs/btclib-org/dependabot/secrets \
  --jq '.secrets[] | "\(.name) \(.visibility)"'
# CLAUDE_CODE_OAUTH_TOKEN all
```

The organization's stores answering with a name are what make the two
zeros absences rather than an endpoint that answers empty for everyone,
and an empty store here is where the standard's decision shows rather
than a facility nobody reached for.

**A facility nobody reached for.** The repository's Actions variables,
self-hosted runners, deploy keys, autolinks and custom property values
each answer empty here, and an empty answer records no decision.
Webhooks are not among them: *Read the Docs* above reads those back,
with the control that makes the `0` an absence rather than a permission
ceiling. Whichever of the rest is reached for one day arrives with the
section that uses it.

**A service's own settings, past the ones the standard states a rule
for.** [Section 11's *Pages and Read the
Docs*](https://github.com/btclib-org/.github/blob/main/README.md#pages-and-read-the-docs)
asks for the source, the build type and the CNAME, and for what `latest`
and `stable` follow; the first three are answered above by the endpoint's
404, there being no site here, and the last two are above too. The Read
the Docs project answers
for more than the `default_branch` and `default_version` read back there,
`privacy_level`, `single_version` and `versioning_scheme` among them, and
its redirects and its environment variables are not in that document at
all: `curl -s -o /dev/null -w '%{http_code}'` against
`https://app.readthedocs.org/api/v3/projects/btclib/redirects/` and
against `.../environmentvariables/` answers `401`, where the project call
above answers unauthenticated. PyPI's side of the trusted publisher is
not here either — the owner, repository, workflow and environment the
index matches an OIDC token against are set on the index, and
[RELEASING.md](./RELEASING.md)'s *One-time setup* is where they are
written down.

What the scope costs is a silent flip. A change to any of the above
shows up here in nothing, and finding one means reading each document
against this file rather than running a command.
