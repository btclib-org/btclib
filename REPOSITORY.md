# Repository configuration

Read this before changing a workflow, a branch rule or a repository
setting; writing code does not need it. `CLAUDE.md` points here rather
than carrying it, so that a session fixing a bug in `ecc/` does not hold
it in context.

The branch rules and the repository settings live *outside* the
repository, so this file is the whole of them: nothing here can be
recovered by reading the tree.

## Required checks on main

**Never name matrix contexts in the branch rule.** The rule lives outside
the repository, so a context that stops being produced blocks every merge
with nothing in the tree to explain why. `test: every job passed` is an
aggregate job at the end of `test.yml` that `needs` the matrix; a new job in
`test.yml` belongs in that job's `needs`, or it gates nothing. Its name
carries the workflow because a context is keyed by name alone: two
workflows with a job named the same thing produce one ambiguous check.

That aggregate skips, rather than fails, when the run itself was
cancelled by the concurrency group superseding it -- a skip satisfies a
required check, the same as this very job's own draft/closed condition
already relies on. A `changes` job gates `suite`, `coverage`,
`no-bindings`, `dist` and `coverage-union` on whether a pull request
touched anything the matrix reads, so `skipped` from any one of those
five is legitimate too, on purpose, whenever the diff is prose alone
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
| `test: every job passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, its only job |
| `Build the documentation` | `docs.yml`, its only job |
| `Regtest against Bitcoin Core` | `integration.yml`, its regtest job |

A workflow needs an aggregate when every one of its jobs has to gate: the
matrix of `test.yml` is the one, and a context naming one cell of it would
leave the rest outside the rule. Where a single job is what gates, that job
*is* the context, which is why most of the checks above are job names.
`integration.yml` holds only the regtest job: the HWI jobs — `HWI against a
Trezor emulator` and `HWI against a Ledger emulator` — live in
`hwi-integration.yml`, a workflow with no `pull_request` trigger at all, so
a firmware release or a Ledger screen that changed wording produces no
pull-request check to ignore, required or not — a job merely skipped on a
pull request still lists there, a workflow that never triggers on one does
not. What a job added back to `integration.yml` would still cost is a
rename: a workflow whose *whole* answer becomes required needs an
aggregate, and this table with it.

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
disposable regtest node, which is less than the matrix it runs beside. It
answers the one claim the recorded vectors cannot make. `integration.yml`
therefore carries no `paths` filter: a required check that never runs blocks
a merge, where a skipped one satisfies it.

`codeql: every job passed` is not among them, and that is the one place a
check was traded for the wait it cost. GitHub Free gives an organization
twenty concurrent jobs (as of 2026-08-21); a commit here asked for
thirty-nine, and measured
over a working afternoon the repository sat at nineteen or twenty running
jobs for 1375 of 2100 seconds — so a pull request's wall clock was the wait
for a slot and not the work. `codeql.yml` now runs on `main` and on its
schedule, the analysis landing on the merge commit rather than ahead of it,
and it still produces that aggregate: the name is available, so requiring it
again is a patch to the rule and nothing in the tree.

What still reads a branch before it merges is the workflow half of the same
question: `zizmor` is a pre-commit hook, so `lint.yml` audits these very
files for an injected expression on every pull request, and that check is
required. What a merge now defers is the rest of the analysis, for the time
between that merge and the next run — which for `main` is the merge itself.

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

So while the setting is on, the analysing jobs and the aggregate are red
rather than absent — which is why the exchange has an order. These four
steps are the order that never leaves `main` unmergeable, and 1 and 2 are a
token rather than a pull request, so only a human can perform them:

1. patch the rule to drop the `CodeQL` context, every other one staying;
1. disable default setup;
1. re-run the pull request's checks: the upload that was refused is
   accepted now, so `codeql: every job passed` goes green;
1. merge.

There is no fifth step adding `codeql: every job passed` to the rule, and
the section above is why: that context is not required, so what the rule
holds is what step 1 leaves it with.

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
# {"state":"not-configured","languages":["python","ruby"], ...}

gh api -X PATCH repos/btclib-org/btclib/code-quality/setup \
  -F state=not-configured
```

What decided it is the concurrency ceiling and not the queries. GitHub
Free gives an organization twenty concurrent jobs (as of 2026-08-21), a
pull request here
asks for twenty-one on purpose, and `Analyze (python)` and `Analyze
(ruby)` were two more on every pull request and every push to `main` —
`Code Quality: PR #N` in the run list, 80 seconds and 32.

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
library. Pages serves btclib.org from `main`'s root, so a `Gemfile` sits
beside the package and autodetection reads a Ruby project; `codeql.yml`
excludes Ruby from its own matrix for that same reason.

`state=configured` is the way back, and the argument for it is that these
queries are a class of finding nothing else here makes: ruff, mypy and the
two spell checkers are the cover, and they are not the same questions. The
trade against them is above, and it is the ceiling, so a fleet that is not
waiting for slots is what would change it.

## Branch protection

`main` is the only branch, and everything reaches it through a pull
request: the four checks above with `strict`, one approving review,
`dismiss_stale_reviews`, **required signatures**, linear history, no force
pushes, no deletions, `required_conversation_resolution`, and
`enforce_admins` *off* — an administrator can bypass all of it.

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
  --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge}'
```

answers `true` for the first and `false` for the other two.

**There is no second path**, the section above having the bypass mode
that closes it and the ruleset entry that names `squash` as the only
merge method the rule will accept.

What a pull request as the only way in costs is a stacked pull
request: once the parent lands, the
child's base is an object no longer on `main` — a button recreates
rather than moves, GitHub's documentation saying rebase-and-merge
"always updates the committer information and creates new commit SHAs"
— so the child is rebased and pays a fresh run of the matrix. That is
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
`squash_merge_commit_title` and `squash_merge_commit_message`, which
CONTRIBUTING.md reads back and explains, both being where a contributor
meets them.

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
no OIDC token, and the job that signs writes no release — and
`vendored-vectors.yml` is the one place that departs from it, declaring
`issues: write` at the workflow level where its only job would do.
The workflow-level `permissions: contents: read` is belt and braces; keep
it, it is what makes the intent readable in the file.

```shell
git grep -n "permissions:$" -- .github/workflows/*.yml
```

re-derives the current list, whenever it's wanted, rather than a count
here going stale the next time a job's own needs change.

## Publishing

**Publishing waits for an approval**: the `pypi` and `testpypi`
environments both require a review, and `pypi` is restricted to `v*`
tags. `RELEASING.md` records the reasoning, including why self-review
stays allowed.

## Pages, which is btclib.org

**The website is this repository's own root**, served by GitHub Pages, and
the three things that decide it are settings rather than files:

```shell
gh api repos/btclib-org/btclib/pages \
  --jq '{cname, build_type, source, https_enforced}'
# {"cname": "btclib.org", "build_type": "legacy",
#  "source": {"branch": "main", "path": "/"}, "https_enforced": true}
```

`source` is what makes `README.md` the homepage and every other file in
the root a URL under btclib.org — CONTRIBUTING.md's "The website" section
is what that costs and `_config.yml`'s `exclude:` is what limits it.
Moving the source to `/docs` or to another branch would republish the site
as whatever that path holds, silently and immediately.

`build_type: legacy` is the classic Jekyll builder, and it is the reason
`website.yml` exists. GitHub runs it on its own side, keeps no log a
maintainer can read, and reports a failure nowhere: a layout it cannot
render is served broken until somebody fetches the page. The workflow
builds the same site with the same gem, where a failure is a red check.
`build_type: workflow` would replace that builder with an Actions workflow
and make the failure visible by itself; it is a change of its own, and
what it costs is a deploy that no longer happens by pushing to `main`.

`cname` is the custom domain, and `CNAME` in the root is the same value: A
records for `btclib.org` and the `https_enforced` certificate hang off it.
The file is what Pages reads on each build, so deleting it from the tree
un-sets the setting on the next push.

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
  version follows is *accepted*, answered with `{"build_triggered": false,
  "versions": []}`, which is a green delivery and a site frozen at its last
  build (issue #574).
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

Tags older than the rule are mostly not activatable rather than merely not
activated: a build needs `.readthedocs.yaml`, which reaches back to
`v2026.8.7` alone, so an older tag answers with a failed build instead of
with the documentation of 2023. None was backfilled, `v2026.8.9` — which
could have been — included, so `/en/v<version>/` starts at the first tag
pushed after the rule and there is nothing behind it. `/en/stable/` is the
last release either way, which is what makes the backfill skippable.

**The webhook has to carry a secret.** A delivery from one that does not is
refused with 400 and the reason in the body, which GitHub records in the
hook's delivery log and reports nowhere else:

```shell
gh api repos/btclib-org/btclib/hooks \
  --jq '.[] | [.config.url, (.config.secret != null), .last_response.code]'
# ["https://app.readthedocs.org/api/v2/webhook/btclib/331149/",true,200]
```

A hook added here by hand has no secret and cannot be given one that Read
the Docs knows. The one that works was issued by the project's integration
page, and that is also how it is replaced: delete the integration there
and add it again, rather than editing the hook on this side.

## Plan-gated settings

Some settings cannot be enabled and fail silently: secret scanning's
non-provider patterns and validity checks need paid Secret Protection,
and the API answers a PATCH with 200 while leaving them disabled. Do not
read that 200 as success. The `detect-secrets` hook is the compensating
control.
