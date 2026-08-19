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

`main` requires four checks, and only four:

| Check | Produced by |
| --- | --- |
| `test: every job passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, its only job |
| `Build the documentation` | `docs.yml`, its only job |
| `Regtest against Bitcoin Core` | `integration.yml`, its regtest job |

A workflow needs an aggregate when every one of its jobs has to gate: the
matrix of `test.yml` is the one, and a context naming one cell of it would
leave the rest outside the rule. Where a single job is what gates, that job
*is* the context, which is why three of the four are job names.
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
twenty concurrent jobs; a commit here asked for thirty-nine, and measured
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
Free gives an organization twenty concurrent jobs, a pull request here
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

### The maintainer's second path: two rulesets beside the classic rule

`enforce_admins` off is one switch that exempts an administrator from
every rule above at once — there is no way, inside the classic rule
alone, to relax the review requirement for a solo merge while keeping
signatures and linear history unconditional. Every issue tracking a
change to the library gets one of two endings: a pull request that
carries a real review from somebody else, which closes it automatically
on merge (`Closes #N`); or, when the maintainer is working alone, this
second path, which closes it by hand, referencing the commit that
landed.

Two rulesets carry that split, additive to the classic rule rather than
replacing it — rules aggregate across rulesets and classic protection,
taking the most restrictive combination wherever they overlap:

- `main-integrity`: required signatures, required linear history, no
  force pushes, no deletions. No bypass actor, for anyone, ever.
- `main-self-merge`: require a pull request (one approving review,
  dismiss stale reviews, conversation resolution). Bypass: the
  maintainer, "Always" mode.

"Always" is what permits a direct push rather than only a PR merge
without review, and it is scoped to `main-self-merge` alone: being
bypassed there does not exempt from `main-integrity`, which has no
bypass entry for anyone. Verified on a disposable branch before either
ruleset touched `main`: a direct push with no bypass was rejected
("Changes must be made through a pull request"); the same push,
bypassed, was accepted as a fast-forward with no new commit created
("Bypassed rule violations"); a force-push under that same bypass was
still rejected ("Cannot force-push to this branch"), which is the proof
that the isolation holds rather than an assumption about it.

What the maintainer cannot do, with or without the bypass, is land
something on `main` that is unsigned or that rewrites history:
`main-integrity` answers that question the same way for every push,
admin or not. Exercising the bypass is therefore always the same
sequence — the fast-forward is what has to hold, not a force push
standing in for one:

```shell
git fetch origin && git rebase origin/main   # must end fast-forwardable
git log --format='%h %G?' origin/main..      # every commit G, none N
# local gates: pytest, pre-commit run --all-files, the sphinx -W build
git push origin <branch>:main
```

Where the branch carries more than one commit it is squashed into a
single signed commit first — `git reset --soft origin/main && git
commit`, with `--author` where the branch is somebody else's, GitHub's
button being what would otherwise have kept their name on it — and that
commit is what the push fast-forwards. Squashing here rather than
pressing the button is the whole of what keeps the signature the
maintainer's: GitHub composes a squash server-side and signs it with its
own web-flow key, while a push signs nothing and has nothing to sign, the
commit arriving with the signature it already carried.

**The bypass is not the whole of the permission.** The classic protection
still carries `required_pull_request_reviews` and its `strict` required
checks, and what a push to `main` clears those with is `enforce_admins`
being `false` and the pusher holding `admin`; the ruleset bypass alone
would not be enough. So the path depends on two settings, and the fragile
one is that: turning `enforce_admins` on closes the fast-forward whatever
the ruleset says.

**Whether GitHub reconciles the push depends on one thing: whether what
lands is the sha the pull request names at that moment**, a pull request
being marked merged when its head becomes reachable from the base branch.

- **it names what lands** — the branch's own head is fast-forwarded,
  whether it reached that shape as one commit or as a squash **pushed to
  the branch first**, and a rebase force-pushed to the branch is this
  case too. GitHub marks the pull request **Merged** on its own, the
  `Closes #N` in its description closes the issue, and
  `delete_branch_on_merge` takes the head branch a second later.
- **it names something else** — the squash or the rebase was made locally
  and pushed straight to `main`. What lands is an object no pull request
  names, so nothing is reconciled and nothing is deleted: close it by
  hand, and let the issue close from the `Closes #N` in the *commit
  message*, which is the reason for the keyword to be there and not only
  in the description.

Which is an argument for pushing the squash to the branch before landing
it: CI then runs on the very object that will land rather than on a head
that never will, and the reconciliation does the closing. Both halves
were measured here — #953 was squashed straight onto `main` and is
**Closed** with `mergedAt: null`, its issue having closed twenty-two
seconds earlier from the commit message, and #930 was deleted ahead of
the reconciliation and came out Closed with its commit on `main` all the
same.

## Merge methods

**No button is how a pull request lands here.** Every landing is the
fast-forward of the sequence above, through the `main-self-merge` bypass,
with the squash a multi-commit branch needs made locally before it. What
that buys is what a button cannot: the commit is signed by the maintainer
rather than by GitHub's web-flow key, and where what lands is the head CI
ran on, its sha does not change either, so a branch stacked on it keeps
applying instead of needing a rebase and a fresh run of the matrix per
level.

What the settings below bound is therefore a landing nobody drove from a
shell, and **squash is the only *button* enabled**:

```shell
gh api repos/btclib-org/btclib \
  --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge}'
```

answers `true` for the first and `false` for the other two. The
auto-merge dropdown below is what reaches that button, and GitHub's key
is what signs whatever it presses.

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

A fast-forward is covered where GitHub reconciles it, the setting hanging
on the merge GitHub records rather than on the one a button performed.
Measured in btclib-secp256k1, whose configuration is this one: a squash
pushed to the branch and then fast-forwarded was marked Merged at
12:39:19 and had `head_ref_deleted` at 12:39:20, with nobody asking. What
is left there is not to get ahead of it, #930 being what that costs; the
deletion by hand belongs to the landing GitHub never sees.

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more must declare it. Four of those declarations are in
`release.yml`: `contents: write` on `github-release`, `id-token: write` on
the two publish jobs, and `id-token: write` with `attestations: write` on
`attest`. The fifth is `codeql.yml`'s `analyze`, whose
`security-events: write` is what uploading a SARIF to code scanning takes,
with `actions: read` beside it — redundant while this repository is public,
and written down so that the file does not quietly stop working the day it
is not. Its aggregate job needs none of that and declares none of it: one
elevation per job is the shape to keep — the job that writes releases holds
no OIDC token, and the job that signs writes no release — and
`vendored-vectors.yml` is the one place that departs from it, declaring
`issues: write` at the workflow level where its only job would do.
The workflow-level `permissions: contents: read` is belt and braces; keep
it, it is what makes the intent readable in the file.

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
