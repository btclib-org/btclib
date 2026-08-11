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

`main` requires five checks, and only five:

| Check | Produced by |
| --- | --- |
| `test: every job passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, its only job |
| `Build the documentation` | `docs.yml`, its only job |
| `Regtest against Bitcoin Core` | `integration.yml`, its only job |
| `codeql: every job passed` | `codeql.yml`, aggregate over the languages |

A workflow with one job needs no aggregate: the job *is* the context, which
is why three of the five are job names. The day one of them grows a second
job, an aggregate and a change to this rule are what that costs.

`Build the documentation` is named on its own on purpose: a rule naming
`Lint and type-check` alone would leave a red docs build outside the
required checks entirely. It moved from `lint.yml` to a workflow of its own
without the rule changing, which is worth knowing before renaming anything:
a context is matched by name, not by the workflow that reported it, so
moving a job is free and renaming one is not — the pull request that renames
a required check stops producing the old name and never produces one the
rule is waiting for.

`Regtest against Bitcoin Core` is the newest of the five, and it is here
because its cost was measured rather than assumed: 36 seconds of work for a
disposable regtest node, which is less than the matrix it runs beside. It
answers the one claim the recorded vectors cannot make. `integration.yml`
therefore carries no `paths` filter: a required check that never runs blocks
a merge, where a skipped one satisfies it.

`codeql: every job passed` is the only one of the five whose predecessor was
not a file at all. Code scanning ran from default setup, a repository
setting, which made the check that reads these workflows for an injected
expression the one part of CI no diff could review — while every other check
is a workflow with its actions pinned to commit SHAs. `codeql.yml` holds it
now, one job per language and an aggregate over them, for the reason
`test.yml` has one; the section below has how the switch was thrown, because
the two cannot be exchanged in either order without a step that blocks
every merge.

Renaming a required check is the one change that cannot be made in a pull
request, so the rule moves first, against the branch, and the pull request
that renames the job reports the name the rule now wants:

```shell
branch=repos/btclib-org/btclib/branches/main
gh api -X PATCH "$branch"/protection/required_status_checks \
  -F strict=true \
  -f 'contexts[]=test: every job passed' \
  -f 'contexts[]=Lint and type-check' \
  -f 'contexts[]=Build the documentation' \
  -f 'contexts[]=Regtest against Bitcoin Core' \
  -f 'contexts[]=codeql: every job passed'
```

That `PATCH` sends `contexts`, which names no app, and what is there is
not uniformly that: some of the five are bound to the app that produces
them and the rest to nothing, which lets any app reporting one of those
names satisfy it. Read it before assuming either shape:

```shell
gh api repos/btclib-org/btclib/branches/main/protection \
  --jq '.required_status_checks.checks'   # PATCH that sub-endpoint
```

Binding all five is the stricter form — `checks` with an `app_id` in the
body, 15368 for Actions, rather than the bare `contexts` list — and
adopting it is a decision separate from this list.

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
rather than absent — which is why the exchange has an order. These five
steps are the order that never leaves `main` unmergeable, and 1, 2 and 5
are a token rather than a pull request, so only a human can perform them:

1. patch the rule to drop the `CodeQL` context, the other four staying;
1. disable default setup;
1. re-run the pull request's checks: the upload that was refused is
   accepted now, so `codeql: every job passed` goes green;
1. merge;
1. patch the rule to add `codeql: every job passed`.

Step 2 is what makes the setting let go of the analysis. It is not the
command that enabled default setup and there is no need to keep that one:
what a browser switched on, this switches off, and the tree is where the
configuration lives afterwards.

```shell
gh api -X PATCH \
  repos/btclib-org/btclib/code-scanning/default-setup \
  -F state=not-configured
```

Steps 1 and 5 patch the `checks` array rather than `contexts`, so that the
bindings the rule already has survive the edit, and **a JSON body on stdin
is what that takes**: `-f` sends every value as a string and the endpoint
answers 422 for a string `app_id`. Step 1:

```shell
branch=repos/btclib-org/btclib/branches/main
gh api -X PATCH "$branch"/protection/required_status_checks --input - <<'JSON'
{
  "strict": true,
  "checks": [
    {"context": "test: every job passed", "app_id": 15368},
    {"context": "Regtest against Bitcoin Core", "app_id": 15368},
    {"context": "Lint and type-check"},
    {"context": "Build the documentation"}
  ]
}
JSON
```

Step 5 is that body with one entry added, bound to Actions because Actions
is what reports it — the `CodeQL` it replaces was unbound for the opposite
reason, the app producing it not being Actions:

```shell
branch=repos/btclib-org/btclib/branches/main
gh api -X PATCH "$branch"/protection/required_status_checks --input - <<'JSON'
{
  "strict": true,
  "checks": [
    {"context": "test: every job passed", "app_id": 15368},
    {"context": "Regtest against Bitcoin Core", "app_id": 15368},
    {"context": "codeql: every job passed", "app_id": 15368},
    {"context": "Lint and type-check"},
    {"context": "Build the documentation"}
  ]
}
JSON
```

## Branch protection

`main` is the only branch, and everything reaches it through a pull
request: the five checks above with `strict`, one approving review,
`dismiss_stale_reviews`, **required signatures**, linear history, no force
pushes, no deletions, `required_conversation_resolution`, and
`enforce_admins` *off* — an administrator can bypass all of it.

That last one is what carries the review. A review cannot be satisfied by
its author, GitHub not allowing self-approval, so on a solo-maintainer
repository the rule as written stops every pull request the maintainer
opens, and the bypass is what lets one merge at all. The trade is the
review's other half: it is there for a contributor's pull request, where
there *is* somebody else to ask.

Required signatures cost the maintainer nothing for the same reason
nothing here pushes to `main` directly: the only thing writing to it is a
merge GitHub performs itself, and GitHub signs those with its web-flow
key.

Dependabot, its security updates and pre-commit.ci all open pull requests
here, none of them naming a target branch: what they get is the default
branch, and it is the only branch there is. Issue #158 was the other
arrangement — two bots pushing through an integration branch that carried
no protection at all — and one branch is what closed it.

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

## Plan-gated settings

Some settings cannot be enabled and fail silently: secret scanning's
non-provider patterns and validity checks need paid Secret Protection,
and the API answers a PATCH with 200 while leaving them disabled. Do not
read that 200 as success. The `detect-secrets` hook is the compensating
control.
