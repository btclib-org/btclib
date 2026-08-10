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
| `CodeQL` | CodeQL workflow |

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
  -f 'contexts[]=CodeQL'
```

`contexts` rather than `checks` with an `app_id`, which is the shape the
rule already has here: binding each context to the app that produces it is
the stricter form, and adopting it is a separate decision from this list.

Each check is bound to the app that produces it — `checks` with an
`app_id` rather than the bare `contexts` list, 15368 for Actions and
57789 for CodeQL — so nothing else can satisfy one.

```shell
gh api repos/btclib-org/btclib/branches/master/protection \
  --jq '.required_status_checks'   # PATCH that sub-endpoint to change
```

**PATCH that sub-endpoint, never PUT the whole protection object**: a
partial PUT drops the reviews, the signatures and the rest. Repeat
`strict: true` in the body, which replaces the object rather than merging
into it.

## Branch protection, both branches

Both branches are protected, and differently on purpose.

`master`: those four checks with `strict`, one approving review,
`dismiss_stale_reviews`, **required signatures**, linear history, no force
pushes, no deletions, `required_conversation_resolution`, and
`enforce_admins` *off* — an administrator can bypass all of it.

`dev`: no force pushes, no deletions, linear history, resolved
conversations, and nothing beyond that — no required check, no review, no
signature, so a direct push still works, which is what `uv run` and both
bots rely on.

That asymmetry is the answer to issue #158, and it is a choice rather
than a copy for two measured reasons. Commits on `dev` are **unsigned**
(`git log --format='%G?'` prints `N`), so `required_signatures` there
would reject every push, the bots' included. And one approving review
cannot be satisfied by the author, GitHub not allowing self-approval, so
on a solo-maintainer branch it is a stop rather than a speed bump.

What `dev` does buy is the thing the issue was about: Dependabot targets
it for both ecosystems, pre-commit.ci autoupdates it, and Dependabot
security updates are on, so bot-authored commits reach `master` through
it — and the branch cannot be rewritten or deleted under them.

Requiring the four checks on `dev` as well is the next step if one is
wanted, and it costs the direct push.

## Head branches after a merge

`delete_branch_on_merge` is on, since 7 August 2026:

```shell
gh api repos/btclib-org/btclib --jq '.delete_branch_on_merge'
```

GitHub deletes the head branch of a pull request when it is merged, which
is what keeps the branch list a list of live work rather than a history of
every change ever made. It was turned on after a sweep that removed nine
merged head branches from here, none of which anybody could tell from live
work without comparing each against `dev` commit by commit.

Two cases it does not cover, both deliberate. A protected branch is never
deleted, protection winning over this setting, so the release pull request
that merges `dev` into `master` leaves `dev` where it is. And a pull
request **closed without merging** keeps its head branch: GitHub cannot
know whether that work was abandoned or is waiting, so those are the ones
still worth looking at now and then.

## Token permissions

**The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
needing more must declare it. Only `release.yml`'s `github-release` does
(`contents: write`), plus `id-token: write` on the two publish jobs. The
workflow-level `permissions: contents: read` is belt and braces; keep it,
it is what makes the intent readable in the file.

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
