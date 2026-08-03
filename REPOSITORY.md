# Repository configuration

Read this before changing a workflow, a branch rule or a repository
setting; writing code does not need it. `CLAUDE.md` points here rather
than carrying it, so that a session fixing a bug in `ecc/` does not hold
it in context.

The branch rules and the repository settings live *outside* the
repository, so this file is the whole of them: nothing here can be
recovered by reading the tree.

## Required checks on master

**Never name matrix contexts in the branch rule.** The rule lives outside
the repository, so a context that stops being produced blocks every merge
with nothing in the tree to explain why. `tests-passed` is an aggregate
job at the end of `test.yml` that `needs` the matrix; a new job in
`test.yml` belongs in that job's `needs`, or it gates nothing.

`master` requires four checks, and only four:

| Check | Produced by |
| --- | --- |
| `tests-passed` | `test.yml`, aggregate over the matrix |
| `Lint and type-check` | `lint.yml`, first job |
| `CodeQL` | CodeQL workflow |
| `Build the documentation` | `lint.yml`, second job |

`Build the documentation` is named on its own on purpose: a rule naming
`Lint and type-check` alone would leave a red docs build outside the
required checks entirely. `lint.yml` triggers on `pull_request` with no
branch and no `paths` filter, so both its jobs report on every pull
request, forks included.

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

`dev`: no force pushes, no deletions, linear history, and nothing else —
no required check, no review, no signature, so a direct push still works,
which is what `uv run` and both bots rely on.

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
