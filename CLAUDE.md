# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Commands

uv is the only tool that must be installed; it fetches interpreters,
linters and packaging tools itself. `uv sync` creates the environment.

```shell
uv run pytest                                   # the suite
uv run pytest tests/ecc/test_dsa.py             # one file
uv run pytest -k test_low_cardinality           # one test
uv run pre-commit run --all-files               # every gate, see below
uv run pre-commit run mypy --files btclib/curves/curve.py   # one hook
uv run --python 3.9 pytest                      # another interpreter
```

`CONTRIBUTING.md` has the command for each CI job, verbatim; keep it true
if a workflow changes.

## Architecture

Pure-python bitcoin cryptography, with secp256k1 arithmetic delegated to
the `btclib_libsecp256k1` cffi bindings — and delegated conditionally,
which is the single most important thing to know before touching
`btclib/curves/` or `btclib/ecc/`:

- `curves.curve.mult` calls the bindings for secp256k1 and the generator
  alone; anything else runs the python double-and-add of
  `curves/curve_group.py`
- `ecc.dsa.sign` calls them for secp256k1 with sha256, lower-s, and no
  caller-imposed nonce; `ecc.ssa.sign` for secp256k1 with sha256 **and a
  32-byte message**. That last clause is issue 169: BIP340 lifted its
  32-byte restriction in 2023-04, btclib takes a message of any size since,
  and the bindings still answer "the message hash must be 32 bytes", so a
  message of any other length takes the python path — which makes it the
  only path that can verify four of BIP340's own vectors
- the python path is not dead code and not constant-time: it serves every
  other curve, other hash functions, and caller-supplied nonces, and the
  test suite validates it *against* the bindings, which are the authority
  on the answer. `SECURITY.md` states this as a limitation; keep it true

Layers, roughly bottom-up: `curves/` (curve arithmetic) → `ecc/` (dsa, ssa,
bms, borromean, pedersen, rfc6979/bip340 nonces) → keys and encodings
(`to_prv_key`, `to_pub_key`, `b58`, `b32`, `bech32`, `base58`) → `bip32/`,
`mnemonic/` → `script/`, `tx/`, `block/`, `psbt/`, `descriptors`.
`alias.py` holds the type aliases the public API accepts, and much of the
surface takes "anything convertible" rather than one type.

Three of those pairs are one idea split in two, and each split runs one
way only: `curves/` is arithmetic and `ecc/` is what is built on it;
`base58` and `bech32` are codecs with no bitcoin in them, `b58` and `b32`
the bitcoin semantics on top. `ecc` imports `curves`, `b58` imports
`base58`, `b32` imports `bech32`, and never the reverse. `curves/` was
`ec/` until issue 148, one character from `ecc/`; the README has the
layout as a table, and each of the six modules says it in its own
docstring.

## Non-obvious facts that will otherwise waste a session

- **A session works in its own worktree, never in the shared checkout.**
  Several sessions run against this repository at the same time, and one
  working tree cannot hold two of them: a plain `git commit` (or `git add
  -A`) picks up whatever another session has staged, and `git rebase`,
  `git stash` and the `pre-commit` hooks that fix files in place rewrite
  or shelve files that are not this session's. So `git worktree add
  --detach <scratchpad>/wt<issue> dev`, `uv sync --locked` in it (a second
  venv, about a minute), then edit, gate and commit *there*, `git push
  origin HEAD:dev`, and `git worktree remove --force` at the end. Nothing
  destructive then reaches a file another session holds, and the commit
  cannot contain their work because their edits were never in it. Expect
  the push to be rejected — `origin/dev` moves while you work — so `git
  fetch && git rebase origin/dev` in the worktree, resolving in favour of
  *both* sides (their change and yours, both HISTORY.md bullets).
  Committing from the shared tree instead takes a throwaway index
  (`GIT_INDEX_FILE`, `git read-tree HEAD`, `git update-index --add` for
  your paths only, `git write-tree`, `git commit-tree`, then
  `git update-ref` guarded by the old value); that is the measure of what
  the worktree buys.
- **Work happens on `dev`**; `master` is the default branch and receives
  merges from it. Dependabot and pre-commit.ci both target `dev`.
- **A dev CI run is usually `cancelled`, not green.** `test.yml`'s
  concurrency group is `test-${{ github.ref }}` with cancel-in-progress,
  so the next session's push to `dev` kills the run for the previous
  commit. The local gates below are the evidence; `cancelled` is not
  `failure`, and waiting for a busy afternoon to settle is waiting for
  nothing.
- **`.pre-commit-config.yaml` is the lint gate**, and `lint.yml` runs
  exactly it. Never add a second list of the same tools to a workflow.
  mypy is a *local* hook shelling out to uv on purpose: the mirrors-mypy
  hook injects `--ignore-missing-imports`, which makes every bindings
  import `Any` and strict mode then fails; and the bindings cannot be
  declared in an isolated hook environment, not being on PyPI.
- **The version is declared once**, in `pyproject.toml`.
  `btclib.__version__` reads it back with `importlib.metadata`, and
  `docs/source/conf.py` parses the file (not the metadata, which would
  need the package installed).
- **`master` requires three checks**, and only three: `tests-passed`,
  `Lint and type-check`, `CodeQL`. `tests-passed` is an aggregate job at
  the end of `test.yml` that `needs` the matrix — never name matrix
  contexts in the branch rule, because the rule lives outside the
  repository and a context that stops being produced blocks every merge.
  A new job in `test.yml` belongs in that job's `needs`, or it gates
  nothing.
- **Both branches are protected, and differently on purpose.** The rules
  live outside the repository, so here is the whole of them. `master`:
  those three checks with `strict`, one approving review,
  `dismiss_stale_reviews`, **required signatures**, linear history, no
  force pushes, no deletions, `required_conversation_resolution`, and
  `enforce_admins` *off* — an administrator can bypass all of it. `dev`:
  no force pushes, no deletions, linear history, and nothing else — no
  required check, no review, no signature, so a direct push still works,
  which is what `uv run` and both bots rely on.
  That asymmetry is the answer to issue #158, and it is a choice rather
  than a copy for two measured reasons. Commits on `dev` are **unsigned**
  (`git log --format='%G?'` prints `N`), so `required_signatures` there
  would reject every push, the bots' included. And one approving review
  cannot be satisfied by the author, GitHub not allowing self-approval, so
  on a solo-maintainer branch it is a stop rather than a speed bump. What
  `dev` does now buy is the thing the issue was about: Dependabot targets
  it for both ecosystems, pre-commit.ci autoupdates it, and Dependabot
  security updates are on, so bot-authored commits reach `master` through
  it — and that branch can no longer be rewritten or deleted under them.
  Requiring the three checks on `dev` as well is the next step if one is
  wanted, and it costs the direct push.
- **The default `GITHUB_TOKEN` is read-only repository-wide**, so a job
  needing more must declare it (only `release.yml`'s `github-release`
  does, `contents: write`, plus `id-token: write` on the two publish
  jobs). The workflow-level `permissions: contents: read` is now belt and
  braces; keep it, it is what makes the intent readable in the file.
- **Publishing waits for an approval**: the `pypi` and `testpypi`
  environments both require a review, and `pypi` is restricted to `v*`
  tags. `RELEASING.md` records the reasoning, including why self-review
  stays allowed.
- **Some plan-gated settings cannot be enabled**: secret scanning's
  non-provider patterns and validity checks need paid Secret Protection,
  and the API answers a PATCH with 200 while leaving them disabled. The
  `detect-secrets` hook is the compensating control.
- `uv run --no-sources` rewrites `uv.lock`; restore it before committing.

## Conventions to match

- **Workflows**: every action pinned to a commit SHA with the tag in a
  trailing comment; every workflow declares `permissions: contents: read`
  and `timeout-minutes`; concurrency groups are named literally
  (`test-${{ github.ref }}`), never through `github.workflow`, which in a
  called workflow is the caller's name; `checkout` passes
  `persist-credentials: false`; uv commands pass `--locked`, never
  `--frozen`. `actionlint` and `zizmor` are hooks, and both must stay at
  zero findings.
- **Comments carry the reasoning, including the negative results** — why
  *not* the obvious alternative. That is the house style throughout the
  workflows and pre-commit config, and it is what makes those files
  reviewable; match it rather than trimming it.
- **Markdown wraps at 80 columns**, tables included (MD013 is on), so
  long commands go in fenced blocks split with `\`.
- pytest is strict: a warning is an error, an unregistered marker is an
  error, an xfail that passes is a failure. Coverage has a `fail_under`
  ratchet in `pyproject.toml`.
- HISTORY.md gets a line for anything a user would notice.

## Verifying

Check exit codes, not filtered output: `pre-commit run ... | grep -v
Passed` hides a failure. Run the command as documented before claiming it
works, and prefer measuring to asserting — every claim in this file was
checked against the tree, and the tree changes.
