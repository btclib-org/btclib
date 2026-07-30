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
uv run pre-commit run mypy --files btclib/ec/curve.py   # one hook
uv run --python 3.9 pytest                      # another interpreter
```

`CONTRIBUTING.md` has the command for each CI job, verbatim; keep it true
if a workflow changes.

## Architecture

Pure-python bitcoin cryptography, with secp256k1 arithmetic delegated to
the `btclib_libsecp256k1` cffi bindings — and delegated conditionally,
which is the single most important thing to know before touching
`btclib/ec/` or `btclib/ecc/`:

- `ec.curve.mult` calls the bindings for secp256k1 and the generator
  alone; anything else runs the python double-and-add of
  `ec/curve_group.py`
- `ecc.dsa.sign` calls them for secp256k1 with sha256, lower-s, and no
  caller-imposed nonce; `ecc.ssa.sign` for secp256k1 with sha256
- the python path is not dead code and not constant-time: it serves every
  other curve, other hash functions, and caller-supplied nonces, and the
  test suite validates it *against* the bindings, which are the authority
  on the answer. `SECURITY.md` states this as a limitation; keep it true

Layers, roughly bottom-up: `ec/` (curve arithmetic) → `ecc/` (dsa, ssa,
bms, rfc6979/bip340 nonces) → keys and encodings (`to_prv_key`,
`to_pub_key`, `b58`, `b32`, `bech32`, `base58`) → `bip32/`, `mnemonic/` →
`script/`, `tx/`, `block/`, `psbt/`, `descriptors`. `alias.py` holds the
type aliases the public API accepts, and much of the surface takes
"anything convertible" rather than one type.

## Non-obvious facts that will otherwise waste a session

- **Work happens on `dev`**; `master` is the default branch and receives
  merges from it. Dependabot and pre-commit.ci both target `dev`.
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
- **`master` is protected and `dev` is not**, which is asymmetric on
  purpose but is not written down anywhere the rules themselves can be
  read, so here is the whole of it. `master`: those three checks with
  `strict`, one approving review, `dismiss_stale_reviews`, **required
  signatures**, linear history, no force pushes, no deletions,
  `required_conversation_resolution`, and `enforce_admins` *off* — an
  administrator can bypass all of it. `dev`: nothing at all
  (`gh api repos/btclib-org/btclib/branches/dev/protection` is a 404),
  while Dependabot targets it for both ecosystems, pre-commit.ci
  autoupdates it, and Dependabot security updates are on. So bot-authored
  changes reach `master` through a branch anyone with write access can push
  to directly, which is issue #158.
  Two things to know before copying `master`'s rules onto `dev`, both
  measured rather than assumed: commits on `dev` are **unsigned**
  (`git log --format='%G?'` prints `N`), so `required_signatures` would
  reject every push including the bots'; and one approving review on a
  solo-maintainer branch cannot be satisfied by the author, GitHub not
  allowing self-approval. Whatever `dev` gets has to be chosen, not copied.
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
