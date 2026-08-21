# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

Repository configuration — branch protection, required checks, token
permissions, publishing environments, secret scanning — is in
`REPOSITORY.md`. Read that file before changing a workflow, a branch rule
or a repository setting. Writing code does not need it.

Reviewing a pull request — what a review establishes before it gives an
ack, what a finding must contain, and why everything it notices that the
diff is not about becomes an issue rather than a comment — is
`REVIEWING.md`, and `/review` is that file as a command. Read it before
reviewing a pull request, and before opening one: it is what the pull
request will be answered against.

## Commands

uv is the only tool that must be installed; it fetches interpreters,
linters and packaging tools itself. `uv sync` creates the environment.

```shell
uv run pytest                                   # the suite, gated at 100%
uv run pytest tests/ecc/dsa_test.py             # one file, not gated
uv run pytest -k test_low_cardinality           # one test, not gated
uv run pre-commit run --all-files               # every gate, see below
uv run pre-commit run mypy --files btclib/curves/curve.py   # one hook
uv run --python 3.10 pytest                     # another interpreter
```

`CONTRIBUTING.md` has the command for each CI job, verbatim; keep it true
if a workflow changes.

## Architecture

Pure-Python bitcoin cryptography, with secp256k1 arithmetic delegated to
the `btclib_secp256k1` cffi bindings — and delegated conditionally,
which is the single most important thing to know before touching
`btclib/curves/` or `btclib/ecc/`:

- `curves.curve.mult`, `double_mult_var` and `multi_mult_var` call the bindings
  for secp256k1 and any point of it, a zero scalar and the point at
  infinity excepted: libsecp256k1 has no scalar for the one and no public
  key for the other, so those two — and a sum landing on infinity — are
  recognized before the call and answered by the Python arithmetic of
  `curves/curve_group.py`, which is what every other curve runs
- `ecc.dsa.sign` calls them for secp256k1 with sha256, lower-s, and no
  caller-imposed nonce; `ecc.ssa.sign` for secp256k1 with sha256, a
  message of **any** size, and no sign-to-contract commitment. The size
  used to be a third condition, which was issue 169 and the four
  arbitrary-size vectors BIP340 gained in 2023-04: the bindings'
  `ssa.sign` takes a 32-byte message, but `ssa.sign_custom` beside it
  takes any, and `ssa.verify` always did — it was the gate in front of
  them that sent those four down the Python path
- the Python path is not dead code and not constant-time: it serves every
  other curve, other hash functions, and caller-supplied nonces, and the
  test suite validates it *against* the bindings, which are the authority
  on the answer. `SECURITY.md` publishes this as a known limitation

Layers, roughly bottom-up: `curves/` (curve arithmetic) → `ecc/` (dsa, ssa,
bms, borromean, pedersen, rfc6979/bip340 nonces). At the key boundary,
`base58` and `bech32` are the low-level codecs; `bip32/` depends on
`base58`; `to_prv_key` and `to_pub_key` depend on `bip32/`; and `b58`
and `b32` depend on those converters. `slip132` therefore sits above the
address encodings, beside `bip44`. `mnemonic/`, `script/`, `tx/`,
`block/`, `psbt/` and `descriptors` build on those layers. `alias.py`
holds the type aliases the public API accepts, and much of the surface
takes "anything convertible" rather than one type.

Each of those pairs is one idea split in two, and each split runs one
way only: `curves/` is arithmetic and `ecc/` is what is built on it;
`base58` and `bech32` are codecs with no bitcoin in them, `b58` and `b32`
the bitcoin semantics on top. `ecc` imports `curves`, `b58` imports
`base58`, `b32` imports `bech32`, and never the reverse. The README
carries the same layout as a table, and each of these modules states its
own direction in its docstring, wherever that direction changes.

## The primary checkout is the maintainer's

**Never work in it.** No edit, no `git add`, no commit, no branch switch,
no rebase, no `git stash`, no `pre-commit run` — the hooks fix files in
place. It is the maintainer's window on the tree: whatever is open in
their editor, whatever they have half-staged, and the branch they are
looking at are theirs, and one working tree has one index and one HEAD to
lose. Reading it is fine — `git log`, `git show`, `git diff`, `gh`, and a
`git fetch`, which writes refs and leaves the work tree alone.

**Every session works in a worktree**, its own, from the first edit:

```shell
WT=<scratchpad>/wt<issue>
git worktree add -b <branch> "$WT" origin/main
cd "$WT" && uv sync --locked          # a second venv, about a minute
# edit, gate and commit here, then
git push origin HEAD:refs/heads/<branch>
git worktree remove --force "$WT"     # removing it is part of finishing
```

The venv is the whole of the cost, and it buys the thing that matters: a
commit cannot contain work that was never in it. Expect `origin/main` to
move while you work, so `git fetch && git rebase origin/main` before
pushing, resolving in favour of *both* sides (their change and yours,
both CHANGELOG.md bullets).

**Never `git stash` in a worktree either: `refs/stash` is shared.** A
worktree isolates files, not refs. The stash is a single ref in the
common `.git`, so `git stash push` pushes onto the same stack every other
session pops from — and on a clean tree it creates nothing, so the `git
stash pop` that follows applies and *drops* whatever another session
shelved. Commit to your own branch instead: a branch is per-worktree in
the way the stash only looks to be. What is already lost is still in the
object store — `git fsck --unreachable` names the commit and `git stash
store <sha>` puts the ref back.

**Do not rewrite `refs/heads/main`, or advance it with work that is not
yours.** `git update-ref`, or a push carrying another session's commits,
leaves every working tree's files alone and moves the base under them, so
their next commit — built on the older copy — reverts what just landed.
Your own branch is what you push, and the pull request is what moves
`main`: CONTRIBUTING.md's "Pull Request" section has how a branch under
review is corrected and how it is merged.

## Model

The default model for this repository is Sonnet. Switch to Opus only
for architectural decisions with conflicting constraints -- design
choices with non-obvious trade-offs, refactors that cross the layer
boundaries above with unclear dependencies, diagnosis where the
symptom does not point to the cause. Use `/model opus` for the
session, then switch back to Sonnet.

Do not use Fable unless explicitly instructed.

## Non-obvious facts that will otherwise waste a session

- **`main` is the only branch**, and nothing is pushed to it directly:
  every change lands through a pull request, Dependabot's and
  pre-commit.ci's included, neither of them naming a branch. Branch
  protection, and why it is what it is, is `REPOSITORY.md`.
- **A branch's CI run can be `cancelled` rather than green.** `test.yml`'s
  concurrency group is
  `test-${{ github.event.pull_request.number || github.ref }}` (plus a
  release-only suffix) with cancel-in-progress, so the next push kills
  the run for the previous commit. The local gates below are the
  evidence; `cancelled` is not `failure`, and waiting for a busy
  afternoon to settle is waiting for nothing.
- **A bare `uv run pytest` is the coverage gate too**: `--cov` is in
  addopts, so the 100% ratchet fails locally instead of only in the
  `coverage` job. A run that selects a subset — paths, `-k`, `-m` — is
  reported and not gated, `tests/conftest.py`'s `coverage_fail_under`
  being what drops the threshold; `--lf`, `--deselect` and an early `-x`
  are not selections and will fail on the tree's coverage. So a green
  full run is the evidence, and a red partial one is worth re-reading
  before believing. Setting the threshold from a plugin means writing to
  `config.known_args_namespace`: pytest-cov reads that copy and never
  `config.option`, so the obvious spelling changes nothing and fails
  silently.
- **`.pre-commit-config.yaml` is the lint gate**, and `lint.yml`'s first
  job runs exactly it. Never add a second list of the same tools to a
  workflow. mypy is a *local* hook shelling out to uv on purpose: the
  mirrors-mypy hook injects `--ignore-missing-imports`, which makes every
  bindings import `Any` and strict mode then fails; and its isolated
  environment would need the bindings declared a second time, beside
  `uv.lock` and pinned by hand.
- **`pre-commit` passing is not the lint gate passing: run sphinx too.**
  `lint.yml`'s second job runs it with `-W`, so a docstring docutils
  cannot parse fails the workflow while every hook passes — a name ending
  in an underscore is a reference to a link target (``mult_``, and the
  fix is those very backticks). Reproduce it before claiming the gate is
  green:

  ```shell
  uv run --locked --no-default-groups --group docs \
      sphinx-build -W --keep-going -b html docs/source docs/build/html
  ```

- **Prefix any `--python <version>` command with
  `UV_PROJECT_ENVIRONMENT=.venv-3.10`.** Without it, `uv run --python
  <version>` rebuilds `.venv`, and a group-restricted command then leaves
  pre-commit out of it: reproducing a matrix cell (`uv run --locked
  --no-default-groups --group test --python 3.10 pytest`) recreates the
  environment with only the `test` group's packages where a plain `uv
  sync` leaves the full dev set — and
  pre-commit's git hook `exec`s `.venv/bin/python -mpre_commit` by
  absolute path, which exists and lacks the module, so its "did you
  forget to activate your virtualenv" fallback never fires and the next
  `git commit` dies with `No module named pre_commit`. `uv sync` restores
  it. Without `--python` the same command prunes nothing, so it is the
  interpreter and not the groups that triggers it.
- **The version is declared once**, in `pyproject.toml`.
  `btclib.__version__` reads it back with `importlib.metadata`, and
  `docs/source/conf.py` parses the file (not the metadata, which would
  need the package installed).

## Conventions to match

- **Workflows**: every action pinned to a commit SHA with the tag in a
  trailing comment; every workflow declares `permissions: contents: read`
  and `timeout-minutes`; concurrency groups are named literally
  (`test-${{ github.event.pull_request.number || github.ref }}`), never
  through `github.workflow`, which in a called workflow is the caller's
  name; `checkout` passes
  `persist-credentials: false`; uv commands pass `--locked`, never
  `--frozen`. `actionlint` and `zizmor` are hooks, and both must stay at
  zero findings.
- **The prose style — tone, comments, docstrings, no history — is
  CONTRIBUTING.md's "Documentation and comments" section**, stated once
  there because contributors read that file and not this one. It
  governs the workflows and the pre-commit config too: the reasoning
  with its negative results is what makes those files reviewable, so
  match it rather than trimming it.
- **Markdown wraps at 80 columns**, tables included (MD013 is on), so
  long commands go in fenced blocks split with `\`.
- pytest is strict: a warning is an error, an unregistered marker is an
  error, an xfail that passes is a failure. Coverage has a `fail_under`
  ratchet in `pyproject.toml`.
- **CHANGELOG.md gets an entry for anything a user would notice**, in
  the group it belongs to; RELEASE_NOTES.md is the release notes on top
  of it and only moves for a change a user has to *act* on. The prose of
  the two is one fact each, deliberately: the breaking-changes list lives
  in RELEASE_NOTES.md and the detail behind it in CHANGELOG.md, so
  neither restates the other. A source-breaking change costs one edit
  more: a bullet in RELEASE_NOTES.md's breaking-changes list, with the
  "before" spelling checked against the `v2023.7.12` tag.
- **Never state how many of anything a file holds** — measure it when a
  release wants it, and do not estimate:

  ```shell
  grep -c '^- ' CHANGELOG.md   # the number, whenever it is wanted
  git ls-files 'tests/_data/*' 'tests/*/_data/*' \
      btclib/mnemonic/_data/wordlist.txt | grep -cv 'README.md'
  ```

  The why is in CONTRIBUTING.md's "Documentation and comments"; what
  this file adds is that nothing states a count now and tests keep it
  that way — `tests/release_notes_test.py` for CHANGELOG.md and
  RELEASE_NOTES.md, `tests/vendored_data_test.py` for
  `tests/_data/README.md` — failing on a stated count rather than on a
  wrong one.
- **A wall clock and a linter's findings are counts too**, and nothing
  fails on those: pyproject.toml's comments and tests/README.md state
  none, and keeping it that way is by hand. What a comment carries
  instead is the reason, which is what decided the setting, with the
  command that re-derives the number beside it:

  ```shell
  uv run ruff check --select N --no-cache btclib tests
  uv run mypy --enable-error-code=redundant-expr btclib tests
  uv run pytest --durations=0 --durations-min=0
  ```

  A survey that says "with the count, so that nobody has to run it
  again" is the shape to distrust: every one of the twelve it recorded
  was wrong when re-run. The exception is a count of what upstream
  published — `tests/_data/README.md`'s "121 vectors, Core's entire
  file" — which pins a vendored file rather than measuring this tree,
  and which `tests/vendored_data_test.py` spares on purpose.
- **CHANGELOG.md and RELEASE_NOTES.md are `merge=union`**, which is what
  `.gitattributes` is for: the insertion point conflicts too — two
  branches appending a bullet to the same group — and union keeps both
  sides' added lines rather than stopping at a conflict with nothing to
  decide, on rebases included. Its price is that these two files now
  never conflict at all, so two branches editing *the same* entry merge
  in silence, and a branch still carrying an edit to one of the old count
  paragraphs puts the number back on rebase without a word. Drop those
  edits while rebasing; the suite says whether you got them all.
  `tests/_data/README.md` cannot take the driver — union is right for a
  list of bullets and nonsense for the prose around them — so there the
  count had to go rather than be merged.

## Verifying

Check exit codes, not filtered output: `pre-commit run ... | grep -v
Passed` hides a failure. Run the command as documented before claiming it
works, and prefer measuring to asserting — every claim in this file was
checked against the tree, and the tree changes.
