# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

How to work here — what the issue tracker takes, the prose style, and how
a pull request is opened, corrected and landed — is `CONTRIBUTING.md`,
the same file in every repository of the organization up to its last
section; that section, *This repository in particular*, is this tree's
and holds the environment, the commands and what gates a merge.
Repository configuration is `REPOSITORY.md`: read it before changing a
workflow, a branch rule or a setting; writing code does not need it.
Reviewing is `REVIEWING.md`, and `/review` is that file as a command;
read it before reviewing a pull request and before opening one, since it
is what the pull request will be answered against.

## Architecture

Pure-Python bitcoin cryptography, with secp256k1 arithmetic delegated to
the `btclib_secp256k1` cffi bindings — and delegated conditionally,
which is the single most important thing to know before touching
`src/btclib/curves/` or `src/btclib/ecc/`:

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
`base58`; `b58` and `b32` depend on `to_pub_key`, which depends on
`to_prv_key`, and neither converter depends on `bip32/` -- so importing
`btclib.b58` does not put `btclib.bip32` in `sys.modules`, which is the
measurement behind the arrow. What each spelling of a key resolves
through is the module that defines it: a WIF is Base58Check with a prefix
and a flag, so `b58.prv_key_data_from_wif` reads it and
`b58.wif_from_prv_key` writes it; an extended key is BIP32's format, so
`bip32.prv_keyinfo_from_xprv`, `bip32.pub_keyinfo_from_xpub`,
`bip32.pub_keyinfo_from_xkey` and `bip32.point_from_xpub` are the parse,
and a caller holding one calls one of them and passes the scalar or the
point on (issue #1188). The scalar and the curve point in their octet
spellings are not a converter's either: they are facts about the curve,
so `curves.scalar_from_prv_key` and `curves.point_from_pub_key` read
them, and what is left to `to_prv_key` and `to_pub_key` is the network
and the compression a record carries and a key does not. `slip132` sits
above the address encodings, beside `bip44`. `mnemonic/`, `script/`,
`tx/`, `block/`, `psbt/` and `descriptors` build on those layers.
`alias.py` holds the type aliases the public API accepts, and much of the
surface takes "anything convertible" rather than one type.

Each of those pairs is one idea split in two, and each split runs one
way only: `curves/` is arithmetic and `ecc/` is what is built on it;
`base58` and `bech32` are codecs with no bitcoin in them, `b58` and `b32`
the bitcoin semantics on top. `ecc` imports `curves`, `b58` imports
`base58`, `b32` imports `bech32`, and never the reverse. The README
carries the same layout as a table, and each of these modules states its
own direction in its docstring, wherever that direction changes.

## The primary checkout is the maintainer's

**Never work in it.** No edit, no `git add`, no commit, no branch
switch, no rebase, no `git stash` — the hooks fix files in place. It is a
local reference only, and it stays on `main`.

Reading it is fine, but `git fetch` moves `refs/remotes/origin/main` and
leaves the work tree where it was, so a `grep` or a `Read` against the
checkout answers for whenever it was last brought forward, not for now.
The read that cannot go stale is `git show origin/main:<path>`: it
answers from the ref `git fetch` just moved, never from the tree.

Where the checkout has to be current rather than merely readable, a
fast-forward of a clean `main` brings it up:

```shell
git fetch origin && git merge --ff-only origin/main
```

That writes no commit, switches no branch and runs no hook, so it is on
the permitted side of *never work in it*, not an exception to it. Stop
if the checkout is not on `main` or is not clean: that is no longer
bringing it forward.

**Every session works in a worktree**, its own, from the first edit, named
`wt-<tracker>-<issue>-<repo>-<role>` rather than after the issue alone, most
general part first: an issue filed in `btclib-org/.github`'s tracker is the key
and the repository is a detail of it — `btclib-org/.github#255` is one issue
owed by seven repositories, `btclib-org/.github#177` by two — so the repository
is what varies underneath an issue rather than the other way round, which is why
`repo` comes after `issue`. Naming it that way also sorts every worktree of one
issue together, which is what a port leaves behind.

Each of the four parts earns its place against a different collision,
and none of them is the same collision. `tracker` is the repository
whose issue tracker holds the issue: an issue number is unique only
within one tracker, so `btclib-org/.github#45` and
`btclib-org/btclib#45` are different issues that would otherwise name
the same worktree. `issue` is what prevents the collision that has
actually happened — two worktrees of different work sharing a generic
basename in one repository's own `.git`, keyed on its path's basename.
`repo` prevents a different collision, a *path* one rather than a `.git`
one: two repositories each keep their own `.git/worktrees/<basename>`
and cannot collide there, but the workers of one session share one
scratchpad directory, so a session carrying one issue into several
repositories computes the same target path for each of them, and `git
worktree add` refuses a directory that already exists — or worse, a
second worker reads the first one's tree. `role` covers the narrower
case of a coder and its reviewer holding a worktree at once, which the
ordinary sequence avoids by each removing its own.

An issue of `btclib-org/.github`'s tracker, worked in `btclib` by a coder, names
its worktree `wt-github-255-btclib-coder`. The environment is created in the
worktree, not the checkout, by whatever that tree's own `CONTRIBUTING.md` names
under *The environment and the gates*, and a session reads that section, not
this one, for the command. The editing, the gates and the commits all happen in
the worktree before the push.

```shell
WT=<scratchpad>/wt-<tracker>-<issue>-<repo>-<role>
git worktree add "$WT" origin/main -b <branch>
git -C "$WT" push origin HEAD:refs/heads/<branch>
```

`-b <branch>` sits after the path and the commit-ish so that the placeholder
ends the command, which is section 9 of `btclib-org/.github`'s rule. With the
placeholder ahead of `"$WT"`, its `<` and its `>` are redirections performed
left to right, so the `>` is reached only where the reader's own directory
already holds the name `branch`: there the `<` succeeds, the line runs, and the
`>` takes `"$WT"` as its target — a path with no directory at it is the file it
creates. Ordinarily nothing holds that name, so the `<` fails first (`no such
file or directory: branch`) and the line ends before the `>` opens anything.

The push names the worktree with `git -C "$WT"` because a `cd` binds the
shell that runs it: a session that runs each line as its own command
starts the next one in the directory it began in, the primary checkout,
so a push after a `cd` offers that checkout's `HEAD` instead of the
worktree's. `env -C <dir>` is the same binding for a command that takes
no `-C` of its own. Neither binding rescues the assignment above it: a
session that loses the `cd` loses `WT` with it, and `git -C ""` is
documented to leave the working directory unchanged, so that push lands
the same way, exit 0 and no diagnostic. That silence is `git`'s rather
than the binding's: the BSD `env` macOS ships documents no case for an
empty `-C` and refuses one — `cannot change directory to ''`, exit 125 —
so a line bound with `env -C` stops there instead of running against the
wrong tree. What the `-C` buys is a path that can be written out in
full; write it out.

Removing the worktree is part of finishing, and it stands in a block of
its own: the block above ends in a placeholder, and a shell that
discards that line as a parse error reads the next as a fresh command —
which, in one block, is this line against whatever `$WT` already held.
Standing alone it is a second fence, so `${WT:?}` is what it writes:
with `$WT` unset or empty the expansion fails and the removal does not
run. Those are the only cases it catches — a `$WT` an earlier session or
command left holding a path expands, and the removal runs against
whatever worktree that path names.

```shell
git worktree remove --force "${WT:?}"
```

**Never `git stash` in a worktree either: `refs/stash` is shared.** A
worktree isolates files, not refs, so `git stash push` pushes onto the
same stack every other session pops from. Commit to your own branch
instead.

**Do not rewrite `refs/heads/main`, and move it only onto
`origin/main`.** That name is the local branch's, and no ruleset reaches
it: a ruleset binds the forge's copy. The fast-forward above moves it
onto `origin/main` and is inside that, where a merge, a commit on `main`
or an `update-ref` to a branch tip leaves the ref somewhere
`origin/main` is not. Your own branch is what you push, and the pull
request is what moves `origin/main`.

## Model

The default model for this repository is Sonnet. Switch to Opus only
for architectural decisions with conflicting constraints -- design
choices with non-obvious trade-offs, refactors that cross the layer
boundaries above with unclear dependencies, diagnosis where the
symptom does not point to the cause. Use `/model opus` for the
session, then switch back to Sonnet.

Do not use Fable unless explicitly instructed.

## Non-obvious facts that will otherwise waste a session

- **The version is declared once**, in `pyproject.toml`.
  `btclib.__version__` reads it back with `importlib.metadata`, and
  `docs/source/conf.py` parses the file (not the metadata, which would
  need the package installed).
- **`[tool.coverage.run] source` names the imported package, not a
  path.** coverage.py's `InOrOut.__init__` (`coverage/inorout.py`) tests
  each entry with `os.path.isdir`: `"btclib"` fails that test and is
  matched against import names instead, which is why the `src/` layout
  move left the line unchanged.
- **A config-level `exclude` does not reach a path named on the command
  line**, so the bare command a gate runs and the natural gesture —
  formatting the file just touched — answer differently, with nothing
  saying which one you asked. Enforcing an exclude against an explicit
  path is its own switch, and the tools here that need it say so:
  `typos` passes `--force-exclude` in its hook args, and
  `[tool.ruff] force-exclude` covers `[tool.ruff.format]`'s `exclude`.
  Lacking it, `ruff format CHANGELOG.md` rewrites a fenced python block
  inside a tag-sealed section, which
  `tests/changelog_immutability_test.py` then fails on. The divergence
  does not reach `[tool.mypy]`'s `exclude`, for an unrelated reason —
  its hook sets `pass_filenames: false` and names directories, so the
  exclude applies by recursion. Ask the tool and not the file, and read
  two key groups rather than one: `ruff check --show-settings` prints
  the switch as `file_resolver.force_exclude` and the file names it
  enforces as `formatter.exclude`, so `file_resolver.exclude`, which
  holds ruff's built-in defaults, answers no for a file the formatter
  does skip.
- **`tests/security_citations_test.py` checks every `path:line` citation
  `SECURITY.md` carries, but a symbol anchor pins only the function.**
  The backticked spans in front of a citation are what it claims: a
  dotted name (`ellswift.xdh`) is matched with `ast` against the
  definition enclosing the cited line, and a quotation of that line —
  the way musig2.py's sum is written — verbatim against the line itself.
  A citation carrying both, the name and then the quotation, is held to
  each of them, which is how dsa.py's `to_bytes` call is written; a name
  the prose puts further back than the quotation is read by nothing, so a
  claim about the definition a cited line sits in is written as that pair.
  A dotted-name anchor is satisfied by any line inside the right function,
  so a citation that drifts a few lines within its own function still
  passes on its name.
  `awk 'NR==N' <file>` verified against the claimed content, not against
  which function the line lands in, is still the check for a dotted-name
  citation — a citation landing inside the right function has still been
  off by several lines; a quoted-line citation already gets that from
  the gate.
- **`btclib-org/.github`'s weekly calendar is two tables, and either can
  move mid-campaign.** Section 10 splits day/hour (per workflow) from
  minute (per repository, `btclib` is `04`); the issue proposing one
  workflow's row can close and land days into a campaign that started
  before it did. Re-fetch the table
  (`gh api repos/btclib-org/.github/contents/README.md -H 'Accept:
  application/vnd.github.raw'`) rather than trusting a value read
  earlier in the same session.
- **`git merge-tree --write-tree` answers a `merge=union` file's
  mergeability better than GitHub's own `mergeStateStatus`.** The
  server-side check does not apply the driver `CHANGELOG.md` carries, so
  it can report `DIRTY`/`CONFLICTING` on a branch a local rebase
  resolves without one conflicting line. Run `merge-tree` first to tell
  a real conflict from this one before spending a rebase on it.
- **`git grep -E` silently drops `\b` word-boundary anchors.** A pattern
  like `\bused to \w+\b` compiles and runs without error under `-E` and
  answers zero on a file that has real matches; `--perl-regexp` is what
  actually honors `\b`. Prove a sweep's zero against a known positive
  before trusting it.
- **Asking what an index serves has to be asked from outside every
  checkout of this project**, and `--isolated --no-project` is not what
  makes it so. Measured on release day, one command
  (`uv run --isolated --no-project --with btclib python -c "import
  btclib; print(btclib.__version__)"`) three ways: `2026.9` run from the
  primary checkout, `2026.8.27` — what PyPI actually served — run from a
  directory belonging to nothing, and the checkout it answered from
  declaring `2026.8.26` in its own `pyproject.toml`. So it is not
  reading the tree either, and "the tree is current" is not the guard: a
  cached build of some earlier state of it is enough to shadow the
  index, and the version it hands back is plausible enough to be written
  into a release verification. `cd` to the scratchpad first, and print
  `btclib.__file__` beside the version when the answer decides anything.
- **A test that executes `docs/source/conf.py` by path only reproduces
  on CI, never locally.** `tomllib` (stdlib from 3.11) and
  `docutils`/`sphinx.*` (the `docs` group alone) are both imported
  unconditionally at the top of the file, before anything else runs.
  `tests/copyright_test.py` once loaded `conf.py` with
  `importlib.util` and executed it to check that its Sphinx `author`
  derives from `pyproject.toml` rather than repeating it; the coverage
  jobs (3.14, no `docs` group) failed on the `docutils` import and
  `os-macos`'s 3.10 cells failed on `tomllib` itself, and both stayed
  invisible under a contributor's own `uv sync`, which installs every
  group including `docs` (issue #1538). `[tool.coverage.run] source =
  ["btclib", "tests"]` rules out the obvious guard: a
  `pytest.importorskip` around such a test turns the gap into a
  100%-floor failure in the very environment that also lacks the
  import, a skipped test's body counting as uncovered lines of
  `tests/`. What worked instead was reading the line as source text
  with a regex — the idiom `_pyproject_author()` in the same file
  already uses on `pyproject.toml`, for the identical reason — rather
  than executing the module.
- **A GitHub squash-merge can land `CHANGELOG.md` missing the blank
  line above a new `###` heading, and nothing stops the merge button
  from doing it.** `.gitattributes`' `merge=union` on `CHANGELOG.md`
  applies to a local `git rebase`, which is where that blank line is
  ordinarily eaten and then restored by `markdownlint-cli2 --fix`;
  GitHub's server-side merge does not apply the driver at all, so a
  squash-merge landing two branches that both append an entry can
  commit the seam damage straight to `main` with no local gate ever
  having seen it (issue #1568, its own commit `0bc9e72d`). `lint.yml`'s
  `push: branches: [main]` trigger runs the same hooks the pull request
  did and is what catches it, so this is a detective control rather
  than a preventive one. The remedy is reconstruction, not the rebase's
  own output, which can silently carry the same damage forward: build
  the expected file from the pre-rebase blob's own added block spliced
  into the new base's blob, verify the result byte for byte against
  what actually landed on `main`, then run `markdownlint-cli2` on the
  reconstructed file to restore the blank line before pushing the fix.
- **`pre-commit run markdownlint-cli2` can report `Passed` on
  `CHANGELOG.md` without applying a fix its own `--fix` is configured
  to make.** Measured under concurrent load from several sessions'
  pre-commit and pytest runs sharing one machine-wide
  `~/.cache/pre-commit/repo<hash>` hook cache: `pre-commit run
  markdownlint-cli2 --files CHANGELOG.md` answered `Passed` with zero
  diff on a file that still carried the blank-line defect above, and
  invoking the pinned tool directly against the same file immediately
  found and fixed it. An isolated repro — same file, same tool, same
  config, no concurrent load — did not reproduce the false pass, so
  contention over the shared cache under heavy concurrent load is the
  standing hypothesis rather than a confirmed code path (issue #1863).
  Whenever a rebase has touched `CHANGELOG.md`, invoke the pinned tool
  directly as a second check rather than trusting a bare `Passed`: find
  the cache directory by matching its `package.json`'s `version`
  against `.pre-commit-config.yaml`'s pinned `rev` for
  `markdownlint-cli2`, then run

  ```shell
  d=~/.cache/pre-commit/repo<hash>/node_env-system/lib/node_modules/markdownlint-cli2
  node "$d/markdownlint-cli2-bin.mjs" \
    --fix --config .markdownlint.jsonc CHANGELOG.md
  ```

  **And the direct invocation's own `Summary: N issues in M files` line
  is not the confirmation either.** `markdownlint-cli2.mjs`'s
  `flattenTaskResults` builds `filesReported` only from result entries
  whose `errorInfos.length > 0` — a file with nothing left to report
  reads identically whether the tool fixed every issue it found or
  never opened the file at all. `Summary: 0 issues in 0 files` is
  consistent with both, even *with* `--fix`: the tool re-lints after
  applying a fix, so a file whose only defects were fixable reports the
  same `Summary: 0 issues in 0 files` as a file it never opened, and
  neither exits 1 nor names a rule — that only happens on a check-only
  run, `--fix` dropped. What actually confirms the run touched the file
  is `git diff` showing the blank line restored, or the `--fix`
  invocation's own `Attempted: N fixes in M files` line, present only
  when a real pre-fix pass found something to fix and not filtered the
  way `Summary` is; a planted control makes this concrete: delete a
  known blank line above a `###` heading, run the check-only form
  (`--config .markdownlint.jsonc CHANGELOG.md`, no `--fix`) and confirm
  it exits 1 naming `MD022`/`MD032`, then run the `--fix` form and
  confirm it reports `Attempted: 2 fixes in 1 file`, then restore the
  line and re-run to confirm both go quiet again.
- **`uv run --project <worktree> pytest` with no path argument can
  collect a different tree's test files than the source it runs
  against.** `[tool.pytest.ini_options] testpaths = ["tests"]` in
  `pyproject.toml` is relative, and `--project` changes which project's
  environment and dependencies `uv` resolves, not the process's working
  directory — so `testpaths` resolves against wherever the shell's cwd
  already is, which resets to the primary checkout between tool calls.
  `btclib` itself still resolves correctly (the editable install's
  absolute-path finder wins regardless of cwd), so the failure is
  narrower and easier to miss than an ordinary wrong-tree import: source
  from the worktree, tests from the primary checkout's unmodified copy,
  producing failures that read as real regressions in code the worktree
  never touched. `env -C <worktree> uv run pytest` (no path argument
  needed once cwd is bound) is unaffected; so is any invocation that
  passes the test path explicitly, `uv run --project <worktree> pytest
  <worktree>/tests`.

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
- **A pin's comment names the point release, and where the action's
  repository publishes only a floating major it names that tag with the
  calls that resolve it beside the pin.** What the comment buys is a
  legible bump: a point release changes with the sha it names, where a
  bare major reads the same on either side of one and leaves the sha as
  the whole of the diff. Where the major is the only tag upstream has,
  nothing else names the commit, so the comment keeps it and the
  workflow carries the calls that list the tags and peel the one the
  comment names: those calls, and not the comment, are what say whether
  a point release has appeared and whether the pin is still current.
  Beside is not always trailing: a pin that already fills
  `.yamllint.yaml`'s width takes the comment on the line above.
  `.github/workflows/fuzz.yml`'s `google/clusterfuzzlite` pins are both
  cases at once.
- **The prose style — tone, comments, docstrings, no history — is
  section 9 of the organization standard**, which
  `CONTRIBUTING.md`'s *Documentation and comments* is the pointer to.
  It governs the workflows and the pre-commit config too: the reasoning with its
  negative results is what makes those files reviewable, so match it
  rather than trimming it.
- **CHANGELOG.md gets an entry for anything a user would notice**;
  RELEASE_NOTES.md is the release notes on top of it and only moves for
  a change a user has to *act* on. The prose of the two is one fact each,
  deliberately: the breaking-changes list lives in RELEASE_NOTES.md and
  the detail behind it in CHANGELOG.md, so neither restates the other. A
  source-breaking change costs one edit more: a bullet in
  RELEASE_NOTES.md's breaking-changes list, with the "before" spelling
  checked against the `v2023.7.12` tag.
- **A `###` in the open section names one entry, never a theme several
  entries share** (issue btclib-org/.github#586): section 9 of the
  organization standard rejects grouping by theme. Where the open
  section already carries a heading that groups several entries under
  one theme, that heading is landed text and stays as it is; a new entry
  never joins it — it takes its own `###` heading at the end of the
  section instead, naming only that entry.
- **Never state how many of anything a file holds** — measure it when a
  release wants it, and do not estimate:

  ```shell
  git ls-files 'tests/_data/*' 'tests/*/_data/*' \
      src/btclib/mnemonic/_data/wordlist.txt | grep -cv 'README.md'
  ```

  CHANGELOG.md has no command of this kind: a `###` heading names one
  entry or a theme several entries share, and an entry's own claims sit
  in a bullet or, where it makes a single claim, in a paragraph with no
  bullet at all — so counting its entries is a reading of the file, not
  a pattern any command matches.

  The why is section 9 of the organization standard, which
  `CONTRIBUTING.md` points at; what this file adds is that nothing states
  a count now and tests keep it that way —
  `tests/release_notes_test.py` for CHANGELOG.md and
  RELEASE_NOTES.md, `tests/vendored_data_test.py` for
  `tests/_data/README.md` — failing on a stated count rather than on a
  wrong one.
- **A wall clock and a linter's findings are counts too**, and nothing
  fails on those: pyproject.toml's comments and tests/README.md state
  none, and keeping it that way is by hand. What a comment carries
  instead is the reason, which is what decided the setting, with the
  command that re-derives the number beside it:

  ```shell
  uv run ruff check --select N --no-cache src/btclib tests
  uv run mypy --enable-error-code=redundant-expr src/btclib tests
  uv run pytest --durations=0 --durations-min=0
  ```

  A survey that says "with the count, so that nobody has to run it
  again" is the shape to distrust: every one of the twelve it recorded
  was wrong when re-run. One exception is a count of what upstream
  published — `tests/_data/README.md`'s "121 vectors, Core's entire
  file" — which pins a vendored file rather than measuring this tree,
  and which `tests/vendored_data_test.py` spares on purpose.
  `REVIEWING.md`'s *This repository in particular* names the other:
  `.github/mutation/`, where a profile's stated mutant count,
  kill/survive/skip breakdown or wall clock is what a session measured
  over its own scope at its own sha, re-derived by the commands
  `CONTRIBUTING.md`'s mutation section already gives.
  `tests/mutation_counts_test.py` is not what spares it: that script
  tests the counting script's own arithmetic against a synthetic
  session, never whether a profile's prose states a figure, so a stale
  count there fails nothing.

## Verifying

Run the command as documented before claiming it works, and read its
exit code rather than its filtered output: `pre-commit run ... | grep -v
Passed` hides a failure, and a `grep` that finds nothing exits 1, which
is not the gate's answer to anything. `REVIEWING.md`'s *The gates are the
evidence* is where that rule is written for a reader who is not this
one.

**A failed thing is loud and an absent thing is silent**, so "nothing is
red" is not the question — "did every step I expected actually run" is.
A CI job skipped rather than failed leaves the run green where it is
missing: v2026.8.27 published with its post-publish sentinel never
having run, and nothing anywhere said so, because `needs:` without
`always()` gates on the whole transitive chain and not on the jobs it
lists (issues #1461 and #1470; `RELEASING.md` carries the check).
The same asymmetry is what makes a zero from a sweep worth distrusting,
above, and an empty `grep` worth reading twice.

Prefer
measuring to asserting: every claim in this file was checked against the
tree, and the tree changes.
