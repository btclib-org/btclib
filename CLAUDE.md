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

[ARCHITECTURE.md](./ARCHITECTURE.md) is the design: the curve arithmetic
btclib_ecc provides, the layers, and the import edges the tests hold.
Read it before touching `src/btclib/ecc/`, which holds `bms` and
`ellswift` alone, the rest of the curve arithmetic and the schemes being
`btclib_ecc`'s and imported from it, never re-exported; `xdh`, the script
engine and `script.taproot` delegate to the bindings only where
`btclib_ecc.curves.is_libsecp256k1_serving()` and the call site both
admit it, so a change there has two paths to keep right.

## The primary checkout is the maintainer's

Never work in it: no edit, no `git add`, no commit, no branch switch, no
rebase, no `git stash` — the hooks fix files in place. The one write
allowed there brings it forward, and only while it is on `main` and
`git status --porcelain` prints nothing; where it is not, stop:

```shell
checkout=<checkout>
```

```shell
git -C "${checkout:?}" pull --ff-only
```

Read it only after that, once this prints one sha twice:

```shell
git -C "${checkout:?}" rev-parse HEAD origin/main
```

A measurement that has to hold at a named revision reads
`git -C "${checkout:?}" show <sha>:<path>` instead.

Every session works in a worktree of its own, from its first edit, named
`wt-<tracker>-<issue>-<repo>-<role>` — `wt-github-255-btclib-writer` for
issue 255 of `btclib-org/.github`'s tracker, worked in `btclib` by a
writer. The environment is created there, with the command `CONTRIBUTING.md`
names under *The environment and the gates*. Every path is written out in
full, `<scratchpad>` being the session's scratch directory:

```shell
git worktree add \
  <scratchpad>/wt-<tracker>-<issue>-<repo>-<role> origin/main -b <branch>
```

Removing it is part of finishing:

```shell
git worktree remove --force <scratchpad>/wt-<tracker>-<issue>-<repo>-<role>
```

`refs/stash` and the local `main` are shared by every worktree: never
`git stash`, and move `main` only by the `git pull --ff-only` above.

## Model

Default model: Sonnet; Opus for design decisions with conflicting
constraints. Do not use Fable unless instructed.

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
- **A config `exclude` does not reach a path named on the command line:**
  `typos` needs `--force-exclude`, ruff `force-exclude`. Without it
  `ruff format CHANGELOG.md` rewrites a sealed section and
  `tests/changelog_immutability_test.py` fails.
- **`tests/security_citations_test.py` checks `SECURITY.md`'s `path:line`
  citations, and a dotted-name anchor pins only the enclosing function:**
  a citation that must land on one line also quotes it. The test's
  docstring has the grammar.
- **`btclib-org/.github`'s weekly calendar (section 10) can move
  mid-campaign:** re-fetch it (`gh api
  repos/btclib-org/.github/contents/README.md -H 'Accept:
  application/vnd.github.raw'`) rather than trusting a value read earlier
  in the session.
- **Asking what an index serves has to be asked from outside every
  checkout of this project**, and `--isolated --no-project` is not what
  makes it so: a cached build of some earlier state of the tree can
  shadow the index and hand back a plausible version. Run it with
  `env -C <scratchpad>`, and print `btclib.__file__` beside the version
  when the answer decides anything.
- **Never execute `docs/source/conf.py` from a test:** it imports the
  `docs` group at top level, which the coverage job lacks. Read it as text,
  as `_pyproject_author()` does (issue #1538).
- **`check-changelog` is served from `btclib-org/.github`;**
  `env -C <worktree> uvx pre-commit run check-changelog --all-files` runs
  it alone.
- **`uv run --project <worktree>` does not change the working
  directory,** so `testpaths` resolves against the primary checkout: use
  `env -C <worktree> uv run pytest`.

## Conventions to match

- **Workflows** follow section 10 of the organization standard.
  `actionlint` and `zizmor` are hooks, and both must stay at zero
  findings.
- **A pin comment names the point release** (or the floating major plus
  the calls that resolve it). Prose never copies a pinned value: it names
  the file that holds it; a measurement's stamp and a floor are the two
  exceptions (issues #2046, #2079).
- **The prose style — tone, comments, docstrings, no history — is
  section 9 of the organization standard**, which
  `CONTRIBUTING.md`'s *Documentation and comments* is the pointer to.
  It governs the workflows and the pre-commit config too: the reasoning with its
  negative results is what makes those files reviewable, so match it
  rather than trimming it.
- **The changelog and the release notes**: `CONTRIBUTING.md`'s *Pull requests*
  says which pull request writes them.
- **A source-breaking change is named in the release's own RELEASE_NOTES.md
  breaking-changes list**, its "before" checked against the `v2023.7.12` tag.
- **Never state how many of anything a file holds.**
  `tests/release_notes_test.py` and `tests/vendored_data_test.py` fail on a
  stated count in CHANGELOG.md, RELEASE_NOTES.md and
  `tests/_data/README.md`; `SECURITY.md` is kept by hand (issue #2035).
  The exception is a count of what upstream published, which the vendored
  data test spares.

## Verifying

Read exit codes, not filtered output. A skipped CI job leaves the run
green: check that every expected step ran (`RELEASING.md` carries the
check, issues #1461 and #1470).
