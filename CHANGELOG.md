# Changelog

<!-- markdownlint-configure-file
  {
    // MD024/no-duplicate-heading - a group heading repeats under every
    // release with an entry in that group ("Packaging, linting and CI",
    // "Tests", "Repository"), which is what keeps the page readable
    // scrolling down it; only a duplicate under the same release heading
    // would be the accident this rule looks for
    "MD024": { "siblings_only": true }
  }
-->

Every change of a release, in full: what changed, why, and what it cost.
The release notes, which say what a user has to *act* on, are in
[RELEASE_NOTES.md](./RELEASE_NOTES.md); this file is the record behind
them.

Only v2026.8.7 and what follows it are recorded in the changelog at all.
The releases before it were documented at release-notes length in the
first place, and are still in [RELEASE_NOTES.md](./RELEASE_NOTES.md)
rather than duplicated here.

This file carries the cycle in progress and the most recent release;
every release before those has a file of its own under `changelog/`,
holding that release's section and nothing of any other. Past a size
ceiling GitHub's contents API answers a file with an empty `content` at
HTTP 200, which reads as an empty file rather than as an error, and one
file per release is what keeps each of them under it.

- [v2026.9.13](./changelog/v2026.9.13.md)
- [v2026.9.10](./changelog/v2026.9.10.md)
- [v2026.9.3](./changelog/v2026.9.3.md)
- [v2026.8.29](./changelog/v2026.8.29.md)
- [v2026.8.27](./changelog/v2026.8.27.md)
- [v2026.8.21](./changelog/v2026.8.21.md)
- [v2026.8.9](./changelog/v2026.8.9.md)
- [v2026.8.7](./changelog/v2026.8.7.md)

## v2026.10 (work in progress, not released yet)

### `requires-python` moves to `>=3.11`

3.10 reaches end of life on 2026-10-31. The classifiers and every
workflow matrix move with the floor.

### The attestation's signer is `reusable-attest.yml` from v2026.9.24 on

- **`RELEASING.md`, `SECURITY.md` and `sdist-rebuild.yml` name the
  called workflow as the signer**, the path of `release.yml` kept for
  v2026.9.13 and earlier, which it signed (issue btclib-org/.github#1301).

## v2026.9.24

### A schedule comment names the `pull_request` trigger below it

- **`integration-bitcoind.yml`, `links.yml`, `py-arm-authority.yml`,
  `vendored-vectors.yml` and `zkp-oracle.yml` say a branch reaches the
  workflow through the dispatch below the comment and through the
  `pull_request` trigger further down** (closes btclib-org/.github#736).
  Each of them declares that trigger, so *alone* claimed an exclusivity
  the same file refuses a few lines lower, and it sent a reader asking
  how to see the run before it lands to a hand dispatch their own pull
  request had already made unnecessary.
- **The wording is `btclib-secp256k1`'s**, taken there under this issue
  at `8b174ce5` and `a7236b9d`. That tree's `codeql.yml` ends the clause
  *pull_request trigger above*, its `pull_request:` standing ahead of its
  `schedule:`; here the trigger sits below the comment in each of the
  files named, which is what *further down* is derived from, file by
  file.
- **The other workflow files carrying the sentence are untouched**:
  `deps-latest.yml`, `integration-hwi.yml`, `os-macos.yml`,
  `os-ubuntu.yml`, `os-windows.yml` and `pypi-install.yml` declare no
  `pull_request:` trigger at all, so the contradiction this issue is
  about does not arise in them. `os-macos.yml`, `os-ubuntu.yml` and
  `os-windows.yml` each declare `workflow_call:` below that sentence,
  and `release.yml` calls all three in jobs with no `if:`, which a
  `workflow_dispatch` rehearsal reaches from any branch:
  btclib-org/.github#1040 is where that is filed, for this tree and for
  `btclib-secp256k1`.

### A schedule comment names the `workflow_call` trigger below it

- **`os-macos.yml`, `os-ubuntu.yml` and `os-windows.yml` say a branch
  reaches the workflow through the dispatch below the comment and
  through the `workflow_call` trigger above that dispatch** (issue
  btclib-org/.github#1040). Each declares that trigger, and
  `release.yml` calls each of them in a job with no `if:`, so a
  `workflow_dispatch` rehearsal reaches them from whatever branch it is
  dispatched on -- which is what *alone* denied.
- **The clause is the one btclib-org/.github#736 landed in
  `links.yml`**, with `workflow_call` where that one says `pull_request`
  and *above it* where it says *further down*: in each of these files the
  trigger stands ahead of the dispatch the sentence has just named, where
  in `links.yml` it follows it. The clause does not name `release.yml`:
  the comment introducing that trigger already says a call is what lets
  that workflow gate a publication, and section 9's *One fact in one
  place* is the reason.
- **`pypi-install.yml` carries the sentence beside a `workflow_call:`
  too and keeps it, the claim being true there.** `release.yml`'s
  `publish-pypi` job requires `github.event_name == 'push'` and the only
  push that starts that workflow is a `v*` tag, so a rehearsal
  dispatched from a branch skips it; the `pypi-install` job beside it is
  gated on `needs.publish-pypi.result == 'success'`, which a skipped job
  does not give. Run 34723411299, dispatched on a branch, skipped both
  of those jobs and ran the platform workflows above.
- **`btclib-secp256k1` already carries the same wording**, its own
  commit `68432dd6` having closed the issue, which is why this cites it
  rather than closing it.

### A run coverage's configuration never reached is refused

- **`tests/conftest.py` let a run coverage read no configuration for
  pass as the gate** (issue btclib-org/.github#443): coverage looks for
  its configuration in the directory the process started in, so
  `env -C tests uv run pytest` finds no `fail_under`, no `source` and no
  `branch = true`, while pytest walks up and reads `pyproject.toml` all
  the same. That asymmetry is what the hook keys on, rather than the
  floor's own value, which `pyproject.toml` is the one place for; what
  it raises is `pytest.UsageError`, which pytest prints without a
  traceback and exits 4 for, so the exit code says the run measured
  nothing rather than that something in the tree failed.
- **The message names the root as the remedy, and `--cov-config` as one
  that restores the floor and not the file set.** coverage keeps an
  `omit` pattern that does not open with a wildcard and adds beside it
  the form it makes absolute against the directory the run started in,
  so `tests/integration/*` from `tests/` names an integration directory
  under `tests/tests` and matches nothing. The files under
  `tests/integration/` are then measured rather than omitted, and those
  tests skip themselves without `BTCLIB_INTEGRATION`, so what the report
  gains is the switch rather than a defect -- which is what that `omit`
  entry's comment in `pyproject.toml` says it is there to keep out.
  `source` is not what carries this tree: `btclib` is an import name
  from either directory, and `tests` is a directory at the root and an
  import name from `tests/` that reaches the same files.
- **Section 8 of the organization standard leaves a tree to point such a
  run at its configuration or to make it say it is ungated, and this is
  the second of the two.** A sentence in `CONTRIBUTING.md` telling a
  reader to start from the root is the rejected alternative, on the
  defect being that a plausible spelling switches the floor off in
  silence: what the sentence buys is a silent failure somebody had been
  told about.
- **Left alone are `--no-cov`, `--help`, `--collect-only` and an
  explicit `--cov-fail-under`, none of them a run held to a floor it
  cannot see.** `--markers` and `--fixtures` from `tests/` are refused
  with the rest, that exemption being an enumeration rather than every
  run pytest-cov leaves ungated. `test.yml` meets the guard from the
  root either way: its `no-bindings` job names `--cov-fail-under=0`, and
  `coverage-union` runs `coverage report` and no pytest at all.
- **`btclib-node`, `bitcoin-core-rpc` and `btclib-benchmarks` all carry
  the guard now**, btclib-org/.github#443 having taken that decision for
  the family: `btclib-secp256k1` landed it at `bd71d7c8`, and
  `btclib-benchmarks` landed it last, its own commit `63435e87` closing
  the issue rather than this entry, which is why this cites it instead
  of closing it.

### A root-file link's dead target warns, then falls back to an anchor

- **The docs gate's second step is documented as a second defense, not
  the only one** (closes #2044). `CONTRIBUTING.md` said MyST emits an
  anchor on the page it is already on "rather than a warning" for a
  root-file link it cannot resolve; `MystReferenceResolver` warns
  unconditionally before that fallback, which is what `-n -W` already
  fails the build on, and the grep instead guards the fallback node
  against a regression: `conf.py`'s `suppress_warnings` staying empty,
  or a myst-parser upgrade no longer warning unconditionally.

### `CONTRIBUTING.md`'s breaking-changes example names a released heading

- **The worked example pointed at `` `v2026.9` ``, a heading that never
  carried a long breaking-changes list and stops existing at every
  release** (closes #2052). It now names `` `v2026.8.7` ``, a released
  heading whose list is long and does not move.

### The tree gains the `deps-oldest` sentinel

- **`.github/workflows/deps-oldest.yml` resolves every direct dependency
  to the oldest release its own specifier allows and runs the suite on
  it, weekly** (issue btclib-org/.github#323). Section 10's *Which trees
  carry which sentinel* names this repository for that row, and
  `git grep -l 'lowest-direct' -- .github/workflows/` at `e2c534ac`
  answered nothing with `uv lock` in `deps-latest.yml` as the control
  that the path was read: every `>=` `pyproject.toml` declares was a
  claim no run had installed.
- **The cron is `4 3 * * 4`**, read off section 10's two tables: the
  workflow table's `deps-oldest` row gives Thursday and hour 03, the
  repository table's `btclib` row gives minute 04.
- **The cell is 3.10, the end `requires-python` names, and not the 3.14
  `.python-version` pins.** That file's header leaves checking the
  oldest to "the matrix's job and the two linters'", and only the
  interpreter half of it holds: the platform sweeps do run a 3.10 cell
  and ruff and mypy do read 3.10, but each of them takes its
  dependencies from `uv.lock`, so no run reached a declared floor.
- **`UV_RESOLUTION` is declared on the job rather than passed to the
  step that resolves.** `uv lock` records a non-default mode inside
  `uv.lock`, and a later uv command under the default `highest` reads
  that lock as stale, so `uv run --locked` would refuse the lock the
  step above it had just written.
- **The pytest step passes `--no-cov`, and the assertion in front of it
  is what that costs.** Section 10 gives a sentinel cell running the
  suite that flag, the ratchet being section 8's claim about one
  interpreter on one image; but `btclib._libsecp256k1` imports the
  bindings' surface in one `try` that sets `INSTALLED = False` on any
  `ImportError`, and `tests/conftest.py` then skips every
  `bindings`-marked test, so a floor that installs and does not serve
  passes a run with no coverage number to fall under.
  `deps-latest.yml`'s `suite-bindings-latest` asks the same question of
  the newest release and is where the step's wording comes from.
- **No second job for the bindings floor, where `deps-latest.yml` has
  one.** That job is there because a broad upgrade moves a dozen
  packages at once and a bindings release would be one suspect among
  them; `lowest-direct` puts `btclib-secp256k1` on the single release
  `>=0.8.0.6` names, which is another claim of the same kind rather than
  a second point on a range.
- **The resolution is over every group, and each `[dependency-groups]`
  entry declares a lower bound.** `uv lock --help` lists one option
  naming a group, `--upgrade-group`, and none that selects or excludes one.
- **The checkout passes no `fetch-tags`, where `deps-latest.yml`'s suite
  job does.** There the tags are what keeps
  `tests/changelog_immutability_test.py` from skipping, a skip leaving
  uncovered lines of `tests/` under the 100% floor; `--no-cov` here
  leaves no floor for the skip to fall under.
- **`btclib-secp256k1` already carries the same workflow, at
  `af788bf2`**, and btclib-org/.github#323 was closed at `f235da30`,
  the commit that deleted the `BACKLOG` row keyed on it -- which is why
  this cites the issue rather than closing it.

### Three operation-count comments in `curves/` state a relation or a command instead

- **`curve_group.py`'s tangent-law comment states the relation the
  argument needs instead of a doubling count**: the spelling is decided
  in `CurveGroup.__init__` rather than inside `_double_jac_helper`,
  which every Jacobian doubling reaches -- `double_jac`'s own, and
  `add_jac`'s and `add_jac_aff`'s when the two points they are given
  coincide -- which holds at any window width and needs nothing kept in
  step with one.
- **`_double_mult_regular_window`'s docstring states its 143 additions
  and 254 doublings at a stated `w` and `scalar_len`, counted by the
  `_CountingGroup` instrument `curve_group.py`'s own regular-window
  figure already cites**, rather than "over 200 random pairs" with no
  seed; `_CountingGroup`'s own docstring now runs the function and
  prints the pair. `_double_mult_w_NAF_var`'s range beside it is gone
  instead of corrected: the docstring's own 101 to 116 carried no seed
  at all, and re-deriving over the issue's own stated seed
  (`random.Random(0x2040)`) independently, twice, answered two
  different pairs of endpoints -- 99 to 117 in the issue, 99 to 116
  here. A seed does not pin "200 random pairs" on its own, so the
  endpoints are a property of the script rather than of the function,
  and what the comparison needs is the relation already beside it: that
  the wNAF's additions follow the recoded weight of the two coefficients
  rather than being constant, and that is what stays.
- **`_additions_by_position`'s docstring stops pricing the pre-issue-906
  loop it no longer runs.** 512 is the GLV split's own nominal width
  (four halves of 128 positions) and stands as that rather than as a
  count the loop made; the 79 answered and 433 not were a property of the
  coefficients that loop happened to be timed against, not re-derivable
  without reconstructing code this tree deleted, and CHANGELOG.md's own
  entry for issue #906 already has them (closes #2041).

### RELEASING.md's placeholder names the month the next release is expected in

- **The retitle step and *Open the next cycle's version* say the "work in
  progress" heading opened after a retitle names the month the next release is
  expected to fall in, not the cycle of the release just cut** (closes #2047).
  Where the month named is a later one, a checkout of `main` declares a version
  above the release just cut and above any further release the same cycle still
  ships -- `2026.10` sorts above both `2026.9.3` and a later `2026.9.20` under
  PEP 440 -- and a further release in the month already left behind retitles the
  heading back down at its own retitle step, both costs stated rather than
  dropped.

### RELEASING.md names the sibling whose workflow ships a bill of materials

- **`RELEASING.md` says bitcoin-core-rpc's release workflow builds, attests and
  attaches a bill of materials as of `btclib-org/bitcoin-core-rpc#441`, and that
  btclib-secp256k1 has no bill-of-materials workflow yet** (closes #2050).
  `generate_sbom.py`'s two issue references are qualified as
  `btclib-org/btclib#1280` and `btclib-org/btclib#1194`, so a repository that
  takes the same file reads a citation resolving in btclib's tracker rather than
  one pointing at its own, where neither number exists.

### RELEASING.md's reason for naming a release commit is count-independent

- **The reason for passing `--subject` and `--body-file` explicitly no longer
  rests on a release branch carrying more than one commit** (closes #2051). A
  squash always mints a fresh commit object at the button, whatever the branch
  held, and naming the title and body explicitly is harmless at any commit count
  -- it replaces the two `squash_merge_commit_*` defaults with a title and body
  chosen on purpose.

### `coverage-union`'s report step types `coverage report` and no flag

- **`test.yml`'s `coverage-union` job asks for no `--fail-under` of its
  own** (closes #2057). Section 8 of the organization standard tells an
  argument a job's own construction asks for from a copy of a tree-wide
  setting by whether the run does anything differently without it, and
  this run does not: from the checkout root, against a coverage data file
  short of 100, `coverage report` and `coverage report --fail-under=100`
  both refuse the report, and the floor the first of them names is
  `[tool.coverage.report]`'s `fail_under`, no flag having named one.
- **The step's comment states what makes `fail_under` reach a
  `coverage report`**, which is where the run starts: coverage reads its
  configuration from the process's own directory and this step starts at
  the checkout root, so a flag naming 100 would gate a run that found
  no configuration rather than the one this step makes. The same command
  against the same data file, from a directory holding no configuration,
  reports and exits 0.
- **`CONTRIBUTING.md`'s reproduction of `coverage-union` drops the flag
  too**, and says the two commands there are run from the repository
  root, which is what puts a local run under the floor the job's own run
  is held to.
- **`--cov-fail-under=0` in the `no-bindings` job stays.** Nothing in
  `pyproject.toml` names that argument, and the run it lifts the floor
  for is one whose own report cannot reach 100 by construction, the
  delegated arms being unreachable with the bindings absent.

### `conf.py`'s `RootFileLinks` comment states that myst warns and `-W` fails

- **The comment block above the `RootFileLinks` post-transform in
  `docs/source/conf.py` said the build succeeds and `-W` sees nothing for
  a target myst cannot resolve, where the same block also said myst
  reports a path that exists nowhere and `-W` then fails** (closes
  #2060). What the block states now is the pair myst emits -- the
  warning, and then the anchor on the page the link is already on -- with
  the anchor as what a filter on `myst.xref_missing` would leave: a dead
  relative link appended to `README.md` makes `sphinx-build -n -W` exit 1
  on that subtype and still renders the anchor, which is what `docs.yml`
  greps the built html for.
- **The sentence saying `-W` fails no longer dates itself to the removal
  of `suppress_warnings`**: `conf.py`'s own `no suppress_warnings` comment
  is where that setting's absence is stated.

### A cited `#heading` is resolved against the headings its target has

- **`tests/markdown_citations_test.py` reads the fragment half of a
  citation too, resolving `path#heading` against the headings the file the
  link reaches carries** (closes #2059). A release renames the open
  cycle's own heading of `CHANGELOG.md` and of `RELEASE_NOTES.md`, so a
  citation naming that heading stops resolving on a schedule rather than
  by accident, and with nothing in the file carrying the citation having
  changed.
- **The fragment is read off a link's own target**, a backticked
  `path#anchor` being prose about the shape of a link rather than a link,
  and the slug is GitHub's: lowercased, every character that is not a word
  character, a hyphen or a space dropped, the spaces hyphenated, and the
  `-1`, `-2` suffix on a heading that several releases repeat.
  `docs/source/conf.py`'s `myst_heading_anchors` answers the same question
  over the root files the `*_link.md` shims include, where an `-n -W`
  build fails on a fragment myst cannot find; a fragment naming a heading
  of a file that build does not render reaches no resolver there, and
  resolving those is what the test adds. myst's slugifier is not what it
  reads either: `myst-parser` is in the `docs` group, which no workflow's
  own pytest step installs.

### The yamllint and `toml-comment-width` preambles state no column count

- **`.pre-commit-config.yaml`'s `yamllint` and `toml-comment-width`
  preambles stated a column width for a workflow's yaml and for a
  `pyproject.toml` comment, and said the second was found by reading**
  (issue btclib-org/.github#880). Once each hook holds its own files no
  command re-derives either width, and section 9 of the organization
  standard asks a number in prose to carry the command that produces it.
- **What each preamble states now is why its hook is there, in the present
  tense**: nothing else the lint config runs measures a yaml line's width --
  but for the inline sequence prettier explodes -- or a toml comment's at
  all, and the yaml and the toml here both carry prose in their comments.
- **The yaml preamble names `markdownlint` where it said *the hook
  above***: the hook immediately above `yamllint` is `taplo`, and markdown
  is held to 80 columns by `markdownlint-cli2` further up.

### A markdown link target's own path is resolved against the tracked set

- **`tests/markdown_citations_test.py` reads the path half of a link
  target as well as the `#fragment` on it, resolving what the link reaches
  against `git ls-files`** (closes #2075). A link is the citation form a
  reader clicks rather than retypes, and a typo in its destination left
  such a citation dead in both halves at once: the fragment rule leaves a
  target this tree does not track alone, a file this tree does not have
  carrying no headings to read, and the path rule read a backticked span
  and no link target at all.
- **A local destination is what carries a `./` or a `../`**, which
  `.pre-commit-config.yaml`'s `local-link-prefix` hook is what keeps true,
  so that prefix is what tells one from a url and from a fragment naming a
  heading of the citing file itself. A link quoted inside a backticked
  span is prose about the shape of one, so the spans go before the targets
  are read -- which is the distinction that hook already spells as a
  lookbehind.
- **`docs/source/conf.py`'s `RootFileLinks` answers the same question over
  the root files the `*_link.md` shims render**, an `-n -W` build failing
  on a target that is no file of the tree. A link written in
  `REPOSITORY.md` or in `RELEASING.md` is rendered by no page of that
  build and reaches no resolver in it, and that build asks the filesystem
  where the test asks the index.

### A comment points at a pinned tool's revision instead of copying it

- **`CLAUDE.md`'s *Conventions to match* asks a comment that needs a
  pinned tool's revision to name the places the revision lives, rather
  than the version itself** (closes #2046). A copied version is a second
  place to remember and the first to go stale: a refresh moves the `rev:`
  and nothing points at the comment, which goes on reading as provenance.
- **A numeral stamping a measurement stays legitimate, and so does a
  floor.** "Measured on ruff 0.16.7" dates what was measured and survives
  the bump; "not below actionlint 1.7.12" is a requirement on the pin
  rather than a copy of it, and a `rev:` below it is what falsifies it.
- **No hook reads the convention.** A pattern cannot tell a measurement's
  stamp from an assertion about the pin, so a check would need the
  spelling to separate them first or an allowlist of judgements, which is
  the trade `CLAUDE.md` refuses for `SECURITY.md`'s counts (issue #2035).
- **The comments in `pyproject.toml`, `.pre-commit-config.yaml` and
  `.github/workflows/docs.yml` drop the assertion and keep what they
  measured.** The `force-exclude` comment reads "Measured on ruff
  0.16.7"; the docs gate's grep step is measured on myst-parser 5.1.0 and
  sphinx 9.1.0 rather than on "the currently pinned toolchain"; the
  zizmor hold names the actionlint pinned above instead of 1.7.12, that
  pin reading `rev: v1.7.12.24` where 1.7.12 is the floor the
  `actionlint-py` entry states as a floor.

### `.pre-commit-config.yaml`'s preambles state no file size

- **The `check-readthedocs` and `actionlint` preambles stated a size for
  `.readthedocs.yaml` and for the workflows, and neither number was what
  `git cat-file -s` answered** (closes #2076). Section 9 of the
  organization standard asks a number in prose to carry the command that
  produces it, and re-measuring these two would leave the same sentences
  to go stale again.
- **What each preamble states now is why its hook is there, in the
  present tense, by naming what its neighbours do not read.** `check-yaml`
  above asks whether `.readthedocs.yaml` is yaml and
  `tests/docs_commands_test.py` reads the `sphinx-build` line out of it,
  which leaves the file as a build definition to `check-readthedocs`; an
  expression is what `check-yaml` and `yamllint` cannot read in a
  workflow, which is what `actionlint` is there for.
- **The `actionlint` preamble says in the present tense what a run
  discovers by failing.** *nothing validated them* was past tense, and
  the hook it introduces is what makes it false.
- **The `check-added-large-files` preamble drops the size of the blob it
  names**, keeping what that size was there to show: the already vendored
  `script_assets_test.json` does not trip a hook that measures only what
  is being added, and the next blob its size does. The default the hook
  is configured with stays named, being a threshold rather than a
  measurement of this tree.

### The reproduction commands are read against the steps they quote

- **`tests/docs_commands_test.py` reads the platform matrices' cell, the
  `coverage-union` pair and the data file each coverage job writes
  against the way `CONTRIBUTING.md`'s *Reproducing what CI runs* prints
  them** (closes #2071). The section said of the cell, and of the
  `COVERAGE_FILE` in front of the coverage job's command, that CI runs it
  verbatim, and nothing read either spelling against the step it quotes.
- **`--python` is what the documented cell adds**:
  a matrix cell takes its interpreter from `astral-sh/setup-uv`. The
  section says so where it claimed identity, and the comparison reads
  that argument against the site that holds it, as it already does the
  directory the documentation build writes to.
- **`COVERAGE_FILE` is compared as its value**: `test.yml` writes the
  assignment as a step's `env:` mapping and the section as a shell prefix
  in front of the command, so the value is the whole of what the two
  sites can share.

### The symlink case's pragma takes the case, not the handler alone

- **The `# pragma: no cover` sits on the case's `def`** (closes
  btclib-org/.github#1042): an exclusion on a line that introduces a
  block takes the whole block, so it reaches the assertions after the
  skip as well. On the `except` it reaches the handler and the
  `pytest.skip` alone, which are the lines that do not run wherever the
  link is made, and a platform refusing `os.symlink` then meets the skip
  and a coverage floor it cannot reach in the same run -- the exit code
  the floor's and the failure naming a percentage rather than a symlink.
  Measured with a plugin making `Path.symlink_to` raise `OSError`: with
  the pragma on the `except` the documented `uv run pytest` exits 1 with
  the lines after the skip named missing, and with it on the `def` the
  same run meets the floor and the case reports `SKIPPED`.
- **The comment above the line says why coverage can ask nothing of the
  case, and what the exclusion costs**: the body is reachable only where
  the platform makes a symbolic link, so a floor over a `source` naming
  `tests` asks about the runner rather than about the suite, and dead
  code inside the case stops being flagged in exchange. The inline half
  names the case and the rest of the reason stands above the line, which
  is the shape CONTRIBUTING.md's *The environment and the gates* gives a
  reason too long for the line it belongs to.
- **The docstring's sentence -- a platform that refuses says so as a
  skip, which `-ra` reports -- is what the move makes true of the run**:
  the case skips either way, and with the pragma on the `except` the run
  it skips in fails the floor.
- **The comment's wording is `bitcoin-core-rpc`'s at `45824228` and
  `btclib-benchmarks`' at `ef96af25` byte for byte**, the plural those
  two carry holding here where `btclib-node`'s singular would not.
  `btclib-node`, `bitcoin-core-rpc` and `btclib-benchmarks` have landed
  the shape, so this tree is the last the issue names and the citation
  closes where each of theirs cites.

### A command-line `..` segment reads as the whole suite, and a case pins it

- **`tests/conftest_test.py` gains
  `test_a_parent_directory_segment_names_the_whole_suite_too`** (closes
  btclib-org/.github#1049), the name `bitcoin-core-rpc` and
  `btclib-benchmarks` already carry for it. It asks `coverage_fail_under`
  the two commands their copies ask -- `pytest tests/../tests` from the
  rootdir, and `pytest ../tests` from inside `tests/` -- against a
  `tmp_path` rootdir, a positional being read against the working
  directory where a `testpaths` entry is read against `rootpath`.
- **`Path.resolve` on the command line's side makes the path absolute,
  collapses a `..` segment and follows a link, and this file pinned the
  first and the last.** Measured over the whole module by writing each
  rewrite of the comprehension into the tree, asserted before use and
  the file restored by blob id after: `Path(path)` fails the relative
  spellings of `test_a_path_that_collects_the_suite_is_a_whole_run`,
  which is the first, and `Path(os.path.abspath(path))` fails
  `test_a_symlinked_spelling_of_one_tree_is_still_the_whole_suite`
  alone, which is the last. What separates that rewrite from
  `Path(path).absolute()` is the collapsing, and this case is what one
  of the two passes and the other does not.
- **The symlinked case is behind a `pytest.skip` and this one asks for
  no privilege.** With `.absolute()` written into the tree and
  `Path.symlink_to` made to refuse, the module is green without this
  case and fails on this case alone with it.
- **`btclib-node` landed its half at `fa86147a`**, which is why this
  citation closes the issue where that one cited it.

### `source-exclude` names the `.hypothesis` a run from inside `tests/` leaves

- **`[tool.uv.build-backend]`'s `source-exclude` gains `.hypothesis`**
  (closes btclib-org/.github#1058). Hypothesis puts its storage at
  `Path.cwd() / ".hypothesis"`, so `pytest` started from inside `tests/`
  writes `tests/.hypothesis` and `source-include`'s `"tests/**"` packs
  it. Measured against the directory such a run left in this tree: the
  sdist built without the line carries `tests/.hypothesis/constants/`
  and `uv run pre-commit run check-sdist --all-files` exits 1 on `SDist
  does not match git`, and with the line the two member lists differ by
  those paths alone and the hook exits 0.
- **`.gitignore` names `.hypothesis/` and the backend does not read
  that file**, so `git status` is clean while the build packs the
  directory, and the sdist is the only place it shows.
- **Its own entry rather than a fourth name under the comment above
  `.mypy_cache`.** That comment is about a cache written beside the file
  its tool has just checked, which is why it names an extension putting
  one under `src/btclib/` and `tests/` alike; this directory follows the
  working directory of the run instead.
- **`btclib-node` landed its half at `0f777682`**, which is why this
  citation closes the issue where that one cited it.

### The `needs:` reader is the spelling the organization's copies share

- **`_NEEDS` and `_ITEM` are `bitcoin-core-rpc@b2b9d114`'s, byte for
  byte** (closes btclib-org/.github#1038): the run of items takes a
  comment line and a blank one as well as an item's own trailing
  comment, and the inline half stops at a `#` rather than reading the
  rest of the key's own line. Each of those is one thing to a yaml
  reader, and a run of adjacent item lines ends at it and drops every
  item below. `btclib-node`, `bitcoin-core-rpc` and `btclib-secp256k1`
  carry it already, so this tree is the last and the citation closes
  where each of theirs cites.
- **The comment above them is `btclib-node@c14dec30`'s, byte for
  byte**, and its last paragraph replaces the one this tree wrote for
  itself: of what that one named as dropped, a comment among the items
  and a trailing comment leaving one space behind are read now, so
  porting it whole would land a sentence the same diff makes false. Its
  first paragraph names both of the things a reader blind to the block
  shape does and its third ends in a full stop, which is
  btclib-org/.github#1057's correction; `bitcoin-core-rpc` took that at
  `96c6529` and carries neither the second paragraph's
  direction-neutral form nor the last paragraph, so what stands here is
  `btclib-node`'s text rather than a text all the copies share.
- **The paragraph naming the empty closure as the loud failure goes**:
  `_needed` opens with the key itself, so a closure is never the empty
  thing, and what the free-threading check reads is an empty
  interpreter tuple. The argument that paragraph also made -- that the
  block shape is read because a free-threaded build behind a dropped
  edge goes unseen -- is the family comment's first paragraph, which is
  section 9's *One fact in one place*.
- **`test_needed_reads_needs_in_each_of_its_three_shapes` asserts the
  closure each shape's own text earns against a flat job dict** (closes
  btclib-org/.github#1053), the shapes written under the key standing
  as a named dict asserted in a loop so that a red names the
  shape, and each comment case's stripped form spelled out beside the
  comment itself. A dict in which `changes` waited on `coverage` would
  give every case a second route to `coverage`, so an item dropped
  below a residue is reached anyway and the comment and blank-line rows
  hold under a reader with no whole-line alternative at all. Measured
  by rebinding `_NEEDS` and `_ITEM` to mutants of the pattern as
  written: an item alternative with no trailing-comment tolerance is
  killed by *a comment on an item*, one with no `[ \t]*` by *a comment
  on an item* and *that one stripped*, a whole-line alternative with no
  comment tolerance by *a comment among the items*, and no whole-line
  alternative at all by *a comment among the items*, *that comment
  stripped* and *a blank line between two items*. The shape is
  `bitcoin-core-rpc@ca9db975`'s and the assertions are
  `btclib-secp256k1@a10aa5a8`'s, that tree's walk raising where
  `btclib-node`'s absorbs.
- **One chained dict stands below the flat rows**: flat, one hop is the
  whole closure, and `test.yml`'s own aggregate names each job it waits
  on directly, so a `_needed` reading a job's direct `needs:` and
  stopping would answer every row above and the real gate alike. What
  the other copies say beside that dict -- that it is the module's only
  assertion of a job reached through another -- is not said here:
  *A job outside the closure answers for no gate* below asserts one
  too, and rebinding `_needed` to that one-hop reader turns both red.
- **`test_needed_reads_no_step_of_a_job_as_a_job_it_waits_on` and
  `test_needed_takes_no_token_of_a_comment_on_the_needs_line` assert on
  the `KeyError`'s own argument**, each with a widened reader
  monkeypatched in as the control. `_needed` indexes `jobs` by every
  name it reads, so a step line where an item goes and a comment on the
  key's own line each raise, and a bare `pytest.raises` would answer as
  readily to a job dict the test spelled wrong.
- **What the reader answers for this tree's workflows is unchanged**:
  every job block of every workflow, read under the spelling this
  replaces and under this one, agrees. The control is one `needs:` line
  per workflow spiked with a trailing comment *after* `_COMMENT` has
  run, which makes the two disagree wherever a workflow has one --
  spiked before the strip they agree, `_COMMENT` taking the comment
  away, and that is why nothing here changed in the first place.
- **The docstring of *A job outside the closure answers for no gate*
  names the shape rather than the spelling**: what makes `test.yml`
  unable to show the difference is that every `needs:` it writes stands
  on the key's own line, where *a flow one* is false of the ones naming
  a single job after the key.

### The lint gate's prose names a local run, not a commit

- **`.pre-commit-config.yaml`, `.vscode/extensions.json`, `CONTRIBUTING.md` and
  `lint.yml` say what a local run enforces and the inert `git commit` recipe
  goes** (issue btclib-org/.github#966).

### A changelog entry is its title and at most three lines

- **`REVIEWING.md`, `CONTRIBUTING.md` and `check_changelog.py` follow
  `btclib-org/.github`** (issue btclib-org/.github#1075): what is filed
  is one test, and an entry's body past three lines is refused.

### A test pins where `pytest_configure` writes the coverage threshold

- **`tests/conftest_test.py` pins where `pytest_configure` writes the
  threshold** (closes #2056): on `known_args_namespace`, the copy
  pytest-cov holds, and not on `config.option`.

### The lint command and two `pytest` steps are compared to their sites too

- **`tests/docs_commands_test.py` also compares the lint job's command,
  the two `pytest` steps and the bindings assertion against
  `CONTRIBUTING.md`'s own spelling of each** (closes #2081).

### `coverage combine` and `coverage report` name their own configuration file

- **Both take `--rcfile=pyproject.toml`, in `test.yml` and in
  `CONTRIBUTING.md` alike** (closes #2072): a directory holding no
  configuration used to pass `coverage report` at no floor at all.

### `CHANGELOG.md` regains the `..`-segment entry's closing bullet

- **The bullet naming `fa86147a` as `btclib-node`'s half of issue
  btclib-org/.github#1049 is whole again** (issue #2089): a rebase's
  union merge had split it around another entry's own new heading.

### `links.yml` calls the organization's reusable workflow

- **The lychee job lives in `btclib-org/.github`** (issue
  btclib-org/.github#35): this file keeps the trigger, the schedule and
  the files it checks.

### Comments and prose name the file a pinned value lives in

- **Comments and documentation point at `.python-version`, `HWI_VERSION`
  and `fail_under` rather than copy their values** (closes #2079): the
  convention `CLAUDE.md` holds for a tool's `rev:` reaches any pinned value.

### Every `[dependency-groups]` entry declares a lower bound

- **Each is the release `uv.lock` resolves, under a comment naming the run
  behind it, and the docs tooling is declared from 3.12** (closes #2061):
  `uv lock --resolution lowest-direct` completes rather than failing.

### `lint.yml` says its pre-commit step installs the bindings

- **The comment above *Run the pre-commit hooks* says `--only-group lint`
  installs the bindings the `lint` group includes and not btclib itself**
  (closes #2094).

### The wiki and the projects board are off

- **`REPOSITORY.md` records both as `false`** (issue
  btclib-org/.github#550), the settings having been turned off.

### The `needs:` shape test reads hyphenated job keys

- **A block list of `test-passed` and `free-threaded` is read whole**
  (closes btclib-org/.github#1063), so an item token narrowed to stop
  at a hyphen fails the test.

### `sdist-rebuild.yml` verifies the latest release's sdist weekly

- **The sdist is rebuilt from the tag as `RELEASING.md` rebuilds it**
  (issue btclib-org/.github#523), and `gh attestation verify` fails the
  run where no attestation `release.yml` signed carries its digest.

### `TlsLineTransport` ships, and `ElectrumFetcher` takes no default transport

- **`btclib.fetch.TlsLineTransport(host, port)` verifies the server's
  certificate by default** (closes #1127); `btclib.fetch`'s docstring says
  where a protocol's codec, client and server live (closes #1193).

### A release rehearsal no longer cancels `main`'s docs and platform runs

- **`docs.yml`, the three `os-*.yml` sweeps and `integration-bitcoind.yml`
  take the `concurrency-suffix` `release.yml` passes as `-release`**
  (issue btclib-org/.github#1083), matching `test.yml` and `lint.yml`.

### `docs.yml` and `integration-bitcoind.yml` key on the pull request's number

- **The group no longer keys on `github.head_ref`** (issue #1158),
  matching `test.yml` and `lint.yml`: two forks pushing a same-named
  branch collide under a name and not under a number.

### `tests/imports_test.py` checks a substrate candidate's own closure

- **Each substrate candidate asserts its own import closure against an
  allowlist, and the application slab asserts that nothing imports it**
  (issue #1192).

### The concurrency group is keyed on the pull request's number, not `github.head_ref`

- **`links.yml`, `py-arm-authority.yml`, `vendored-vectors.yml`,
  `zkp-oracle.yml` and `sdist-rebuild.yml`** (closes #2101), matching
  `docs.yml`, `integration-bitcoind.yml`, `test.yml` and `lint.yml`.

### `codeql.yml` calls the organization's reusable workflow

- **The analysis job lives in `btclib-org/.github`** (issue
  btclib-org/.github#35): this file keeps the trigger, the schedule and
  the aggregate job, and declares the permissions the called job needs.

### `docs.yml` calls the organization's reusable workflow

- **The checkout, the build and the unresolved-link check move to
  `btclib-org/.github`'s `reusable-docs.yml`** (issue
  btclib-org/.github#35): this file keeps the trigger and the group.

### `REPOSITORY.md` reads the required checks back in the endpoint's order

- **The required-checks table and the `PATCH` example put
  `Lint and type-check` before `test: every job passed`, and
  `Regtest against Bitcoin Core` before `docs`** (issue btclib-org/.github#35).

### `lint.yml` calls the organization's reusable workflow

- **The checkout, the uv setup and the pre-commit run move to
  `btclib-org/.github`'s `reusable-lint.yml`** (issue btclib-org/.github#35):
  `main`'s required check renames to `lint / Lint and type-check`.

### `tests/docs_commands_test.py`'s lint-command comparison goes

- **`lint.yml` holds no command left to compare** (issue
  btclib-org/.github#35): the comparison against `CONTRIBUTING.md` would
  pass vacuously, so it goes.

### `lint.yml` no longer says its pre-commit step installs the bindings

- **The step moved to `btclib-org/.github`'s `reusable-lint.yml`** (issue
  btclib-org/.github#35), whose own comment does not repeat this tree's
  claim about the bindings the `lint` group installs.

### `ecc.dsa` and `ecc.ecies` stop importing `btclib.to_pub_key`

- **A public key's unproven SEC octets are `curves.sec_point._sec_from_pub_key`'s**
  (issue #1188); `ecc.ecies.derive_keys` also stops proving the key twice,
  the same redundant lift issue 887 fixed for `ecc.dsa`.

### `REPOSITORY.md` puts the lint rename's check at the rule's tail

- **The required-checks table and the `PATCH` example put `lint / Lint and
  type-check` last** (issue btclib-org/.github#35); the preceding entry's
  claim that it came before `test: every job passed` no longer holds.

### The libsecp256k1 symbol pin follows upstream's `ge_parse` split

- **`tests/_data/secp256k1_symbols.txt` is re-extracted at `46db7871`**
  (closes #2104), where `ge_parse` has become a size-keyed family; neither
  name the split removed is one this tree's prose credits.

### Every released section of the changelog is a file of its own

- **`CHANGELOG.md` keeps the cycle in progress, the release it follows and
  an index of the rest, each release before those being
  `changelog/v<version>.md`** (closes #2109).

### `CHANGELOG.md` is small enough for the contents API to serve

- **Past a size ceiling that endpoint answers `"encoding": "none"` with no
  content at HTTP 200**, which reads as an empty file rather than as an
  error (issue #2109).

### A link into `CHANGELOG.md` naming an archived release stops resolving

- **The index at the top of that file is what leads to the release**, on
  the forge and in the documentation build alike (issue #2109).

### The sdist carries the changelog's window and not what is archived

- **`[tool.check-sdist]`'s `git-only` names `changelog/`** (issue #2109):
  what an unpacked sdist holds of the changelog is the window and the
  index into the rest.

### An address is built from a `key.PubKeyData`, not from a key union

- **The base58 and bech32 address builders, the `ScriptPubKey`
  constructors, `script.taproot`'s internal key and `wallet.KeyWallet`
  take the half of a key pair a caller states** (issue #1188).

### `ScriptPubKey.p2ms` refuses keys of several networks

- **A multisig output's keys have to agree on their network** (issue
  #1188), where the one `network` argument the call used to take filled
  the first key's in for all of them.

### `[tool.mypy] exclude` is anchored to the `build/` directory it means

- **`"build"` was an unanchored regex, matching any path containing that
  substring rather than only its own directory** (closes #2115), and it
  dropped test files from the type gate as a result.

### `block.build_coinbase` takes a `ScriptPubKey` for its output script

- **Its `script_pub_key` was annotated `Octets` while forwarding straight
  into a `TxOut`, which has always taken either** (issue #2115): the
  annotation was narrower than the call the function already made.

### `to_prv_key` and `to_pub_key` are deleted

- **Each spelling of a key is read by the module that owns the format,
  and the record above it is `key.PrvKeyData` or `key.PubKeyData`**
  (closes #1188): the two aggregators are a layer with nothing left in it.

### `conf.py`'s version comment no longer blames read the docs

- **`.readthedocs.yaml` installs btclib, so the comment's false clause
  goes** (issue btclib-org/.github#1098): the reason is now that a
  version should not depend on whether the project happens to be installed.

### Three prose sites are re-pointed at the identifiers they now name

- **`tests/_data/README.md`, `tests/script/taproot_test.py` and
  `.github/mutation/wallet.toml` each named a converter no module still
  defines** (closes #2121): each now cites the call site that replaced it.

### `tests/__init__.py` builds one key pair's spellings on call, not at import

- **A module named `..._test.py` holding no test is the shape
  `tests/__init__.py`'s own docstring rejects** (closes #2120): the
  spellings move into a `key_pair_spellings` function, called on demand.

### `tests/imports_test.py` asserts `b58` and `b32` import no `btclib.bip32`

- **CLAUDE.md's *Architecture* states the arrow and nothing tested it**
  (closes #2125): `test_b58_stays_below_bip32` is built the way
  `test_address_encodings_stay_below_script` already is.

### The census's documented local recipe keeps the bindings out

- **A bare `uv run` after `uv sync --no-default-groups --group harness`
  reinstalled the bindings** (closes #2132): the flags move onto
  `uv run` itself, and `measure()` refuses to run where they are installed.

### `Sig.serialize` writes DER length octets, not CompactSize ones

- **The sequence length was CompactSize, which diverges from X.690 at
  128 octets** (closes #2130): `bpp512r1`, `nistp521` and `secp521r1`
  reach it; `parse` still refuses the long form it never wrote.

### The `[tool.mypy] exclude` comment no longer claims one shared anchoring

- **mypy's own `--exclude` help text anchors its own example too, but
  at the other end** (closes #2137): `/setup\.py$` pins a trailing `$`
  to one filename, `^build/` a leading `^` to a directory.

### `release.yml`'s three release-only jobs become calls into `btclib-org/.github`

- **`version-check`, `public-api` and `documented` now call
  `btclib-org/.github`'s reusable workflows, pinned at `@main`**
  (issue btclib-org/.github#35): the fan and the publishing jobs stay.

### `links.yml`'s `targets:` reaches every tracked markdown file

- **`targets:` left `changelog/*.md`, `.claude/` and `.github/` outside
  lychee's reach** (issue btclib-org/.github#1104): it becomes
  `"**/*.md" ".github/**/*.md" ".claude/**/*.md" "docs/**/*.rst"`.

### `CONTRIBUTING.md`'s docs-gate grep matches the widened pattern

- **The local reproduction still read the pre-widening `href="#\./`**
  (issue btclib-org/.github#1105): it now reads `href="#\.\.\?/`, and
  the prose explaining it is corrected to match.

### `deps-oldest.yml` calls `btclib-org/.github`'s reusable workflow

- **The floor sentinel's own job becomes a call to
  `btclib-org/.github`'s `reusable-deps-oldest.yml`** (issue
  btclib-org/.github#35): the bindings assertion becomes `pre-suite-script`.

### `RELEASING.md`'s bill-of-materials step no longer contradicts itself

- **RELEASING.md's bill-of-materials step contradicted itself about the
  btclib-secp256k1 SBOM exemption** (closes #2142): all four publishers
  attach one, naming the vendored library at the commit its gitlink pins.

### `interpreters_test.py` reads a caller's `with:` beside the block

- **`_PYTHONS_CALLER` reads the JSON-encoded interpreter list a caller
  of `reusable-os-suite.yml` will carry, beside `_PYTHONS`'s own block
  sequence** (issue btclib-org/.github#1119): no such caller exists yet.

### `docs_commands_test.py` decides what it is once its subjects move

- **The module had no written answer for the comparisons
  `btclib-org/.github#35` empties** (closes #2141): a comparison left
  with one site goes, and the module goes with the last of them.

### `ecc.ssa` gains the anti-exfil protocol

- **`anti_exfil_host_commit`, `anti_exfil_signer_commit`, `anti_exfil_sign`
  and `anti_exfil_host_verify` mirror `dsa`'s own** (closes #2147): BIP340's
  nonce derives from the host's commitment alone, not `sign_`'s aux mix.

### The three `os-*.yml` sweeps call `reusable-os-suite.yml`

- **`os-ubuntu.yml`, `os-macos.yml` and `os-windows.yml` are that caller now**
  (issue btclib-org/.github#35). This bears on *`interpreters_test.py` reads a
  caller's `with:` beside the block* above: that caller now exists.

### `tests/ecc/anti_exfil_test.py` is renamed `dsa_anti_exfil_test.py`

- **The name named no module, unlike `ssa_anti_exfil_test.py` beside
  it** (closes #2149): `.github/mutation/signatures.toml` and
  `tests/_data/README.md` follow the `git mv`.

### `source-exclude` drops a dot-prefixed name under a shipped tree

- **The shape replaces the cache names, `.hypothesis` among them**
  (issue btclib-org/.github#1070), and `tests/sdist_dotted_names_test.py`
  refuses a dotted path a shipped tree means to carry.

### `test.yml`'s `changes` job calls the organization's reusable workflow

- **The event handling, the pagination and the decision move to
  `btclib-org/.github`'s `reusable-changes.yml`** (issue
  btclib-org/.github#35): this file keeps which files are its own prose.

### `CONTRIBUTING.md` and `REVIEWING.md` gain the entry-position instrument

- **`check-changelog` reads no position, so `CONTRIBUTING.md` now prints
  the open section's headings in order and `REVIEWING.md` asks whether
  the branch's own entry is last** (issue btclib-org/.github#1097).

### `check-changelog` runs on every invocation of the gate

- **`always_run: true`, and no `files:`** (issue btclib-org/.github#1138):
  the script reads the open section off disk, and the rebase that eats
  the seam stages nothing.

### `check_changelog.py` states its own rebase comparison, not a dead citation

- **The citation to `CONTRIBUTING.md`'s *Committing and rebasing* pointed at a
  heading no tree carries** (issue btclib-org/.github#1137): the docstring now
  states what the rebase comparison does, in its own words.

### zizmor's `self-repository` audit is declined per site, and the pin follows

- **`zizmor-pre-commit` moves to v1.30.1, and each `uses: ./` site
  carries its own `# zizmor: ignore[self-repository]`** (closes #2156):
  the form goes red when a thirteenth site appears with none.

### `mutation_counts.py`'s aside drops a crash cosmic-ray 8.5.0 already fixed

- **The `cosmic-ray dump` aside drops a crash claim cosmic-ray 8.5.0
  fixed, stating instead why `sqlite3` reads only the two columns and
  the count this needs** (issue btclib-org/.github#1152).

### `mutation.yml`'s matrix becomes a call, and its budgets keep their reasons

- **The matrix becomes a JSON `profiles` input and its reasoning moves
  above it: what set a budget stays, what the scope's own
  `.github/mutation/*.toml` already counts goes** (issue btclib-org/.github#35).

### `scorecard.yml` calls the organization's reusable workflow

- **The analysis job's checkout, scan, artifact and SARIF upload steps
  move to `btclib-org/.github`'s `reusable-scorecard.yml`** (issue
  btclib-org/.github#35): the calling job keeps the elevated permissions.

### `ecc` gains FROST threshold signing

- **`ecc.frost` implements BIP445's threshold Schnorr signing, pinned to
  v0.10.0 of `bitcoin/bips#2070`** (closes #2158): a *t*-of-*n* signer
  subset produces one BIP340 signature; key generation stays out of scope.

### `sdist-rebuild.yml` calls the organization's reusable workflow

- **The release lookup, the checkout, the build, the normalizer and
  `gh attestation verify` move to `btclib-org/.github`'s own
  `reusable-sdist-rebuild.yml`** (issue btclib-org/.github#35).

### `deps-latest.yml` calls `btclib-org/.github`'s reusable workflow

- **`lint-latest` and `suite-latest` become one `reusable-deps-latest.yml`
  call** (issue btclib-org/.github#35), the other two jobs staying:
  `measure-coverage: true` keeps this tree's 100% ratchet through the upgrade.

### `transport_test.py`'s deadline test drops the real clock

- **`test_every_operation_gets_what_is_left_of_one_deadline` monkeypatches
  `monotonic`, like its neighbor, and asserts the exact timeout
  sequence** (closes #2167): a loaded runner could starve the real clock.

### `pypi-install.yml` calls `btclib-org/.github`'s reusable workflow

- **`wait-for-index`'s checkout, uv setup and wait script become one
  `reusable-wait-for-index.yml` call** (issue btclib-org/.github#35),
  the two install matrices staying, `needs: wait-for-index` unchanged.

### `check_vendored_vectors.py` can re-check a pin off the default branch

- **A ledger entry's own `ref` field reaches GitHub's "commits touching a
  path" API as its `sha` parameter** (closes #2160): a pin standing on a
  fork's pull-request branch is checked rather than permanently excused.

### The documentation says where a threshold lives

- **`docs/source/where-the-threshold-lives.md` compares the script
  threshold, MuSig2 and FROST** (closes #2175): what each costs, where
  each lives in this tree, and why *t* = *n* FROST is not MuSig2.

### `ecc.ssa` and `ecc.dsa` raise on a structurally invalid signature or key

- **`verify`, `verify_`, `batch_verify` and `batch_verify_` raise, instead
  of answering `False`, for a signature or a key whose size or encoding
  makes it impossible** (issue #2170), converging on BIP340's reference.

### A BIP340 x-only public key that does not lift still answers `False`

- **A 33/65-byte SEC key or a native point is proved on the curve while
  parsing in both modules; a bare 32-byte x-only key's lift stays
  deferred to the equation** (issue #2170), as BIP340's `lift_x` is.

### `ecc.dsa`'s malformed DER encoding still answers `False`

- **Reclassified as structural, it would fail
  `wycheproof_test.py::test_ecdsa_der`, measured against its own vectors**
  (issue #2170): left as it was, unlike BIP340's fixed 64 bytes.

### `claude-review.yml` calls `btclib-org/.github`'s reusable workflow

- **`review` and `mention` become one `reusable-claude-review.yml`
  call** (issue btclib-org/.github#35): the verdict jq gains
  btclib-org/btclib-secp256k1#394's fix, and the pin moves to `ef8bb1e4`.

### A `ready_for_review` comment names the workflow the draft condition is in

- **`docs.yml`, `links.yml` and `lint.yml` name the reusable workflow
  each of them calls as where the draft condition is** (issue
  btclib-org/.github#1177): the caller's own job carries none.

### `pytest_report_header`'s coverage comes from a test, not the runner

- **`tests/conftest_test.py` asserts the sentence each `ZKP_AVAILABLE`
  arm yields** (closes #2179): pytest calls the hook only where it
  writes a session header, so a `-q` run missed the statement.

### `docs.yml` says the draft and closed declines are `reusable-docs.yml`'s

- **The `jobs:` comment names the called workflow as what declines a draft
  and a closed pull request, reading the event off this caller's
  trigger** (closes btclib-org/.github#1179).

### The rest of `ecc` raises on a structurally invalid argument too

- **`bms.verify`, `borromean.verify`, `pedersen.verify`,
  `dleq.verify_proof` and `rangeproof.verify` join `ssa` and `dsa`**
  (closes #2170), and every `ecc` verification draws that line.

### An address is `ecc.bms`'s public key

- **`bms.verify` raises for a string that decodes to no address, and for
  octets no 65-octet compact signature has** (issue #2170); an address
  that is simply another key's is `False`.

### A borromean or rangeproof serialization is parsed before the walk

- **Octets that are no signature over those rings, or no proof at all,
  raise** (issue #2170): the wire form says how many scalars follow in
  neither case, `pubk_rings` and the header saying it instead.

### `ecc.pedersen.verify` raises for an opening that is no number

- **An `Integer` spelled as text no number reads leaves nothing to
  recompute the commitment from** (issue #2170); an r of 0 mod n is a
  number, and is `False`.

### A message of declared size raises where it is not that size

- **`dsa.verify_`'s digest, on both arms, and `dleq.verify_proof`'s
  32-octet message** (issue #2170); a BIP340 message declares no size, so
  a short one is a message that was not signed and is `False`.

### `claude-review.yml` takes the `closed` pull request type

- **The trigger's `types:` gains `closed`, with the reason at the key**
  (issue btclib-org/.github#1182): the workflow-level group can now
  cancel a still-running review, which the callee's own `if:` declines.

### `ecc.rangeproof` asks a `RangeProof` argument its own validity

- **`assert_as_valid` and `rewind` refuse a proof built with
  `check_validity=False` in a state `RangeProof.assert_valid` names, and
  `verify` answers `False`** (closes #2182), as `ecc.bms` does a `Sig`.

### The `bindings` and `zkp` skips are covered by tests, not by the build

- **`tests/conftest_test.py` drives both skip helpers and the hook under
  each value of `INSTALLED` and `ZKP_AVAILABLE`** (closes #2185): no
  `pragma` stands in for the arm a machine's own build cannot reach.

### `bip322.verify` raises on a structurally invalid address or signature

- **A string that decodes to no address, and text written in none of the
  encodings this module reads, are refused** (closes #2181); a real
  address the signature does not spend is `False`.

### `bip322.verify`'s comment states its own split

- **What is refused ahead of the try, and what the try answers `False`
  for** (closes #2177), in place of a sentence `ecc.dsa.verify_` no
  longer carries.

### `psbt.frost` carries a FROST session through a psbt

- **The BIP445 rounds over BIP174 proprietary records under a `btclib`
  identifier, which no other wallet reads and which are dropped rather
  than aliased once a psbt BIP assigns FROST type bytes** (closes #2174).

### `wait_for_pypi_release.py` carries the body the four trees can share

- **This copy keeps what any copy said and says nowhere else, qualifies
  its citation, passes `"$PACKAGE"`, drops `import sys`, and splits the
  `except` into two clauses** (issue btclib-org/.github#1160).

### `release.yml`'s `attest` and `github-release` become calls into `btclib-org/.github`

- **Both jobs now call `btclib-org/.github`'s reusable workflows, pinned
  at `@main`** (issue btclib-org/.github#35): the signer identity stays
  `release.yml`'s until this tree's next release.

### The twenty-two mutation profiles stop stating totals

- **Every `.github/mutation/*.toml` header drops its mutant, kill,
  survive and skip counts and rates** (closes #2166, issue
  btclib-org/.github#1158); the judgement stays, read off the run.

### `codeql.yml`'s `analyze` block documents its grants too

- **The two grants `zizmor --persona=auditor` flags in the `analyze`
  block take a trailing comment, the leading prose kept** (issue
  btclib-org/.github#1164): `codeql-passed` already carried the repeat.

### `wait_for_readthedocs_build.py` carries the body the four trees can share

- **This copy takes the reference's usage example, drops `import sys`,
  templates `USER_AGENT` on the project `unserved` now takes as a third
  argument, and qualifies its citation** (issue btclib-org/.github#1186).

### `bip322`'s module docstring names both classes an invalid signature raises

- **Invalid is a `BTClibValueError` or a `BTClibRuntimeError`, where the
  docstring named the first alone** (closes #2195): one `ful` payload
  over too few octets raises the second, and no rule is stated about which.

### `CONTRIBUTING.md` names both classes `bip322.verify` raises on unreadable input

- **The carve-out named `BTClibValueError` alone** (closes #2197): the
  same `ful` payload over too few octets draws `BTClibRuntimeError`
  too, and no rule is stated about which.

### `CONTRIBUTING.md` and `REVIEWING.md` stop describing a stated count

- **`CONTRIBUTING.md` and `REVIEWING.md` described a mutation-profile
  header's stated count, which PR #2201 already removed** (closes
  #2202): both now match the header instead of a count that is gone.

### `ecc.rangeproof` refuses a mantissa `check_validity=False` lets through

- **`RangeProof.max_value`, `rsizes`, `sign_key_idx`, `nonce_chain`,
  `serialize` and `pubk_rings` refuse a mantissa outside 1..64**
  (closes #2190), where each once answered a bare exception or a wrong value.

### `tests/build_system_test.py`'s reader takes an entry from its own line

- **`_source_exclude` and the `secp256k1` extra reader use `_ENTRY`,
  an entry's own line, not `_QUOTED`'s any quoted string** (closes
  #2152): a comment's mention of a path no longer counts as one.

### `CLAUDE.md` stops describing a mutation profile's stated count too

- **The same stale claim survived in `CLAUDE.md`'s own copy, missed by
  #2202's scope** (closes #2204): it now matches `REVIEWING.md`'s and
  `CONTRIBUTING.md`'s current wording too.

### The zizmor hook takes `--persona=auditor`, and the tree measures zero

- **Every flagged grant carries a comment, and every
  `template-injection` site is declined or reads its matrix value from
  the environment** (issue btclib-org/.github#1164 and btclib-org/.github#1198).

### FROST is in a mutation scope

- **`.github/mutation/frost.toml` mutates `ecc/frost.py` and
  `psbt/frost.py` under `mutation.yml`'s own `frost` profile**
  (closes #2193): its header judges a run's survivors; new tests kill some.

### `CLAUDE.md` says how the seam a rebase eats is named and repaired

- **A rebase can eat the blank line above the entry, and the first run
  that repairs it exits 1**: both are measured on a rebased tree and
  stated in *Non-obvious facts*.

### `vendored-vectors.yml` calls `btclib-org/.github`'s reusable workflow

- **The vector sentinel's own job becomes a call to
  `btclib-org/.github`'s `reusable-vendored-vectors.yml`** (issue
  btclib-org/.github#1196): the calling job now grants `issues: write`.

### `check_vendored_vectors.py`'s docstring names every guarded trigger

- **`--dry-run`'s docstring names what
  `reusable-vendored-vectors.yml` passes now, not one trigger**
  (issue btclib-org/btclib-benchmarks#362).

### `integration-bitcoind.yml` calls `btclib-org/.github`'s reusable workflow

- **The regtest job becomes a call to `btclib-org/.github`'s
  `reusable-integration-bitcoind.yml`** (issue
  btclib-org/.github#1196): the calling job grants `contents: read`.

### `fuzz.yml`'s header says why it does not call `btclib-node`'s

- **The header states the Python-version constraint that keeps it apart
  from `btclib-node`'s `fuzz.yml`** (issue btclib-org/.github#1196):
  ClusterFuzzLite's builder image pins 3.11.13 against that tree's `>=3.14`.

### `check_changelog.py` gains the fifth check, and its own grandfathered count

- **The hook now refuses an entry landed above `RULE_HEADING`** (issue
  btclib-org/.github#1215): `_GRANDFATHERED_ENTRIES` is 23, the count
  the open section held above that heading the day the check was ported.

### The `check-changelog` hook's comment names no count

- **`.pre-commit-config.yaml`'s `check-changelog` comment stops naming
  how many checks its docstring lists** (issue btclib-org/.github#1225):
  the docstring already enumerates them.

### `[tool.uv] required-version`'s floor matches the pin Dependabot bundles

- **The floor moves to `>=0.12.17`, and `astral-sh/uv-pre-commit`'s own
  `rev:` moves with it** (issue btclib-org/.github#1229): below the pin,
  the floor admitted a `uv` older than the one Dependabot locks with.

### The command line's design leaves the tree for the organization tracker

- **`docs/proposals/cli.md` goes to btclib-org/.github#1235, and the four
  files that cited it cite the issue** (issue #357): the tree the command
  line mirrors is four distributions' once #2129 lands.

### `TF2.md` leaves btclib, and a `test_framework` citation names no revision

- **`TF2.md` and `tests/tf2_ledger_test.py` are gone** (issue #2220): a
  citation of Core's `test/functional/test_framework/` now names the
  file and the function alone.

### The workflows with `closed` and no `push` gain the merge-aware conditional

- **`links.yml`, `sdist-rebuild.yml`, `vendored-vectors.yml` and
  `zkp-oracle.yml` gain it** (issue btclib-org/.github#1226): a merged
  close queues behind the run in flight, and a bare close still cancels.

### `ElectrumFetcher`'s docstring states the script-keyed boundary as a reason

- **Its final paragraph no longer narrates an issue** (closes #2222): it
  says every `Fetcher` question is keyed on an identifier the caller
  already holds, and a script is not one.

### `wallet.py`'s refusal paragraph drops its two false clauses

- **"What no wallet here does" drops its two false clauses**
  (closes #2225): transaction building reads no chain, and no
  `Fetcher` question is keyed on a script, `get_tx_out` included.

### `tests/_data/README.md`'s stale pins move to upstream's tip

- **BIP374's verify-proof vectors gain failure cases btclib already
  refuses; the rest of this README's pins advance with nothing new**
  (closes #2228).

### `fetch/` gains a `FeeEstimator` protocol; `fee.py` narrows its refusal

- **`FeeEstimator`, beside `Broadcaster`, quotes a `FeeQuote` -- a rate and
  the target it is valid for -- on `BitcoinCoreFetcher`, `ElectrumFetcher`
  and `EsploraFetcher`** (closes #2223): `fee.py` no longer declines it.

### `REPOSITORY.md` marks its one observation

- **The organization plan reading carries `a fact about a changing
  world` and the instant it was read** (issue btclib-org/.github#1017):
  every other quoted answer in this file is a setting.

### `REPOSITORY.md` stops hiding readings from its own readback

- **An aside glued to `.security_and_analysis`'s answer, an ellipsis
  inside two JSON values, and a fence indented under a bullet** (issue
  btclib-org/.github#1017): each misled the parser or hid what follows.

### `.pre-commit-config.yaml`'s `pyroma` hook is `repo: local`

- **Bound now by the `check` group's `pyroma>=5.0.1` instead of a
  `rev:`** (issue btclib-org/.github#1199): `autoupdate` has no `rev:`
  left to offer it a prerelease on.

### The shared scripts are served from `btclib-org/.github` now

- **`check_changelog.py`, `mutation_counts.py`, `wait_for_pypi_release.py`
  and `wait_for_readthedocs_build.py` leave `.github/scripts/` for it**
  (issue btclib-org/.github#1293): `check-changelog` is a remote hook now.

### `REPOSITORY.md` names the regtest check the way the rule does

- **The table, the `PATCH` example and the prose name the check
  `regtest / Regtest against Bitcoin Core`** (closes #2234); the first two
  list it last, as the endpoint does, not before `docs` as an earlier entry did.

### `tests/imports_test.py` guards row 5 of the decomposition

- **`_APPLICATION_SLAB` names the units of `btclib-wallet`, and the scan
  for an inbound edge leaves `mnemonic/` out** (issue #2129): its
  seed-to-key functions import `bip32` and are row 5 by that issue's table.

### `notice-rgx` admits a `#!` line ahead of the copyright notice

- **`^(#![^\n]*\n)?` precedes the escaped `COPYRIGHT` text instead of a
  bare `^`** (issue btclib-org/.github#1294): only a `#!` line may
  precede the notice, for a script run by path.

### The btclib names `btclib-wallet` imports are public

- **`curves` exports `sum_var`, `tweak_add_var`, `TweakChain`,
  `is_x_coordinate_var` and `mult_pub_key`** (closes #2242); names of
  `bech32`, `ecc.frost`, `network`, `script_pub_key` and `tx.tx` become public.
