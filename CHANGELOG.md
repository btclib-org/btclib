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

- [v2026.9.10](./changelog/v2026.9.10.md)
- [v2026.9.3](./changelog/v2026.9.3.md)
- [v2026.8.29](./changelog/v2026.8.29.md)
- [v2026.8.27](./changelog/v2026.8.27.md)
- [v2026.8.21](./changelog/v2026.8.21.md)
- [v2026.8.9](./changelog/v2026.8.9.md)
- [v2026.8.7](./changelog/v2026.8.7.md)

## v2026.10 (work in progress, not released yet)

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

## v2026.9.13

### `ecc.rangeproof.sign` writes the rangeproof of a blinded value

- **A Confidential Transactions rangeproof over a range, and not only
  over a value stated in the clear** (issue #1072). `sign` takes a
  blinding factor, a value and a nonce, and `min_value`, `exp` and
  `min_bits` beside them; what comes back is the proof
  `secp256k1_rangeproof_sign_impl` writes for those arguments, octet
  for octet. `sign_public_value` is that walk at an exponent of -1.
- **The header is what the format has room for, not what was asked
  for.** `secp256k1_range_proveparams` lowers the exponent until the
  proven range fits a uint64, lowers `min_bits` to the precision the
  floor leaves, sets the mantissa to the wider of that precision and
  the bits the rescaled value needs, and rewrites `min_value` to what
  that value no longer reaches. A `min_value` at the ceiling of the
  field codes no range at all and writes the exact-value proof; a
  nonzero floor under a value past `2**63-1`, or a nonzero value over a
  floor at or past it, is refused.
- **Each stated ring commitment's sign bit is computed as quadratic
  residuosity, not parity.** `secp256k1_rangeproof_serialize_point` writes
  `!secp256k1_fe_is_square_var(&point->y)`, which the `02`/`03` SEC
  prefix and BIP340's x-only convention disagree with on some points
  and agree with on others, so the familiar reading writes a proof that
  verifies nowhere and fails nothing locally.

### `docs/proposals/cli.md` states no count, and its module list is current

- **The four figures that document stated are gone** (closes #1977),
  and each sentence keeps the claim they sat in front of. The
  `rootxprv`/`mxprv` argument was "at 53 occurrences of `rootxprv` and
  51 of `mxprv` over library and tests"; over that same scope the tree
  answers 43 and 16, so one of the two was wrong by roughly three
  times. Those are occurrences of the whole word, which is
  `git grep -oh --perl-regexp '\brootxprv\b' -- src tests | wc -l` and
  its `mxprv` twin. Both halves of that command carry the figure:
  `git grep -E` drops `\b` in silence and answers zero, and counting
  matching lines rather than occurrences answers 113 and 61 instead.
  What the sentence is actually about -- two names for one object, and
  `mxprv` the one matching the `m/...` notation -- needs no arithmetic
  in front of it. The `__all__` paragraph stated two more,
  "the twenty-two at the top level" and "the fifty-nine below the
  packages", and those are worse than drifted: the sentence is past
  tense, describing the tree before any module declared an `__all__`,
  so nothing re-derives them and nothing can.
- **`descriptors` and `keystore` leave that paragraph's list of
  top-level modules**, which named them to illustrate what "at the top
  level" meant. `descriptors` is a package now, and there is no
  `keystore` at all -- the package is `btclib.wallet`. The five that
  remain, `b58`, `b32`, `network`, `amount` and `fee`, are each still a
  `src/btclib/*.py`. They are dropped rather than repointed because the
  sentence is about the tree the audit found: renaming a module inside a
  past-tense description would make it false in the other direction.

### The gate runs section 4's local hooks

- **`reasonless-coverage-pragma` refuses a `#`-comment `pragma: no cover`
  or `pragma: no branch` with nothing after it on its line** (issue
  btclib-org/.github#965): the hook's `entry:` and `types:` are
  `btclib-org/.github`'s at `69a47e6`. Every `no cover` here carried its
  reason inline already; every `no branch` carried it in the comment
  above the line, which section 8 names as the rejected alternative the
  port rewrites, so each of those takes the inline half naming the case
  and keeps the comment above it.
- **`unquoted-placeholder` refuses a placeholder standing as a whole
  argument in quotes, in every markdown file but `CHANGELOG.md` and
  `RELEASE_NOTES.md`** (issue btclib-org/.github#706): section 9 of the
  organization standard keeps the rule and section 4 names the quotes
  the pattern exempts and the three shapes it cannot see; the exclusion
  is the standard's own, both files being append-only. The tree is green
  under the hook at the run that adds it.
- **`check-changelog` refuses a `###` heading repeated in this file's
  open section, an issue `(closes #N)` by two entries, and a heading
  with no blank line above it** (issue btclib-org/.github#21):
  `.github/scripts/check_changelog.py` is `btclib-org/.github`'s at
  `69a47e6` byte for byte, which section 14 owes every repository, and
  the hook sits ahead of `markdownlint-cli2`, whose `--fix` repairs the
  seam the third check names. `pyproject.toml` lets the script print as
  it lets the scripts beside it: what it prints is its report. The
  script's `_BLANK_LINE` carries an attribute docstring that
  `check-docstring-first` reads as a second module docstring
  (btclib-org/.github#995), so that hook's `exclude:` names the script,
  the file being owed byte for byte rather than this tree's to edit.
- **`toml-comment-width`'s `name:` states the pattern's own predicate,
  an unbroken final token past byte 80** (issue btclib-org/.github#843,
  issue btclib-org/.github#885): the width is bytes, pygrep matching the
  pattern against the raw line, and the comment above the hook says
  "byte 80" where it said "column 80"; the `entry:` is unchanged.
  v2026.9.10's *`toml-comment-width`'s comment describes the pattern and
  no other tool* left the `name:` to a decision every tree carrying the
  hook takes together, and `btclib-org/.github` took it at `51f717e`.
- **`.yamllint.yaml`'s `allow-non-breakable-words` comment states only
  the setting's own predicate** (issue btclib-org/.github#883): the
  clause comparing it to MD013's exemption for a bare URL goes rather
  than being corrected, which is what btclib-org/.github#883 settled,
  and the file matches `btclib-org/.github`'s at `69a47e6` byte for
  byte, which is section 14's comparison.

### `ecc.rangeproof` verifies a proof and rewinds it

- **A proof is checked against the commitment it was written for**
  (closes #1072). `verify` answers whether it holds and
  `assert_as_valid` raises the reason;
  `RangeProof.pubk_rings` already rebuilt the rings
  `secp256k1_borromean_verify_impl` is handed, and what is added is the
  walk over them. The range proven stays the proof's own `min_value`
  and `max_value`, which the header states and a parse reads, where
  `zkp.rangeproof.verify` answers it from the octets for want of
  anything else to answer from.
- **`rewind` reads the value, the blinding factor and the message back
  out of a proof.** `secp256k1_rangeproof_rewind_inner` is called from
  inside `secp256k1_rangeproof_verify_impl` and consumes the per-key
  challenges that walk produced, so verification retaining them is what
  a rewind is built on rather than a second pass: whoever holds the
  nonce re-derives the chain over a zeroed buffer, reads the value out
  of the last ring, recovers the scalars the real signatures were
  written under, and is refused where what comes back does not open the
  commitment.
- **`sign` embeds a message for that rewind to find.** It rides at the head
  of the buffer the chain is folded with, one scalar per key at the stride
  the chain indexes them by; the rings before the last are the whole of the
  room, and a proof of one ring carries none. Where the header states a
  range, a rewind answers every key of every ring, less the two the last
  ring spends on the value encoding and on the key its own digit opens.
  So what comes back is the message and then the zeros behind it, with
  nothing in a proof saying where one ends.
- **A generator of the caller's is still not taken** (issue #1986). A
  proof written or read here is written against `ecc.pedersen`'s own
  second generator.

### `ecc.rangeproof` binds octets of a caller's own into a proof

- **`sign`, `assert_as_valid`, `verify` and `rewind` take
  `extra_commit`** (closes #1984): octets of the caller's own -- the
  output a commitment belongs to, say -- bound into the proof rather
  than carried by it, so a verifier is handed them again or the proof
  does not hold for it. `include/secp256k1_rangeproof.h` states what
  the binding buys: without it a prover can move a scalar from one
  digit commitment to another and obtain a second valid proof for the
  same commitment and witness.
- **It closes the message the rings are signed over and reaches
  nothing else.** `secp256k1_rangeproof_sign_impl` and
  `secp256k1_rangeproof_verify_impl` write it into `sha256_m` after
  the ring commitments and immediately before finalizing, where
  `secp256k1_rangeproof_genrand` takes no such argument -- so the
  header, the sign bits and the ring commitments a proof states are
  those of a proof written under none, the signature over them is not,
  and a rewind answers the same blinding factor, value and message.
- **Keyword-only, as the sign-to-contract `commit` of `ecc.dsa` and
  `ecc.ssa` is.** The octets have to be the same where a proof is
  written and where it is read, and naming the argument at both call
  sites is what shows they are.

### The vendored fixed rangeproofs are rewound under the nonces upstream uses

- **All six can now be rewound** (closes #1988). The transcription of
  libsecp256k1-zkp's `test_rangeproof_fixed_vectors` and
  `test_rangeproof_fixed_vectors_reproducible` left the nonce out,
  written when this tree held only a parse, so nothing in it could be
  asked the rewind direction at all. `nonce_3` and the `vector_nonce`
  the reproducible entries share are read out of that C source at the
  commit `tests/_data/README.md` pins the file to.
- **Two entries have no nonce array, and are rewound under the
  commitment.** Upstream rewinds `vector_1` and `vector_2` of the first
  function under `pc.data`, and
  `secp256k1_pedersen_commitment_parse` ends `memcpy(commit->data,
  input, 33)` -- so that buffer is the published commitment itself and
  the 32 octets a rewind reads out of it are its own first 32. One of
  the two carries an embedded message of upstream's own -- ASCII, 113
  characters and the terminator its `sizeof` covers -- where the five
  entries beside it carry uniform `0xFF` or nothing.
- **`vector_0` is a maximum-length message at the widest mantissa**, a
  shape no recording here carries: it answers
  `SECP256K1_RANGEPROOF_MAX_MESSAGE_LEN` octets of `0xFF` and then the
  padding its last ring leaves. The run and the padding are asserted
  separately, so a rewind answering the run alone fails.

### `ecc.dh` states the timing of the multiplication it delegates

- **The delegated shared point is variable time in the private key**
  (closes #1992). `secp256k1_ec_pubkey_tweak_mul` reaches
  `secp256k1_ecmult`, whose windowed NAF holds at most one more digit
  than the scalar has bits, so the work follows the scalar; the module
  docstring, `diffie_hellman`'s own and the mutation docstring of
  `tests/ecc/dh_test.py` said constant time. The delegation is
  unchanged, and so is what it buys: the speed and libsecp256k1's
  answer.
- **`secp256k1_ecmult_const` is the multiplication that is constant
  time in its scalar, and `secp256k1_ecdh` is what reaches it.**
  Nothing here calls that entry point, for the reason `ecc.dh`'s module
  docstring already gave: it hashes the shared point with SHA256, where
  every derivation here differs.
- **`SECURITY.md` publishes it among the limitations of the delegated
  path**, and `README.md` carries the short form. What is published is
  the shape of the multiplication and not a list of call sites:
  `curves.curve.mult` delegates every point that is neither the
  generator nor infinity, so any point a caller supplied, multiplied by
  a secret scalar, arrives at the same call. `ecc.ellswift.xdh` is not
  an exception — `secp256k1_ellswift_xdh` multiplies with
  `secp256k1_ecmult_const_xonly`, which is constant time in its scalar
  and is not `secp256k1_ecmult_const`. The bindings' own docstrings
  carry the sentence btclib's came from, and are corrected in
  btclib-org/btclib-secp256k1#864.

### An upstream credit is answered for, and one shape of it is gated

- **The wording of a refusal is the bindings' and not the C library's**
  (closes #1964). `silent_payments`' two delegated arms and the
  docstring of `tests/ecc/dsa_test.py`'s fallback case credited
  libsecp256k1 with a message: the C library answers a call with a
  return code, and `btclib_secp256k1` is what turns one into a
  sentence.
- **`tests/upstream_symbols_test.py` gains the sweep keyed on that
  attribution**, beside the one keyed on a `secp256k1_*` name, and the
  module docstring says what its zero means. The pattern is fitted to
  the phrasings it lists, so a zero says that none of those is in the
  swept files and never that no such credit is there; recall against a
  phrasing nobody has written is not measurable. Each shape it does key
  on is planted back by a control, a pattern landing on a tree just
  cleaned of it being green from its first run.
- **A credit that has gone stale gets no gate**, and the ones here are
  corrected by hand: libsecp256k1 keeps its precomputed tables as
  file-scope statics rather than in the context `curves.curve` named,
  and it flips the recovery id by the same flag its
  `secp256k1_scalar_cond_negate` negates s with, where `ecc.dsa` quoted
  a `*recid ^= 1` beside a conditional negation. What such a credit
  asserts is a fact about another project's present source, which only
  a read of upstream at the pinned revision settles.
- **A zero tweak is one libsecp256k1's header admits**, beside the
  tweaks its `secp256k1_ec_seckey_verify` accepts, and the key it
  answers with is the group arithmetic rather than an answer the header
  states: `tests/bip32/bip32_test.py` said the header states it.

### The bindings dispatch is stated by its shape, not by a population

- **A comment on `dsa.gen_keys` and the `btclib.curves` census each
  named a population that is not one** (closes #1994). The generator was
  "the one multiplication libsecp256k1 is dispatched to", where
  `curves.curve.mult` delegates every point that is neither the
  generator nor infinity; and a variable-base multiplication of a secret
  scalar was `ecc.dh` in this package, where BIP374's proof, the ECDH
  share of a BIP375 input and the key generation of BIP38's EC-multiply
  mode each write one too. `SECURITY.md` publishes that population, so
  neither site restates it. The docstrings of
  `curves.curve._libsecp256k1_serves` and of `tests/all_test.py`'s export
  test named the generator the same way, and are repaired with them.
- **What is kept at the generator is what is true of it alone**, which
  is the call: `secp256k1_ec_pubkey_create`, constant time in its
  scalar, where every other point is `secp256k1_ec_pubkey_tweak_mul`.
- **The issue #849 figure stays with what was measured.** 1.13x is
  `ecc.dh` with the bindings switched off, and it says nothing about a
  call it did not time, so the census names `ecc.dh` as the subject of
  the measurement rather than as the place such a multiplication
  happens.

### `SECURITY.md` cites the line that reads a buffer into a Python `int`

- **The read is at `src/btclib/ecc/commit_nonce.py:158` and at
  `src/btclib/script/taproot.py:480`** (closes #1995). The citations
  named the blank line after the first, and the `prvkey_tweak_add` call
  that fills the buffer ahead of the second; the sentence around them is
  about the read.
- **The anchor in front of the `commit_nonce` citation is the quoted
  line rather than `commit_nonce.commit_nonce_`.**
  `tests/security_citations_test.py` matches a dotted name against the
  definition holding the cited line, which a line elsewhere in that
  definition satisfies too, and matches a quotation against the line
  itself, so that citation fails on a drift the name passes. The
  `taproot` citation keeps its dotted name, which cannot reject a drift
  within `_tweaked_prvkey` either (issue #2001).

### `docs/source/guide.rst` states the delegation by what a caller passes

- **`ssa.sign` and `dsa.sign` dispatch on no message size, and the
  guide's constant-time bullet said they did** (closes #1993).
  `ssa.sign` asks `_libsecp256k1_serves(ec, hf) and commit_hash is None`,
  the bindings' `sign_custom` beside their `sign` taking BIP340's
  message of any size (issue #169); `dsa.sign`'s guard names no size
  either. A caller's own nonce, listed in the same sentence, is
  `dsa.sign`'s condition alone -- `ssa.sign` takes an `aux` and has no
  nonce to impose.
- **What the bullet gives instead is what a reader can apply to the
  call they are about to make**, rather than the operations it named.
  `curves.curve._libsecp256k1_serves` is the predicate every dispatch
  asks, and only its curve half is absolute: another curve is the
  Python path whatever the call. The hash function is a condition of
  the operations that pass the predicate one, compared there by
  identity, so a wrapper around `sha256` declines; a guard passing
  `None` does not consult it at all. `ecc.commit_nonce.commit_nonce_`
  and `ecc.dh.diffie_hellman` are where the difference shows: each
  takes an `hf` and asks `_libsecp256k1_serves(ec, None)`, so
  `hf=sha512` on secp256k1 still delegates the tweak of the secret
  nonce and the multiplication by the secret scalar. Those
  per-operation conditions are `SECURITY.md`'s *Limitations, not
  vulnerabilities* section, which the bullet already links to; the
  guide gives none of them a second wording.

### `SECURITY.md`'s routing sentence states a condition, not a roster

- **The opening section named three delegated operations where the
  dispatch is wider** (closes #1999), disagreeing with the same file's
  *Limitations, not vulnerabilities* bullet, which states the
  delegation by shape -- `curves.curve.mult` delegates every point that
  is neither the generator nor infinity. What routes a report is the
  condition, so that is what the sentence gives: the installation, the
  curve, the hash function and the arguments of the operation, with
  that section named as where it is spelled out. Nothing of it is
  restated.
- **A `libsecp256k1_*.*` grep is a floor and not the surface.** It
  reads a call made through one of the bindings' modules and misses
  every one made through a flat alias, `curves.curve`'s generator arm
  and `_libsecp256k1_multi_mult` among them.
  `src/btclib/_libsecp256k1.py` binds both kinds, being the one module
  that imports the bindings at runtime, so the surface is read there
  rather than matched for.

### `CLAUDE.md` carries the shared primary-checkout section byte for byte

- **`CLAUDE.md`'s `## The primary checkout is the maintainer's` matches
  `btclib-org/.github`'s `CLAUDE.md` at `97947a6`, heading to heading**
  (issue btclib-org/.github#1010): section 14 of the organization
  standard compares that section byte for byte in every repository. The
  section defers the environment step to `CONTRIBUTING.md`'s *The
  environment and the gates*, so the sentence saying no `uv sync` follows
  `git worktree add` goes with it.
- **Nothing moves below the section.** What the copy said beyond the
  standard's text is the wording that text replaces: `pre-commit run` in
  the list of what never runs in the checkout, the checkout as the
  maintainer's window on the tree, and the list of reads that leave it
  alone. Or it is git's or uv's behaviour rather than this tree's: the
  worktree's own `.venv`, `git stash pop` after a push that created
  nothing, `git fsck --unreachable`, and `git update-ref` moving the base
  under every working tree. Or it is stated elsewhere: the rebase onto
  `origin/main` before the push is `CONTRIBUTING.md`'s *Landing it*, with
  `.gitattributes`' `merge=union` resolving `CHANGELOG.md`, and the pointer
  at `CONTRIBUTING.md`'s *Pull requests* is `CLAUDE.md`'s own opening
  paragraph. The sentence naming `btclib-org/.github`'s `CLAUDE.md` at
  `20ad654` as what the fence converged on goes too, the section itself
  being that comparison now.

### `ecc.pedersen` derives a generator from a seed

- **The Shallue-van de Woestijne map, which is how a generator that is
  not `second_generator` is made** (closes #1989).
  `generator_from_seed` hashes a seed under
  `secp256k1_generator_generate_internal`'s two prefixes, maps each
  digest onto the curve and sums the points, so the result has no known
  discrete logarithm with respect to `G` or to any other generator it
  answers -- which is what a confidential transaction committing each
  of several assets under its own generator needs. A blinding factor
  adds `blind*G` to that sum, one function taking it where the C
  publishes `secp256k1_generator_generate` and
  `secp256k1_generator_generate_blinded`.
- **sqrt(-3) and (sqrt(-3) - 1)/2 are derived, not transcribed.**
  libsecp256k1-zkp writes both as field literals; for a p of 3 mod 4
  `number_theory.mod_sqrt_var` answers the root that is itself a
  square, and that is the root those literals hold.
- **The candidates are tried in order rather than selected with a
  constant-time move.** zkp forms all three square roots and chooses
  among them with `secp256k1_fe_cmov`; this asks
  `curves.curve._is_x_coordinate_var` for existence and forms the one
  root it needs, a generator's seed being published.

### `ecc.pedersen` and `ecc.rangeproof` take the generator they work at

- **`commit(r, v, gen, ec)` takes the generator and no longer derives
  one** (closes #1986), as `secp256k1_pedersen_commit` takes its own
  `gen`; `assert_as_valid` and `verify` take it beside the commitment.
  The hash function is gone from all three: a hash is how a generator is
  derived and says nothing about a sum of points, and
  `second_generator(ec, hf)` is what a caller wanting the old default
  passes.
- **`ecc.rangeproof.sign`, `sign_public_value`, `assert_as_valid`,
  `verify` and `rewind` take it too**, as zkp's own three entry points
  take `gen_bytes`, and thread it to the octets hashed into the message
  every ring is signed over, the weight each ring's keys step down by,
  and the `min_value` offset a verifier subtracts.
  `RangeProof.pubk_rings` and `RangeProof.nonce_chain` take it for the
  same reason.
- **A proof written under one generator holds under no other**, which
  is asserted in both directions against libsecp256k1-zkp over a
  generator `zkp.generator.generate` derives.

### The `mention` job's `pull-requests: write` carries its reason

- **`claude-review.yml`'s `mention` job says at its `pull-requests: write`
  line what the grant is for** (issue btclib-org/.github#915): the
  `review` job's grant and the `id-token: write` beside this one each
  carry a reason at their line, and this grant carried none. The
  sentence is the one `btclib-node` and `btclib-benchmarks` carry above
  theirs, `# what posting the reply takes`, taken byte for byte so that
  one reason is not worded two ways across the copies. Section 14 of the
  organization standard keeps the file out of `tests/verbatim_test.py`'s
  comparison -- `claude-review.yml` "is owed by every repository section
  11 governs, and section 15's existence loop is what checks that — not
  this list" -- so a copy carrying the comment beside one that does not
  turns nothing red. The other copies are owed the same line, which is
  why this entry cites the issue rather than closing it.

### An anchor in `SECURITY.md` is chosen by what its sentence claims

- **`bip32.__prv_key_derivation`, `taproot._tweaked_prvkey` and
  `dh.diffie_hellman` carry a quotation of the line cited, beside the
  name** (closes #2001). `tests/security_citations_test.py` matches a
  quotation against that line and a dotted name against the definition
  holding it, so a name is satisfied by every line of the definition --
  and each of these holds a Python arm that the sentence around the
  citation is not about.
- **`ellswift.xdh` is named rather than quoted**, its sentence being
  about the function: it returns octets rather than an `int`, and what
  an `into=` buffer would cost there is `xdh`'s public signature.

### The vendored symbol set states which library it is a set of

- **`tests/_data/README.md` says which question the set answers**
  (closes #1997), where the entry gave the reason for `src` over
  `include` and was silent on which revision. The pin is
  bitcoin-core/secp256k1's own, and `btclib-secp256k1` builds the
  library a caller loads from a submodule of that repository, so the
  two differ in both directions: a name upstream has added since the
  last bump is in the set and not in that library, and a name upstream
  has renamed away is in that library and not in the set. The entry
  carries the call that prints the submodule's revision and the command
  that names the difference from it.
- **Upstream is what a credit asks about, and that is what decides the
  pin.** A credit is followed into bitcoin-core/secp256k1's source, so
  a set taken from the submodule would keep a renamed-away name and
  pass a credit landing its reader on a function upstream does not
  have. Neither direction of the difference is spelled in a `.py` of
  `src/btclib` or `tests`, so no paragraph here rests on which of the
  two runs.
- **`tests/upstream_symbols_test.py`'s docstring carries the choice**,
  beside the blind spots it already enumerates. Whether the installed
  bindings expose a name is a third question, and neither pin answers
  it.

### The issue-form hooks join the `check-jsonschema` block

- **`check-github-issue-config` and `check-github-issue-forms` run beside
  `check-dependabot` and `check-readthedocs`, in the `check-jsonschema`
  block at `rev: 0.38.0`** (issue btclib-org/.github#767): the pair
  section 4's *schemas* bullet of the organization standard names. Both
  select under `types: [yaml]` -- `.github/ISSUE_TEMPLATE/config.yml`
  under that spelling for the first, the directory's other yaml for the
  second, here `bug_report.yml`, `feature_request.yml` and
  `question.yml` -- so `check-hooks-apply` finds a file for each. The
  comment above the pair is `btclib-org/.github`'s own, byte for byte.
  `config.yml` and the forms validate clean as they stand, so nothing
  under `ISSUE_TEMPLATE/` moves. The other copies are owed the same pair,
  which is why this entry cites the issue rather than closing it.

### `_jac_double_mult` names the guard its callers asked

- **The docstring gave four reasons dsa's and ssa's verifications are
  on the Python arithmetic, and two of them are conditions of neither**
  (closes #2003): a BIP340 message that is not 32 bytes, which the gate
  imposing it no longer exists to impose, and a caller-imposed nonce,
  which a verification does not take. What stands in a verification's
  guard is `curves.curve._libsecp256k1_serves` and nothing else, and
  what the predicate tests is the dispatch switch, the curve and the
  hash function.
- **A signer reaches the same function, on a guard of its own**, and
  the docstring now says so rather than describing the verification's
  guard as the only way in: a nonce or a sign-to-contract commitment
  puts `sign_` on the Python arm, which checks the signature it wrote
  through the same `_assert_as_valid_`. Which reason brought a caller
  decides nothing about the double multiplication, the predicate being
  asked again with no hash function.

### A citation in `SECURITY.md` is held to every anchor written for it

- **A dotted name in front of a quoted line is read** (closes #2009).
  `tests/security_citations_test.py` took the span immediately in front
  of a citation and no other, so where the prose writes the name, the
  word `at`, the quotation and then the citation, the quotation was the
  anchor and the name was checked against nothing. Both are now read,
  the name against the definition holding the cited line and the
  quotation against the line itself.
- **The citation at `src/btclib/curves/curve.py:823` names
  `curve._mult_checked`**, which is the definition that line sits in:
  the arm `curves.curve.mult` and `PreparedPoint.mult` share. The
  sentence around the citation reaches that arm through `mult`, and the
  quotation of the line is unchanged.

### `ecc.dsa`'s dispatch comments name the guard of the reach they are about

- **`lower_s` was missing from the conditions `_sign_recoverable_`'s
  comment gave for a signature the bindings did not make** (closes
  #2010), and it is a conjunct of `sign_`'s guard and of
  `sign_recoverable_`'s alike: a caller asking for the s that was
  computed signs through that function, on the Python arm. The same
  list named a sign-to-contract commitment, which is `sign_`'s
  condition and not the other's -- `sign_recoverable_` takes no
  commitment at all, and its docstring says why. What the comment gives
  instead is the guard itself: `curves.curve._libsecp256k1_serves`,
  which every caller's guard asks, and the conditions each spelling adds
  beside it.
- **`_libsecp256k1_sign_`'s comment promised a count its own list did
  not match**, and states none now. What it lists is what `sign_`'s
  guard settles before the call, which is the one guard that reaches
  it.
- **A commitment to check and a caller-imposed nonce were given as
  reasons `ecdsa_verify` declined the verification `_assert_as_valid_`
  answers** (closes #2007): `_assert_commitment_` runs ahead of that
  dispatch and on both arms, and `assert_as_valid_` takes no nonce, a
  verification being independent of how the signature it checks was
  made. Both belong to a signer's guard, which reaches the same function
  through the check a signer makes on the signature it has just written,
  so they are attributed there rather than struck. What a verification's
  guard asks is `curves.curve._libsecp256k1_serves` and nothing else,
  and what sent a caller in decides nothing about the double
  multiplication unless it was the dispatch switch or the curve,
  `_jac_double_mult` asking that predicate itself.

### `test.yml` types `pytest` and takes the suite's flags from `pyproject.toml`

- **The `coverage` job runs `pytest` with nothing after it** (closes
  btclib-org/.github#433): `addopts` carries `--cov`, so a copy of it in
  the workflow is a flag a contributor's own `uv run pytest` does not
  have, and the CI gate and the local gate can stop being the same
  measurement with nothing turning red. Section 8 of the organization
  standard is where the flags are put in one file.
  `CONTRIBUTING.md`'s *Reproducing what CI runs* quotes that job's
  command verbatim, so it moves with the step.
- **`--cov-fail-under=0` is the whole of what the `no-bindings` job
  types**: nothing in `pyproject.toml` names it, so it is that job's own
  argument rather than a second copy of a tree-wide setting.
  `[tool.coverage.report]`'s `fail_under` is the floor it lifts for a run
  whose delegated arms are unreachable by construction, and the
  instrumentation reaches that job from `addopts` like the `coverage`
  job's. Section 8 names the `--no-cov` of a platform sentinel and the
  `COVERAGE_FILE` of a combining job as the arguments of that kind, and
  btclib-org/.github#1021 is where a third one is put to the standard.

### `SECURITY.md` names the definition its `ecc/dsa.py` citation lands in

- **`dsa.Signer.__init__` is written beside the line the citation
  quotes** (closes #2017): the name, the word `at`, the quotation and
  then the path and line number, which is the pair
  `tests/security_citations_test.py` reads. The name was the subject of
  the sentence instead, behind the spans that check reads, so a rename
  of the definition left the pointer green.
- **A dotted name further back than the quotation stays unread by
  decision.** What the prose leaves there names something the citation
  does not point into, which no definition holding the cited line
  answers for; `tests/security_citations_test.py`'s docstring states the rule.

### The prose around the bindings dispatch states its guard

- **The `btclib.ecc` package docstring made secp256k1, sha256 and a
  nonce btclib derives sufficient for a delegated signature** (closes
  #2015). `dsa.sign_` ands `nonce is None`, `lower_s` and `commit_hash
  is None` onto `curves.curve._libsecp256k1_serves`, so a signature
  asked for with `lower_s=False` and one carrying a sign-to-contract
  commitment each answer that description and each run the Python
  arithmetic `SECURITY.md` publishes as not constant-time. What the *Secrets*
  paragraph gives instead is the predicate -- the process-wide dispatch
  switch, the curve and the hash function -- with the conditions of the
  call site anded onto it, and it leaves those conditions to
  `SECURITY.md`, which the paragraph already points at.
- **`curves.PreparedPoint`'s docstring gave a deployment without the
  compiled bindings as what puts a caller on the Python arithmetic**
  (closes #2016). The first test `_libsecp256k1_serves` makes is the
  process-wide switch, which `set_libsecp256k1_serving` and
  `BTCLIB_NO_LIBSECP256K1` move in a process that has the bindings
  installed: `tests/script_engine/python_path_test.py` clears
  `curve._libsecp256k1_available` and reruns the consensus vectors
  under it, skipping where the bindings are absent.
- **A hash function of the caller's is not a way onto those tables**,
  which that sentence gave as one. `mult` and `_jac_double_mult` ask
  the predicate with no hash function, so a verification the hash
  function alone sent to the Python equation has its multiplication
  delegated still, and the tables a prepared point handed down are
  dropped there.
- **`ssa._assert_as_valid_`'s comment gave a declined verification as
  the way in** (closes #2018). `sign_` reaches the same function to
  check the signature it has just written, on a guard of its own --
  `_libsecp256k1_serves(ec, hf) and commit_hash is None` -- so a BIP340
  signature carrying a sign-to-contract commitment is verified there.
  The comment names each reach with the guard that brought it, and
  leaves what the multiplication does to `_jac_double_mult`.
- **The clause dating the message-size condition is gone.** The comment
  above `assert_as_valid_`'s own guard states in the present tense that
  the curve and the hash function decide the dispatch and the size of
  the message does not.

### `codeql.yml` ends in an aggregate a branch rule can name

- **`codeql: every job passed` is the one context this workflow offers a
  branch rule** (closes btclib-org/.github#459). A cell of the `analyze`
  matrix is a context per language, and `REPOSITORY.md`'s "Never name
  matrix contexts in the branch rule" is why none of them may be named:
  the rule lives outside the repository, so a language joining the matrix
  falls outside it with nothing red to say so. Whether the rule asks for
  the aggregate is the `checks` array `REPOSITORY.md` reads back live,
  which does not name it; what this adds is the option.
- **The step reads the run's own job listing rather than
  `needs.*.result`**, which is section 10 of the organization standard's
  shape for a workflow only ever run directly. `release.yml` calls
  `test.yml`, so that aggregate keeps `needs` — a called workflow's
  listing is the caller's run, and holds jobs waiting on the aggregate
  itself — and nothing in this tree calls `codeql.yml`. What the listing
  buys beside that is the shape issue #1001 recorded: a matrix cell that
  dies in *Set up job* is a `failure` row there while
  `needs.analyze.result` does not carry it.
- **The allowlist accepts `skipped` beside `success`**, which is what
  section 10 asks of a listing step. Nothing in this workflow is
  conditional on what a pull request touched and a superseded run skips
  the aggregate before its step runs, so a legitimate `skipped` row is
  unreachable — but that is a claim about the jobs the file holds rather
  than about the shape, and a `changes` job or an `if:` narrower than the
  aggregate's own makes it false without anything going red.
  btclib-org/.github#990 is where the aggregates narrowed to `success`
  alone are swept.
- **`REPOSITORY.md` and `CONTRIBUTING.md` said this workflow carried no
  aggregate a rule could name**, in `REPOSITORY.md`'s *Required checks on
  main* and *Code scanning* and in `CONTRIBUTING.md`'s *What runs when*;
  each says what the rule could name and that it does not.
  `REPOSITORY.md`'s *Token permissions* gains the aggregate's
  `actions: read`, which is what asking the API for a run's own jobs
  takes and what `contents: read` does not carry. `codeql.yml`'s own
  comments said it too, in their own words — no other job elevating,
  one elevation on the one job that needs it, both jobs below going red
  while the default setup is on — and each now describes a file with an
  aggregate in it.

### Open-section sentences a landing has since made false are superseded

- **This supersedes *`ecc.rangeproof` verifies a proof and rewinds it*
  above, whose entry says a generator of the caller's is still not taken
  and that a proof written or read here is written against
  `ecc.pedersen`'s own second generator** (issue btclib-org/.github#946):
  issue #1986 is closed, on 2026-09-11. `f0358d56` is what closed it, and
  *`ecc.pedersen` and `ecc.rangeproof` take the generator they work at*
  above is its entry -- `ecc.rangeproof`'s entry points take a `gen`, and
  a proof is written against the generator its caller passes.
- **This supersedes *The `mention` job's `pull-requests: write` carries
  its reason* above, whose entry says the other copies are owed the same
  line** (issue btclib-org/.github#946): btclib-org/.github#915 is
  closed, on 2026-09-12, and no copy is owed it. `git grep -c 'what
  posting the reply takes' origin/main --
  .github/workflows/claude-review.yml` answers `1` in every repository of
  the organization that carries the file, with `permissions:` in the same
  pathspec as the control that the search reads.
- **This supersedes *The issue-form hooks join the `check-jsonschema`
  block* above, whose entry says the other copies are owed the same
  pair** (issue btclib-org/.github#946): btclib-org/.github#767 is
  closed, on 2026-09-12, and no copy is owed it. `git grep -c
  'check-github-issue-config' origin/main -- .pre-commit-config.yaml`
  answers `1` in every one of them, and so does the same search for
  `check-github-issue-forms`.

### A `SECURITY.md` citation with no line number carries no anchor

- **A dotted name in front of a path cited with no line number was
  paired with it and checked against nothing** (closes #2021).
  `_defect` answers before it looks at an anchor wherever the line is
  empty, so `tests/security_citations_test.py` parametrized that name
  as a case of its own and passed it whatever it said. A path-only
  citation carries no anchor now, and what it is held to is naming a
  file that exists.
- **Reading the name instead would hold the prose to a claim it does
  not make.** `btclib.ecc.musig2` in front of the citation of
  `src/btclib/psbt/musig2.py` names the public API a delegation would
  grow, where the file cited holds the decision against carrying
  session state, and a pairing that fails that sentence names the prose
  for what the pairing did.

### `README.md` states the predicate the bindings dispatch asks

- **The *Secrets, and where constant time ends* section made secp256k1,
  sha256 and a nonce btclib derives sufficient for a delegated
  signature** (closes #2023), and gave another curve, another hash
  function or a nonce of the caller's as the ways out of it. Each
  function it named ands conditions of its own onto
  `curves.curve._libsecp256k1_serves`, and those differ: `dsa.sign`
  declines a signature asked for with `lower_s=False` and one carrying a
  sign-to-contract commitment, `ssa.sign` declines the commitment and
  takes no nonce at all, and `silent_payments.output_keys` takes none of
  those arguments. The section gives the predicate and leaves the
  per-function conditions to `SECURITY.md`, which it already points at.
- **The runtime switch is named beside the Python arithmetic it selects.**
  `curves.set_libsecp256k1_serving(serving=False)` and
  `BTCLIB_NO_LIBSECP256K1` put a process holding the bindings on that
  arithmetic for every operation, and for `silent_payments.output_keys`,
  whose guard fixes the curve and passes no hash function, it is the
  whole of what decides.
- **The opening paragraph gave the install as what decides**, secp256k1
  always calling the bindings. The delegation is a runtime switch
  besides an install, and a call reaches the bindings where its own
  guard admits them.

### The hyphen hook reads Python and rst beside markdown

- **`no-hyphen-at-end-of-line` carries `types_or: [markdown, python, rst]`,
  under `btclib-org/.github`'s own comment with its `README.md` read as
  the organization standard, the phrase the comments beside it use for
  the standard** (closes btclib-org/.github#921): section 4 of the
  organization standard gives the hook the file types whose prose a
  build renders, and a docstring reaches that rendering through
  docutils, which leaves the source break inside the paragraph it
  builds and lets html collapse it to a space, as it does markdown's
  join.
- **The lines the widened hook refused hold their token whole**: the
  module docstring of `docs/source/conf.py` wrapped its Sphinx URL at
  `sphinx-`, `curves/curve_group.py`'s function docstrings each wrapped
  `left-to-right` at one of its own hyphens, and the rest are comments or
  docstrings across `p2p`, `psbt`, `tx`, `wallet` and the test suite,
  each rejoined at the word its own hyphen split.

### `README.md` states the timing of a delegated multiplication

- **The *Secrets, and where constant time ends* section gave `mult` as
  sending every point that is not the generator to
  `secp256k1_ec_pubkey_tweak_mul`** (closes #2026), which asserts the
  delegation for those points instead of resting on it. The arm
  `curves.curve._mult_checked` delegates from is behind
  `curves.curve._libsecp256k1_serves`, a nonzero scalar and a point that
  is not infinity, so the predicate stated one paragraph above decides
  the call before any point does. The sentence rests on the delegation
  now, and `mult` stays its subject: where that conjunction delegates a
  `mult` of a point that is not the generator, its work follows the
  scalar.
- **The subject is a `mult` and not whatever the conjunction
  delegates.** `ellswift.xdh` guards on the same predicate
  (`src/btclib/ecc/ellswift.py:364`) and delegates a secret times a
  point the caller encoded, so a claim about every delegation would
  cover it — and what it delegates to is `secp256k1_ellswift_xdh`, whose
  `secp256k1_ecmult_const_xonly` is constant time in the scalar.
  `SECURITY.md` states that call and this one apart, and the README
  sentence carries the scope that keeps them apart.
- **The C entry point is named where the accounting is.** What that arm
  calls is the bindings' `keys.pubkey_tweak_mul_sum`, whose terms are
  `secp256k1_ec_pubkey_tweak_mul` and whose sum is
  `secp256k1_ec_pubkey_combine`, so a reader grepping the tree for the
  name the section carried does not find it at the call.
  `SECURITY.md`'s "Limitations, not vulnerabilities" keeps the name and
  what the timing claim rests on, and the section points there.

### `SECURITY.md` closes its dispatch account with the predicate, not a roster

- **The closing sentence gave another curve, another hash function or a
  nonce of the caller's as the ways onto the Python arithmetic** (closes
  #2028), where the same bullet states more above it: the process-wide
  switch, which no argument of a caller's reaches; `dsa.sign`, which
  declines a signature asked for with `lower_s=False` and one carrying a
  sign-to-contract commitment; and `silent_payments.output_keys`, whose
  guard fixes the curve and passes no hash function, so nothing a caller
  passes selects either path for it. What the predicate and a call's own
  conditions decline is what runs the Python implementation.
- **The predicate opens the bullet the per-function conditions are anded
  onto.** `curve._libsecp256k1_serves` asks for the switch, then for the
  curve, then for the hash function, and this file is where the chain
  ends: `README.md` and `src/btclib/ecc/__init__.py` state the predicate
  and leave the conditions here, so a summary in this file cannot answer
  by pointing on.
- **The routing sentence of *What belongs here, and what belongs
  upstream* gave the installation as a term of the decision**, where what
  decides is the process-wide dispatch switch — an install without the
  bindings is one state of it — and it folded the conditions of each call
  site into the arguments of the operation.

### `SECURITY.md` states that the hash function is matched by identity

- **The condition written for each delegated operation is sha256, and
  the test is `hf is sha256`** (closes #2029), so
  `functools.partial(sha256)`, or any other wrapper a caller writes to
  fit an interface, reads as delegated and is on the Python arithmetic
  this file publishes as not constant-time. The identity is stated where
  the predicate is, the wrapper named, and the fallback given as silent.
- **Stated once, and not at each operation that names sha256.** The hash
  function is a conjunct of the shared predicate rather than a condition
  a call site ands onto it, so a copy at each operation would put one
  fact where it is not decided and give it that many places to drift. A
  reader checking one operation meets it on the way in, the predicate
  opening the bullet those conditions are written in.

### `SECURITY.md` states `mult`'s delegated arm as its guard tests it

- **The arm was given as every point that is neither the generator nor
  infinity** (closes #2033), a set of points with no condition in front
  of it, where the bullet's subject is which multiplications are not
  constant time and a reader uses it to decide whether their own key
  agreement is on the C path. `_mult_checked` opens that arm asking for
  a non-zero reduced scalar and then for the predicate, so a scalar that
  reduces to zero, a process with the dispatch switch off and any curve
  but secp256k1 are the Python arithmetic whatever the point is.
- **The predicate is asked there with no hash function**, which leaves
  the switch and the curve as the whole of what the predicate decides
  for this multiplication. The two excepted points are the right two: the
  generator is a different libsecp256k1 call inside the same arm, and
  infinity is no public key, so `m*INF` is answered where every other
  declined multiplication is.

### `SECURITY.md` names the places a secret meets the curve, not how many

- **The roster of call sites where a secret meets the curve stated how
  many it names** (issue #2035), which `CLAUDE.md` forbids of prose that
  lands and which no gate reads this file for:
  `tests/release_notes_test.py` names `CHANGELOG.md` and
  `RELEASE_NOTES.md`, and the tests that do read `SECURITY.md` read its
  citations and its links. The names are in the same sentence and carry
  it alone, so the numeral goes and nothing is lost. Whether that guard
  should reach this file is the other half of the issue and is not
  decided here.

### `CLAUDE.md` says which files a test keeps free of a stated count

- **`CLAUDE.md`'s *Never state how many of anything a file holds* named
  the tests that enforce it and no file the rule governs without one**
  (closes #2035): `SECURITY.md` is such a file, so the sentence reads as
  coverage the suite does not give. That bullet names it, and the reason,
  where it names the tests.
- **The instrument that fits the files it does name does not fit this
  one.** `merge=union` restores a count paragraph on a rebase with
  nothing in the merge output to say so, and
  `git check-attr merge -- SECURITY.md` answers `unspecified`. Naming
  the file in `tests/release_notes_test.py`'s `_FILES` is inert, those
  patterns being keyed on the paragraph each forbids; a guard of
  `tests/vendored_data_test.py`'s shape asks for an exemption per
  `path:line` citation, pinned verbatim, where an edit anywhere in a
  cited module moves the line number.

### The anchor depth, the gate's closure and one codeql clause converge

- **`docs/source/conf.py`'s `myst_heading_anchors` is 6** (issue
  btclib-org/.github#715): section 2 of the organization standard makes
  six every level markdown heads at, which is what makes the number a
  fixed point rather than a depth re-derived from the files it covers.
  `CONTRIBUTING.md`'s shared half is ported to every repository by
  section 14, so a heading added there moves a tree-derived depth in
  each of them at once, and which tree finds out is whichever carries a
  link into it. The key is already load-bearing here -- `README.md`
  links into `CONTRIBUTING.md`'s *Breaking a caller is not an argument*
  and `CONTRIBUTING.md` into `REVIEWING.md`'s *The gates are the
  evidence* -- so the widening reaches a depth no link needs today
  rather than repairing one that was broken. What says the depth is wide
  enough is a link into a heading and not a comparison of two builds:
  docutils gives every section an id whatever myst accepts as a target,
  so the pages this source renders are the same bytes at either value,
  and would be with a heading at `#####` in them.
- **`tests/interpreters_test.py` takes the free-threading
  biconditional's second side from the aggregate's `needs:` closure**
  (issue btclib-org/.github#634): section 3 of the standard makes the
  second side the jobs the required check waits on, and names reading
  the workflow file as the rejected alternative, an interpreter a job
  outside the closure names being the "it passed somewhere" that section
  refuses. `test: every job passed` waits on every job `test.yml`
  declares, so the two readings do not disagree over this tree's own
  workflow; the workflow text they do disagree over is built in the
  module, a job the aggregate waits on, one beside it, and one reached
  only through a block-sequence `needs:`. That third job is what holds
  the closure's own reading of `needs:` to a block list under the key as
  well as the flow shapes beside it: with `coverage-union`'s `needs:`
  rewritten as a block list and a free-threaded job reachable only
  through it, the flow-only pattern answers `3.14` where the closure
  runs `3.14t` as well, and a closure short of an edge is short of the
  jobs behind it.
- **`.github/workflows/codeql.yml` says this job goes red, not that a
  required check fails** (issue btclib-org/.github#1028). The comment
  above *Fail unless every other job of this run succeeded* argues the
  allowlist into naming `success` and `skipped` both, and that argument
  is untouched: a `changes` job, or an `if:` narrower than the
  aggregate's own, makes a legitimate `skipped` row reachable. What was
  false is the consequence drawn from it. No required context of `main`
  comes from this workflow, which `REPOSITORY.md` already says in its
  own words, and the classic `branches/main/protection` endpoint is
  where that is read -- this repository's rulesets carry no
  `required_status_checks` rule at all, so a rulesets-only read answers
  that nothing here is required. The citation advances the issue rather
  than closing it because the same clause is section 10 of the
  organization standard's own sentence -- *what says the allowlist has
  stopped matching the run is the required check failing* -- and that
  half is a change to another repository.

### `SECURITY.md` refers to the call sites it names without counting them

- **Two sentences over one roster stated how many call sites it holds**
  (closes #2038), the roster being the places a binding's output is read
  straight into a Python `int`: a numeral counting a population of this
  codebase rather than a structure the sentence closes, which is what
  `CLAUDE.md` forbids of prose that lands and what no gate reads this
  file for. The names are in the same sentence and carry it alone, so the
  numeral goes and nothing is lost.
- **The second sentence refers back to those call sites, not to *the*
  others.** "The other call sites" would claim a completeness nothing
  here holds, where "the call sites above" names the ones the bullet has
  just named.
- **One numeral in the file stays.** "Those three" counts the
  libsecp256k1 entry points the sentence before it names, so it
  summarises an enumeration that passage closes rather than a roster this
  library adds to.

### The stated addition and doubling counts name what counts them

- **The figures for what a scalar multiplication costs had no command
  beside them** (closes #2040), which `CLAUDE.md` asks of a number that
  lands. `_CountingGroup` in `tests/curves/curve_group_test.py` is what
  counts them and its docstring carries the command; the figures that are
  one value for every scalar come back from it exactly, so this is a
  stated instrument and not a corrected number.
- **A counting group built the obvious way recodes a digit more at
  w=4.** With no n to read, `CurveGroup` takes the Hasse bound plen + 1
  for its scalar_len where `Curve` narrows it to nlen, and a
  multiplication's digits being ceil(scalar_len / w), a subclass of the
  group left at that bound gives a 256-bit scalar one digit more at that
  width: `_mult_regular_window` answers 72 additions and 257 doublings
  there against the 71 and 253 its docstring states, which reads as prose
  that drifted. The delta is the `ceil`'s rather than the bound's -- at
  w=5 and w=6 both bounds recode the same digit count -- and
  `_mult_endomorphism_secp256k1` passes a scalar_len of its own, so its
  figures are the same either way. The class takes the curve's own length
  and says why, and counts doublings beside additions -- the pair a
  window is made of, and what the property test now asserts a single
  value of.
- **`SECURITY.md` states the relation rather than the figures.** What the
  argument there needs is that the cost is one value for every scalar of
  the curve, so that the size of a secret is hidden; a figure in a
  security file invites a reader to take it for a measurement of the
  library as it stands, and the ranges among those it stated were over a
  sample whose seed it did not give, which nothing reproduces. The
  contrast with the plain fixed window stays as the recoding it comes
  from, ceil(m.bit_length() / w) digits against ceil(nlen / w).
- **The dispatch comment that offers the interleaved wNAFs as cheaper no
  longer prices them.** `curves.curve` stated the same unseeded range
  this entry withdraws, and what refuses them there is regularity, which
  the sentence above it already carries.

### `REVIEWING.md` and `.gitattributes` carry `btclib-org/.github`'s copies

- **`REVIEWING.md` above `## This repository in particular` is
  `btclib-org/.github`'s at `6a47f845` byte for byte** (issue
  btclib-org/.github#353): section 14 of the organization standard
  compares the file up to that heading and leaves what stands below it
  to this tree, so the half above it is replaced whole rather than
  difference by difference. What it says that the copy it replaces did
  not: a finding about the wording of prose no user reads is named at
  the foot of the review rather than filed, on btclib-org/.github#976's
  authority; `NACK` stands beside `ACK` and `CHANGES REQUESTED` as a
  verdict, and the ack of record is posted as a review of type COMMENT
  rather than as a forge approval; and *Re-review* reads the old sha off
  the previous round's verdict, an amend or a rebase leaving it off the
  branch. `.github/workflows/claude-review.yml`'s prompt already tells a
  reviewer that `REVIEWING.md` has the three lines and why a reading
  ending without one is not a `NACK`, which is a claim about this tree's
  own copy. Every heading is one the half already carried, so
  `CONTRIBUTING.md`'s link into *The gates are the evidence* points at a
  heading that is there.
- **`.gitattributes` says what the union driver charges at the seam, and
  what rejects not setting the driver at all** (issue
  btclib-org/.github#1026): above `## This repository in particular` the
  file is `btclib-org/.github`'s `.gitattributes` at `6a47f845` byte for
  byte, and below the heading the `-whitespace` attribute on
  `src/btclib/mnemonic/_data/electrum_portuguese.txt` is this tree's and
  unchanged. Union joins the two sides' added lines directly, so a block
  opening with a heading lands against the line above it while `git
  rebase` exits 0 and nothing conflicts; `check-changelog` is the hook
  that paragraph names, and `.pre-commit-config.yaml` here runs it ahead
  of the `markdownlint-cli2` autofix, which would otherwise repair the
  seam before anything named it.

### Dependencies are refreshed, and neither a floor nor a hold moves

- **`uv lock --upgrade` takes `build` to 1.6.1 and `ruff` to 0.16.7**,
  and moves nothing else. Neither sibling has anywhere to move to:
  `uv lock --upgrade-package btclib-secp256k1 --dry-run` and the same for
  `bitcoin-core-rpc` each detect no lockfile change, so the floors
  `[project.dependencies]` and `[project.optional-dependencies]` name
  stay where they are, each coinciding with what the lock pins.
- **`pre-commit autoupdate` takes `astral-sh/ruff-pre-commit` to v0.16.7
  and `astral-sh/uv-pre-commit` to 0.12.13.** That hook and `uv.lock`
  resolve the same ruff, so the lint gate and a bare `uv run ruff`
  answer alike; `[build-system]`'s `uv_build` range is what the build
  has to satisfy rather than a pin at the uv hook's rev, and it is
  unchanged.
- **The two revisions `autoupdate` also offers are declined by the gate
  and not only by the comment beside them.** Walked to
  `zizmorcore/zizmor-pre-commit` v1.30.1 and `regebro/pyroma` 5.1b1, the
  lint gate exits 1 on `pinned-rev`, on `held-rev` and on `zizmor`
  itself. `autoupdate` walks past the hold because the marker sits on
  the `rev:` line it rewrites, leaving a value and a marker that
  disagree, which is what `held-rev` reads; 5.1b1 is a prerelease,
  which `pinned-rev` refuses.
- **zizmor 1.30.1 is what the hold is against** (issue #1563): its
  `self-repository` audit flags the workspace-relative `uses: ./...`
  form wherever `.github/workflows/` writes it, and actionlint 1.7.12
  does not parse the `$/...` form the auto-fix offers in its place.
- **`astral-sh/setup-uv` moves to v10.1.0**, sha and trailing comment
  together wherever a workflow sets uv up.
- **`anthropics/claude-code-action` moves to v1.0.223**, sha and comment
  together in the review step and in the mention step. Issue #1924 asks
  this pin for the commit the newest `v1.0.<n>` tag resolves to, peeled
  from the annotated tag rather than read off `git/ref/tags`; the commits
  it advances over move the Claude Code release that action installs and
  the `@anthropic-ai/claude-agent-sdk` its own code runs on, and touch
  nothing else.
- **`github/codeql-action` stays at v4.38.0.** Its `releases/latest`
  answers a `codeql-bundle-` tag, a different naming series rather than
  a newer release of what is pinned, and the newest `v4` tag is the one
  the pin carries.
- **`google/clusterfuzzlite` stays where it is.** `v1` is still the only
  tag it publishes and still peels to the pinned commit, which the calls
  `fuzz.yml` carries beside that pin re-derive.
