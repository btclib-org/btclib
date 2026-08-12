# How to contribute to btclib

<!-- These badges report no state: each names a choice this file explains,
or a place to go. The README keeps the ones that can turn red. -->
[![calendar versioning: yyyy.m.d](https://img.shields.io/badge/cal_ver-yyyy.m.d-1674b1.svg?logo=calver)](https://calver.org/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![format: ruff](https://img.shields.io/badge/format-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/formatter/)
[![lint: ruff](https://img.shields.io/badge/lint-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/)
[![docstrings: ruff](https://img.shields.io/badge/docstrings-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/rules/#pydocstyle-d)
[![type check: mypy](https://img.shields.io/badge/type_check-mypy-yellowgreen.svg?logo=mypy)](https://mypy-lang.org/)
[![lint: markdownlint-cli2](https://img.shields.io/badge/lint-markdownlint--cli2-yellowgreen.svg?logo=markdown)](https://github.com/DavidAnson/markdownlint-cli2)
[![pre-commit enabled](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)
[![GitHub repository: btclib-org/btclib](https://img.shields.io/badge/GitHub-btclib--org%2Fbtclib-181717?logo=github)](https://github.com/btclib-org/btclib/)
[![slack: btclib_dev](https://img.shields.io/badge/slack-btclib_dev-white.svg?logo=slack)](https://bbt-training.slack.com/messages/C01CCJ85AES)

Thank you for investing your time in contributing to our project.
We are glad you are reading this, because we need volunteer developers
to help this project come to fruition.

If you haven't already:

- see the [README](./README.md) file to get an overview of the project
- read our [Code of Conduct](./CODE_OF_CONDUCT.md) to keep our community
  approachable and respectable
- come find us on [Slack](https://bbt-training.slack.com/archives/C01CCJ85AES).

In this guide you will get an overview of the contribution workflow from
opening an issue, creating a PR, reviewing, and merging the PR.

## New contributor guide

Here are some resources to help you get started with open source contributions:

- [Finding ways to contribute to open source on GitHub](https://docs.github.com/en/get-started/exploring-projects-on-github/finding-ways-to-contribute-to-open-source-on-github)
- [Set up Git](https://docs.github.com/en/get-started/quickstart/set-up-git)
- [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Collaborating with pull requests](https://docs.github.com/en/github/collaborating-with-pull-requests)

## Getting started

btclib is managed with [uv](https://docs.astral.sh/uv/), the only tool that
must be installed on the development machine: see the
[uv installation instructions](https://docs.astral.sh/uv/getting-started/installation/).

A virtual environment with btclib (in editable way) and all the development
tools, including those needed to build the documentation, is then created with:

```shell
uv sync
```

**The declared dependency is `btclib_secp256k1>=0.7.1.3`, with no
upper bound**, and the absence of a ceiling is a decision. The bindings are
a btclib-org project developed by the same people, and their whole purpose
is to be the bindings this library calls, so a breaking change there is
coordinated with the release here — which is what a version ceiling
substitutes for when it cannot be. A `<0.8` ceiling would cost a btclib
release for every bindings minor, the ones that break nothing included, and
would make a published artifact refuse a version it in fact works with; a
`<1` ceiling constrains nothing, pre-1.0 semver putting the breaking
changes in the minor.

What the policy does not cover: dependency metadata is baked into every
wheel already published, so coordinating the two projects protects the
current pair and not an artifact that went out before. Only the latest
release is supported (SECURITY.md) and nothing is backported, so the
promise is about that pair — a bindings release keeps the runtime API the
supported btclib needs, and an older btclib may one day stop installing or
running against the newest bindings.

The bound is the oldest final release this version supports, and a
prerelease of it sorts below it rather than satisfying it. What a
resolver does with prereleases is its own policy — pip and uv alike
prefer a stable candidate and reach for a prerelease only when no stable
one satisfies the constraints — so the bound states support and nothing
else. See the
[version-specifiers page](https://packaging.python.org/en/latest/specifications/version-specifiers/#handling-of-pre-releases)
and
[uv's prerelease handling](https://docs.astral.sh/uv/concepts/resolution/#pre-release-handling).

Every command is run inside that environment prefixing it with `uv run`
(e.g., `uv run pytest`); alternatively, activate the environment once with
`source .venv/bin/activate` (`.venv\Scripts\activate` on Windows).

The dependency groups defined in pyproject.toml can also be installed
individually, e.g. `uv sync --no-default-groups --group test`.

`.python-version` pins 3.14, so that is the interpreter `uv sync` picks and
the one `uv run` uses. To reproduce a failure that only one cell of the
matrix shows, name the interpreter instead of editing that file:

```shell
uv sync --python 3.10
uv run --python 3.10 pytest
```

**`--python` rebuilds `.venv`, and that has a consequence worth knowing
before it bites.** An interpreter other than the one already there makes uv
report `Removed virtual environment at: .venv` and create it again — so
whatever groups the command asks for are the only ones installed
afterwards. With the group-restricted commands under "Reproducing what CI
runs" below, that leaves an environment holding one group where `uv sync`
installs them all, and pre-commit is not in it. The git hook pre-commit
installs `exec`s `.venv/bin/python -mpre_commit` by absolute path, and
that python does exist, so the hook's own "did you forget to activate your
virtualenv" fallback never runs: the next `git commit` dies with
`No module named pre_commit`. `uv sync` puts it back.

To leave `.venv` alone in the first place, put the other interpreter's
environment somewhere else:

```shell
UV_PROJECT_ENVIRONMENT=.venv-3.10 \
    uv run --locked --no-default-groups --group test --python 3.10 pytest
```

`.gitignore` does not mention that directory and does not need to: uv
writes a `.gitignore` of its own, holding `*`, inside every environment it
creates, so the tree stays clean without a rule per interpreter.

As an annotated Python3 project, btclib is very strict on code formatting
and linting
([ruff](https://docs.astral.sh/ruff/),
which replaces autoflake, bandit, black, docformatter, flake8, isort,
pydocstyle, pylint, pyupgrade, and yesqa)
and proper type definition
([mypy](https://mypy-lang.org/)):
warnings are not tolerated and should be taken care of.
This might be annoying at first, but enforcing formatting rules can be done
easily once you're finished with coding or, even better, automatically
taken care of while coding if you configure your development environment.
Type definition improves code readability and helps in spotting bugs.

Moreover,
the [pytest](https://pytest.org) unit tests
must pass at any time, with
[coverage](https://coverage.readthedocs.io/)
of both the library and the test suite at the `fail_under` ratchet in
pyproject.toml — 100%, and coverage takes that literally: it
special-cases the value, so 99.999% is a red build where the 99.99 this
replaces passed everything above 99.985%, and the 99.9 before it ten
times as much again. No slack, so a statement no test reaches is either
covered by patching what stands in the way, as the ripemd160 fallback
and electrum's round-trip check are, or marked `pragma: no cover` with
the reason beside it. `--cov` is in pyproject.toml's addopts, so `uv run
pytest` prints the total and enforces the ratchet on every whole run, on
the 3.14 the gate is checked on — a run that selects a subset with paths,
`-k` or `-m` reports without gating, since `fail_under` would otherwise
fail it on the tree's coverage rather than on its own.
See [Tests, code coverage, and profiling](./tests/README.md).

These requirements are easily checked (and partially fixed) with:

```shell
uv run ruff check --fix
uv run ruff format
uv run mypy btclib tests .github/scripts
uv run pytest
```

or, in one go, with [pre-commit](https://pre-commit.com/):

```shell
uv run pre-commit run --all-files
```

The suite writes nothing: it runs against a read-only checkout, and from an
installed sdist. The one exception is deliberate and has to be asked for.
Eleven modules compare a dataclass's `to_dict()` against a json file
committed beside them, under `tests/**/_generated_files/`, so that a change
to a serialized form is a failing test rather than something to notice in a
`git diff`. When such a change is the intended one:

```shell
BTCLIB_REGENERATE_GOLDEN=1 uv run pytest
```

rewrites those files, and the diff it leaves is the review the change wants.
The failure message names the command, so there is nothing to remember.

That second command is not a convenience: it is the lint gate itself.
The lint workflow runs this very configuration, so what CI enforces is
what a commit enforces, mark-down included
([markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2) is
one of the hooks, as are ruff, mypy, yamllint, actionlint, and the checks
on packaging metadata and on `uv.lock`).

Prose is held to 80 columns wherever it lives: markdown by MD013, Python
comments and docstrings by ruff's `max-doc-length`. Code is not — the
formatter reflows it to 88 — and neither is yaml, at 100, an action
pinned to a commit SHA being past 80 before anything else is said;
`.yamllint.yaml` has that arithmetic.

One of those hooks needs maintenance, and only one. The test vectors under
`tests/ecc/_data/` and `tests/script/_data/` are private keys by the
hundred, so they are recorded in `.secrets.baseline` as already reviewed —
rather than excluded from the scan, which would leave those files unwatched
for a credential that has no business being there.
`tests/block/_generated_files/block_481824.json` is in the baseline for a
narrower reason: `ACCA` is one of the AWS key prefixes and is also four hex
digits, so the block's own signatures match the detector wherever a script
is rendered as upper-case hex. Adding a vector to one of those files, or
changing what a golden file holds, means regenerating the baseline:

```shell
uvx --from detect-secrets detect-secrets scan --baseline .secrets.baseline
```

That preserves the plugin selection the file already carries, which is
deliberate: the two entropy plugins are off, because in vectors made of
64-character hex strings a new high-entropy string is what a legitimate
addition looks like.

Read the resulting diff before committing it. That is the whole point of a
baseline rather than an exclusion: what appears in it is what nobody has
looked at yet, so regenerating without reading turns the review into a
rubber stamp and the hook into decoration.

### The editor

`.vscode/settings.json` and `.vscode/extensions.json` are tracked, and they
hold no preference: the recommended extensions are the tools
`.pre-commit-config.yaml` already runs, and the settings put the fixing ones
on save. Installing them is optional and changes nothing about what a commit
enforces — what they buy is learning of a finding while typing rather than
at the commit that trips over it.

Anything machine-local — an interpreter path, a telemetry answer, a theme —
belongs in the editor's own user settings instead, those two files being
read by every checkout of this repository.

### What runs when

| workflow | when | what it varies |
| --- | --- | --- |
| `test` | pull request, push | 4 platforms × 7 interpreters |
| `lint`, `docs` | pull request, push | — |
| `integration` | pull request, push | a regtest node |
| `website` | pull request, push, on website files | — |
| `codeql` | pull request, push, Tuesday | 2 languages |
| `macos` | Wednesday, a release | 2 macOS images × 7 interpreters |
| `latest` | Wednesday | platforms sampled, deps upgraded |
| `links`, `mutation` | weekly | — |
| `vendored-vectors` | monthly | upstream's vectors |
| `published` | monthly, a release | what PyPI serves |
| `release` | a tag | calls test, lint, docs, macos, published |

The first four rows are what a merge waits for, and between them they report
the five required checks: `lint` and `docs` share a row and report one
each. macOS is not among them on purpose: it is the platform whose runners
queue — 29.4 and 23.2 minutes of mean wait against 0.5 to 1.6 elsewhere, on
a run of 45 jobs that spent 93 minutes working and 399 waiting — so it
answers weekly, and before a release, rather than before a review. `macos`
and `latest` share a morning half an hour apart, which is what makes the
pair readable: red in both is the platform, red in `latest` alone is the
upgrade. Every workflow in the table also takes `workflow_dispatch`, the
gates included: a branch whose pull request is not open yet has no other way
to ask.

### Reproducing what CI runs

Every job of every workflow is a `uv` command, and `uv` fetches what it
needs: no interpreter, no linter and no packaging tool has to be
installed by hand.

The `Lint and type-check` job of the `lint` workflow, in full — the same
pre-commit the lock pins, which is what `uv run` above gives you too:

```shell
uv run --locked --only-group lint \
    pre-commit run --all-files --show-diff-on-failure
```

`Build the documentation` is a workflow of its own, `docs.yml`, and its
command is the one below under "The documentation".

One cell of the `suite` matrix of `test.yml`. The interpreter is chosen with
`--python`, which accepts any of the ones the matrix lists, `3.14t` and
`pypy3.11` included, and downloads it if the machine has none:

```shell
uv run --locked --no-default-groups --group test --python 3.10 pytest
```

That one rebuilds `.venv` with the test group alone, which is what breaks
the pre-commit hook until the next `uv sync`: see the note under "Getting
started" above, and `UV_PROJECT_ENVIRONMENT` for running it without
touching `.venv`. The command is what CI runs, verbatim, and CI has no
`.venv` to lose.

The `coverage` job, gated by `fail_under` in pyproject.toml:

```shell
uv run --locked --no-default-groups --group test pytest --cov
```

What `--cov` measures and how it reports are `tool.coverage.run`'s
`source` and `tool.coverage.report` in pyproject.toml, so this command
and the bare `uv run pytest` above are the same measurement: the job
cannot gate on a scope a contributor's run does not have. The flag is
written out here even though addopts already carries it, this being the
job's command verbatim.

The `dist` job, which inspects what would be published and then
installs it. The last commands ask for the wheel and nothing else, so
what pulls btclib_secp256k1 in is the `Requires-Dist` the wheel
carries; the lock arrives as constraints, which bind a version without
requesting a package, so a release of the bindings cannot turn a required
check red while the wheel's own metadata still does the work. They run
from an empty directory, or the import finds the source tree instead of
the wheel:

```shell
uv build
uv run --locked --only-group build twine check --strict dist/*
uv run --locked --only-group build check-wheel-contents dist/*.whl
uv run --locked --only-group build pyroma --min 10 dist/*.tar.gz
tmp=$(mktemp -d)
uv export --locked --no-dev --no-emit-project --no-hashes \
    -o "$tmp"/constraints.txt
cd "$tmp" && uv venv &&
    uv pip install --constraints constraints.txt "$OLDPWD"/dist/*.whl &&
    .venv/bin/python -c "import btclib; \
      from btclib.ecc import dsa; \
      from btclib.to_pub_key import pub_keyinfo_from_prv_key; \
      print(btclib.__version__); \
      assert btclib.__version__ != 'unknown'; \
      assert dsa.verify(b'btclib', pub_keyinfo_from_prv_key(1)[0], \
        dsa.sign(b'btclib', 1))"
```

The checks the `release` workflow runs before building anything:

```shell
uv lock --check
uv version --short
```

Its build job then repeats the smoke test above on the wheel it uploads,
which is not the one `dist` built, and repeats it without the
constraints. No pull request waits on that job and no branch rule names
it, where `publish-testpypi` and `publish-pypi` both have it in `needs`:
so it is the place to ask whether the newest published bindings satisfy
the artifact, and a release stopping on that answer is the outcome
wanted. It runs after the upload rather than before, the artifact being
what the publish jobs download: installing a dependency executes its
code, and a compromised one must not reach a `dist/` that has still to
be handed on.

What that job builds is reproducible, and the two steps that make it so
are the two lines below — the first is why two checkouts of one commit
produce the same wheel, the second why they produce the same sdist:

```shell
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
uv run --no-project --python 3.14 .github/scripts/normalize_sdist.py dist/
```

RELEASING.md's "Rebuild a release from its tag" has them in the order a
verifier runs them, with the `gh attestation verify` that gives the
rebuild a verdict and the two bounds on what that verdict means.

The `latest` workflow, which upgrades every dependency uv resolves before
running the suite, the lint gate and the packaging checks. The upgrade
rewrites uv.lock, and here too `git checkout uv.lock` restores it; the
commands after it are the ones already listed above, so only the first is
worth repeating:

```shell
uv lock --upgrade
```

That workflow has a second job, `test-bindings-latest`, upgrading only
the bindings and re-running the suite — narrower than the upgrade above,
which moves every dependency, so a red run here names the one responsible
instead of burying it behind a dozen others:

```shell
uv lock --upgrade-package btclib_secp256k1
uv run --locked --no-default-groups --group test pytest
```

The `published` workflow, monthly, on demand and as part of a release,
installs btclib itself
from PyPI, nothing checked out, and asks whether it works rather than
whether it installs: `import btclib` runs `__init__.py` alone, and the
files under `btclib/*/_data/` — the wordlists among them — are opened by
path at the first call that needs one, not imported, so a wheel missing
one would pass the import and fail only here. Both checks are
version-independent, a BIP340 vector and a BIP39 one whose values are
fixed forever:

```shell
python -m pip install btclib
python -c "import btclib; \
    from btclib.ecc import dsa; \
    from btclib.to_pub_key import pub_keyinfo_from_prv_key; \
    assert dsa.verify(b'btclib', pub_keyinfo_from_prv_key(1)[0], \
      dsa.sign(b'btclib', 1))"
python -c "from btclib.mnemonic.bip39 import seed_from_mnemonic; \
    m = 'abandon abandon abandon abandon abandon abandon abandon ' \
        'abandon abandon abandon abandon about'; \
    assert seed_from_mnemonic(m, 'TREZOR').hex() == ( \
      'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53' \
      '495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f0016' \
      '98e7463b04')"
```

The `links` workflow, weekly and on demand, which is the one that needs a
tool uv does not provide: lychee is a rust binary, and the workflow uses
the action. It gates nothing — a link rots without anybody touching the
repository, so a red merge would be somebody else's weather — and a
failing run is read in the Actions tab. `.lycheeignore` holds the URLs a
checker cannot judge, each with the reason.

The `mutation` workflow, weekly and on demand, which gates nothing either
and for a different reason: it asks whether the suite would *notice* a
wrong line, where coverage only says the line ran, and a surviving mutant
is a test nobody has written rather than a regression somebody just
caused. One parallel job per profile, each under its own budget, and no
list of them here: `.github/mutation/` is the list, and every file in it
states what it mutates, what judges it, and what the last session over it
measured — the consensus code and the wire format it reads, the key,
codec, descriptor, wallet, psbt and script layers, the signature schemes,
and the boundaries where somebody else's bytes arrive. Those
configurations are also what a local run reads, so there is one statement
of what is mutated and what judges it:

```shell
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray baseline .github/mutation/parsers.toml
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray init .github/mutation/parsers.toml parsers.sqlite
uv run --locked --no-default-groups --group test --group mutation \
    cr-filter-operators parsers.sqlite .github/mutation/parsers.toml
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray exec .github/mutation/parsers.toml parsers.sqlite
uv run --locked --no-default-groups --group test --group mutation \
    cr-report --surviving-only --show-diff parsers.sqlite
```

`baseline` first, always: it runs the configured test command against the
unmutated tree, and without it a stale path or a renamed test file fails
every mutant identically and the session reports a perfect kill rate,
which is the one failure mode of a mutation run that looks like good news.
`cr-filter-operators` marks as skipped the mutants a configuration
excludes by operator, and is a no-op for one that excludes none, so the
same five commands run any of them: `parsers.toml` is the one that
excludes a family, and it states which and why. `sig_hash.toml` or
`engine.toml` in place of it is the consensus profile, at 727 mutants and half
an hour of cpu against 2768 and five and a half hours; the parser profile
is 1034 mutants and minutes, so it is the one that finishes. Each
configuration carries its own arithmetic. The report is `--surviving-only`,
which is the whole of what anybody acts on: a killed mutant is the suite
doing its job, and printing all 727 of them buries the dozen that are not.

Three things to know before starting one. The session mutates the source
file in place and restores it afterwards, so nothing else may read the
tree while it runs — no second session, no `pytest` in another shell, and
a `git status` in the middle is a working tree with a mutant in it.
`exec` is resumable, running whatever the session still has pending, so
interrupting one costs only the mutant it was on. And the `.sqlite`
sessions are the artifact the workflow uploads: `cr-report`, `cr-html` and
`cr-rate` all read one, and a downloaded one can be finished locally.

For the counts, read the session with the workflow's own script rather than
`cr-rate`:

```shell
uv run --locked --no-default-groups \
    python .github/scripts/mutation_counts.py parsers.sqlite
```

`cr-rate`'s `is_killed` is `test_outcome != SURVIVED`, so a mutant the
operator filter skipped counts as a kill and the rate divides by every
result: on a filtered profile that reads 0.97% where the executed mutants
are 1.32%, and on a session nothing has run yet it reads a perfect 0.00%.
`cr-report`'s summary line is wrong the same way. The script prints killed,
survived, skipped and never-run beside the rate over what ran, names any
outcome that is no verdict — INCOMPETENT, or a worker that raised — and
exits non-zero for one, which is the only thing the workflow is red about.
Its docstring says why it reads the session file rather than `cosmic-ray
dump`, which cannot read one of these sessions at all.

The `integration` workflow, which gates and is the exception here: it
runs on every pull request, weekly besides, and `Regtest against Bitcoin
Core` is required on `main`. It asks the one question the rest of CI
cannot, whether Bitcoin Core accepts what btclib built. It downloads a
pinned Core release,
verifies its published sha256, and runs the tests `tests/README.md`
documents with the binary named rather than found on PATH:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_BITCOIND=/path/to/bitcoind \
    uv run --locked --no-default-groups --group test \
    pytest tests/integration --junitxml=integration.xml
```

A step after it reads that report and fails the job if a regtest test
skipped: pytest exits 0 for a module that skipped itself, so a job whose
fixture stopped finding the node would stay green while asking Core
nothing. The HWI tests skip there by design, needing a device or an
emulator, and are not counted.

The documentation, which the `Build the documentation` job of `docs.yml`
runs with this same command, as read the docs does. `-W` is what makes an
`automodule` whose module does not import a failure rather than an empty
page — and what catches invalid reStructuredText in a docstring, which no
hook can: markdownlint does not read `.rst`, and ruff's pydocstyle rules
check the form of a docstring rather than whether its body parses. A name
ending in an underscore is the trap to know about, rst reading it as a link
reference, so write it in double backticks:

```shell
uv run --locked --no-default-groups --group docs \
    sphinx-build -W --keep-going -b html docs/source docs/build/html
```

That job has a second step, which reads the pages the first one wrote and
must find nothing — the job fails if this grep exits 0:

```shell
grep -rn 'href="#\./' docs/build/html --include='*.html'
```

A link between the root markdown files — `./SECURITY.md` in README.md, the
spelling GitHub, btclib.org and PyPI need and the one lychee checks — is
one sphinx cannot resolve on its own, and what MyST emits for a target it
cannot resolve is an anchor on the page it is already on rather than a
warning. `docs/source/conf.py` resolves those links and suppresses no
`myst.xref_missing`, so `-W` fails on the next one that has no target; the
grep asks the same question of the HTML, where no suppression can hide the
answer.

Both steps ask whether a page renders and whether its links resolve, and
nothing more. Whether the worked examples on it are still true is a
different question, asked by `tests/docs_examples_test.py`: any page under
`docs/source/` carrying a `>>>` prompt is run as a doctest by the suite, so
an example is edited by running `uv run pytest tests/docs_examples_test.py`
and pasting back what the library answered — never by writing what it ought
to answer. Keep them deterministic, which for `ssa.sign` means passing
`aux` and for a mnemonic means passing the entropy; and keep every key on
those pages a published test vector, so that a reader who copies one copies
something already known to the world.

The only check with no local equivalent is `codeql`: the analysis needs the
CodeQL bundle and a database, which is a download rather than a `uv`
command, so `.github/workflows/codeql.yml` is where it is configured and
GitHub's runners are where it happens. Its findings appear under the
Security tab, and `REPOSITORY.md` has why the workflow is in the tree at
all.

### The website

**btclib.org is this repository.** GitHub Pages serves it from `main`'s
root, so a set of files at the top level are website sources rather than
Jekyll leftovers, which is the opposite of the natural first assumption:

```shell
gh api repos/btclib-org/btclib/pages
# {"cname": "btclib.org", "build_type": "legacy",
#  "source": {"branch": "main", "path": "/"}}
```

What that makes live:

| file | role |
| --- | --- |
| `README.md` | **the homepage**: there is no `index.md` |
| `_config.yml` | the site title, description, logo, theme and exclude list |
| `_layouts/default.html` | the page template, header and footer |
| `assets/` | the logo, the stylesheet and `scale.fix.js` |
| `CNAME` | the custom domain; Pages reads it from the built site |
| `Gemfile` | the `github-pages` gem, pinned to what Pages runs |

Three consequences worth knowing before editing any of them:

- **every README edit is a website deploy.** The README is also the PyPI
  long description, so a typo in it is visible in three places: GitHub,
  btclib.org and the PyPI project page.
- **every other file in main's root is a URL under btclib.org** unless
  `_config.yml`'s `exclude:` says otherwise, the library itself included:
  drop that list's `btclib/` and `pyproject.toml` entries and
  `btclib.org/pyproject.toml` and `btclib.org/btclib/alias.py` answer with
  their own contents. A new top-level file is published by default; add it
  to `exclude:` if it should not be.
- **the build is the classic Pages builder** (`build_type: legacy`), so
  there are no build logs and no control over the Jekyll or theme version.
  A broken template fails silently: the layout served
  `<script src="/%20/assets/js/scale.fix.js">` for as long as it took
  someone to fetch the page and read the HTML. `website.yml` is the answer
  to that: it builds the same site with the same gem on every pull request
  touching a file above, and fails on a build error, on `%20` in a built
  URL, and on a missing homepage. It is not a required check — it carries a
  `paths` filter, and a required check that produces no run blocks a merge.

Because Pages serves from `main`, a website-only commit there also
triggers the full test matrix; `test.yml`'s `push` trigger carries a
`paths-ignore` for these files so that it does not. The `pull_request`
trigger deliberately does not: those checks are required on `main`, and a
required check that produces no run blocks the merge.

To preview locally, with Ruby and Bundler installed — `bundle exec jekyll
build` is what `website.yml` runs, and `serve` is the same build with a
server in front of it:

```shell
bundle install
bundle exec jekyll serve
```

The `github-pages` gem is pinned to the version GitHub's builder runs, and
<https://pages.github.com/versions.json> is what says which that is: it
carries the Ruby, the Jekyll and the theme too, and the gem pins its own
dependency set exactly, so there is no `Gemfile.lock` here to keep in
step. Dependabot's bundler ecosystem moves that pin, which turns a Pages
upgrade into a pull request the build above runs against.

That is the one part of this project not driven by `uv`, and it is only a
preview: what btclib.org serves is whatever the classic builder makes of
`main`.

### Issues

#### Create a new issue

Did you find a bug?
*Do not open up a GitHub issue if the bug is a security vulnerability*,
and instead refer to our [security policy](./SECURITY.md), which asks for
a private advisory, or an email if you would rather not open one.

For any other problem,
[search](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests)
first if an
[issue](https://github.com/btclib-org/btclib/issues) (or a
[fixing pull request](https://github.com/btclib-org/btclib/pulls),
also known as a PR) already exists.
If a related issue/PR does not exist, please open a new issue.

**Every change starts with an issue.** Open one before a pull request,
even a small one — `Closes #N` in the pull request's description is
what closes it once a pull request carrying an approving review merges.

#### Solve an issue

Scan through our
[existing issues](https://github.com/btclib-org/btclib/issues)
to find one that interests you.
As a general rule, we don’t assign issues to anyone.
If you find an issue to work on, you are welcome to open a PR with a fix.

### Make Changes

Work locally on your fork of btclib,
until you are satisfied. Ensure that pre-commit and pytest
have no issue with your modified codebase.

#### The public surface

**Every module and every package declares `__all__`**, at every depth of
the tree. A name is public here because a list says so, not because it
happens to lack a leading underscore: `import *` and the sphinx pages then
stop depending on an import section, and a helper cannot grow into a name
callers depend on without somebody editing that list. An empty list is a
legitimate answer, for a module with nothing public of its own; declaring
nothing is not.

For a package the list is what the `__init__` re-exports, submodules
included: a module named there is a module a caller — and the command line
of `docs/proposals/cli.md`, which reads the command tree off `__all__` —
can descend into. For a module it is what the module itself defines: a
name it imported belongs to the module that defines it, and
`btclib.alias.Octets` is the spelling of `Octets`.

`btclib.__all__` is the root of that tree: every top-level module and
package, imported on demand by the module `__getattr__` in
`btclib/__init__.py`. A module added to `btclib/` is added there too, and
the suite says so — the list is written out rather than discovered,
because a discovered one would publish a new module without anybody
deciding to.

The two halves are independent. A module declares its own surface whether
or not its parent publishes an edge to it, which is how
`btclib.psbt.psbt_utils` and `btclib.curves.curve_group` say what they
offer without becoming anybody's API: the module states the offer, the
parent decides whether it is reachable.

**A public name kept out of the list is a decision, and the docstring
says why.** The `datadir` of `btclib.network` and of
`btclib.curves.curve`, the three checksum tables of
`btclib.descriptors`, and `btclib`'s own `name`, are the ones in the tree
today; each stays
importable from the module that defines it, which is where the test suite
takes it from. `tests/all_test.py` checks all of this and finds the
modules rather than listing them, so a new public name fails the suite
until it is exported or recorded in that file's `UNEXPORTED` table.

#### Documentation and comments

What "satisfied" means for the prose — docstrings, comments, the
sphinx pages, a pull request reply — is written down here, because a
hook can check that a docstring exists but not what it says.

**Tone of voice: neutral, factual, dry.** The same register
everywhere: no wit, no salesmanship, no emphasis where the fact is
enough. Explanatory detail is wanted; decoration is not.

**Length is a cost, and the reason is what buys it.** One
sentence where one will carry it, and a paragraph only where a
shorter one would leave the reader wrong. Three habits lengthen
prose here without adding to it, and each is worth deleting on
sight:

- the same reason in a second wording — not emphasis, but a
  second copy to keep true, and the one that drifts;
- the sentence that only introduces the next one;
- the tour of alternatives, where the rejected one and the thing
  that rejects it are the whole of the negative result.

Nothing checks prose the way the suite checks code, so every line
of it is one a later change can falsify in silence. That is what
its length is weighed against.

**A docstring states the contract.** What the function takes, what it
returns or raises, and the rule the behaviour comes from — not a
restatement of the name. Most readers of a docstring here are new to
btclib: write for them.

**A comment carries the reasoning, including the negative result.**
Say why the code is as it is and why *not* the obvious alternative —
the second half is what stops the next reader from "fixing" a
deliberate choice, and it is what makes a file reviewable rather than
merely readable.

**Cite the authority.** Where behaviour comes from a BIP, an RFC or a
Bitcoin Core function, name it, rather than asserting the behaviour
as if btclib had decided it. Where btclib deviates, say so and say
why.

**Measure, don't assert.** A number in prose comes from a command,
and the command belongs beside it, so the next reader can re-measure
instead of trusting a figure whose date they cannot see. Never state
a count that nothing checks — an unchecked number drifts into a false
claim — and never state how many of anything a file holds: a stated
total is a line every open branch has to edit, and two branches
moving it to the same wrong number merge without a conflict.

**One fact in one place.** Two files stating the same thing become
two files disagreeing about it; the second one points at the first.

**No history in the prose.** Comments and docstrings say why the code
is as it is, in the present tense; they do not tell the story of what
it used to be. "This is here rather than X because X breaks Y" stays,
whatever prompted it; "this used to be X, until Z" goes — unless the
old spelling is something a caller can still encounter (a deprecated
alias, a wire format), in which case it is not history but the
present. History has two files of its own, `CHANGELOG.md` and
`HISTORY.md`, and it is complete there.

### Commit your update

Commit the changes to your fork once you are happy with them. **Every
commit needs a verified signature** — GPG, SSH or S/MIME, [any of the
three GitHub
verifies](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)
— because the branch rule requires one on every commit that reaches
`main`, not only on the pull request as a whole: an unsigned commit is
rejected before review even starts.

### Pull Request

When you're finished with the changes, create a pull request (PR).

- Don't forget to
  [link PR to issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
  if you are solving one.
- Enable the checkbox to
  [allow maintainer edits](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/allowing-changes-to-a-pull-request-branch-created-from-a-fork)
  so the branch can be updated for a merge.
  Once you submit your PR, team members will review your proposal.
  We may ask questions or request additional information.
- We may ask for changes to be made before a PR can be merged, either using
  [suggested changes](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request)
  or pull request comments.
  You can apply suggested changes directly through the UI.
  You can make any other changes in your fork, then commit them to your branch.
- As you update your PR and apply changes, mark each conversation as
  [resolved](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/commenting-on-a-pull-request#resolving-conversations).
- If you run into any merge issues, checkout this
  [git tutorial](https://github.com/skills/resolve-merge-conflicts)
  to help you resolve merge conflicts and other issues.

**A correction is a commit of its own, never an amend.** Once a branch is
pushed and under review, `git commit --amend` and a force-push replace the
commits the review is attached to: the reviewer loses the diff they read,
"changes since your last review" has nothing to compare against, and every
check starts again from a commit nobody has seen. Add the fix on top, with
a message saying what it fixes, and reply to the comment with the sha.

Nothing is lost in `main`'s history by doing so, because **a pull request
is merged with "Squash and merge"**: the branch becomes one commit, so
the review's commits are the record of the review and `main` keeps one
commit per landed change. A merge commit would put the branch's steps
into `main` and a rebase merge would replay them one by one — `main` is
linear by branch rule, and one change is one commit there.

What that commit says is the repository's to answer, not this file's:

```shell
gh api repos/btclib-org/btclib --jq \
  '{t: .squash_merge_commit_title, m: .squash_merge_commit_message}'
# {"t": "COMMIT_OR_PR_TITLE", "m": "COMMIT_MESSAGES"}
```

so a branch of one commit lands under that commit's own subject, a branch
of several under the pull request's title with its number, and the body
is the branch's commit messages either way — never the pull request's
body, which stays on the pull request.

**Read the button before clicking it.** All three methods are enabled on
the repository and GitHub offers whichever was used last, so the squash is
a choice made once per pull request rather than a setting.

The one force-push that stays right is the one that carries no new work: a
`git rebase origin/main` on a branch whose base has moved, which is how a
stale pull request is refreshed. Re-run the gates after it, never only
before it, and say in the pull request that the head moved and why.

**A pull request needs an approving review from somebody other than its
author before it can merge** — GitHub does not allow a self-approval.

**`main` enforces four things on every commit that reaches it, not only
on review**: a verified signature, linear history, no force push, no
branch deletion. These are a GitHub ruleset with no bypass actor, not a
rule trusted to hold on its own — a commit that is unsigned or that
rewrites history is rejected before it is something to review.

### Your PR is merged

Congratulations :tada::tada: The btclib team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the
[contributors page](https://github.com/btclib-org/btclib/graphs/contributors).
