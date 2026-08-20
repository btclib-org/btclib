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

**The declared dependencies are `bitcoin-core-rpc>=2026.8.13` and, as
the `secp256k1` extra, `btclib_secp256k1>=0.8.0.3`, with no upper
bound**, and the absence of a
ceiling is a decision. Both are btclib-org projects developed by the same
people, and the bindings' whole purpose is to be the bindings this library
calls, so a breaking change there is coordinated with the release here —
which is what a version ceiling substitutes for when it cannot be. A
`<0.9` ceiling would cost a btclib
release for every bindings minor, the ones that break nothing included, and
would make a published artifact refuse a version it in fact works with; a
`<1` ceiling constrains nothing, pre-1.0 semver putting the breaking
changes in the minor.

**0.8.0.3 is not on PyPI yet**, and `[tool.uv.sources]` in
`pyproject.toml` is what resolves it: the bindings come from their `main`
branch, so an entry point merged there is callable here before a release
carries it — `xonly.tweak_add_` is the one this tree calls. A git source
has no wheels, so `uv sync` builds the bindings from source, submodule and
C library included; `uv.lock` pins the resolved commit and every job
passes `--locked`, so the branch is followed only when the lock is
regenerated. The floor above names the unreleased version deliberately: it
is what stops a release going out against a bindings that cannot serve
this tree. One release upstream clears both — the source table goes, the
floor stays.

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
    uv run --locked --no-default-groups --group test --python 3.10 pytest \
    --no-cov
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
uv run mypy btclib tests .github/scripts scripts
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
`tests/_data/`, `tests/ecc/_data/` and `tests/script/_data/` are private
keys by the hundred, so they are recorded in `.secrets.baseline` as
already reviewed —
rather than excluded from the scan, which would leave those files unwatched
for a credential that has no business being there.
`tests/block/_generated_files/block_481824.json` is in the baseline for a
narrower reason: `ACCA` is one of the AWS key prefixes and is also four hex
digits, so the block's own signatures match the detector wherever a script
is rendered as upper-case hex. `tests/_data/bip85_test_vectors.json` is
there for a third reason again, and the narrowest: the detector reads the
field name, and BIP85 prints the password of its two password
applications as DERIVED PWD. Adding a vector to one of those files, or
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
| `test` | pull request, push | 2 platforms × 7 interpreters |
| `lint`, `docs` | pull request, push | — |
| `integration` | pull request, push | a node, two device emulators |
| `website` | pull request, push, on website files | — |
| `claude-review` | pull request, and `@claude` in a comment | — |
| `codeql` | push to main, Tuesday | 2 languages |
| `windows` | Saturday, a release | 2 Windows images × 7 interpreters |
| `macos` | Wednesday, a release | 2 macOS images × 7 interpreters |
| `latest` | Wednesday | platforms sampled, deps upgraded |
| `links`, `mutation` | weekly | — |
| `vendored-vectors` | monthly | upstream's vectors |
| `published` | monthly, a release | what PyPI serves |
| `release` | a tag | calls test, lint, docs, macos, windows, published |

The first four rows are what a merge waits for, and between them they report
the four required checks: `lint` and `docs` share a row and report one each.

What the other rows have in common is that a pull request does not wait for
them, and the reason is one number: the ceiling GitHub Free puts on an
organization's concurrent jobs. REPOSITORY.md measures it and what it cost,
and the consequence is this table's: at that ceiling a pull request's wall
clock is the wait for a slot rather than the suite, so a platform row earns
its place before a review only if it is cheap to wait for. macOS queued 29.4
and 23.2 minutes on average against 0.5 to 1.6 elsewhere, and the fourteen
Windows cells were 2357 of the 3556 seconds of matrix work per commit, the
slowest rows and the longest queues. Both answer weekly and before a
release instead, which is a regression sitting on `main` for at most a week
against every review paying for it. `codeql` is there for the same
arithmetic, with `zizmor` in `lint` still reading these workflows on every
pull request.

`macos` and `latest` share a morning half an hour apart, which is what makes
the pair readable: red in both is the platform, red in `latest` alone is the
upgrade. `windows` takes a morning of its own, Saturday being the day
nothing else here asks for — fourteen jobs beside those two would rebuild on
Wednesday the queue this arrangement exists to remove. Every workflow in the
table also takes `workflow_dispatch`, the gates included: a branch whose
pull request is not open yet has no other way to ask, and for `codeql` and
the two platform workflows it is the only way to ask about a branch at all.
`claude-review` is the exception, and takes none: both its jobs read the
pull request or the comment that triggered them, so a manual dispatch
would start a run with nothing to read.

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
uv run --locked --no-default-groups --group test --python 3.10 pytest --no-cov
```

That one rebuilds `.venv` with the test group alone, which is what breaks
the pre-commit hook until the next `uv sync`: see the note under "Getting
started" above, and `UV_PROJECT_ENVIRONMENT` for running it without
touching `.venv`. The command is what CI runs, verbatim, and CI has no
`.venv` to lose.

`--no-cov` is the matrix asking about the platform and not about the
number: it undoes the `--cov` addopts carries, so what a cell reports is
whether that (os, architecture, interpreter) triple passes. The job below
is where coverage is measured, and `macos.yml` and `windows.yml` pass the
flag for the same reason. `latest.yml` does not: it runs no PyPy cell and
has no coverage job of its own, so the ratchet meeting an upgraded
coverage.py is one of the things that workflow exists to find out.

One pair is missing from that matrix, `(3.14, ubuntu-latest)`, and the
coverage job below is it: same image, same interpreter, same suite, and the
only difference is the instrumentation. Reproducing that cell is therefore
the coverage command rather than this one.

The `coverage` job, gated by `fail_under` in pyproject.toml:

```shell
COVERAGE_FILE=coverage-data-bindings \
    uv run --locked --no-default-groups --group test pytest --cov
```

What `--cov` measures and how it reports are `tool.coverage.run`'s
`source` and `tool.coverage.report` in pyproject.toml, so this command
and the bare `uv run pytest` above are the same measurement: the job
cannot gate on a scope a contributor's run does not have. The flag is
written out here even though addopts already carries it, this being the
job's command verbatim. `COVERAGE_FILE` is `--data-file`'s environment
variable, coverage's own, and is the job's real step verbatim too, not a
local-reproduction addition: the two artifacts this job and `no-bindings`
below produce would overwrite each other under the default `.coverage`
name once both land in the `coverage-union` job that reads them. The job
then uploads the data file this command wrote as an artifact, for
`coverage-union` to read; that step has no command of its own to
reproduce, being a plain `actions/upload-artifact`.

The `no-bindings` job, which runs the suite against a btclib that has no
`btclib_secp256k1` to delegate to:

```shell
uv run --locked --no-default-groups --group harness \
    python -c "from btclib._libsecp256k1 import INSTALLED; \
      assert not INSTALLED, 'btclib_secp256k1 is installed'; \
      from btclib.curves import is_libsecp256k1_serving; \
      assert not is_libsecp256k1_serving()"
COVERAGE_FILE=coverage-data-no-bindings \
    uv run --locked --no-default-groups --group harness \
    pytest --cov --cov-fail-under=0
```

`harness` and not `test`: `test` is `harness` plus `bindings`, and uv's
`--no-group` suppresses a group that was selected rather than one another
group includes, so the split in pyproject.toml is what this job is.
`--cov --cov-fail-under=0`, not `--no-cov` (issue #1002): the delegated
arms are still unreachable in this configuration by construction, so a
report of this run *alone* would still fail the 100% gate for the one
reason the run exists to create — `--cov-fail-under=0` collects the data
without gating this run on it. The tests that hold both implementations
and compare them carry the `bindings` marker and skip themselves;
everything else runs. This job's data is uploaded as an artifact too,
under the name `COVERAGE_FILE` gave it above, so it does not collide
with the `coverage` job's when both are downloaded into the same job.

The `coverage-union` job, which combines the two data files above and
gates their union at 100% as well — beside the `coverage` job's own
gate on the delegated run alone, not instead of it, so that a line
covered only by the no-bindings run cannot pass in silence just because
the union reached it:

```shell
uv run --locked --no-default-groups --group harness \
    coverage combine coverage-data-bindings coverage-data-no-bindings
uv run --locked --no-default-groups --group harness \
    coverage report --fail-under=100
```

Reproducing this one locally needs the two data files the commands above
already produced, under the two names they already wrote them with — no
renaming step, since `COVERAGE_FILE` on each command is what named them
that way in the first place. The two commands above run in two passes
either way, one `.venv` not being able to hold and lack the bindings at
once.

The `dist` job, which inspects what would be published and then
installs it. The first two commands after the build read the *members* of
the two archives, which the three that follow do not: an allowlist of what
may be in a wheel and an sdist, and the bill of materials a release
attaches — written here into a temporary directory and thrown away, this
being the copy that says the script still reads a real wheel. That
allowlist is stated in prose in
[the package-content policy](./docs/source/package-content-policy.md),
which the suite compares against the script's own constants, so changing
a rule means changing both. The last
commands ask for the wheel and nothing else, so
what pulls btclib_secp256k1 in is the `Requires-Dist` the wheel carries
for the `secp256k1` extra — which those commands name on both sides, a
wheel installed without it declaring nothing to resolve. The lock
arrives as constraints, which bind a version without
requesting a package, so a release of the bindings cannot turn a required
check red while the wheel's own metadata still does the work. They run
from an empty directory, or the import finds the source tree instead of
the wheel:

```shell
uv build
uv run --no-project --python 3.14 \
    .github/scripts/verify_dist_contents.py dist/
SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) uv run --no-project \
    --python 3.14 .github/scripts/generate_sbom.py dist/ "$(mktemp -d)"
uv run --locked --only-group build twine check --strict dist/*
uv run --locked --only-group build check-wheel-contents dist/*.whl
uv run --locked --only-group build pyroma --min 10 dist/*.tar.gz
tmp=$(mktemp -d)
uv export --locked --no-dev --extra secp256k1 --no-emit-project \
    --no-hashes -o "$tmp"/constraints.txt
cd "$tmp" && uv venv &&
    set -- "$OLDPWD"/dist/*.whl &&
    uv pip install --constraints constraints.txt "$1[secp256k1]" &&
    .venv/bin/python -c "import btclib; \
      from btclib.ecc import dsa; \
      from btclib.to_pub_key import pub_keyinfo_from_prv_key; \
      print(btclib.__version__); \
      assert btclib.__version__ != 'unknown'; \
      assert dsa.verify(b'btclib', pub_keyinfo_from_prv_key(1)[0], \
        dsa.sign(b'btclib', 1))"
```

The checks the `release` workflow runs before building anything, the
first of them being where the tag came from rather than what it says:

```shell
git merge-base --is-ancestor HEAD origin/main
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

The bill of materials that job writes is reproducible for the same reason,
that variable being its timestamp, so a rebuild verifies against the
attestation exactly as the two distribution files do.

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

That workflow has a second job, `suite-bindings-latest`, upgrading only
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
nothing. The HWI tests skip there by design and are not counted; they are
`hwi-integration.yml`'s, a workflow of its own rather than a second job
here.

`HWI against a Trezor emulator` is the first of its two jobs, and it
gates nothing: it downloads a pinned emulator binary from
`data.trezor.io` beside the same node, checks its sha256, installs a
pinned HWI in an interpreter of its own — HWI declares `^3.9,<3.13`, and
`btclib/hwi.py` says why it is a program here rather than a dependency —
loads the seed HWI's own suite uses over DebugLink, and runs:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_HWI_SIGN=1 \
    BTCLIB_HWI="/path/to/hwi --emulators" \
    BTCLIB_BITCOIND=/path/to/bitcoind \
    uv run --locked --no-default-groups --group test \
    pytest tests/integration/hwi_device_test.py -n0 --junitxml=hwi.xml
```

`-n0` because there is one device: `addopts` passes `-n auto`, and three
workers are three HWI processes on one udp port.

`BTCLIB_HWI_SIGN` can be set because HWI opens a udp device with
`TrezorClientDebugLink`, which answers the button request itself. The
workflow carries no `pull_request` trigger at all: a firmware release, an
unreachable `data.trezor.io` or an emulator that stopped starting
headless is trezor's day rather than the branch's, and a workflow that
never triggers on a pull request produces no check there, not even a
skipped one — so it runs weekly, on a push to `main`, and on
`gh workflow run hwi-integration.yml --ref <branch>`, which is how a
branch touching `btclib/hwi.py` is checked before it lands.

`HWI against a Ledger emulator` is the second of the two, and it costs
more because a Ledger does. There is no published app binary, so the job
compiles one from a pinned tag of `LedgerHQ/app-bitcoin` inside Ledger's
own builder image, pinned by digest — and compiles it twice, the coin
being built in: `COIN=bitcoin` answers the mainnet questions of the
module, `COIN=bitcoin_testnet` signs the regtest spend, and one binary
cannot do both. Speculos comes from PyPI, where it carries its launcher
and wants only `qemu-user-static` from the system, and it runs the two
apps in turn:

```shell
SPECULOS_APPNAME="Bitcoin:2.5.0" speculos --display headless \
    --api-port 0 --model nanox \
    --automation file:.github/speculos-automation.json \
    --log-level automation:DEBUG bitcoin.elf
BTCLIB_INTEGRATION=1 BTCLIB_HWI="/path/to/hwi --emulators" \
    uv run --locked --no-default-groups --group test \
    pytest tests/integration/hwi_device_test.py -n0 \
    -k "not signs_what_btclib_built" --junitxml=ledger-mainnet.xml
```

and again with `Bitcoin Test:2.5.0`, `bitcoin-test.elf`,
`BTCLIB_HWI_SIGN=1` and `-k signs_what_btclib_built`. Nothing answers a
button there the way DebugLink does on a Trezor, so `--automation` does:
`.github/speculos-automation.json` is HWI's own file, vendored, and its
rules match the text the app draws. That is the part that breaks when
the app changes wording, and it breaks as a test waiting out btclib's
timeout, which is why `automation:DEBUG` is on and both Speculos logs
are uploaded with the reports.

`.github/scripts/wait_for_hwi_device.py` is what stands between starting
an emulator and running a test against it: Speculos answers no ping, so
the question asked is the real one — `enumerate_devices` until one
device is usable, or an `::error::` naming what was seen instead.

All three jobs install the node through `.github/actions/install-bitcoind`,
the repository's own composite action, so the release and its checksum
are pinned once.

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
GitHub's runners are where it happens. It is also the one check no pull
request runs — `workflow_dispatch` is how a branch asks — so its findings
arrive under the Security tab after a merge rather than before it, and
`REPOSITORY.md` has both why the workflow is in the tree and what that
timing was traded for.

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

#### Breaking a caller is not an argument

**A refactoring that is reasonable gets made, however much it breaks.**
Do not weigh "this renames something callers use" against it, and do not
propose keeping an inconsistency and gating it going forward instead:
consistency across a family — one naming shape, one contract per prefix,
one way to read the same kind of answer — is itself the reason, and a
release is where a break is reported rather than a reason not to make it.

So a census that finds thirty names of one shape and six of another has
found six to change, not a trade-off to price. What the measurement is
for is knowing the blast radius and writing HISTORY.md's
breaking-changes entry, which is how a user is told: read
[HISTORY.md](./HISTORY.md) for what that entry looks like, and note that
`v2026.9`'s list is long on purpose.

The one thing this does not license is a break nobody can act on. An
entry says the old spelling, the new one, and what a caller does about
it; a rename with no note is the defect, not the rename.

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

**Every public function validates its inputs.** Whatever it is handed — a
string, octets, or an object somebody built earlier — a name a caller can
reach checks it before acting on it, and a malformed argument leaves as a
`BTClibTypeError` or a `BTClibValueError`, which is what the callers of
this library are written to catch. The work itself may be deferred to a
private twin that does not validate; that twin is then what the library
composes internally, where the inputs have already been checked and
checking them a second time buys nothing.

**A function that answers a `bool` is total over the types it declares,
and only those.** `is_p2sh` answers False for bytes that are not a p2sh
script, and `dsa.verify` answers False for a signature that does not
verify: that is what the bool is for, and a caller filtering a list of
them wants an answer and not an exception. A value of a type the
signature does not declare is not such an answer — it is the caller's
own mistake, it is a call mypy already refuses, and it leaves as a
`BTClibTypeError` like any other. So `dsa.verify(msg, 12, sig)` raises,
12 being a private key in this library and never a public one, where
`dsa.verify(msg, "not a key", sig)` is False.

The line is the annotation, and deliberately not which built-in a helper
happens to derive from: those two coincide only by accident, which is
what issue #745 found and this replaces. The `assert_*` twin beside each
of these is the spelling that says *why* a value was refused, and the two
are how a caller chooses between an answer and a reason.

**Both halves are gated, and both hold.**
`tests/input_validation_test.py` drives the two rules over every public
function whose required parameters are all library input types.
`tests/bool_contract_test.py` drives them from hand-written fixtures over
the verifications that walk cannot reach — a signature verification needs
a valid message, key and signature, and a `Sig | Octets` no vocabulary of
wrong values can build. `tests/built_object_contract_test.py` does the
same for a function whose parameter is an object the caller already built
— a `Psbt`, a `PsbtIn`, a sequence of extended keys — which is the family
`check_validity=False` makes reachable, an invalid object being something a
caller may legitimately hold. `tests/curve_parameter_test.py` is the
fourth, over a parameter that carries a *default*: reaching one means every
argument in front of it has to be valid, which is the table of valid values
the automatic walk exists to do without, so `ec` is driven from a table
there as `hf` and `network` are driven where their own checks live. None of
the four has an exemption list, which is the state to keep: a finding is a
red test, to be fixed or to be given a reason of its own beside the two
families that have one.

**A `bool` parameter is a kind or a truth, and only the first is
type-checked.** A flag that decides *what is computed* refuses a non-bool,
`musig2._flag` stating the reason: a kind written down and read back — json,
a configuration file, a coordinator's message — arrives as whatever it was
written as, and `"false"` is true, so `KeyGroup(verify=)` would compute
every address of the other script rather than raise. A flag that decides
only *whether a check runs* is read for its truth: `check_validity` and
`slip132`'s `check_root_xkey` either run a check or skip one, and neither
changes an answer. `tests/check_validity_test.py` owns that convention.

**Which of the two a flag is, is written down for every one of them.**
`tests/bool_parameter_test.py` is the census: two tables, a kind driven
until it refuses `"no"`, `0` and `1`, a truth driven until it accepts all
three, and a walk that fails on a `bool` parameter in neither table. So a
flag added anywhere is a decision somebody makes rather than one the
default makes for them — and `0` and `1` are in that vocabulary because
`bool` is a subclass of `int`, which is what leaves `isinstance(value,
int)` no check at all here. `utils.assert_type` is the refusal, and
`check_validity` is the one name subtracted by the walk, its own file
holding it.

Four shapes were what the second gate found when it was written, and they
are worth knowing because each is a way of being handed an argument
without looking at it: a **sequence parameter** walked before it is
checked, so a `None` is "not iterable" from underneath the library; a
**signature** reaching `Sig.b64decode`, which strips before it decodes; an
argument handed **straight to the bindings**, whose own message names a C
parameter; and a **reduction outside the `try`**, which refuses a message
`verify_` would answer False about.

**Which of those a function is, its name says**, and the vocabulary is
closed: a public function that answers a `bool` carries one of the four
prefixes below, or is one of the English predicates
`tests/name_contract_test.py` names — `Psbt.inputs_modifiable` and
`Miniscript.mixes_timelocks` among them, where the name is the standard's
and `is_` would cost the reading. A bool that is neither fails that gate,
so a new one is a prefix or a decision somebody wrote down.

**A member that takes nothing but `self` is a `@property`**, whatever it
answers, and that is gated: it is read off the object rather than called,
so `tx.is_segwit` and not `tx.is_segwit()`, `view.prevouts` and not
`view.prevouts()`. `functools.cached_property` is one of these — a read
that parses once, as `Script.asm` does.

What is *not* a read is exempt by shape rather than by a list of names:
`assert_*` refuses, and a property that refuses is a trap, since reading
`obj.assert_valid` evaluates the method and throws it away; `get_*` talks
to a node or an explorer, so the prefix is the warning a property would
hide; `to_*` hands back a new object; and `close` is an action. The one
exemption named individually is `alias.HashObject`'s `digest`,
`hexdigest` and `copy`, because hashlib calls them that way — and hashlib
draws the same line itself, `block_size` and `digest_size` being
attributes there as they are properties here.

A `Protocol` member is under the rule too, and that makes the shape a
promise: declaring `PsbtSigner.master_fingerprint` a property says
reading it is free, which every implementation of it can keep. Where a
future one cannot — HWI's own `get_master_fingerprint` is a device call —
the answer is to relax the contract deliberately, not to leave room for
it in advance.

The bool half of the same rule: Thirty were properties and six were methods,
which made the six the exception; they are properties now. It also makes
the forgotten-parentheses bug unsayable — `if tx.is_segwit:` on a method
is a bound method, and every bound method is true. mypy's
`truthy-function` names that, and mypy is a gate here, but a shape that
cannot go wrong beats a checker that catches it going wrong.

What the four prefixes buy is a promise read off the name:

- `assert_*` refuses and returns `None`. There are eighty-odd of them
  and they are the reason half of the pair above.
- `is_*` answers a `bool` about a value, and is total over the declared
  types: `is_p2sh` is False for bytes that are not a p2sh script.
- `verify*` answers a `bool` about a signature or a proof, on the same
  terms. `assert_as_valid` beside it says why.
- `check_*` answers a `bool` **and refuses what cannot be an answer** --
  the one prefix that warns a caller it still needs an `except`. There
  are two: `script.engine.script.check_pub_key`, where a wrong length is
  False but a hybrid prefix under STRICTENC is the offence itself, which
  is how Core's `CheckPubKeyEncoding` splits it; and
  `script.taproot.check_output_pubkey`, where a malformed control block
  is no proof rather than a disproof.

Nine functions carried `check_` while refusing and returning `None`, and
two more while returning bytes and a pair of bools, which left the prefix
saying four things and therefore nothing (issue #814). A converter is
named for what it returns -- `bytes_from_octets`,
`b32.bytes_from_witness_program` -- and a query for what it answers.

**`check_validity` is a parameter and not one of those four**, which is
worth saying now that the prefix means something: there `check` is a verb
governing an object — "check the validity" — where a prefix on a function
name classifies what the call answers, and a caller passes this one
rather than reading a result off it. What it gates is `assert_valid`, a
refusal, so the vocabulary above would name it after that if it named it
at all. It keeps the name it has: `validate` says no more, and the
alternative is renaming a keyword on eighty-odd public signatures for a
reading nobody has to make twice.

`check_validity=False` is not an exemption from this. It says "do not
check *now*", not "this object is exempt from here on": these are mutable
dataclasses whose fields are public and get reassigned in place, so
validity at construction is not validity at use. Passing it is supported —
`tests/check_validity_test.py` exercises the flag across the library — so
a public function that takes an already-built object and asks it nothing
is one a caller can reach with an object the library itself would refuse.

`btclib.bip32` is the shape to copy. `derive` validates and calls
`_derive`, which does not, and `_key_data_from_bip32_key` is the one place
a `BIP32Key` of any spelling becomes a validated `BIP32KeyData`, every
public wrapper going through it. `descriptors` then composes the twins
directly — `_xpub_from_xprv(_derive(_key_data_from_bip32_key(xprv),
prefix, None))` — paying one validation instead of three, and no base58
round trip between them. The leading underscore those three carry means
what it means anywhere in Python: private. `__all__` is what decides
publicity, so it is a reader's hint rather than the rule, but an
unvalidating twin belongs on the private side of that list, and calling one
asserts that its caller validated.

**A private function takes no default argument either**, which is the same
absence of an outside caller read the other way: a default is written for
one the author cannot see, and there is none here. So the value the call is
made with is at the call site, where it is read — `_derive`'s `None` above
is the version it forces on the derived key, and `_deserialize_scalar`'s
`strict` decides whether BIP66's minimal encoding is enforced at all. A
flag added to a private function is then a question asked again at each of
its call sites, instead of answered for the ones nobody revisited.
`tests/private_defaults_test.py` is the gate, and its docstring carries
what the rule does not reach.

**A trailing underscore is the other convention, and it is public.** It
marks the spelling whose input the caller has already prepared: `dsa.sign_`
takes the hash `sign` would compute, `musig2.nonce_gen_` the randomness
`nonce_gen` draws, `musig2.partial_sig_verify_` the session context
`partial_sig_verify` aggregates. Both names of the pair are in `__all__`,
so it is an offer to skip work the caller has already paid for, not a way
past the validation above: `sign_` checks its `msg_hash` as `sign` checks
its `msg`. The two conventions are independent, and
`btclib.ecc.dsa._assert_as_valid_` carries both.

Publishing both names is what makes their agreement a promise rather than
a tidiness. A keyword added to `verify` is added to `verify_` or to
neither, with the same default in both: a flag that changes the answer on
one and is missing or defaulted differently on the other makes the pair
two functions instead of two spellings, and a caller who reduced the
message first quietly gets a different rule. The prepared argument is the
one difference the pair exists for.

The exception is a boundary at which nothing can be invalid, and it is
named rather than passed over: where a class's invariants are exactly the
widths of its fields, the decoding enforces them by construction and the
check is unreachable by design rather than missing. `btclib/utils.py`'s
docstring is where that rule is written down, `OutPoint` and `TxIn` being
the classes it holds for.

#### A `_var` suffix means the operand decides the work

A function whose duration follows the value it is given ends in `_var`,
and the plain name beside it is the one a secret may be handed. It is
libsecp256k1's convention and it is used there for the same two halves:
`secp256k1_scalar_inverse_var` sits beside `secp256k1_scalar_inverse`,
`secp256k1_gej_add_var` beside `secp256k1_gej_add_ge`. The point of it is
that the question is answered at the call site rather than in the
docstring of the thing being called.

What "the work" is depends on the function, and each of these was
measured rather than assumed — on secp256k1's order or its `p`, over
random operands of 256 bits down to 64, the ratio between the two ends:

- the count of point operations, for a scalar multiplication:
    `curve_group._mult_jac_var` and `curve_group_2._double_mult_w_NAF_var`
    against `_mult_regular_window`, `_mult_fixed_base` and
    `_double_mult_regular_window`, which make the same number for every
    scalar of the curve. `curves.double_mult_var` and
    `curves.multi_mult_var` carry it for that reason and `curves.mult`
    does not
- the iteration count of an extended Euclid: `mod_inv_var` at 4.21x,
    `xgcd_var` at 4.84x, `mod_inv_batch_var` at 2.01x
- the length of a loop over the operand: `legendre_symbol_var` at 4.26x,
    and `tonelli_var`, whose 1.54x is spread within one operand size
    rather than across sizes — Tonelli-Shanks iterates on the value, not
    on its length. `mod_sqrt_var` reaches that loop only for a `p` of 1
    mod 4: on a 3 mod 4 one it is a single exponentiation with a fixed
    exponent and measures 1.01x, and the catalogue holds both kinds —
    `secp224k1`, `secp224r1` and `nistp224` are 1 mod 4 — so the caller
    picks which it gets and the suffix states the worse case
- one modular inverse, in the layer above: `aff_from_jac_var` at 2.96x,
    `x_aff_from_jac_var` at 1.93x, `aff_from_jac_batch_var` at 1.67x and
    `y_aff_from_jac_var` at 1.42x follow the `Z` they are handed;
    `double_aff_var` at 1.32x, `add_aff_var` at 1.23x and the `add_var`
    over them at 1.22x follow the coordinates. `y_var` and its three
    tiebreakers follow their `x` on the 1 mod 4 curves above, 1.84x on
    `secp224k1`, where on secp256k1 they are flat

**The suffix is measured, never inherited, and that is what stops it.**
Every function that *reaches* one of these through some chain of calls
would otherwise take it: there are 636 of them, 344 public, which is
`hex_string`, `ripemd160` and `p2pkh` — a suffix on the library, saying
nothing. Two things break the chain, and both are facts about the caller
rather than about the callee. Blinding is one: `mult` calls
`aff_from_jac_var` and is 0.99x in its scalar, because `_blinded_jac`
randomized the `Z` that inverse is timed on. A public operand is the
other: `point_from_octets` measures 1.05x, its `y_even_var` being one
fixed exponent on secp256k1 and its `_is_x_coordinate_var` reaching the
bindings. So the question to ask of a new name is not what it calls, but
what its own clock does with what it was handed — and the answer is a
measurement.

**The census is at a measured zero, and these are the exceptions it
leaves.** Every function that spends one of these primitives has been
timed over random inputs of one class, against `add_jac` as the floor —
1.05x, the group law having nothing to branch on. What measures at that
floor keeps its plain name, and each is here so that the next reader does
not have to re-derive it: `dsa._assert_as_valid_` 1.07x and
`dsa._recover_pub_key_` 1.05x, `ssa._recover_pub_key_` 1.06x,
`ellswift._try_sqrt` 1.05x, `sec_point.point_from_octets` 1.01x,
`ssa.point_from_bip340pub_key` 1.03x, `Sig.assert_valid` 1.03x and
`ellswift.xdh` 1.01x. The inverse or the root inside each of them is
real, and it is diluted: an inverse varying by 1.32x is 10 us of a 40 us
verification, and `xdh` is dominated by a `mult` that is blinded.
`ellswift._constants` is memoized on the curve and receives no value at
all.

The one number worth keeping in view is `ellswift._xswiftec_inv_var`, at
**29.62x** — 28 calls of 50 returning under 10 us and 22 over. That is an
early return and not a slower sum, which is what a data-dependent branch
looks like on a clock, and it is why the SwiftEC map carries the suffix
where the ECDH built on it does not.

Three tiers of duration follow, of which only the first is constant-time:

- **constant-time is libsecp256k1's alone.** Every claim of it in this
    library is a claim about the C behind the bindings, which is why
    `SECURITY.md` states argument by argument when a call crosses that
    boundary. Nothing written in Python is constant-time, and no name
    here should be read as promising it.
- **regular, or blinded: the operand does not decide the duration, and
    something else does.** `_mult_regular_window`, `_mult_fixed_base` and
    `_double_mult_regular_window` make the same operations for every
    scalar of the curve; `_blinded_jac` leaves the intermediate values a
    function of a random factor rather than of the scalar alone; and
    `mod_inv` leaves an extended Euclid's iteration count following a
    random factor rather than the caller's operand, at 1.02x where
    `mod_inv_var` is 2.06x over the same range. This is decorrelation and
    not uniformity — the duration still varies, and what changes is what
    it varies with.
- **variable: the operand decides.** Everything suffixed above, and every
    reduction whose cost is the size of what it reduces.

So **a secret takes the plain name and a public value takes the `_var`
one**, which is the opposite of an optimization default and is meant to
be: the fail-safe direction is that forgetting to choose gives the slower
and safer call. `dsa`'s signing inverts the nonce with `mod_inv` while
its `r`, its `s` and a verification's `Z` take `mod_inv_var`, and those
four sit within twenty lines of each other; a reviewer should be able to
tell which is which without tracing where each value came from.

Add the suffix when adding such a function, having measured that it earns
one, and do not add it to the recodings, the tables or the group law:
those take no operand whose size varies, and a suffix on everything says
nothing about anything.

What none of this does is make the Python path safe, and `SECURITY.md`'s
limitations section is what says so at length: a table is still indexed
by a secret digit, and that is out of reach from bytecode. A name in the
second tier closes one measured channel, and the honest form of the claim
is that one — which channel, measured how, and what is left.

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

**A table of measured timings belongs in the CHANGELOG, not in a
docstring.** The rule above wants the command beside the number, and a
timing is the one figure that has none here: the benchmarks are their
own repository, and no gate re-measures — a timing gate on a shared
runner is a flake. What is left to do instead is put it where it is
read as what it is. A docstring is read as a statement about the code
as it stands, so a figure in one is a claim about now; a CHANGELOG
entry is read as the history of a release, and calendar versioning
puts the release day in the heading over it once the release is cut.
So the docstring keeps the number that carries the *reason*, the one a
reader needs to follow the decision — "half of what a signature
costs", "twice as fast, flat in n, no crossover" — and the matrix per
size or per caller goes in the entry that took it. Two figures were
found stale in one week by the branch standing on them, and neither
would have been noticed otherwise (issue #940).

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
lands as one commit**: a branch of several is squashed into one, so the
review's commits are the record of the review and `main` keeps one commit
per landed change. A merge commit would put the branch's steps into
`main` and a rebase merge would replay them one by one — `main` is linear
by branch rule, and one change is one commit there.

**How that commit reaches `main` is the squash button**, pressed by
auto-merge once the review and the checks are in. GitHub composes it and
signs it with its web-flow key, which is a valid signature and therefore
all the branch rule asks for. There is no other path: `main` takes a
pull request and nothing else, a direct push being refused for everyone.
REPOSITORY.md has the settings that make that true.

Either way the decision belongs to the landing and not to the branch,
which is why a correction added on top of a reviewed branch is still the
right shape: by the time it is squashed the review has its record.

What that commit says is the repository's to answer, not this file's:

```shell
gh api repos/btclib-org/btclib --jq \
  '{t: .squash_merge_commit_title, m: .squash_merge_commit_message}'
# {"t": "COMMIT_OR_PR_TITLE", "m": "COMMIT_MESSAGES"}
```

so a branch of one commit lands under that commit's own subject, a branch
of several under the pull request's title with its number, and the body
is the branch's commit messages either way — never the pull request's
body, which stays on the pull request. That is what the button writes,
and a squash made locally follows the same convention by hand, the
setting being the statement of what the message should say rather than
only of what a press produces.

**It is a setting and not a choice made once per pull request**, so
there is no other button to read. REPOSITORY.md has it, what the other
two would have cost, and the ruleset that names `squash` as the only
merge method it accepts.

The one force-push that stays right is the one that carries no new work: a
`git rebase origin/main` on a branch whose base has moved, which is how a
stale pull request is refreshed. Re-run the gates after it, never only
before it, and say in the pull request that the head moved and why.

**A pull request needs an approving review from somebody other than its
author before it can merge** — GitHub does not allow a self-approval.
[REVIEWING.md](./REVIEWING.md) is the standard that review is written
against, and is this file's other half: what a review establishes before
it gives an ack, how a finding states its severity, and why everything it
notices that the pull request is not about becomes an issue rather than a
comment. Read before opening a pull request, it is what the pull request
will be answered against.

**`main` enforces four things on every commit that reaches it, not only
on review**: a verified signature, linear history, no force push, no
branch deletion. These are a GitHub ruleset with no bypass actor, not a
rule trusted to hold on its own — a commit that is unsigned or that
rewrites history is rejected before it is something to review.

### Your PR is merged

Congratulations :tada::tada: The btclib team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the
[contributors page](https://github.com/btclib-org/btclib/graphs/contributors).
