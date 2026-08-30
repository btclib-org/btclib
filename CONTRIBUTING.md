# Contributing

What this repository holds in common with the others of the organization
— the toolchain, the lint gate, the tool tables behind it, the workflow
set and the branch rules — is stated once in the
[btclib-org repository standard](https://github.com/btclib-org/.github),
each rule with the alternative it was decided against. It binds this
repository, so a change departing from it is a divergence, and one filed
as an issue in that repository rather than here: a difference between two
repositories belongs to neither of them.

**This file is the same in every repository of the organization up to
its last section.** What is true of one tree only — the commands that
build its environment, the gates it runs, which of its workflows decide
a merge — is under that heading, and the comparison stops there.

## The issue tracker

Where an issue is filed, and what an alignment finding has to name, is
[the standard's *What this repository is*][s-what]: an issue spanning
repositories, or whose subject is the standard, goes to
[btclib-org/.github](https://github.com/btclib-org/.github/issues), and
one about this tree alone stays here.

A finding noticed while doing something else is filed, not carried.
`REVIEWING.md`'s *Every collateral finding becomes an issue* is the whole
of what to do with one, and it applies to an author as much as to a
reviewer: a pull request answering two questions cannot be accepted for
either.

## Documentation and comments

[Section 9 of the standard][s9] is the prose style, and it governs the
prose this tree ships — comments, docstrings and markdown. It is not
restated here: a second wording is the one that goes stale, which is
that section's own *One fact in one place*.

A commit message is prose this tree ships too, though section 9 does not
say so: [the only merge method the rule accepts][s11] puts it on `main`
as the landing commit's body, so what is written in one is read there
long after the branch is gone.

## Pull requests

What `main` accepts, and what it refuses to everyone, is [section 11 of
the standard][s11]. Run the gates locally before opening anything —
the last section of this file says which they are — because CI runs
exactly them, so a red run there is a local run that was not done.

What a pull request's title and description have to say about the issues
it closes, and why a manual link in the Development panel is a trap
neither of them shows, is [the standard's *What a pull request says it
is*][s-title]. Read it before opening one; it is the rule most often
found broken after the fact.

**Before it is opened, the branch's own commit subjects and bodies are
read against that same rule.** The description does not exist yet to
disagree with them, and [the standard][s-title] has the command that
scans the branch's own commit text for a verb in front of a reference.

**The two spellings are named here as well as there, against [section 9's
*One fact in one place*][s9]**, the paragraph above naming the section
and not the forms, which are the half a citation is got wrong in:
`(closes #N)` cites an issue the change closes, wherever the citation
sits — the title, the commit subject where [*Merge method*][s11] makes
that the thing that lands, and a `CHANGELOG.md` entry — and `(issue #N)`
cites, in those same places, an issue the change advances and does *not*
close. One token holds one meaning whichever file it sits in, so the
pair is chosen by what is true of the change rather than by which file
is being written, and a tree's own landed subjects are not what to copy
it from: nothing already landed is rewritten, so what a repository wrote
before the rule stays where it is.

`REVIEWING.md` is the standard a review is written against, and is this
file's other half. Read before opening a pull request, it is what the
pull request will be answered against.

`CHANGELOG.md` gets an entry for anything a reader would notice, and the
release notes move only for something a user has to *act* on, in the
repositories that publish.

### One subject, opened as soon as it is written

A pull request answers one question. Issues that share a subject are one
pull request, closing each of them; issues that do not are one pull
request each, however small either of them is.

It is opened the moment it is written and verified — not held for the
previous one to be reviewed or to land, and not batched with the next. A
batch arrives as one reviewing job with several subjects, which is the
shape that costs the most to read; a finished pull request held back is
review that could have started and did not.

Working this way stacks branches, which is fine and costs one rule: a
child whose base was amended is moved with the old base named,

```shell
git rebase --onto <new-base> <old-base-sha> <child>
```

because a plain rebase replays the base's old commit inside the child,
and the forge then shows the base's old text as additions with nothing
red anywhere. Read the child's diff afterwards rather than trusting the
rebase, and retarget each child onto `main` as its parent lands.

### The landing queue

Where more than one pull request is open against this repository, only
one is carried to `main` at a time: rebased onto the tip, reviewed on
that head, and landed, while every other one waits, untouched, for its
turn. This governs which of several *already open* pull requests reaches
`main` next; *One subject, opened as soon as it is written* above governs
the moment before that, when a finished one is opened — the two do not
conflict, since a pull request is still opened without delay and still
waits its turn once several are open.

The reason is CI throughput, not the ack a waiting pull request keeps —
`REVIEWING.md`'s *The verdict* states what an ack belongs to, and
*Landing it* below states which rebase voids one. Every rebase queues
this repository's whole check matrix against the organization's ceiling
on concurrent jobs, so rebasing every waiting pull request after each
landing spends that capacity on runs the next landing invalidates
anyway, and delays the one pull request that is actually next: work
spent on a pull request that is not next is work that delays the one
that is. The ceiling's figure is `REPOSITORY.md`'s, under *Plan-gated
settings*, beside the command that re-derives it.

Order is cheapest and least contended first, most invasive last, so that
a large change does not sit at the head blocking everything behind it.

The maintainer may declare a bounded exception — several pull requests in
flight against one repository, for a named piece of work — trading the
cost above for throughput; it is recorded as a comment in
[btclib-org/.github](https://github.com/btclib-org/.github/issues), by
*The issue tracker* above, and holds only for the work it names.

### The review

A review is given promptly and on local evidence. It does not wait for
CI, does not report a check as a finding, and does not discuss a run at
all: whether CI is green is the author's business, once, at landing time.

The exchange is anchored to a sha rather than to a branch, a branch being
free to move under a review:

- the author hands off by naming the sha pushed and the evidence run
  against it, then leaves that head alone;
- the reviewer answers with findings — where, what is wrong, how they
  know it, and whether each is blocking;
- the author accepts what is reasonable, declines the rest with a reason
  in the thread, and pushes the answer without waiting for CI;
- the reviewer resolves the threads they opened, that being what says a
  finding is closed, and re-reviews the delta rather than the branch.

**What ends the loop is the ack of record**, and the author does not
supply their own. A reading that says what it found and delivers no
verdict is a review too and ends nothing; [the standard's *Review*][s-rev]
has which is which, and `REVIEWING.md` has how each is written. A
disagreement that survives a second exchange goes to the maintainer
instead of into a third round.

### Landing it

CI is read once, and this is where. Rebase onto `main`'s tip, push that
head so the checks run on the tree that will land, and only then wait for
them: checks read before a rebase describe a tree nobody is landing. A
rebase that moved nothing but the base leaves the ack standing; one that
resolved a conflict does not, that resolution being a change no reviewer
has seen.

Then squash, [the only method the rule accepts][s11].

**The maintainer's bypass is not automatic — it has to be invoked, and
`gh pr merge` cannot invoke it**, refusing client-side before it asks
GitHub anything:

```text
Pull request is not mergeable: the base branch policy prohibits the merge
```

The merge endpoint applies it server-side, and it is the same endpoint
the merge button asks:

```shell
gh api -X PUT repos/{owner}/{repo}/pulls/<n>/merge \
  -f merge_method=squash -f sha=<the head the checks ran on>
```

**The `sha` is not optional.** Reading the ack and merging are two
calls, and the head is free to move between them — the push that would
move it comes out of the same round the verdict does. Unpinned, the
command takes whatever sits at the head when it runs; pinned, [the
endpoint answers `409` where the head has moved][gh-merge], and a round
lost that way is cheaper than a tree nobody has read reaching `main`.
*The review* above anchors the exchange to a sha and [section 11][s11]
has an ack name one: the pin is that rule reaching the call that
performs the landing.

**Verify what landed rather than trusting the answer**, the signature
[the standard asks for][s-sigs] being a valid one rather than a
particular signer's:

```shell
gh api repos/{owner}/{repo}/commits/main \
  --jq '.commit.verification | {verified, reason}'
```

**What it closed is read again here too, from the landed sha rather
than from the pull request**: [the standard's *What a pull request says
it is*][s-title] has the second read, and why the first alone does not
reach a squash subject composed after it runs.

The forge deletes the head branch itself, per the setting section 11
names. What is still yours is bringing every checkout sitting on `main`
up to date,
that being where the next session starts from and a stale one being where
a branch gets built on a base that has moved. `REPOSITORY.md` carries the
settings and why they are what they are.

[s-what]: https://github.com/btclib-org/.github#what-this-repository-is
[s11]: https://github.com/btclib-org/.github#11-github-settings
[s9]: https://github.com/btclib-org/.github#9-prose-comments-and-docstrings
[s-title]: https://github.com/btclib-org/.github#what-a-pull-request-says-it-is
[s-rev]: https://github.com/btclib-org/.github#review
[s-sigs]: https://github.com/btclib-org/.github#signatures
[gh-merge]: https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request

## This repository in particular

Everything above is the same file in every repository of the
organization; everything below is this one's, and the comparison stops at
this heading.

<!-- These badges report no state: each names a choice the sections below
explain, or a place to go. The README keeps the ones that can turn red. -->
[![calendar versioning: yyyy.m.d](https://img.shields.io/badge/cal_ver-yyyy.m.d-1674b1.svg?logo=calver)](https://calver.org/)
[![type check: mypy](https://img.shields.io/badge/type_check-mypy-yellowgreen.svg?logo=mypy)](https://mypy-lang.org/)
[![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv)
[![format: ruff](https://img.shields.io/badge/format-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/formatter/)
[![lint: ruff](https://img.shields.io/badge/lint-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/)
[![docstrings: ruff](https://img.shields.io/badge/docstrings-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/rules/#pydocstyle-d)
[![lint: markdownlint-cli2](https://img.shields.io/badge/lint-markdownlint--cli2-yellowgreen.svg?logo=markdown)](https://github.com/DavidAnson/markdownlint-cli2)
[![pre-commit enabled](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit)

### The environment and the gates

btclib is managed with [uv](https://docs.astral.sh/uv/), the only tool that
must be installed on the development machine: see the
[uv installation instructions](https://docs.astral.sh/uv/getting-started/installation/).

A virtual environment with btclib (in editable way) and all the development
tools, including those needed to build the documentation, is then created with:

```shell
uv sync
```

**Two dependencies are required and one, the bindings, is the `secp256k1`
extra; every one of them is a floor with no upper bound**, and the absence
of a ceiling is a decision. Which releases those floors name is
`pyproject.toml`, next to the reason each one is where it is: a floor
moves whenever this tree starts calling something newer, so a copy of the
number here would be a second place to remember and the first to go
stale. `typing-extensions` is the backport of what the 3.10 floor does
not have, and its floor is the release adding the latest name this tree
imports from it. The other two are btclib-org projects developed by the
same people, and the bindings' whole purpose is to be the bindings this
library calls, so a breaking change there is coordinated with the release
here —
which is what a version ceiling substitutes for when it cannot be. A
`<0.9` ceiling would cost a btclib
release for every bindings minor, the ones that break nothing included, and
would make a published artifact refuse a version it in fact works with; a
`<1` ceiling constrains nothing, pre-1.0 semver putting the breaking
changes in the minor.

**One is required and the other is an extra, and that was weighed rather
than inherited.** Making `bitcoin-core-rpc` a `fetch` extra was
considered and refused: an optional dependency whose absence changes a
*speed* is a different object from one whose absence removes a
*capability*, and only the first is what an extra is for. The bindings
are the first — btclib answers without them, on a pure-Python arm that
is supported, covered by CI and documented — and nothing stands behind
"ask a node". A caller either has a client or does not have the feature,
so a `fetch` extra would leave `btclib.fetch` importable and unable to
answer, which is the shape an extra exists to avoid.

**Both sibling floors name a release PyPI serves**, so `pyproject.toml` carries
no `[tool.uv.sources]` table and uv resolves the bindings from the index
like anything else: `uv.lock` pins a version and its wheels, every job
passes `--locked`, and `uv sync` downloads rather than compiling
libsecp256k1 in each environment. The floor is then the whole of the
coordination with that sibling, and it carries weight the specifier
alone does not show: `src/btclib/_libsecp256k1.py` imports the bindings'
surface in a single `try` whose `except ImportError` sets
`INSTALLED = False`, so an install that resolves one release short of
what this tree imports does not lose the entry point it is missing — it
loses every delegation, quietly, on to the Python arithmetic that
SECURITY.md publishes as slower and not constant-time. Calling something
new is therefore the same commit that raises the floor in both of its
places, with the reason written beside it.

Calling an entry point merged upstream but not yet released is what a
`[tool.uv.sources]` entry pointing `btclib-secp256k1` at its `main`
branch is for, and it is a state to leave rather than to keep.
`[tool.uv]` is not distribution metadata, so `dependencies` still
publishes a plain floor and PyPI still accepts a release — where a
direct reference written into `dependencies` instead would have to be
written back over before publication, which is what RELEASING.md's step
1 refuses. What the entry costs is the wheels: a git source has none, so
every environment builds the bindings from source, submodule and C
library included, and `uv.lock` pins the resolved commit, so the branch
is followed only when the lock is regenerated. One release upstream
clears it — the source table goes and the floor moves to the version
that carries what is being called.

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
uv run mypy src/btclib tests .github/scripts
uv run pytest
```

or, in one go, with [pre-commit](https://pre-commit.com/):

```shell
uv run pre-commit run --all-files
```

The suite writes nothing: it runs against a read-only checkout, and from an
installed sdist. The one exception is deliberate and has to be asked for.
Several modules compare a dataclass's `to_dict()` against a json file
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

#### The editor

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
| `test` | pull request, push | — |
| `lint`, `docs` | pull request, push | — |
| `integration-bitcoind` | pull request, push, weekly | a node |
| `website` | pull request, push, on website files | — |
| `claude-review` | pull request, and `@claude` in a comment | — |
| `codeql` | pull request, push to main, and weekly | 2 languages |
| `fuzz` | weekly, and by hand before a release | — |
| `scorecard` | weekly, push to main | — |
| `os-ubuntu` | weekly, a release | ubuntu images and interpreters |
| `os-macos` | weekly, a release | macOS images and interpreters |
| `os-windows` | weekly, a release | Windows images and interpreters |
| `deps-latest` | weekly | platforms sampled, deps upgraded |
| `integration-hwi` | weekly, push to main | two device emulators |
| `links`, `mutation` | weekly | — |
| `vendored-vectors` | weekly | upstream's vectors |
| `pypi-install` | weekly, a release | what PyPI serves |
| `py-arm-authority` | weekly, push to main | the arm-authority table |
| `release` | a tag | the workflows `release.yml` names in a `uses:` |

That last cell is a pointer rather than a list on purpose: which
workflows a release calls is read out of the file, where a list here goes
stale the next time one is added or dropped.

```shell
grep -n 'uses: \./\.github/workflows/' .github/workflows/release.yml
```

The `test`, `lint`/`docs` and `integration-bitcoind` rows are what a
merge waits for, and between them they report the required checks: `lint`
and `docs` share a row and report one each. They run one image on one
interpreter: `ubuntu-latest`, and the version `.python-version` names.
`website` is not among them: it carries a `paths` filter, and a required
check that a filtered trigger can skip would block a merge the filter
was meant to let through, which is the workflow's own reason for staying
optional.

Which day each of the rest runs is section 10 of the organization
standard, in `btclib-org/.github`, and not this file's to restate — one
calendar in one place is one thing to keep true, where a copy of it in
every repository would be one more.

Why so little gates is one number: the ceiling GitHub Free puts on an
organization's concurrent jobs, shared across every repository in it.
REPOSITORY.md measures what a wider gate cost against that ceiling,
and the consequence is this table's: at that ceiling a pull request's
wall clock is the wait for a slot rather than the suite. `os-macos.yml` and
`os-windows.yml` each carry the measurement for their own cells, the
queueing and the runner seconds. `codeql` spends against that same
ceiling on every pull request too now, for the OpenSSF Scorecard's
`SAST` check rather than for this table's arithmetic — REPOSITORY.md has
that trade — but it still does not gate the merge, no matrix cell of its
`analyze` job being nameable in the branch rule on its own and the
workflow carrying no aggregate that could be. `zizmor` in `lint` reads
these same workflow files for an injected expression on every pull
request, which is a different question from what `codeql` asks.

The trade, stated here rather than discovered later: the gate does not
refuse a regression on `3.10`, on arm, on PyPy or on a platform. It sits
on `main` until the sentinel for it runs, at most six days.

**What a sentinel varies, it varies whole.** `os-ubuntu` runs the images and
the interpreters the gate leaves alone *and* the cell it spends. A matrix
with the gate's cell cut out of it is one nobody can read the shape of,
and whoever asked what ran would have to re-derive the hole from
`test.yml`.

`os-ubuntu`, `os-macos` and `os-windows` hold the dependencies at the lock and move
the platform; `deps-latest` moves both. Red in one of the three with `deps-latest`
green is that platform; red in both is the upgrade. Every workflow in the
table also takes `workflow_dispatch`, the gates included: a branch whose
pull request is not open yet has no other way to ask, and for the three
platform workflows it is the only way to ask about a branch at all.
`claude-review` and `scorecard` are the exceptions, and take none: both
of `claude-review`'s jobs read the pull request or the comment that
triggered them, so a manual dispatch would start a run with nothing to
read; `scorecard`'s triggers are `ossf/scorecard-action`'s own, whose
README names push and schedule as supported and calls `workflow_dispatch`
experimental.

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

One cell of the matrix `os-ubuntu.yml`, `os-macos.yml` and `os-windows.yml` each
carry. The interpreter is chosen with `--python`, which accepts any of the
ones those workflows list, `3.14t` and `pypy3.11` included, and downloads
it if the machine has none:

```shell
uv run --locked --no-default-groups --group test --python 3.10 pytest --no-cov
```

That one rebuilds `.venv` with the test group alone, which is what breaks
the pre-commit hook until the next `uv sync`: see the note under "The
environment and the gates" above, and `UV_PROJECT_ENVIRONMENT` for
running it without touching `.venv`. The command is what CI runs,
verbatim, and CI has no `.venv` to lose.

`--no-cov` is the matrix asking about the platform and not about the
number: it undoes the `--cov` addopts carries, so what a cell reports is
whether that (os, architecture, interpreter) triple passes. The job below
is where coverage is measured, which is the reason `os-ubuntu.yml` gives and
the other two cite. `deps-latest.yml` does not pass the flag: it runs no PyPy
cell and has no coverage job of its own, so the ratchet meeting an
upgraded coverage.py is one of the things that workflow exists to find
out.

The `(3.14, ubuntu-latest)` cell of those matrices is the gate, and the
job below is it: same image, same interpreter, same suite, and the only
difference is the instrumentation. Reproducing that cell is therefore the
coverage command rather than this one.

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

The `no-bindings` job runs the suite against a btclib that has no
`btclib_secp256k1` to delegate to. CI starts it from an empty
environment; locally `uv run` syncs additively, so a `.venv` any other
command in this section left behind — `uv sync` above included — still
holds the bindings, and the assert below fires on it. `--exact` is what
prunes them back to the one group this job runs with:

```shell
uv sync --exact --no-default-groups --group harness
uv run --locked --no-default-groups --group harness \
    python -c "from btclib._libsecp256k1 import INSTALLED; \
      assert not INSTALLED, 'btclib_secp256k1 is installed'; \
      from btclib.curves import is_libsecp256k1_serving; \
      assert not is_libsecp256k1_serving()"
COVERAGE_FILE=coverage-data-no-bindings \
    uv run --locked --no-default-groups --group harness \
    pytest --cov --cov-fail-under=0
uv sync
```

The closing `uv sync` restores the environment `--exact` just pruned to
`harness` alone, the same restoration the note above makes for any
group-restricted command in this section.

`harness` and not `test`: `test` is `harness` plus `bindings`, and uv's
`--no-group` suppresses a group that was selected rather than one another
group includes, so the split in pyproject.toml is what this job is.
`--group test` in place of `harness` installs the bindings back and runs
the whole suite with them present, reporting it as a passing no-bindings
run with nothing to say it was not one.
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

The `dist` job, which builds the distribution files, checks them and
then installs one. This is the one build there is (issue #1166):
`release.yml`'s `test` job calls this workflow, so a tag runs the very
same job, and its own `publish-testpypi` and `publish-pypi` jobs download
the `dist` artifact this job uploads rather than building a second copy —
so what the checks below judge is what an index ends up serving, byte for
byte. The first two commands after the build do not make two checkouts of
one commit agree: `uv_build` ignores `SOURCE_DATE_EPOCH` and writes the
same fixed metadata into the wheel and the sdist either way, so those two
archives are already byte for byte the same file across checkouts before
either command runs. What the two buy instead is that the published bytes
are this repository's own choice rather than the backend's — the first
pins `mtime` to the commit date, and the second, `normalize_sdist.py`,
rewrites the sdist's member metadata to it — so a rebuild of a released
tag reproduces what was *published* rather than only reproducing itself.
`sha256sum` after them is the digest a rebuild from the tag is compared
against. The two after that read the *members* of the two archives,
which the three checks further down do not: an allowlist of what may be
in a wheel and an sdist, and the bill of materials a release attaches.
That allowlist is stated in prose in
[the package-content policy](./docs/source/package-content-policy.md),
which the suite compares against the script's own constants, so changing
a rule means changing both. Both are written before anything is
installed and uploaded before anything below reads `dist/` — installing
a dependency executes its code, and a compromised one must not reach a
`dist/` that still has to be handed on, so what the publish jobs will
download is frozen before the twine, check-wheel-contents and pyroma
steps below install anything at all. The two smoke tests ask for the
wheel and nothing else, so what pulls btclib-secp256k1 in is the
`Requires-Dist` the wheel carries for the `secp256k1` extra — which they
name on both sides, a wheel installed without it declaring nothing to
resolve. The first pins the lock as constraints, which bind a version
without requesting a package, so a release of the bindings cannot turn a
required check red while the wheel's own metadata still does the work;
the second is unconstrained and release-only, asking instead whether the
*newest* published bindings still satisfy the wheel, which is what a
user installing it resolves — no pull request waits on it, only
`release.yml`'s call sets the input that turns it on. That the bindings
then *serve* is asserted rather than assumed in both: with the extra
resolving to nothing, or to a release this tree cannot import, btclib
falls back to the Python arithmetic and answers the version and the
signature correctly — the supported configuration `no-bindings` runs the
whole suite in — so the assertion is the only thing between that
resolution and a green check. They run from an empty directory, or the
import finds the source tree instead of the wheel:

```shell
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
uv build
uv run --no-project --python 3.14 .github/scripts/normalize_sdist.py dist/
sha256sum dist/*
uv run --no-project --python 3.14 \
    .github/scripts/verify_dist_contents.py dist/
uv run --no-project --python 3.14 .github/scripts/generate_sbom.py dist/ sbom/
uv run --locked --only-group check twine check --strict dist/*
uv run --locked --only-group check check-wheel-contents dist/*.whl
uv run --locked --only-group check pyroma --min 10 dist/*.tar.gz
tmp=$(mktemp -d)
uv export --locked --no-dev --extra secp256k1 --no-emit-project \
    --no-hashes -o "$tmp"/constraints.txt
cd "$tmp" && uv venv &&
    set -- "$OLDPWD"/dist/*.whl &&
    uv pip install --constraints constraints.txt "$1[secp256k1]" &&
    .venv/bin/python -c "import btclib; \
      from btclib.curves import is_libsecp256k1_serving; \
      from btclib.ecc import dsa; \
      from btclib.to_pub_key import pub_keyinfo_from_prv_key; \
      print(btclib.__version__); \
      assert btclib.__version__ != 'unknown'; \
      assert is_libsecp256k1_serving(), \
        'the secp256k1 extra resolved, the bindings do not serve'; \
      assert dsa.verify(b'btclib', pub_keyinfo_from_prv_key(1)[0], \
        dsa.sign(b'btclib', 1))"
cd "$OLDPWD" &&
    uv run --isolated --no-project --with "$(echo dist/*.whl)[secp256k1]" \
    python -c "import btclib; \
      from btclib.curves import is_libsecp256k1_serving; \
      from btclib.ecc import dsa; \
      from btclib.to_pub_key import pub_keyinfo_from_prv_key; \
      print(btclib.__version__); \
      assert btclib.__version__ != 'unknown'; \
      assert is_libsecp256k1_serving(), \
        'the secp256k1 extra resolved, the bindings do not serve'; \
      assert dsa.verify(b'btclib', pub_keyinfo_from_prv_key(1)[0], \
        dsa.sign(b'btclib', 1))"
```

A rehearsal (`workflow_dispatch`) runs one command ahead of the block
above, which the tag path skips: `.github/actions/dev-version` rewrites
`pyproject.toml`'s version with the `.dev<run*100+attempt>` suffix
`release.yml`'s `version-check` job computed and re-locks, so that
`uv build` above ships a version TestPyPI has not already seen. Neither
of the two checks minds — what they judge is metadata syntax, README
rendering, wheel layout and metadata quality, none of which a `.dev<N>`
suffix changes — and both smoke tests do mind, installing the wheel that
suffix names.

The checks `release.yml`'s `version-check` job runs before anything is
built, the first of them being where the tag came from rather than what
it says:

```shell
git merge-base --is-ancestor HEAD origin/main
uv lock --check
uv version --short
```

RELEASING.md's "Rebuild a release from its tag" has the reproducibility
commands above in the order a verifier runs them, with the
`gh attestation verify` that gives the rebuild a verdict and the two
bounds on what that verdict means.

The `deps-latest` workflow, which upgrades every dependency uv resolves before
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
instead of burying it behind a dozen others. That the newest release
then *serves* is asserted before the suite rather than assumed: a release
this tree cannot import leaves btclib on the Python arithmetic, the
suite skipping every `bindings`-marked test, and the run failing on
coverage — which reads as a dependency this tree has not caught up with
rather than as the answer the job was asked for:

```shell
uv lock --upgrade-package btclib-secp256k1
uv run --locked --no-default-groups --group test python -c \
    "from btclib.curves import is_libsecp256k1_serving; \
     assert is_libsecp256k1_serving(), \
       'the newest btclib_secp256k1 does not import'"
uv run --locked --no-default-groups --group test pytest
```

The `pypi-install` workflow, weekly, on demand and as part of a release,
has two jobs, entitled to different answers about what the index
serves.

`install-published` installs btclib itself from PyPI, nothing checked
out, and asks whether it works rather than whether it installs:
`import btclib` runs `__init__.py` alone, and the files under
`src/btclib/*/_data/` — the wordlists among them — are opened by path at the
first call that needs one, not imported, so a wheel missing one would
pass the import and fail only here. This install names no extra, so the
bindings are not asked for and the job is not entitled to assert they
serve — the supported no-bindings configuration of issues #990, #991
and #992. The first two checks below are version-independent, a BIP340
vector and a BIP39 one whose values are fixed forever:

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

`install-published-secp256k1` installs `btclib[secp256k1]` instead,
wheels only for both `btclib` and `btclib-secp256k1`, so a wheel the
index does not have for a platform fails the job rather than falling
back to a source build that answers a different question. Naming the
extra is what entitles it to the assertion the other job cannot make: a
resolution that installs and imports but does not serve — issue #1116,
live on `main` once already — is invisible to a signature check alone,
so this one asks `is_libsecp256k1_serving()` first, and the signature
after it is meaningful because of that:

```shell
python -m pip install --only-binary btclib --only-binary btclib-secp256k1 \
    "btclib[secp256k1]"
python -c "import btclib; \
    from btclib.curves import is_libsecp256k1_serving; \
    from btclib.ecc import dsa; \
    from btclib.to_pub_key import pub_keyinfo_from_prv_key; \
    assert is_libsecp256k1_serving(), \
      'the secp256k1 extra resolved, the bindings do not serve'; \
    assert dsa.verify(b'btclib', pub_keyinfo_from_prv_key(1)[0], \
      dsa.sign(b'btclib', 1))"
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
`engine.toml` in place of it is the consensus profile, minutes of cpu
against hours; the parser profile is the one that finishes fastest. Each
configuration carries its own arithmetic — `cosmic-ray baseline` reports
the mutant count and the cpu cost for whichever one is run, rather than a
figure fixed here that the source can grow past. The report is
`--surviving-only`, which is the whole of what anybody acts on: a killed
mutant is the suite doing its job, and printing every one of them buries
the handful that are not.

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

The `integration-bitcoind` workflow, which gates and is the exception here: it runs
on every pull request, on every push to `main` and before a release, and
`Regtest against Bitcoin Core` is required on `main`. It runs weekly too,
and that workflow's own header says what the weekly run asks that the
others do not: it pins one Core release, so the tree is not the question a
schedule puts to it -- whether bitcoincore.org still serves that release
is. It asks the one question the rest of CI cannot, whether Bitcoin Core
accepts what btclib built. It downloads a pinned Core release, verifies
its published sha256, and runs the tests `tests/README.md` documents with
the binary named rather than found on PATH:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_BITCOIND=/path/to/bitcoind \
    uv run --locked --no-default-groups --group test \
    pytest tests/integration --junitxml=integration.xml
```

A step after it reads that report and fails the job if a regtest test
skipped: pytest exits 0 for a module that skipped itself, so a job whose
fixture stopped finding the node would stay green while asking Core
nothing. The HWI tests skip there by design and are not counted; they are
`integration-hwi.yml`'s, a workflow of its own rather than a second job
here.

`HWI against a Trezor emulator` is the first of its two jobs, and it
gates nothing: it downloads a pinned emulator binary from
`data.trezor.io` beside the same node, checks its sha256, installs a
pinned HWI in an interpreter of its own — HWI declares `^3.9,<3.13`, and
`src/btclib/hwi.py` says why it is a program here rather than a dependency —
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
`gh workflow run integration-hwi.yml --ref <branch>`, which is how a
branch touching `src/btclib/hwi.py` is checked before it lands.

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
reference, so write it in double backticks. `-n` is what turns an
unresolved cross-reference — a renamed class in a `:class:` role, a moved
function — into a warning for `-W` to fail the build on, rather than a
link that resolves to nothing on a green build; `conf.py`'s
`intersphinx_mapping` is what it resolves the standard library against,
and its `nitpick_ignore` carries the entries that reason cannot reach,
each with the reason beside it:

```shell
uv run --locked --no-default-groups --group docs \
    sphinx-build -n -W --keep-going -b html docs/source docs/build/html
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
GitHub's runners are where it happens. It runs on every pull request now,
alongside `push` to `main` and its weekly schedule, so its findings reach
a branch before a merge rather than only after one; `REPOSITORY.md` has
why it is still not a required check.

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
  drop that list's `src/` and `pyproject.toml` entries and
  `btclib.org/pyproject.toml` and `btclib.org/src/btclib/alias.py` answer
  with their own contents. A new top-level file is published by default;
  add it to `exclude:` if it should not be.
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
triggers the whole gate; `test.yml`'s `push` trigger carries a
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

### Breaking a caller is not an argument

**A refactoring that is reasonable gets made, however much it breaks.**
Do not weigh "this renames something callers use" against it, and do not
propose keeping an inconsistency and gating it going forward instead:
consistency across a family — one naming shape, one contract per prefix,
one way to read the same kind of answer — is itself the reason, and a
release is where a break is reported rather than a reason not to make it.

So a census that finds thirty names of one shape and six of another has
found six to change, not a trade-off to price. What the measurement is
for is knowing the blast radius and writing RELEASE_NOTES.md's
breaking-changes entry, which is how a user is told: read
[RELEASE_NOTES.md](./RELEASE_NOTES.md) for what that entry looks like,
and note that `v2026.9`'s list is long on purpose.

The one thing this does not license is a break nobody can act on. An
entry says the old spelling, the new one, and what a caller does about
it; a rename with no note is the defect, not the rename.

### The public surface

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
`src/btclib/__init__.py`. A module added to `src/btclib/` is added there
too, and the suite says so — the list is written out rather than discovered,
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
caller may legitimately hold. `tests/curve_parameter_test.py` drives
the same rules over a parameter that carries a *default*: reaching one
means every argument in front of it has to be valid, which is the table
of valid values the automatic walk exists to do without, so `ec` is
driven from a table there as `hf` and `network` are driven where their
own checks live. None of these test files has an exemption list, which is
the state to keep: a finding is a red test, to be fixed or to be given a
reason of its own beside the two families that have one.

**A `bool` parameter is a kind or a truth, and only the first is
type-checked.** A flag that decides *what is computed* refuses a non-bool,
`musig2._flag` stating the reason: a kind written down and read back — json,
a configuration file, a coordinator's message — arrives as whatever it was
written as, and `"false"` is true, so `KeyGroup(verify=)` would compute
every address of the other script rather than raise. A flag that decides
only *whether a check runs* is read for its truth: `check_validity` and
`slip132`'s `check_root_xkey` either run a check or skip one, and neither
changes an answer. `tests/check_validity_test.py` owns that convention.

**A truth's `True` has to be its conservative value**, which is the second
half of the same rule and the one issue #884 asked for. Every wrong value
is true, so the misreading is never "the flag was off": it is always the
one the flag's `True` stands for. That is what makes a truth safe —
`verify_checksum="no"` checks the checksum, `strict="no"` is strict,
`forbid_zero_size="no"` forbids — and it is a fact about the *name*, not
about the check. So a flag whose `True` is the permissive value is a kind
however little it computes, because the misreading waives the very refusal
it was written to make: `verified` suppressing the script engine's NULLFAIL
is the sharp one, with `allow_partial` accepting an input nobody signed and
`hybrid` parsing the prefixes it was written to keep out. `verify_script`'s
`final` beside `verified` is the contrast that shows the rule is about
direction and not about the engine: it demands a true stack, so a non-bool
there fails a script rather than passing one.

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

- `assert_*` refuses and returns `None`, and is the reason half of the
  pair above.
- `is_*` answers a `bool` about a value, and is total over the declared
  types: `is_p2sh` is False for bytes that are not a p2sh script.
- `verify*` answers a `bool` about a signature or a proof, on the same
  terms. `assert_as_valid` beside it says why.
- `check_*` answers a `bool` **and refuses what cannot be an answer** --
  the one prefix that warns a caller it still needs an `except`:
  `script.engine.script.check_pub_key`, where a wrong length is
  False but a hybrid prefix under STRICTENC is the offence itself, which
  is how Core's `CheckPubKeyEncoding` splits it — and
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
alternative is renaming a keyword across every public signature that
carries it, for a reading nobody has to make twice.

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

Prepared is not unchecked, and a bare `int` the trailing underscore takes
instead of an `Integer` still refuses a `bool`: `utils.is_integer` is the
policy `int_from_integer` carries for every coerced parameter, and the
underscore spelling asks it of what it is handed already prepared rather
than skipping it -- `ssa.challenge_`'s `x_Q` and `x_K`, and
`dsa.recover_pub_key_`'s `key_id`, both pinned in
`tests/integer_policy_test.py`'s census (issue #1248).

The exception is a boundary at which nothing can be invalid, and it is
named rather than passed over: where a class's invariants are exactly the
widths of its fields, the decoding enforces them by construction and the
check is unreachable by design rather than missing. `src/btclib/utils.py`'s
docstring is where that rule is written down, `OutPoint` and `TxIn` being
the classes it holds for.

### A `_var` suffix means the operand decides the work

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
would otherwise take it: most of the library's own call graph, public
functions included, right down to `hex_string`, `ripemd160` and
`p2pkh` — a suffix on the library, saying nothing. Two things break
the chain, and both are facts about the caller rather than about the
callee. Blinding is one: `mult` calls
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

### Prose in this tree

[Section 9 of the standard][s9] is the whole of the prose style, and
*Documentation and comments* above says why it is not restated. What
follows is what this tree adds to it, and it holds for docstrings,
comments, the sphinx pages and a pull request reply alike.

**Most readers of a docstring here are new to btclib: write for them.**

**A table of measured timings belongs in the CHANGELOG, not in a
docstring.** *Measure, don't assert* wants the command beside the
number, and a timing is the one figure that has none here: the
benchmarks are their own repository, and no gate re-measures — a timing
gate on a shared runner is a flake. What is left to do instead is put it
where it is read as what it is. A docstring is read as a statement about
the code as it stands, so a figure in one is a claim about now; a
CHANGELOG entry is read as the history of a release, and calendar
versioning puts the release day in the heading over it once the release
is cut. So the docstring keeps the number that carries the *reason*, the
one a reader needs to follow the decision — "half of what a signature
costs", "twice as fast, flat in n, no crossover" — and the matrix per
size or per caller goes in the entry that took it. Two figures were
found stale in one week by the branch standing on them, and neither
would have been noticed otherwise (issue #940).

### Every change starts with an issue

Open one before the pull request, however small the change is. The
standard's *What a pull request says it is* has what the title and the
description then do with it.

A security vulnerability is the exception and does not go in the tracker
at all. [SECURITY.md](./SECURITY.md) is what to follow instead: it asks
for a private advisory, or for an email if you would rather not open one.

### What a squash writes here

What the landing commit says is a repository setting and not a decision
made once per pull request, so there is one place to read it from:

```shell
gh api repos/btclib-org/btclib --jq \
  '{t: .squash_merge_commit_title, m: .squash_merge_commit_message}'
# {"t": "COMMIT_OR_PR_TITLE", "m": "COMMIT_MESSAGES"}
```

A branch of one commit therefore lands under that commit's own subject, a
branch of several under the pull request's title with its number, and the
body is the branch's commit messages either way — never the pull
request's body, which stays on the pull request. A squash made by hand
follows the same convention, the setting being the statement of what the
message should say rather than only of what a press produces.
REPOSITORY.md has what the other two merge methods would have cost.
