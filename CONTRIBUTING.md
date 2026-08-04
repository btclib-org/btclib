# How to contribute to btclib

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

Development tracks the
[btclib_libsecp256k1](https://github.com/btclib-org/btclib_libsecp256k1)
bindings under development, not the released ones: see tool.uv.sources in
pyproject.toml. They are compiled from source, so a C toolchain is required
(cmake comes as a build dependency); the released btclib keeps depending on
the plain btclib_libsecp256k1 wheels from PyPI.

**The declared dependency is `btclib_libsecp256k1>=0.7.1rc1`, with no
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

The lower bound names a release candidate, and that is what makes
prereleases of that package eligible at all: PEP 440 has pip exclude them
unless the specifier itself names one, and uv's default strategy is the
same. A resolver still prefers a stable release among the candidates, so
the rc is installed only while nothing stable satisfies the bound — the day
a final `0.7.1` is published, `>=0.7.1rc1` resolves to it with no edit
here.

**`pip install -e .` does not work here, and the error will not say why.**
tool.uv.sources is uv-only metadata: pip does not read it, so it resolves
btclib_libsecp256k1 from PyPI, where the newest release is older than the
`>=0.7.1rc1` this project pins. The constraint is satisfiable only from
git, so pip reports an unsatisfiable requirement and nothing points at the
table that would have satisfied it. Use `uv sync`. If you need a
pip-installed tree anyway, install the bindings from git yourself and then
the project without its dependencies:

```shell
pip install git+https://github.com/btclib-org/btclib_libsecp256k1@dev
pip install -e . --no-deps
```

Read the docs hits this same wall, which is why `.readthedocs.yaml` drives
uv rather than pip.

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
runs" below, that leaves an environment of 15 packages where `uv sync`
leaves 84, and pre-commit is not among them. The git hook pre-commit
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
the reason beside it. `pytest --cov` prints the total on every run, on
the 3.14 the gate is checked on.
See [Tests, code coverage, and profiling](./tests/README.md).

These requirements are easily checked (and partially fixed) with:

```shell
uv run ruff check --fix
uv run ruff format
uv run mypy btclib tests
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

\[To do: document how to do it in VS Code\]

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

### Reproducing what CI runs

Every job of every workflow is a `uv` command, and `uv` fetches what it
needs: no interpreter, no linter, no packaging tool has to be installed by
hand, and even the `cmake` that builds the bindings arrives as a build
requirement.

The `Lint and type-check` job of the `lint` workflow, in full — the same
pre-commit the lock pins, which is what `uv run` above gives you too:

```shell
uv run --locked --only-group lint \
    pre-commit run --all-files --show-diff-on-failure
```

That workflow has a second job, `Build the documentation`, whose command is
the one below under "The documentation".

One cell of the `test-py` matrix. The interpreter is chosen with
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

The `coverage-py` job, gated by `fail_under` in pyproject.toml:

```shell
uv run --locked --no-default-groups --group test \
    pytest --cov=btclib --cov=tests
```

The `dist-py` job, which inspects what would be published:

```shell
uv build
uv run --locked --only-group build twine check --strict dist/*
uv run --locked --only-group build check-wheel-contents dist/*.whl
uv run --locked --only-group build pyroma --min 10 dist/*.tar.gz
```

The checks the `release` workflow runs before building anything:

```shell
uv lock --check
uv version --short
```

The `published` workflow, which resolves btclib_libsecp256k1 from PyPI by
the declared pin instead of following `tool.uv.sources`. It therefore
cannot pass `--locked`, and it rewrites uv.lock: restore that with
`git checkout uv.lock` before committing.

```shell
uv run --no-sources --no-default-groups --group test pytest
```

The `latest` workflow, which upgrades every dependency uv resolves before
running the suite, the lint gate and the packaging checks. The upgrade
rewrites uv.lock, and here too `git checkout uv.lock` restores it; the
commands after it are the ones already listed above, so only the first is
worth repeating:

```shell
uv lock --upgrade
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
caused. Scoped to the consensus code — `btclib/script/engine/` and
`btclib/script/sig_hash.py` — by the two configurations under
`.github/mutation/`, which is also what a local run reads, so there is one
statement of what is mutated and what judges it:

```shell
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray baseline .github/mutation/sig_hash.toml
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray init .github/mutation/sig_hash.toml sig_hash.sqlite
uv run --locked --no-default-groups --group test --group mutation \
    cosmic-ray exec .github/mutation/sig_hash.toml sig_hash.sqlite
uv run --locked --no-default-groups --group test --group mutation \
    cr-report --surviving-only --show-diff sig_hash.sqlite
```

`baseline` first, always: it runs the configured test command against the
unmutated tree, and without it a stale path or a renamed test file fails
every mutant identically and the session reports a perfect kill rate,
which is the one failure mode of a mutation run that looks like good news.
`engine.toml` in place of `sig_hash.toml` is the other scope, at 2768
mutants against 727 and five and a half hours against half an hour of cpu;
each configuration says what its own arithmetic is. The report is
`--surviving-only`, which is the whole of what anybody acts on: a killed
mutant is the suite doing its job, and printing all 727 of them buries the
dozen that are not.

Three things to know before starting one. The session mutates the source
file in place and restores it afterwards, so nothing else may read the
tree while it runs — no second session, no `pytest` in another shell, and
a `git status` in the middle is a working tree with a mutant in it.
`exec` is resumable, running whatever the session still has pending, so
interrupting one costs only the mutant it was on. And the `.sqlite`
sessions are the artifact the workflow uploads: `cr-report`, `cr-html` and
`cr-rate` all read one, and a downloaded one can be finished locally.

The documentation, which the `Build the documentation` job of `lint.yml`
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

The only check with no local equivalent is CodeQL, which GitHub runs on
its side; its findings appear under the Security tab.

### The website

**btclib.org is this repository.** GitHub Pages serves it from `master`'s
root, so a set of files at the top level are website sources rather than
Jekyll leftovers, which is the opposite of the natural first assumption:

```shell
gh api repos/btclib-org/btclib/pages
# {"cname": "btclib.org", "build_type": "legacy",
#  "source": {"branch": "master", "path": "/"}}
```

What that makes live:

| file | role |
| --- | --- |
| `README.md` | **the homepage**: there is no `index.md` |
| `_config.yml` | the site title, description, logo, theme and exclude list |
| `_layouts/default.html` | the page template, header and footer |
| `assets/` | the logo, the stylesheet and `scale.fix.js` |
| `CNAME` | the custom domain; Pages reads it from the built site |
| `Gemfile` | the `github-pages` gem, for a local `bundle exec jekyll serve` |

Three consequences worth knowing before editing any of them:

- **every README edit is a website deploy.** The README is also the PyPI
  long description, so a typo in it is visible in three places: GitHub,
  btclib.org and the PyPI project page.
- **every other file in master's root is a URL under btclib.org** unless
  `_config.yml`'s `exclude:` says otherwise, the library itself included:
  drop that list's `btclib/` and `pyproject.toml` entries and
  `btclib.org/pyproject.toml` and `btclib.org/btclib/alias.py` answer with
  their own contents. A new top-level file is published by default; add it
  to `exclude:` if it should not be.
- **the build is the classic Pages builder** (`build_type: legacy`), so
  there are no build logs and no control over the Jekyll or theme version.
  A broken template fails silently: the layout served
  `<script src="/%20/assets/js/scale.fix.js">` for as long as it took
  someone to fetch the page and read the HTML.

Because Pages serves from `master`, a website-only commit there also
triggers the full test matrix; `test.yml`'s `push` trigger carries a
`paths-ignore` for these files so that it does not. The `pull_request`
trigger deliberately does not: those checks are required on `master`, and a
required check that produces no run blocks the merge.

To preview locally, with Ruby and Bundler installed:

```shell
bundle install
bundle exec jekyll serve
```

That is the one part of this project not driven by `uv`, and it is only a
preview: what btclib.org serves is whatever the classic builder makes of
`master`.

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

#### Documentation and comments

What "satisfied" means for the prose — docstrings, comments, the
sphinx pages, a pull request reply — is written down here, because a
hook can check that a docstring exists but not what it says.

**Tone of voice: neutral, factual, dry.** The same register
everywhere: no wit, no salesmanship, no emphasis where the fact is
enough. Explanatory detail is wanted; decoration is not.

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

Commit the changes to your fork once you are happy with them.

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

### Your PR is merged

Congratulations :tada::tada: The btclib team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the
[contributors page](https://github.com/btclib-org/btclib/graphs/contributors).
