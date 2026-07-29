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

<!-- markdown-link-check-disable -->

- [Finding ways to contribute to open source on GitHub](https://docs.github.com/en/get-started/exploring-projects-on-github/finding-ways-to-contribute-to-open-source-on-github)
- [Set up Git](https://docs.github.com/en/get-started/quickstart/set-up-git)
- [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Collaborating with pull requests](https://docs.github.com/en/github/collaborating-with-pull-requests)

<!-- markdown-link-check-enable -->

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

Every command is run inside that environment prefixing it with `uv run`
(e.g., `uv run pytest`); alternatively, activate the environment once with
`source .venv/bin/activate` (`.venv\Scripts\activate` on Windows).

The dependency groups defined in pyproject.toml can also be installed
individually, e.g. `uv sync --no-default-groups --group test`.

As an annotated python3 project, btclib is very strict on code formatting
and linting
([ruff](https://docs.astral.sh/ruff/),
which replaces autoflake, bandit, black, docformatter, flake8, isort,
pydocstyle, pylint, pyupgrade, and yesqa;
and [sourcery](https://pypi.org/project/sourcery-cli/))
and proper type definition
([mypy](https://mypy-lang.org/)):
warnings are not tolerated and should be taken care of.
This might be annoying at first, but enforcing formatting rules can be done
easily once you're finished with coding or, even better, automatically
taken care of while coding if you configure your development environment.
Type definition improves code readability and helps in spotting bugs.

Moreover,
the [pytest](https://pytest.org) unit tests
must pass at any time with
100% [coverage](https://coverage.readthedocs.io/)
of both the library and the test suite.
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

Finally, even when it comes to mark-down (i.e., *.md files),
please use [markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2).

\[To do: document how to do it in VS Code\]

### Issues

#### Create a new issue

Did you find a bug?
*Do not open up a GitHub issue if the bug is a security vulnerability*,
and instead refer to our [security policy](README.md).

<!-- markdown-link-check-disable -->

For any other problem,
[search](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests)
first if an
<!-- markdown-link-check-enable -->
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

### Commit your update

Commit the changes to your fork once you are happy with them.

### Pull Request

When you're finished with the changes, create a pull request (PR).

<!-- markdown-link-check-disable -->
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
<!-- markdown-link-check-enable -->

### Your PR is merged

Congratulations :tada::tada: The btclib team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the
[contributors page](https://github.com/btclib-org/btclib/graphs/contributors).
