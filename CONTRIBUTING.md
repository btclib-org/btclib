# How to contribute to btclib

Thank you for investing your time in contributing to our project.
We are glad you are reading this, because we need volunteer developers
to help this project come to fruition.

If you haven't already:

- see the [README](./README.md) file to get an overview of the project
- read our [Code of Conduct](./CODE_OF_CONDUCT.md) to keep our community approachable and respectable
- come find us on [Slack](https://bbt-training.slack.com/archives/C01CCJ85AES).

In this guide you will get an overview of the contribution workflow from opening an issue, creating a PR, reviewing, and merging the PR.

## New contributor guide

Here are some resources to help you get started with open source contributions:

- [Finding ways to contribute to open source on GitHub](https://docs.github.com/en/get-started/exploring-projects-on-github/finding-ways-to-contribute-to-open-source-on-github)
- [Set up Git](https://docs.github.com/en/get-started/quickstart/set-up-git)
- [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Collaborating with pull requests](https://docs.github.com/en/github/collaborating-with-pull-requests)

## Getting started

Development tools are required to develop and test btclib;
they can be installed with:

    python -m pip install --upgrade -r requirements-dev.txt

Developers might also consider installing btclib in editable way:

    python -m pip install --upgrade -e ./

Finally, additional packages are needed to build the documentation:

    python -m pip install --upgrade -r docs/requirements.txt

As an annotated python project, btclib is very strict on code formatting
([isort](https://pycqa.github.io/isort/),
[black](https://github.com/psf/black),
[pylint](https://pylint.pycqa.org/en/latest/),
[bandit](https://github.com/PyCQA/bandit),
[flake8](https://flake8.pycqa.org/en/latest/),
and [check-manifest](https://pypi.org/project/check-manifest/))
and proper type definition
([mypy](https://mypy-lang.org/)):
warnings are not tolerated and should be taken care of.
This might be annoying at first, but enforcing formatting rules can be done
easily once you're finished with coding or, even better, automatically
taken care of while coding, especially if you properly setup your development environment.
Type definition improves code readability and helps in spotting bugs.

Moreover, [unit tests](https://github.com/pytest-dev/pytest/) must pass at any time with 100% [coverage](https://coverage.readthedocs.io/) of both the
library and the test suite.

These requirements are easily checked (and partially fixed) if you test
the impact of your contribution with [tox](https://tox.wiki/).

We also like the contribution of [sourcery](https://sourcery.ai/): you might too.

Finally, even when it comes to mark-down (*.md files),
please use [markdownlint](https://github.com/DavidAnson/markdownlint).

\[To do: document how to do it in VS Code\]

### Issues

#### Create a new issue

Did you find a bug?
*Do not open up a GitHub issue if the bug is a security vulnerability*,
and instead refer to our [security policy](README.md).

For any other problem,
[search](https://docs.github.com/en/github/searching-for-information-on-github/searching-on-github/searching-issues-and-pull-requests)
first if an [issue](https://github.com/btclib-org/btclib/issues) (or a [fixing pull request](https://github.com/btclib-org/btclib/pulls), also known as a PR) already exists.
If a related issue/PR does not exist,
please open a new issue.

#### Solve an issue

Scan through our [existing issues](https://github.com/btclib-org/btclib/issues) to find one that interests you. As a general rule, we don’t assign issues to anyone. If you find an issue to work on, you are welcome to open a PR with a fix.

### Make Changes

Work locally on your fork of btclib,
until you are satisfied. Ensure that tox has no issue
with your modified codebase.

### Commit your update

Commit the changes to your fork once you are happy with them.

### Pull Request

When you're finished with the changes, create a pull request (PR).

- Don't forget to
[link PR to issue](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue)
if you are solving one.
- Enable the checkbox to
[allow maintainer edits](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/allowing-changes-to-a-pull-request-branch-created-from-a-fork) so the branch can be updated for a merge.
Once you submit your PR, team members will review your proposal.
We may ask questions or request additional information.
- We may ask for changes to be made before a PR can be merged, either using
[suggested changes](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/incorporating-feedback-in-your-pull-request)
or pull request comments.
You can apply suggested changes directly through the UI.
You can make any other changes in your fork, then commit them to your branch.
- [Sourcery](https://sourcery.ai/) might suggest changes, please accept them.
- As you update your PR and apply changes, mark each conversation as
[resolved](https://docs.github.com/en/github/collaborating-with-issues-and-pull-requests/commenting-on-a-pull-request#resolving-conversations).
- If you run into any merge issues, checkout this
[git tutorial](https://github.com/skills/resolve-merge-conflicts)
to help you resolve merge conflicts and other issues.

### Your PR is merged

Congratulations :tada::tada: The btclib team thanks you :sparkles:.

Once your PR is merged, your contributions will be publicly visible on the
[contributors page](https://github.com/btclib-org/btclib/graphs/contributors).
