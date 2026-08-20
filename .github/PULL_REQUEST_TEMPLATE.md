<!-- markdownlint-disable-next-line first-line-heading -->
## What this changes

<!-- What the code does now that it did not do before, and why.
     Link the issue it closes, if there is one: "Closes #123". -->

## How it was verified

<!-- The test that covers it, the vector it reproduces, the command you
     ran. New behaviour without a test is the usual reason a pull request
     waits: the suite is expected to keep its coverage (see
     tool.coverage.report in pyproject.toml). -->

## Checks

<!-- CI runs all of this, and rejects the pull request if any of it fails:
     the point of running it locally is not to wait for CI to tell you. -->

- [ ] `uv run pre-commit run --all-files` is clean (ruff, mypy strict,
      markdownlint, the copyright notice, `uv.lock`)
- [ ] `uv run pytest` passes
- [ ] `CHANGELOG.md` has an entry, if a user would notice the change;
      `RELEASE_NOTES.md` too, if it is one a user has to act on

## Anything the reviewer should know

<!-- A decision you are unsure of, an alternative you rejected, a
     specification that is ambiguous, a follow-up you left out on
     purpose. Delete the section if there is none. -->
