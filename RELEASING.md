# Releasing btclib

Releases are published by GitHub Actions
([release.yml](.github/workflows/release.yml)), not from a developer
machine. Pushing a `v<version>` tag runs the full test matrix, builds
and checks the distribution files, publishes them to PyPI, and creates
the GitHub release. There is no PyPI token anywhere: both indices are
configured to trust the workflow itself
([Trusted Publishing](https://docs.pypi.org/trusted-publishers/)).

The same workflow, started by hand instead of by a tag, is a full
rehearsal against TestPyPI. A rehearsal is never tagged.

## One-time setup

Already done for btclib-org/btclib; kept here for the record.

1. On [PyPI](https://pypi.org/manage/project/btclib/settings/publishing/),
   add a trusted publisher: owner `btclib-org`, repository `btclib`,
   workflow `release.yml`, environment `pypi`.

1. On [TestPyPI](https://test.pypi.org/), add the same trusted
   publisher, with environment `testpypi`.

1. In the GitHub repository settings, create the `pypi` and `testpypi`
   environments. Protect `pypi`: restrict it to `v*` tags and, if
   desired, add required reviewers so a release waits for a human
   approval before uploading.

## Rehearse on TestPyPI

A rehearsal runs the identical pipeline — test matrix, version checks,
check-manifest, pyroma, build, wheel smoke test — and publishes to
[TestPyPI](https://test.pypi.org/project/btclib/) instead of PyPI.

1. On GitHub, Actions → release → Run workflow, and pick the branch to
   rehearse (usually `dev`).

1. The workflow appends `.dev<run number>` to the version, so every
   rehearsal is unique on TestPyPI and sorts before the release it
   rehearses. Re-running a finished rehearsal would reuse its run
   number and be refused by TestPyPI: dispatch a fresh run instead.

1. Check the upload on <https://test.pypi.org/project/btclib/>, and
   optionally install it (its dependencies come from the real PyPI):

   ```shell
   uv run --isolated --no-project \
     --index https://test.pypi.org/simple/ \
     --index-strategy unsafe-best-match \
     --with btclib==<version>.dev<run number> \
     python -c "import btclib; print(btclib.__version__)"
   ```

## Release to PyPI

1. Make sure the released btclib_libsecp256k1 satisfies the pin in
   pyproject.toml. Development tracks the bindings' dev branch
   (`tool.uv.sources`), but the published btclib resolves them from
   PyPI: if the pin is only satisfied by an unreleased version, release
   the bindings first. The wheel smoke test fails exactly on this, so a
   rehearsal catches it.

1. Set the release version (calendar versioning, `YYYY.M.D`) in
   btclib/\_\_init\_\_.py and docs/source/conf.py — the workflow fails
   if the two disagree, or if either disagrees with the tag.

1. Retitle the "work in progress" section of HISTORY.md as
   `## v<version>` and make sure it covers every major change: the
   workflow lifts the GitHub release notes from that section.

1. Run `uv run pre-commit run --all-files` and `uv run pytest`, follow
   docs/README.rst to check that the documentation builds, and get the
   above onto master through the usual pull request. Verify the
   [read the docs](https://readthedocs.org/projects/btclib/builds/)
   build, and that [the website](https://btclib.org) and the
   [documentation](https://btclib.readthedocs.io/en/latest/) render
   correctly.

1. Rehearse on TestPyPI (see above) from master.

1. Tag the release commit and push the tag:

   ```shell
   git tag -a v2023.8 -m "release v2023.8"
   git push origin v2023.8
   ```

1. The workflow does the rest: full matrix, build and checks, PyPI
   upload, and the GitHub release with the distribution files attached
   and the HISTORY.md section as its body. Give the release notes a
   read once it lands.

1. Open the next cycle: set a generic next version without the day
   (e.g. after 2023.8.4, use 2023.9) in btclib/\_\_init\_\_.py and
   docs/source/conf.py, and start a new "work in progress" section in
   HISTORY.md.

## If something goes wrong

- The workflow failed before the `publish-pypi` job: nothing was
  uploaded. Delete the tag, fix, and tag again:

  ```shell
  git tag -d v2023.8
  git push origin :refs/tags/v2023.8
  ```

- The upload succeeded but the release is broken: PyPI never accepts a
  file name twice, even after deletion. Yank the bad release on PyPI
  and publish a new patch version (`2023.8` → `2023.8.1`).

- Only the `github-release` job failed: the PyPI upload is already
  done; re-run the failed job, or create the release by hand from the
  `dist` artifact of the run.
