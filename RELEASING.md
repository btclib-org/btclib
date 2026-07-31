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
   environments. Both require a review from `fametrano`, so neither
   index is uploaded to without a human approving that run; the two
   `publish-*` jobs are the only holders of `id-token: write`, and this
   is the gate in front of them. `pypi` is additionally restricted to
   `v*` tags, which is the only ref its job runs on anyway — the
   restriction is what makes that true of the environment and not just
   of an `if:` in a file a pull request could change.

   Self-review stays allowed on purpose: the maintainer who pushes the
   tag is the reviewer, and forbidding it would deadlock a one-maintainer
   release. The approval is a confirmation step, not a second pair of
   eyes; it becomes one as soon as there is a second reviewer to add.

## Rehearse on TestPyPI

A rehearsal runs the identical pipeline — lint gate, test matrix, the
packaging checks of the `dist-py` job (twine, check-wheel-contents,
pyroma), build, wheel smoke test — and publishes to
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
   pyproject.toml, the only place it is declared, and re-lock (the
   `uv-lock` pre-commit hook does it, uv.lock carrying the project
   version too). btclib.\_\_version\_\_ reads it back from the installed
   metadata and docs/source/conf.py reads it from the file, so there is
   nothing else to keep in step; the workflow fails if it disagrees with
   the tag, or if uv.lock was not re-locked. It also refuses a version
   that is not final: a tag is the trigger that publishes to PyPI itself,
   so an `rc`, a `.dev` or a `.post` reaching it would burn a real
   version. Trial runs go to TestPyPI through workflow_dispatch, above,
   and are never tagged.

1. Retitle the "work in progress" section of **both** HISTORY.md and
   CHANGELOG.md as `## v<version>`. The workflow lifts the GitHub
   release notes from HISTORY.md's section alone, so that one has to
   read as the release notes it becomes; CHANGELOG.md is the detail it
   points at, and the two are retitled together or the link goes
   nowhere. `version-check` refuses a tag whose heading still carries
   anything after the version, in either file, or whose section is
   empty: the extraction matches `## v<version>` followed by a space
   too, so an unretitled HISTORY.md would have published "work in
   progress, not released yet" as the release notes. A rehearsal is
   exempt, being what runs before this step.

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
   git tag -a v2026.8 -m "release v2026.8"
   git push origin v2026.8
   ```

1. The workflow does the rest: full matrix, build and checks, PyPI
   upload, and the GitHub release with the distribution files attached
   and the HISTORY.md section as its body. Give the release notes a
   read once it lands.

1. Open the next cycle: set a generic next version without the day
   (e.g. after 2026.8.4, use 2026.9) in pyproject.toml, and start a new
   "work in progress" section in HISTORY.md and CHANGELOG.md.

## If something goes wrong

- The workflow failed before the `publish-pypi` job: nothing was
  uploaded. Delete the tag, fix, and tag again:

  ```shell
  git tag -d v2026.8
  git push origin :refs/tags/v2026.8
  ```

- The upload succeeded but the release is broken: PyPI never accepts a
  file name twice, even after deletion. Yank the bad release on PyPI
  and publish a new patch version (`2026.8` → `2026.8.1`).

- Only the `github-release` job failed: the PyPI upload is already
  done; re-run the failed job, or create the release by hand from the
  `dist` artifact of the run.
