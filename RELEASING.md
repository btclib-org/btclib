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

**A workflow GitHub has not registered cannot be dispatched, and it
registers one only once its file has reached the default branch.** That
makes `release.yml`, `latest.yml`, `published.yml`, `macos.yml` and
`windows.yml` — `schedule` and `workflow_dispatch` only, so nothing else
ever triggers them — answer `gh: Not Found (HTTP 404)` until the release
pull request is merged. It bites once, on the first release after any of
them is written, and it inverts the order below: the TestPyPI rehearsal
and the `latest` run that this file asks for *before* the merge can only
happen after it, still before the tag. It also means such a workflow
reaches `main` having never run, which is how `published.yml` shipped a
`windows-11-arm` cell that failed at setup.

## Which version string is which

Telling these apart is most of what can go wrong when cutting a release.

- **`pyproject.toml`'s own `version`** takes three shapes over one
  cycle, never two at once: `2026.8`, month only, between releases —
  the placeholder "Open the next cycle" sets, so a checkout of `main`
  reports itself as work in progress rather than as a release it is
  not; `2026.8.4`, with the day added on release day — calendar
  versioning, `YYYY.M.D` — which is what gets published and the only
  value `btclib.__version__` reads back from installed metadata; and
  `2026.8.4.1`, a fourth number added only if `2026.8.4` shipped broken
  and cannot be reuploaded (see "If something goes wrong"). All three
  are typed by hand. Three components is always the release day; four
  is always a patch on it. The day is never dropped in favor of a
  fourth digit standing in for it, which is what would make the two
  indistinguishable — and `version-check` refuses a tag on the
  placeholder shape for exactly that reason: two components reach the
  check and nothing past it, whichever one is declared. It does not
  tell three apart from four, both being a release it accepts
- **`v2026.8.4`**, the tag, carries no version of its own: it picks the
  index, PyPI rather than TestPyPI, and `version-check` exists to
  confirm it says what `pyproject.toml` says
- **`2026.8.4.dev7`** is a rehearsal, and nobody types it either half at
  a time: `.dev<run number>` is the template the `build` job patches into
  `pyproject.toml` when `workflow_dispatch` starts the workflow, the
  number being `github.run_number` counted for `release.yml` alone, so
  the seventh such run rehearsing `2026.8.4` produces exactly that. The
  count is what makes a rehearsal's version unique, and what makes
  re-running a finished one collide with itself rather than mint a new
  one. Nothing commits the result: `uv lock` runs straight after, so the
  lockfile the sdist ships agrees with the version it is named for
- **`2026.8.4rc1`**, and a `v2026.8.4rc1` tag, have no place in this
  scheme: there is no pre-release here, only a version not yet tagged.
  `version-check` refuses anything that is not digits and dots, which
  is what stops `2026.8.4rc1` at `pyproject.toml` before a tag is even
  pushed — and what a `v2026.8.4rc1` tag would otherwise pass, the
  comparison against it burning a version `--pre` installs would then
  resolve

PEP 440 sorts `2026.8.4.dev7` before `2026.8.4`, so a rehearsal never
shadows the release it rehearses. `git tag` on its own does not read
the numbers the same way: measured, `v2026.10` lists before `v2026.7`,
alphabetically rather than chronologically. `git tag --sort=v:refname`
reads them as PEP 440 does.

## One-time setup

Already done for btclib-org/btclib; kept here for the record.

1. On [PyPI](https://pypi.org/manage/project/btclib/settings/publishing/),
   add a trusted publisher: owner `btclib-org`, repository `btclib`,
   workflow `release.yml`, environment `pypi`.

1. On [TestPyPI](https://test.pypi.org/), add the same trusted
   publisher, with environment `testpypi`.

1. In the GitHub repository settings, create the `pypi` and `testpypi`
   environments. Both require a review from `fametrano`, so neither
   index is uploaded to without a human approving that run; every job
   holding `id-token: write` either runs under one of those two
   environments directly, or — `attest` — only after one of them has
   already succeeded, so nothing exchanges for an OIDC token ahead of
   the review. `pypi` is additionally restricted to
   `v*` tags, which is the only ref its job runs on anyway — the
   restriction is what makes that true of the environment and not just
   of an `if:` in a file a pull request could change.

   Self-review stays allowed on purpose: the maintainer who pushes the
   tag is the reviewer, and forbidding it would deadlock a one-maintainer
   release. The approval is a confirmation step, not a second pair of
   eyes; it becomes one as soon as there is a second reviewer to add.

## Rehearse on TestPyPI

A rehearsal runs the identical pipeline — lint gate, test matrix, the
packaging checks of the `dist` job (twine, check-wheel-contents,
pyroma), build (which runs those same three checks again, on the files
it is about to publish), wheel smoke test — and publishes to
[TestPyPI](https://test.pypi.org/project/btclib/) instead of PyPI.

1. On GitHub, Actions → release → Run workflow, and pick the branch to
   rehearse: `main`, or the release branch while its pull request is
   still open — the workflow has to be registered on the default branch
   to be dispatched at all, which is the paragraph at the top of this
   file, but it runs against whichever branch is picked.

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

`latest` is worth dispatching before the tag rather than waiting for its
Wednesday cron, because what it answers is cheaper to know before a version
is consumed than after. It gates nothing, so it will not stop you:
reading it is the point. Its `suite-bindings-latest` job is the one worth
reading closely: it asks about the newest btclib_secp256k1 release
alone, precisely, rather than folding it into the broader upgrade the
rest of the workflow makes — a release of the bindings is a release in
another repository, which nothing here has to change for the pair to
stop working, and this release is the moment to find out before shipping
against a pin about to be a version behind.

**Read it per job, not as a verdict.** A red run means either "one
dependency moved and this tree has not caught up" or "the bindings are
broken against it", and only the second is a reason to stop — so which
job failed is the question, and a run that is red overall while
`bindings at latest` is green on every runner is saying the pin is
sound. The second says which it is now (issue #1136): a newest release
this tree cannot import fails that job's **Assert the bindings are
serving** step, by name and before the suite, where it used to reach you
as a coverage shortfall under a suite that passed — the shape of the
first, and the reading that does not stop a release. Red on a test
below that step is the other blocking shape, the bindings importing and
answering differently. Open the failure rather than inferring it from a
sibling: on v2026.8.7 seven jobs were red, six tests and the lint one,
and reading a single test log and generalising happened to be right —
the lint job was mypy reporting the same four errors — but nothing said
so until it was checked.

**Usually a red run is future work, and sometimes it blocks.** A release
ships what `uv.lock` pins, so drift against a newer version of some
dependency does not make the release wrong — it says the next bump is
going to be work. That holds while the dependency that moved is a
stranger. It does not hold when it is another btclib-org
project whose new release this release should depend on: v2026.8.7 was
cut the day `bitcoin-core-rpc` renamed two exported functions with no
alias, and shipping against the pinned older one would have published a
btclib that could not be installed beside its own sibling. The paragraph
above says exactly this about the bindings; it is true of both, word for
word, and step 1 asks it of both.

Whether to act on a stranger's drift now, or leave it for Dependabot's
own pull requests to catch up, is a decision worth stating rather than
defaulting by omission — `uv lock --upgrade` is gated by nothing here,
so silence at the tag reads as "nobody looked" and not as "looked and
chose to leave it". State the choice in the release pull request, next
to `latest`'s own result.

1. Make sure the newest release of **each btclib-org dependency** —
   btclib_secp256k1 and bitcoin-core-rpc — is the one this release
   should depend on, and that `pyproject.toml`'s pin says so. Two
   questions, not one: whether the pin *resolves*, which the wheel smoke
   test of the `dist` job already answers on every pull request by
   failing when only an unreleased version satisfies it, and whether the
   floor should *move*, which nothing automates because only a person
   knows what the sibling's release was for. Both projects are pinned
   without a ceiling and both can publish on the morning of a release.

   **A direct reference is not a pin this release may carry.** Either
   line can be `<name> @ git+…@main` while a branch here calls what has
   just landed there and no release of it carries that yet; PyPI refuses
   a direct reference in metadata, and nothing before `publish-pypi`
   does — the whole matrix builds, the artifacts upload, and the upload
   fails at the end. So a floor is written back over the reference, `>=`
   the release that carries what this tree calls: the sibling has to be
   released first, and there is no shipping against a commit.

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

1. Check the breaking-changes list against the API itself, which nothing
   automates on a commit:

   ```shell
   uv run --with griffe griffe check btclib -a <previous release tag>
   ```

   `tests/release_notes_test.py` keeps both release-note files count-free:
   it rejects entry counts and breaking-change totals, because those
   figures drift and create merge conflicts. It cannot know whether the
   list is complete, the list being prose about the public API. griffe
   reads both revisions and answers that: it reports breakage alone — a
   public object removed, a parameter that changed kind or default or
   moved, an attribute whose value changed — and says nothing at all about
   an addition, so every line it prints wants an entry. What the step asks
   is that nothing it names is missing from RELEASE_NOTES.md. The converse is
   not its to answer: an entry describing a break it did not find is a
   claim about the prose, which review still has to read. It exits 1 on a
   finding.

   Breakage by griffe's classification is not breakage a user would
   notice, though, and two shapes are most of the noise. `Attribute value
   was changed: Union[X, Y] -> X | Y` is PEP 604 spelling and breaks
   nobody, and `__version__` and `__copyright__` report the same way. And
   one systemic change repeats once per site: `check_validity` going
   keyword-only is dozens of lines on its own and belongs in
   RELEASE_NOTES.md once, as a rule, not once per class. Discount those and
   what is left is short enough to check bullet by bullet — four entries
   were missing from v2026.8.7's list, and all four were in that remainder.

   Not a gate on every commit, and deliberately so: the comparison is
   against the previous *release* tag, so it reports the whole of a
   development cycle, typically hundreds of differences. No branch stands
   still at the last release for it to read instead, one branch being one
   moving tree, so the tag is the only target it has and a cycle's worth
   of output is the only shape its answer takes.

1. Retitle the "work in progress" section of **both** RELEASE_NOTES.md
   and CHANGELOG.md as `## v<version>`. The workflow lifts the GitHub
   release notes from RELEASE_NOTES.md's section alone, so that one has
   to read as the release notes it becomes; CHANGELOG.md is the detail
   it points at, and the two are retitled together or the link goes
   nowhere. `version-check` refuses a tag whose heading still carries
   anything after the version, in either file, or whose section is
   empty: the extraction matches `## v<version>` followed by a space
   too, so an unretitled RELEASE_NOTES.md would have published "work in
   progress, not released yet" as the release notes. A rehearsal is
   exempt, being what runs before this step.

1. Run `uv run pre-commit run --all-files` and `uv run pytest --cov`,
   follow docs/README.rst to check that the documentation builds, and get
   the above onto `main` through the usual pull request. The local gates
   are the evidence until that pull request exists: `test.yml` and
   `lint.yml` trigger on `pull_request` and on a push to `main` alone,
   deliberately, so that a branch with an open pull request is not tested
   twice — which means **a commit on a branch with no pull request open
   runs neither**.

   Then verify the
   [read the docs](https://app.readthedocs.org/projects/btclib/builds/)
   build, and that [the website](https://btclib.org) and the
   [documentation](https://btclib.readthedocs.io/en/latest/) render
   correctly. Read the *builds* page and not only the rendered one: a
   site that answers 200 may be serving the last build that succeeded,
   which for three years was v2023.7.12's — the webhook had been
   refusing every delivery with a 400 and nobody was told (issue #484).
   This is the half no check covers: `latest` is the tip of `main`, so
   nothing names a version to ask about. The tag's own build is asked
   about, by the `documented` job below.

   Two things about that pull request, both of them before the button
   rather than after it.

   Give it its title and its body. The title is the version; the body
   says what the release is — what moved, what did not, and which of the
   two a user would notice. The squash takes its message from the
   branch's commits and not from that body:

   ```shell
   gh api repos/btclib-org/btclib --jq .squash_merge_commit_message
   # COMMIT_MESSAGES
   ```

   so the pull request is where the body stays, and where a reader
   arriving from the release commit ends up. A template left unfilled, or
   a bot's summary of the diff, is not a substitute — the summary can
   stay, but what the diff cannot say has to be written, and what a
   reader should not have to discover at the button belongs there too.

   Write it from RELEASE_NOTES.md's "work in progress" section, which the
   cycle has been filling one landed change at a time, and check that
   against `git log v<previous version>..main --oneline` regardless of
   how current it looks, rather than trust that every line landed when it
   should have. Griffe's result and `latest`'s run belong here too, each
   a line rather than a screenshot — both are steps nothing else
   enforces, and a pull request that never mentions them reads exactly
   like one that skipped them.

   And land it the way every other pull request here lands: the squash
   button, pressed by auto-merge once the review and the checks are in.
   There is no other way in: `main` takes a pull request and nothing
   else. That the commit under the tag carries GitHub's web-flow
   signature rather than the maintainer's costs nothing: the branch rule
   asks for a valid signature and not for a particular signer.

   `gh pr merge <n> --squash` alone can still refuse this pull request —
   `the base branch policy prohibits the merge` — the way it did on
   btclib-secp256k1's own v0.8.0.4 (btclib-secp256k1#288): a
   solo-maintainer repository never clears `REVIEW_REQUIRED`, so gh's
   client-side mergeable check declines before it asks the server at
   all, and `--auto` only waits longer for the same review that will not
   arrive. `--admin` is the flag that clears it — the pair
   REPOSITORY.md's "Branch protection" names, `enforce_admins` `false`
   together with holding `admin` — and it is the one to reach for first:
   measured directly here across #1111, #1113, #1114 and #1133, each
   landing from `BLOCKED` and `REVIEW_REQUIRED` with a verified
   signature, one of them (#1113) `BEHIND` as well and cleared the same
   way. Name the release commit's title and body explicitly when using
   it — `gh pr merge <n> --squash --admin --subject "<title>"
   --body-file <path>` — rather than leave them to
   `squash_merge_commit_message`'s repository default, `COMMIT_MESSAGES`
   here: this branch carries more than one commit every time (the
   paragraph below this one), and that default composes the commit under
   the tag from all of them rather than from what step 3 wrote.

   `gh api -X PUT repos/{owner}/{repo}/pulls/<n>/merge -f
   merge_method=squash` is the fallback for when `--admin` is
   unavailable, and needs `commit_title` and `commit_message` passed the
   same way for the same reason. It is what landed btclib-secp256k1's
   0.8.0.4 clean — but only because that branch carried a single commit,
   so `COMMIT_MESSAGES`'s concatenation and that commit's own message
   were the same string; a multi-commit release branch without the two
   parameters would not be so lucky.

   This branch carries more than one commit every time, a version bump
   and two retitles never being one, so the commit that lands is one
   GitHub composes at the button and no local object matches it. That
   is why the checks are read again below, on what `main` ends up at
   rather than on the branch head they ran against.

   Then read `lint` and `test` on the commit `main` ends up at before
   tagging, rather than trust the pull request's own green run:

   ```shell
   gh run list --commit "$(git rev-parse origin/main)"
   ```

   the merge pushes to `main`, and that push fires both workflows again
   from their own `push` trigger — a run of its own, not the
   `pull_request` run already green a moment earlier, and the paragraph
   above on the local gates is why there is no third one to fall back on.

1. Rehearse on TestPyPI (see above) from `main`.

1. Tag the release commit and push the tag. **Name the commit**, and read
   the tag back before pushing it:

   ```shell
   git tag -s v2026.8.4 -m "release v2026.8.4" <sha of the release commit>
   git show v2026.8.4:pyproject.toml | grep '^version'
   git push origin v2026.8.4
   ```

   `git tag` with no commit tags whatever HEAD the shell is in, and every
   step above ran in a worktree while the primary checkout sits on
   another branch — so the argumentless form is one `cd` away from
   tagging the commit before the version bump. That is how v2026.8.7 was
   first tagged; `version-check` refused it, comparing `2026.8` against
   the tag's `2026.8.7` and failing the run with nothing uploaded, which
   is the guard doing its job. The `git show` above is the same check one
   step earlier, where it costs nothing.

   The commit has to be one `main` contains, and `version-check` refuses
   the tag otherwise: `git merge-base --is-ancestor` against the default
   branch is the first thing it asks, before it has read a version at all.
   What that catches is the other half of the same mistake — the right
   version on a commit nobody merged, a branch whose pull request is still
   open, or the pre-squash commit of one that landed, which the squash left
   on no branch at all.

1. The workflow builds the full matrix and the distribution files, then
   pauses at the `pypi` environment for the review "One-time setup"
   describes. Approve it. That approval is not the point of no return:
   the OIDC token exchange happens after it, so a trusted publisher
   whose claims do not match fails there having uploaded nothing, and
   the version survives — delete the tag, fix the registration, tag
   again. The same holds for a rehearsal failing the same way on
   TestPyPI: its `.dev<run number>` is not consumed either, and `gh run
   rerun --failed` re-runs the publish job alone, against the artifacts
   already built, rather than the whole matrix again. The upload itself
   is the point of no return, PyPI accepting no file name twice even
   after deletion; the GitHub release follows it, with the distribution
   files attached, `btclib-<version>.cdx.json` and
   `<tag>.attestation.jsonl` beside them, and the RELEASE_NOTES.md section
   as its body. Read those notes once it lands: a run that logs
   `RELEASE_NOTES.md has no v<version> section` generated them from the
   merged pull requests instead — the fallback `version-check` exists to
   make unreachable, not a second way to write release notes — and they
   are worth replacing by hand if it ever fires.

1. Read the `documented` job rather than the site: read the docs activates
   and builds a new release tag from the automation rule REPOSITORY.md
   records, and that job waits for
   `https://btclib.readthedocs.io/en/<tag>/` to be served and is red if it
   never is. Green means the release has a permanent URL of its own, which
   is the one to link when the version is named anywhere. Red means the
   build is missing and
   [the builds page](https://app.readthedocs.org/projects/btclib/builds/)
   says why: nothing about the publication depends on it, so the fix is a
   build on their side and never a moved tag.

1. Install what was just published into an environment of its own,
   then exercise something that touches the shipped data rather than
   only importing it. `import btclib` runs `__init__.py` alone, and the
   files under `_data/` — the BIP39 wordlists among them — are opened
   by path at the first call that needs one, not imported, so a wheel
   missing `wordlist.txt` would install and import cleanly and only
   fail there:

   ```shell
   uv run --isolated --no-project --with btclib \
     python -c "from btclib.mnemonic.bip39 import seed_from_mnemonic; \
       m = 'abandon abandon abandon abandon abandon abandon abandon ' \
           'abandon abandon abandon abandon about'; \
       print(seed_from_mnemonic(m, 'TREZOR').hex())"
   ```

1. Check the PEP 740 attestations SECURITY.md says every release
   carries. The JSON API is not where: its `provenance` field answers
   `null` even on a release that has them. The project page shows them,
   and machine-readably they are under
   `/integrity/<project>/<version>/<filename>/provenance`, whose
   `attestation_bundles[].publisher` should name this repository and
   `release.yml`.

   That endpoint answers whether an attestation is *there*. Whether it
   verifies is a second question, and the one worth asking:

   ```shell
   uv run --isolated --no-project --with pypi-attestations \
     pypi-attestations verify pypi <file> \
     --repository https://github.com/btclib-org/btclib
   ```

1. Read the bill of materials attached to the release,
   `btclib-<version>.cdx.json`: a CycloneDX 1.6 document naming the
   distribution, its licence, the two files with their SHA-256, and one
   component per dependency the wheel's metadata declares. What is worth
   reading rather than assuming is that list — it is `Requires-Dist` as
   published, so a `git+https://` still in it is a release that should not
   have got this far, and each component carries a `version` only where the
   requirement is a `==` pin, a floor being a range and not a version.
   Attested with the distribution files, so `gh attestation verify` below
   covers it too.

   **Neither sibling repository carries one, on purpose.**
   bitcoin-core-rpc declares `dependencies = []`, and `published.yml`
   already asserts that against the installed package on every run; a
   bill of materials there would be an empty `components` list restating
   a fact CI checks more directly. btclib-secp256k1's interesting
   dependency is the vendored, statically-linked libsecp256k1 C library
   pinned in its `secp256k1` submodule, which this generator cannot
   describe — it reads `Requires-Dist`, and the submodule is not a
   Python dependency. A bill of materials built the way this one is
   would name `cffi` and say nothing about the pin a verifier of that
   package would most want described, which is worse than omitting the
   document. See issue #1159 for the evaluation and what would change
   it.

1. Read the release run's `published` job, which is this workflow called
   with the tag rather than a dispatch to remember: it has no checkout, so
   it resolves to what PyPI actually serves rather than to a source tree,
   and it waits for the version the tag names before installing anything,
   so it cannot pass by testing the release before it. It checks a BIP39
   vector against the `_data/` files a wheel missing one would still
   install and import cleanly, and a BIP340 vector besides — both fixed
   forever, so neither needs an edit after a release the way a
   version-pinned assertion would. From then on it runs monthly on its
   own, and a failure means the outside world moved, not this repository —
   a new interpreter release, PyPI serving a file that does not match its
   own hash — which is why it is a workflow of its own rather than a job
   of this one. Actions → published → Run workflow is for asking between
   those runs, with no particular version in mind.

1. Open the next cycle: set a generic next version without the day
   (e.g. after 2026.8.4, use 2026.9) in pyproject.toml, and start a new
   "work in progress" section in RELEASE_NOTES.md and CHANGELOG.md,
   through a pull request like any other.

   Those two sections are where the next release's notes accumulate, one
   landed change at a time, and the merge step above is what reads them
   back. Nothing else holds them: with one branch there is no pull
   request standing open for the length of a cycle to be written into as
   it runs, so a change that lands without its entry leaves nothing
   behind to reconstruct it from but the diff.

## Rebuild a release from its tag

The `build` job exports `SOURCE_DATE_EPOCH` from the commit date and
normalizes the sdist, so a rebuild of a released tag is the same bytes as
what was published. Anyone can check that, and the check is one command
short of the provenance one above: verify the *rebuilt* file rather than a
downloaded one, and it can only pass if the digests agree. A release whose
assets carry `<tag>.attestation.jsonl` has the signed statement on disk
too, so `--bundle <that file>` asks the same question of it without
reaching the attestations API — which is the form for whoever mirrors the
releases page rather than trusting it live. `--signer-workflow` is the
flag that makes either form say *which* workflow signed: without it a
valid attestation from any workflow in the repository passes.

A worktree and not `git checkout`, for the reason CLAUDE.md gives: the
primary checkout is the maintainer's, and a rebuild wants a tree of its
own regardless.

```shell
git worktree add --detach /tmp/btclib-rebuild v<version>
cd /tmp/btclib-rebuild
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
uv build
uv run --no-project --python 3.14 \
  .github/scripts/normalize_sdist.py dist/
uv run --no-project --python 3.14 \
  .github/scripts/generate_sbom.py dist/ sbom/
repo=btclib-org/btclib
gh attestation verify dist/btclib-<version>-py3-none-any.whl \
  --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml"
gh attestation verify dist/btclib-<version>.tar.gz \
  --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml"
gh attestation verify sbom/btclib-<version>.cdx.json \
  --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml"
```

The bill of materials is rebuilt with them and verified like them: its
timestamp is `SOURCE_DATE_EPOCH` and its serial number is derived from the
two digests, so it is the same bytes as the released copy — which is the
only reason a third `gh attestation verify` can pass at all.

Two things bound that guarantee, and both are worth knowing before reading
a mismatch as tampering:

- **the build backend is resolved, not pinned.** `[build-system] requires`
  asks for `setuptools>=77` and an isolated build takes whatever is
  current, so a rebuild months later runs a setuptools the release never
  saw. A mismatch dates the rebuild before it accuses anyone; pinning the
  backend to a version is the fix, and the cost is a floor that ages.
- **the rehearsal is a different version, by construction.** A TestPyPI
  dispatch appends `.dev<run number>` to the version, so its files are not
  a second build of the release's — they are their own artifact, published
  where they say they are. The attestation the rehearsal writes covers
  those, and no digest is shared with the release.

`btclib_secp256k1` is not a third bound. It is a runtime dependency,
resolved by whoever installs the wheel, and the only trace of it in either
distribution file is the `Requires-Dist` pyproject.toml already spells and
the pin `uv.lock` carries into the sdist — both of them text belonging to
the tag. Nothing the build resolves is a runtime dependency: an isolated
build installs `[build-system] requires` and no more, and the rebuild
above needs no `uv sync` to produce the published bytes.

## If something goes wrong

- The workflow failed before the `publish-pypi` job: nothing was
  uploaded. Delete the tag, fix, and tag again:

  ```shell
  git tag -d v2026.8.4
  git push origin :refs/tags/v2026.8.4
  ```

  Both lines, and the local one is the half that is easy to skip: a tag
  is per-repository where a branch is per-worktree, so deleting it in one
  worktree leaves it in every other, and the `git tag -s` that follows
  answers `fatal: tag 'v2026.8.4' already exists` — from a checkout that
  looks uninvolved. Delete locally wherever it is, then re-create.

- `publish-pypi` itself ran and failed at the token exchange
  (`invalid-publisher`), after the matrix had already built everything:
  nothing was uploaded, but retagging would rebuild what was never at
  fault. A registration that matched once goes stale on its own — a
  repository rename is enough — and nothing here flags it before the
  upload tries; sibling repository btclib_secp256k1 hit exactly this
  on a real tag rather than a rehearsal. Fix the registration and re-run
  the publish job alone against what is already built:

  ```shell
  gh run rerun <run id> --failed
  ```

  a fresh approval of the `pypi` environment is still required, the
  protection applying per deployment attempt rather than once per run.
  This is a different case from the one above: there, the workflow never
  reached `publish-pypi`, so there is nothing to re-run and no artifact
  to re-run it against.

- The upload succeeded but the release is broken: PyPI never accepts a
  file name twice, even after deletion. Yank the bad release on PyPI
  and publish a new patch version (`2026.8.4` → `2026.8.4.1`).

- Only the `github-release` job failed: the PyPI upload is already
  done; re-run the failed job, or create the release by hand from the
  `dist` artifact of the run.
