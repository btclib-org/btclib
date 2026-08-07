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
makes `release.yml`, `latest.yml` and `published.yml` — `schedule` and
`workflow_dispatch` only, so nothing else ever triggers them — answer
`gh: Not Found (HTTP 404)` until the release pull request is merged. It
bites once, on the first release after any of them is written, and it
inverts the order below: the TestPyPI rehearsal and the `latest` run
that this file asks for *before* the merge can only happen after it,
still before the tag. It also means such a workflow reaches `master`
having never run, which is how `published.yml` shipped a
`windows-11-arm` cell that failed at setup.

## Which version string is which

Telling these apart is most of what can go wrong when cutting a release.

- **`pyproject.toml`'s own `version`** takes three shapes over one
  cycle, never two at once: `2026.8`, month only, between releases —
  the placeholder "Open the next cycle" sets, so a checkout of `dev`
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

`latest` is worth dispatching before the tag rather than waiting for its
Wednesday cron, because what it answers is cheaper to know before a version
is consumed than after. It gates nothing, so it will not stop you:
reading it is the point. Its `test-bindings-latest` job is the one worth
reading closely: it asks about the newest btclib_libsecp256k1 release
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
sound. Open the failure rather than inferring it from a sibling: on
v2026.8.7 seven jobs were red, six tests and the lint one, and reading
a single test log and generalising happened to be right — the lint job
was mypy reporting the same four errors — but nothing said so until it
was checked.

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

1. Make sure the newest release of **each btclib-org dependency** —
   btclib_libsecp256k1 and bitcoin-core-rpc — is the one this release
   should depend on, and that `pyproject.toml`'s pin says so. Two
   questions, not one: whether the pin *resolves*, which the wheel smoke
   test of the `dist-py` job already answers on every pull request by
   failing when only an unreleased version satisfies it, and whether the
   floor should *move*, which nothing automates because only a person
   knows what the sibling's release was for. Both projects are pinned
   without a ceiling and both can publish on the morning of a release.

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
   is that nothing it names is missing from HISTORY.md. The converse is
   not its to answer: an entry describing a break it did not find is a
   claim about the prose, which review still has to read. It exits 1 on a
   finding.

   Breakage by griffe's classification is not breakage a user would
   notice, though, and two shapes are most of the noise. `Attribute value
   was changed: Union[X, Y] -> X | Y` is PEP 604 spelling and breaks
   nobody, and `__version__` and `__copyright__` report the same way. And
   one systemic change repeats once per site: `check_validity` going
   keyword-only is dozens of lines on its own and belongs in HISTORY.md
   once, as a rule, not once per class. Discount those and what is left
   is short enough to check bullet by bullet — four entries were missing
   from v2026.8.7's list, and all four were in that remainder.

   Not a gate on every commit, and deliberately so: the comparison is
   against the previous *release*, so it reports the whole of a
   development cycle, typically hundreds of differences. Against
   `origin/master` it becomes usable as a pull-request check once this
   release lands there, master still being at the 2023 tree.

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

1. Run `uv run pre-commit run --all-files` and `uv run pytest --cov`,
   follow docs/README.rst to check that the documentation builds, and get
   the above onto master through the usual pull request. The local gates
   are the evidence here in a way they are not on an ordinary branch:
   `test.yml` and `lint.yml` trigger on `pull_request` and on a push to
   `master` alone, deliberately, so that a branch with an open pull
   request is not tested twice — which means **a commit pushed straight
   to `dev` runs neither**, and the next CI it meets is the push to
   `master`. Correcting the release branch after the pull request is
   merged is exactly that case.

   Then verify the
   [read the docs](https://readthedocs.org/projects/btclib/builds/)
   build, and that [the website](https://btclib.org) and the
   [documentation](https://btclib.readthedocs.io/en/latest/) render
   correctly. Read the *builds* page and not only the rendered one: a
   site that answers 200 may be serving the last build that succeeded,
   which for three years was v2023.7.12's — the webhook had been
   refusing every delivery with a 400 and nobody was told (issue #484).

   Two things about that pull request, both of them before the button
   rather than after it.

   Give it its title and its body. The title is the version; the body
   says what the release is — what moved, what did not, and which of the
   two a user would notice. A rebase leaves no merge commit, so none of
   that reaches `master`'s history: the pull request is where it stays,
   and where a reader of any commit in it arrives. A template left
   unfilled, or a bot's summary of the diff, is not a substitute — the
   summary can stay, but what the diff cannot say has to be written, and
   what a reader should not have to discover at the button belongs there
   too.

   The previous cycle's last step opened this pull request asking for the
   body to fill in one merged pull request at a time, and said so itself:
   "a promise kept only if someone remembers to keep it." Check it against
   `git log v<previous version>..dev --oneline` regardless of how current
   it looks, rather than trust that every line landed when it should have.
   Griffe's result and `latest`'s run belong here too, each a line rather
   than a screenshot — both are steps nothing else enforces, and a pull
   request that never mentions them reads exactly like one that skipped
   them.

   And merge it with **"Rebase and merge"**, never *"Squash and merge"*.
   All three methods are enabled here and GitHub preselects whichever was
   used last, so which button it is has to be read before it is pressed.
   A squash folds every landed change into one commit, leaving `master`
   with a single line where `dev` carried the reasoning one decision at a
   time — and that cannot be undone afterwards, the tag on the squashed
   commit and the attestations bound to it outliving any attempt to
   rewrite the history back.

   **Past 100 commits there is no button at all.** "Rebase and merge" is
   [limited to 100 commits](https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits),
   and answers `This branch can't be rebased` above it — v2026.8.7
   carried 469. The limit belongs to the feature, so no branch rule and
   no administrator bypasses it, and the other two buttons are barred by
   the paragraph above and by `master`'s required linear history. What is
   left is the command line the button wraps:

   ```shell
   git fetch origin
   git merge-base --is-ancestor origin/master origin/dev && echo fast-forward
   git push origin origin/dev:master
   ```

   Read that middle line before pushing, because it decides the last step
   of this file too. If `master` is already an ancestor of `dev` — which
   it is whenever nothing has landed on `master` alone since the previous
   release — the push is a **fast-forward**: every commit keeps its sha,
   `dev` and `master` end on the same commit, and "Realign `dev` onto
   `master`" below has nothing to do. A rebase, replaying commits under
   new shas, is what makes that step necessary; a fast-forward is what
   makes it moot. `git diff origin/master origin/dev` answers which
   happened rather than leaving it to be assumed.

   Either way, read `lint` and `test` on the commit `master` ends up at
   before tagging, rather than trust the pull request's own green run:

   ```shell
   gh run list --commit "$(git rev-parse origin/master)"
   ```

   the merge pushes to `master`, and that push fires both workflows again
   from their own `push` trigger — a run of its own, not the
   `pull_request` run already green a moment earlier, and the paragraph
   above on the local gates is why there is no third one to fall back on.

1. Rehearse on TestPyPI (see above) from master.

1. Tag the release commit and push the tag. **Name the commit**, and read
   the tag back before pushing it:

   ```shell
   git tag -a v2026.8.4 -m "release v2026.8.4" <sha of the release commit>
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
   files attached and the HISTORY.md section as its body. Read those notes
   once it lands: a run that logs
   `HISTORY.md has no v<version> section` generated them from the merged
   pull requests instead — the fallback `version-check` exists to make
   unreachable, not a second way to write release notes — and they are
   worth replacing by hand if it ever fires.

1. Install what was just published into an environment of its own,
   then exercise something that touches the shipped data rather than
   only importing it. `import btclib` runs `__init__.py` alone, and the
   25 files under `_data/` — the twelve BIP39 wordlists among them —
   are opened by path at the first call that needs one, not imported,
   so a wheel missing `wordlist.txt` would install and import cleanly
   and only fail there:

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

1. Dispatch the `published` workflow (Actions → published → Run workflow)
   and expect it green: no checkout, so it resolves to what PyPI actually
   serves rather than to a source tree. It checks a BIP39 vector against
   the twenty-five `_data/` files a wheel missing one would still install
   and import cleanly, and a BIP340 vector besides -- both fixed forever,
   so neither needs an edit after a release the way a version-pinned
   assertion would. From then on it runs weekly on its own, and a failure
   means the outside world moved, not this repository — a new interpreter
   release, PyPI serving a file that does not match its own hash — which
   is why it is a workflow of its own rather than a job of this one.

1. Realign `dev` onto `master`, before anything else is committed to it —
   **if the merge was a rebase.** Ask first, because a fast-forward needs
   none of what follows:

   ```shell
   git fetch origin
   git rev-parse origin/master origin/dev    # the same sha? then skip this step
   ```

   after a fast-forward the two branches *are* one commit, the merge base
   is that commit, and there is nothing to archive or move; v2026.8.7 was
   this case. The rest of this step is for the other one.

   **Rebase and merge** replays `dev`'s commits with new SHAs, so the
   moment a release lands the two branches hold the same tree through
   different histories, and their merge base stops advancing. Left
   alone, the next release's pull request presents the whole of this one
   as new, and asks the rebase to replay commits `master` already
   carries — which is exactly what happened to btclib-bitcoin-core-rpc
   after its first rebase-and-merge release, `dev` and `master` sitting
   on two different commits for the one that cut it, neither an ancestor
   of the other. Archive what is about to become unreachable, then move
   the branch:

   ```shell
   git fetch origin
   git tag -a history/dev-2026.8.4 dev -m "dev's own commits for 2026.8.4"
   git push origin history/dev-2026.8.4
   git switch dev && git reset --hard origin/master
   git push --force-with-lease origin dev
   ```

   the tag is what keeps `dev`'s own commits readable, and it must not
   start with `v`, `release.yml` triggering on `tags: ["v*"]`. Nothing in
   the working tree changes, the two trees being identical, and
   `git diff origin/master origin/dev` is how to say so rather than
   assume it.

   `git switch dev` assumes a checkout free to hold it, which the
   convention CLAUDE.md asks every session to follow — its own worktree,
   never the primary checkout — does not give a worktree already busy
   with a branch of its own, and should not be made to have by switching
   branches inside it. Without a local checkout of `dev` at all:

   ```shell
   git push --force-with-lease=refs/heads/dev:<the old dev tip> origin \
     origin/master:refs/heads/dev
   ```

   pushes the read-only remote-tracking ref `origin/master` straight to
   `refs/heads/dev`, the lease keyed to the `dev` tip a `git fetch`
   already holds rather than to a branch checked out locally.

   That last push can fail on its own: `dev`'s branch protection blocking
   force pushes is not one of the rules "Include administrators" being
   off exempts an administrator from — that toggle covers required
   reviews, required status checks, required signatures and required
   linear history, and blocking force pushes is a rule of its own that
   GitHub applies to every push over the git protocol regardless of who
   is pushing. btclib_libsecp256k1's 0.7.1.1 release is where this was
   learned: the maintainer's own push, run by hand, came back
   `remote: - Cannot force-push to this branch`. What worked was flipping
   the setting itself, immediately before the push and immediately
   after, reading its other fields back first so the PUT does not
   silently drop them:

   ```shell
   gh api repos/btclib-org/btclib/branches/dev/protection --jq \
     '{required_status_checks, enforce_admins: .enforce_admins.enabled,
       required_pull_request_reviews, restrictions,
       required_linear_history: .required_linear_history.enabled,
       allow_force_pushes: true, allow_deletions: .allow_deletions.enabled,
       block_creations: .block_creations.enabled,
       required_conversation_resolution: .required_conversation_resolution.enabled,
       lock_branch: .lock_branch.enabled,
       allow_fork_syncing: .allow_fork_syncing.enabled}' \
     | gh api -X PUT repos/btclib-org/btclib/branches/dev/protection --input -
   ```

   push, then set `allow_force_pushes` back to `false` through the same
   PUT at once — the setting, not only this one push, is what stands open
   in between.

   Every branch still open against `dev` has had its base moved out from
   under it, and reports the whole release as its own diff until it is
   rebased:

   ```shell
   git rebase --onto origin/master <the old dev tip> <branch>
   ```

   GitHub's own `mergeable`/`mergeStateStatus` on that branch's pull
   request can still read `CONFLICTING`/`DIRTY` for a few seconds after
   the force-push that follows, before it finishes recomputing against
   the new tip — worth a second look rather than read as the rebase above
   having failed.

   this comes before the next step rather than after it: that step's
   bump is on `dev`, and the force update above would discard it.

1. Open the next cycle: set a generic next version without the day
   (e.g. after 2026.8.4, use 2026.9) in pyproject.toml, and start a new
   "work in progress" section in HISTORY.md and CHANGELOG.md.

1. Open a draft pull request from `dev` to `master` for the cycle just
   opened, title included, and leave its body for what the merge step
   above already asks for: written before the release is cut, not
   reconstructed from the diff at the last minute. A draft one is what
   that step could not be until now — everything that lands on `dev`
   between one release and the next has a place to be described as it
   lands, rather than a promise kept only if someone remembers to keep
   it. Marking it ready and pressing **Rebase and merge** is what that
   step still is; this one is what makes reaching it with a body already
   written the ordinary case rather than the exception.

## If something goes wrong

- The workflow failed before the `publish-pypi` job: nothing was
  uploaded. Delete the tag, fix, and tag again:

  ```shell
  git tag -d v2026.8.4
  git push origin :refs/tags/v2026.8.4
  ```

  Both lines, and the local one is the half that is easy to skip: a tag
  is per-repository where a branch is per-worktree, so deleting it in one
  worktree leaves it in every other, and the `git tag -a` that follows
  answers `fatal: tag 'v2026.8.4' already exists` — from a checkout that
  looks uninvolved. Delete locally wherever it is, then re-create.

- `publish-pypi` itself ran and failed at the token exchange
  (`invalid-publisher`), after the matrix had already built everything:
  nothing was uploaded, but retagging would rebuild what was never at
  fault. A registration that matched once goes stale on its own — a
  repository rename is enough — and nothing here flags it before the
  upload tries; sibling repository btclib_libsecp256k1 hit exactly this
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
