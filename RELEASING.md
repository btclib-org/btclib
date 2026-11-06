# Releasing

Releases are published by GitHub Actions
(`.github/workflows/release.yml`), not from a developer
machine. Pushing a `v<version>` tag runs the full test matrix, builds and
checks the distribution files, publishes them to PyPI, and creates the
GitHub release. There is no PyPI token anywhere: both indices are
configured to trust the workflow itself
([Trusted Publishing](https://docs.pypi.org/trusted-publishers/)).

The same workflow, started by hand instead of by a tag, is a full rehearsal
against TestPyPI. A rehearsal is never tagged.

**This file is the same in every repository that publishes, up to its
last section.** Section 14 of the
[organization standard](https://github.com/btclib-org/.github#14-copied-verbatim-and-decided-per-repository)
says so, and `tests/verbatim_test.py` of that repository compares the
copies. The steps read this tree's names from shell variables, set by a
block in its last section: run that block first, in the shell the steps
run in. Prose and URLs write the same names as `<repo>`, `<dist>` and so
on. What one tree does beyond these steps is under that section too.

**A workflow GitHub has not registered cannot be dispatched, and it
registers one only once its file has reached the default branch.** Any new
workflow therefore answers `gh: Not Found (HTTP 404)` to `gh workflow run`
until the pull request adding it is merged. What makes that more than a
nuisance is the set no commit and no pull request fires either, which is
otherwise never exercised before the merge at all: `release.yml`, whose
`push:` names tags and nothing else, and the workflows below.

```shell
grep -L -E '^  (push|pull_request):' .github/workflows/*.yml
```

It bites once, on the first release after any of them is written, and it
inverts the order below: the TestPyPI rehearsal that this file asks for
*before* the merge can only happen after it, still before the tag. It also
means such a workflow reaches `main` having never run.

## Which version string is which

Telling these apart is most of what can go wrong when cutting a release.

- **`pyproject.toml`'s own `version`** shifts shape over one cycle,
  never two at once: `2026.9`, month only, between releases — the
  placeholder "Open the next cycle" sets, so a checkout of `main` reports
  itself as work in progress rather than as a release it is not;
  `2026.8.6`, the date of release day — calendar versioning, `YYYY.M.D`
  — which is what gets published, its month that date's own and not
  necessarily the placeholder's; and `2026.8.6.1`, a fourth number added
  only if `2026.8.6` shipped broken and cannot be reuploaded (see "If
  something goes wrong"). All three are typed by hand. Three
  components is always the release day; four is always a patch on it. The
  day is never dropped in favour of a fourth digit standing in for it,
  which is what would make the two indistinguishable — and `version-check`
  refuses a tag on the placeholder shape for exactly that reason: two
  components reach the check and nothing past it, whichever one is
  declared. It does not tell three apart from four, both being a release
  it accepts
- **`v2026.8.6`**, the tag, carries no version of its own: it picks the
  index, PyPI rather than TestPyPI, and `version-check` exists to
  confirm it says what `pyproject.toml` says
- **`2026.8.6.dev701`** is a rehearsal, and nobody types it either half
  at a time: `.dev<run*100+attempt>` is the template `release.yml`
  appends to what `pyproject.toml` declares when `workflow_dispatch`
  starts it, `github.run_number` counted for that workflow alone and
  `github.run_attempt` counted for one dispatch of it, so the seventh
  such run's first attempt, rehearsing `2026.8.6`, produces exactly
  that. The multiplier is what makes a re-run a version of its own
  rather than a collision: a re-run keeps the run's own number and only
  raises the attempt, so the run number alone would be identical across
  every re-run of one dispatch and PEP 440 could not tell them apart.
  Placing the attempt below the run number's own place value keeps a
  run's later attempts sorting after its earlier ones and before the
  next run's, the attempt therefore capped at two digits and the workflow
  refusing a hundredth rather than silently wrapping into the next run's
  range. Nothing writes it down, and no commit ever carries it
- **`2026.8.6rc1`**, and a `v2026.8.6rc1` tag, have no place in this
  scheme: there are no release candidates here, only a version not yet
  tagged. `version-check` refuses anything that is not digits and dots,
  which is what stops `2026.8.6rc1` before a tag is even pushed — and
  what a `v2026.8.6rc1` tag would otherwise pass, burning a pre-release
  on PyPI itself, where `--pre` installs would find it from then on

PEP 440 sorts `2026.8.6.dev7` before `2026.8.6`, so a rehearsal never
shadows the release it rehearses. `git tag` on its own does not read the
numbers the same way: measured, `v2026.10` lists before `v2026.7`,
alphabetically rather than chronologically. `git tag --sort=v:refname`
reads them as PEP 440 does.

## One-time setup

A publisher attached to a project can only be added to a project that
exists, and a first upload has nothing else to authenticate with, there
being no token anywhere. So where an index holds no project of that name
yet, its entry below is added as a *pending* publisher, on the account's
own publishing page, and the first upload it accepts turns the entry into
an ordinary one. Where the project exists, the entry is added on that
project's publishing page.

1. On PyPI, add a trusted publisher to the project `dist` names: owner
   `btclib-org`, the repository `repo` names, workflow `release.yml`,
   environment `pypi`.

1. On TestPyPI, add the same trusted publisher to the project
   `test_dist` names, with environment `testpypi`.

1. In the GitHub repository settings, create the `pypi` and `testpypi`
   environments. Both require a review from one of `fametrano`,
   `giacomocaironi` and `pmazzocchi`, so neither index is uploaded to
   without one of them approving that run; `publish-pypi`
   and `publish-testpypi` are the only holders of `id-token: write` that
   carry one of these two environments, and this is the gate in front of
   them. The `attest` job of `btclib-org/.github`'s `reusable-build.yml`,
   which `release.yml`'s `build` job calls, holds `id-token: write` too,
   for its own Sigstore exchange, and no environment: it signs the
   distribution files before either reviewed job starts, and signs only
   files whose digests the build job printed. `publish-testpypi`,
   `publish-pypi`, `github-release` and the `dist` job check what they
   download against those digests, and fail where a file differs, is added
   or is missing.
   `pypi` is additionally restricted to `v*` tags, which is the only ref
   its job runs on anyway — the restriction is what makes that true of
   the environment and not just of an `if:` in a file a pull request could
   change.

   Self-review stays allowed: the environment does not require the
   approver to differ from whoever pushed the tag, so the tag's own
   pusher may also be the one who approves its release. That approval is
   a confirmation step rather than a second pair of eyes; an approval
   from either of the other two owners is the second pair of eyes the
   pusher cannot be for their own release.

## Rehearse on TestPyPI

A rehearsal runs the identical pipeline — lint gate, test matrix, the
`build` job's build and signature, the `dist` job's packaging checks
(twine, check-wheel-contents, pyroma) and its wheel smoke test — and
publishes the very files those checks passed to TestPyPI instead of
PyPI, so what `release.yml` publishes and what `test.yml` checked are
the same files (issue btclib-org/btclib#1166).

**What it answers is whether the publish path still works**, so it earns
its run when that path or what travels it has moved: `release.yml` or a
workflow it calls, `pyproject.toml`'s packaging metadata — the build
backend and the patterns of `[tool.uv.build-backend]` above all —
`normalize_sdist.py`, the trusted publisher registration, or the addition
of a file the distribution has to carry. A cycle that changed the module
and the prose and nothing else is one the tag's own run judges as well,
every job up to `publish-pypi` being the same job — and skipping it is
the maintainer's call to make and to say out loud in the release pull
request, not a step to leave silently undone. What is given up either way
is the token exchange and the upload, which no rehearsal on `main` proves
for PyPI anyway: `pypi` and `testpypi` are two registrations, and only
the tag exercises the first.

1. On GitHub, Actions → release → Run workflow, and pick the branch to
   rehearse (usually `main`). A release with any public-API finding is
   rehearsed from the release pull request's branch, after its notes are
   written: before, `public-api` reads the previous release's section and
   fails.

1. The workflow publishes under the name `test_dist` holds, and appends
   `.dev<run*100+attempt>` to whatever `pyproject.toml` declares on the
   branch dispatched — the outgoing cycle's placeholder if the version
   about to ship has not landed yet, which publishes something like
   `2026.9.dev401` and still tests the identical pipeline the tag will
   run; the number is not what is being asked about.
   Every rehearsal is unique on TestPyPI this way, re-runs included: a
   re-run raises only `github.run_attempt`, which the run number is
   multiplied by 100 to make room for, so re-running a failed or finished
   rehearsal mints its own version instead of colliding with the one it
   repeats. It sorts before the release it rehearses once that release's
   own version is the one declared, which is what the rehearsal after
   the merge below runs on; a placeholder naming a later month sorts
   after the day it rehearses instead, which costs nothing — `.dev` is a
   pre-release no plain install resolves, and the release itself never
   reaches TestPyPI.

1. Check the upload, and optionally install it, naming the `.dev`
   version the run published — its dependencies are PyPI's, and TestPyPI
   is the extra index that holds this one file:

   ```shell
   dev=<the version the rehearsal published>
   ```

   The assignment stands in a fence of its own, for the reason the
   tagging step below gives.

   ```shell
   uv run --isolated --no-project \
     --index https://test.pypi.org/simple/ \
     --index-strategy unsafe-best-match \
     --with "${test_dist:?}==${dev:?}" \
     python -c "${smoke:?}"
   ```

1. Check that the `build` job is green. It signs a rehearsal's files too,
   which is what it is here for: a permission or an API that only works
   on release day is one this job would find there. The signature is made
   before the `testpypi` approval, so the rehearsal's certificate can be
   read without approving anything. What it produces goes no further than
   an artifact of the run — no release is cut from a dispatch — and the
   attestation it records names a `.dev` version nothing resolves, and a
   branch as its source ref, so the `--source-ref` of *Verify the
   provenance of an asset* refuses it.

## Release to PyPI

**A release is a tag on `main`, and everything below that edits a file
does so on a branch of its own.** Nothing is pushed to `main` directly,
this release included: the steps that write the release's sections and
set the version are one pull request, the one that sets the next cycle's
version is another, and the tag names the commit the first of them left
behind.

`deps-latest` is worth dispatching before the tag rather than waiting for
its cron, because what it answers is cheaper to know before a version is
consumed than after. It gates nothing, so it will not stop you: reading it
is the point.

**Read it per job, not as a verdict**, and open the failure rather than
inferring it from a sibling. A release ships what `uv.lock` pins, so drift
against a newer version of some dependency does not make the release
wrong — it says the next bump is going to be work.

**The drift it reports is left to Dependabot.** The release pull request
does not run `uv lock --upgrade`: section 1's
[`uv.lock`](https://github.com/btclib-org/.github#uvlock) says what moves
the lock, and its one exception, a single package the audit asks for,
holds here as on any other pull request. Say so in the release pull
request, next to `deps-latest`'s own result.

1. Read what is open, and land first anything that fixes the release path
   itself:

   ```shell
   gh pr list --state open
   gh pr list --state open --search "release.yml OR pypi-install.yml"
   ```

   A pull request touching `release.yml`, anything under
   `.github/scripts/`, or any workflow `release.yml` calls is one the tag
   is about to run, so leaving it in review means running the defect it
   fixes on the release. What it calls is a list this file would only let
   rot, so read it from the file itself:

   ```shell
   grep -n 'uses: [.$]/\.github/workflows/' .github/workflows/release.yml
   ```

   It is not caught anywhere else: every one of those workflows is
   green on the pull request that fixes it, which is what makes it look
   like something that can wait. `pypi-install.yml` is the case to watch,
   its own failures arriving after PyPI has already accepted the files.

   The reverse question is worth the same minute: a pull request that is
   *not* ready is one this release ships without, so what the notes claim
   is what landed rather than what is nearly landed.

1. Read the public API against the previous release, before the notes that
   describe it are declared final. `RELEASE_NOTES.md` promises that a breaking
   change is announced there, the calendar version promising nothing, and
   nothing else reads that promise: the suite judges the code, and a reviewer
   weighs what the prose says rather than what it leaves out. griffe and
   `api_gaps.py` read both revisions and answer that second question for the
   breaks they compare — not whether the list is right, but whether it is
   complete:

   ```shell
   tag=v<previous version>
   ```

   ```shell
   uv run --no-project --python 3.15 --with griffe==2.2.0 \
       griffe check "${pkg:?}" -s . -s src -a "${tag:?}"
   ```

   griffe reads the `-a` revision from a temporary git worktree and
   resolves each `-s` search path against that worktree's root, which is
   the only path it searches when none is given, so without `-s src` it
   answers `ModuleNotFoundError` for a package under `src/`. The pair is
   the one `release.yml`'s `public-api` job passes.

   The griffe version is the one that job pins, and `tests/api_gaps_test.py`
   of btclib-org/.github holds this step to it: two griffe releases can
   answer differently for the same two revisions (btclib-org/.github#1977).

   Then run btclib-org/.github's `api_gaps.py`, against the same tag and
   with the same griffe, as the job does after griffe. It reports, in
   griffe's format, the breaks its docstring names, which griffe does not
   compare or can skip:

   ```shell
   gaps=$(mktemp -d) &&
   ref=$(grep -oE 'reusable-public-api\.yml@[0-9a-f]{40}' \
       .github/workflows/release.yml | cut -d@ -f2) &&
   gh api -X GET -H 'Accept: application/vnd.github.raw' -f "ref=${ref:?}" \
       repos/btclib-org/.github/contents/.github/scripts/api_gaps.py \
       > "${gaps:?}/api_gaps.py" &&
   uv run --no-project --python 3.15 --with griffe==2.2.0 \
       "${gaps:?}/api_gaps.py" "${pkg:?}" "${tag:?}"
   ```

   The script is fetched at the commit `release.yml` pins
   `reusable-public-api.yml` to, because the job runs the script at that
   commit and `main`'s copy can differ from it. Where `release.yml` names
   no such commit, `${ref:?}` stops the chain before the fetch.

   The script is written to a file before it runs, because a failed fetch
   piped into `uv run -` runs an empty script, which exits 0. An error
   starting `gh:` is the fetch failing, and the chain stops before the
   script runs.

   The first release has no previous tag, and there is nothing for this
   step to read; `release.yml`'s `public-api` job skips its check for the
   same reason.

   The two report each break they compare — a public object removed, a parameter
   that changed kind or default, an attribute whose value moved, a changed
   return annotation — and an annotation change that breaks nothing, such as a
   parameter's widened or one only spelled anew (`Optional[int]` to `int |
   None`). An addition is silent, so the output is short and every line of it
   wants an entry — what the step asks is that nothing they name is missing from
   RELEASE_NOTES.md. The converse is not theirs to answer: an entry describing a
   break they did not find is a claim about the prose, which review still has to
   read. Not a hook and not a job of `lint.yml`, deliberately: the comparison is
   against the previous *release*, so a break lands on `main` on purpose and
   remains a finding until the release that announces it, leaving every pull
   request in between red for something no branch introduced. Each exits 1 on a
   finding, so the day that reasoning stops holding — a cycle that means to
   break nothing — making the step a gate is a line per command.

   Some breaks neither reports: a kind neither compares, such as an
   `@overload`'s signatures, and what griffe alone compares on a pair it skips.
   The docstring of the `api_gaps.py` fetched above says what is known of both.
   Read those changes since the previous tag by hand: a break among them wants
   an entry too.

   griffe also exits 1 when it fails on an error it does not catch, such
   as a tag the repository lacks: its output is then a Python traceback,
   not findings. So an exit of 1 is read in the output before it is taken
   for a finding. `api_gaps.py` exits 2 when it fails. Any other non-zero
   exit is the tool failing, which answers nothing: read its error before
   going on.

   `release.yml` asks the same question again as its `public-api` job. A red
   one there is a finding `RELEASE_NOTES.md` does not name, or one of the two
   tools failing: read the job's log to tell which. The job gates nothing, its
   own comment saying why, and every job behind it opens its `if:` with
   `always()` and names the results it does require, so a red `public-api`
   costs the release nothing. What it costs is the run's own badge, red while
   every job that matters is green, which is why the step after the approval
   below reads the run job by job rather than as a whole.

1. Name in RELEASE_NOTES.md every change to the release's assets or to how they
   are verified — a file name, a signer, a `--source-ref` — in the release that
   first ships it. A script that downloads or verifies a release by the old
   value fails, and the notes are what tell its user the new one
   (btclib-org/.github#1596).

1. Write the release's sections in the release pull request, above the
   previous release's, as section 12 of the organization standard says:
   `## v<version>` in `CHANGELOG.md`, from the squash
   subjects since the previous tag, grouped and shortened,

   ```shell
   git log "${tag:?}"..HEAD --format=%s
   ```

   and in `RELEASE_NOTES.md`, what a user has to act
   on. The heading must be the version alone and the section must not be
   empty: `release.yml` checks both before anything is built, because PyPI
   never accepts a version's file names twice, even once the release is
   deleted. No other pull request writes either file, and nothing opens
   the next cycle's section.

   A `(work in progress, not released yet)` section, where one remains,
   is folded into the release's section by its pull request, which
   deletes the heading.

1. Set the version in `pyproject.toml`, which is the one place it is
   declared, to the date the release is cut, `YYYY.M.D`, and re-lock so
   `uv.lock` agrees:

   ```shell
   uv lock
   ```

   The date replaces the placeholder rather than extending it. *Open the
   next cycle* below sets the month after the release's, so a second
   release in the same month, built by appending the day to the
   placeholder, names a day of the next month — a date in the future,
   which sorts above every release that next month cuts before that day.
   On a tag push `version-check` refuses a version that names no
   calendar date, such as `2026.11.31`, and one dated after the date at
   UTC+14, the time zone furthest ahead, when the job runs, so it
   refuses the version built that way. `build` needs `version-check`, so
   nothing is uploaded. The cost is a failed run, and a new tag once the
   version is fixed, as "If something goes wrong" below says.

   **If `main` moves while the gates run, throw the branch away and redo
   these edits on top of it — never rebase it, and never merge `main` into
   it.** A rebase over a change that wrote to CHANGELOG.md or
   RELEASE_NOTES.md near this release's edits stops on a conflict there, and
   deleting the markers at git's default conflict style drops a line both
   sides share. Reset onto the new tip, then redo the sections, the version
   and `uv lock`, and gate again:

   ```shell
   git fetch origin
   git reset --hard origin/main
   ```

   The sections are written again from `git log` of the new tip, and the
   version is a few lines.

1. Give the release pull request its title and its body, before merging it
   and not after. The title is the version; the body says what the release
   is — what moved, what did not, and which of the two a user would
   notice. A squash leaves one commit whose message is that title, so the
   pull request is where the rest stays, and where a reader arriving from
   that commit lands. A template left unfilled, or a bot's summary of the
   diff, is not a substitute — the summary can stay, but what the diff
   cannot say has to be written, and what a reader should not have to
   discover at the button belongs there too.

   The section of RELEASE_NOTES.md written above is what that body is
   written from. The public API step's result belongs in the body too, a
   line rather than a screenshot — it is a step nothing else enforces, and a
   pull request that never mentions it reads exactly like one that skipped
   it.

1. Run `uv run pre-commit run --all-files` and `uv run pytest --cov`
   before pressing anything, then verify the Read the Docs build renders,
   on `https://app.readthedocs.org/projects/<rtd>/builds/`. Read the
   *builds* page and not only the rendered one: a site that answers 200
   may be serving the last build that succeeded, the webhook having
   quietly refused every delivery since.

1. Merge it as `CONTRIBUTING.md`'s *Landing it* says.

   Name the release commit's title and body explicitly, rather than leave
   them to `squash_merge_commit_message`'s repository default, which
   concatenates the branch's commit messages:

   ```shell
   gh pr merge <n> --squash --match-head-commit <head> \
     --body-file <path> --subject <title>
   ```

   In an emergency, once the bypass is added back, `--admin` is added.

   That the commit is composed by GitHub and signed with its web-flow
   key rather than yours costs nothing. The signature check on `main`
   asks for a verified signature, not a signer. `main-integrity` holds
   linear history, no force push and no branch deletion with no bypass
   actor at all, for administrators too.

   ```shell
   pr=<the release pull request's number>
   ```

   Split for the reason the tagging step gives.

   ```shell
   gh pr view "${pr:?}" --json state,mergeCommit \
     --jq '{state, merged_as: .mergeCommit.oid}'
   ```

   `MERGED` is what it reads, its `Closes #N` closes the issue, and
   GitHub deletes the release branch itself.

   Then read `lint` and `test` on the commit `main` ends up at before
   tagging, rather than trust the pull request's own green run:

   ```shell
   gh run list --commit "$(git rev-parse origin/main)"
   ```

   a squash creates a commit that is not the one the pull request tested,
   and the merge fires both workflows again from their own `push`
   trigger — a run of its own, not the `pull_request` run already green a
   moment earlier. That trigger is the whole reason `main` keeps one, and
   the run to read is the `push` run on `main`.

1. Rehearse on TestPyPI (see above) from `main`, if this cycle touched the
   publish path — that section says which changes make it worth the run,
   and asks that a skip be stated in the release pull request rather than
   left to be inferred.

1. Tag the release commit on `main` and push the tag. **Name the
   commit**, and read the tag back before pushing it. The values stand
   in a fence of their own with nothing under them to reach, and the
   fence below writes each as `${name:?}` and chains. Both are needed:
   `:?` fails at run time, which the chain propagates, where a parse
   error takes its own `&&` with it. Section 9 of the organization
   standard is the rule.

   ```shell
   version=<the version being released>
   sha=<the sha of the release commit>
   ```

   ```shell
   git tag -s "v${version:?}" -m "release v${version:?}" "${sha:?}" &&
   git show "v${version:?}:pyproject.toml" |
     grep -Fx "version = \"${version:?}\"" &&
   git push origin "v${version:?}"
   ```

   `git tag` with no commit tags whatever HEAD the shell is in, and every
   step above ran in a worktree while the primary checkout sits on another
   branch — so the argumentless form is one `cd` away from tagging the
   commit before the version bump. `version-check` would refuse it,
   comparing the declared version against the tag's and failing the run
   with nothing uploaded, which is the guard doing its job; the `git show`
   above is the same check one step earlier, where it costs nothing, and
   the chain is what makes the push wait on it.

   `version-check` reads the version with `uv version --short`, which
   reads a project directory and so needs the tag checked out. `grep -Fx`
   reads the tag's `pyproject.toml` without one, and matches only the
   whole line `version = "${version}"`, its dots as dots, so a tag on a
   commit that declares another version stops the chain. A tag that does
   not exist stops it too: `git show` prints nothing on its output, and
   `grep` finds no line.

   Where the chain stops at `grep`, which prints nothing, the tag
   `git tag -s` made is still in the local repository: on the wrong
   commit, or under the wrong name where `version` was the wrong value.
   Delete it with `git tag -d "v${version:?}"` while `version` still
   holds the value it was made with, then correct the values and run the
   fence again. A tag left in place makes `git tag -s` refuse the same
   name, as *If something goes wrong* says.

1. Read the tag's signature back from the API, now that it is pushed. It
   answers `true`: an unsigned annotated tag answers `false`, and a
   lightweight tag answers 404 at the second call. `version` is the one
   set above:

   ```shell
   tagsha=$(gh api \
     "repos/btclib-org/${repo:?}/git/refs/tags/v${version:?}" \
     --jq '.object.sha') &&
   gh api "repos/btclib-org/${repo:?}/git/tags/${tagsha:?}" \
     --jq '.verification.verified'
   ```

1. Approve the `pypi` environment when the workflow asks, a red `public-api`
   read first: `Publish to PyPI` lists it in `needs:`, so it has ended by
   then. Up to here nothing is public and the tag can still be deleted; the
   upload that follows is the point of no return — the upload, and not the
   approval, the token exchange happening after it. A registration that does
   not match the claims fails there having uploaded nothing, and a version
   survives a failed exchange: delete the tag, fix the registration, tag
   again.

   A registration that matched once can still go stale on its own — a
   repository rename is enough — without anything here flagging it before
   the upload tries. Where only the token exchange failed, fixing the
   registration and running `gh run rerun <run id> --failed` republishes
   from the artifacts already there; retagging is the right answer only
   when the failure happened before those artifacts existed — see "If
   something goes wrong" below.

   A job that sits `queued` with no runner assigned for tens of minutes,
   on an ordinary `ubuntu-latest` label, past the point where the
   environment approval has already gone through, is not this repository's
   problem to fix: the org's GitHub Actions concurrency is shared across
   every `btclib-org` repository, and a burst of CI elsewhere in the
   organization is enough to queue this one behind it. Confirm
   there is nothing to fix rather than assume it — githubstatus.com green,
   no `pending_deployments` left on the run, no concurrency group of this
   repository's own blocking it — then wait; cancelling or re-dispatching
   a job that is merely queued, not failed, risks a second attempt racing
   the first one into `publish-pypi`.

1. Read the run job by job once it has ended, for `skipped` rather than
   for red. A failed job is loud; a skipped one carries no step, starts
   and completes in the same second, and leaves the run looking finished
   with a job missing from it, which is what a bare `needs:` behind a
   red `public-api` produces — section 12 of the organization standard
   has the rule, and the `github-release` case under "If something goes
   wrong" below is the same mechanism behind a skipped job rather than a
   failed one:

   ```shell
   run=<run id>
   ```

   The assignment stands in a fence of its own, and the fence below
   takes the pair the tagging step explains: inside quotes a placeholder
   is no parse error, so the fence is not its own guard.

   ```shell
   gh api --paginate \
     --jq '.jobs[] | [.conclusion, (.steps|length), .name] | @tsv' \
     "repos/btclib-org/${repo:?}/actions/runs/${run:?}/jobs?per_page=100"
   ```

   On a tag `Publish to TestPyPI` is `skipped`, its trigger being the
   dispatch. `public-api` is red only for the reasons the public API step
   above gives, and otherwise reads `success`; a red one is read before the
   approval, as the approval step says. `Run the lint workflow / lint /
   Dependency review` and `Run the lint workflow / lint / Sign-off` are
   `skipped` on every run, as they run only on a `pull_request`; a tagged
   commit had both checks on its own pull request. Every other job reads
   `success`, the ones behind `public-api` included: each of them opens its
   `if:` with `always()` and names the results it does require, so a red
   `public-api` costs the release nothing, and a `skipped` among them is a
   defect in `release.yml` rather than a red to look past. A rehearsal is the
   mirror image, `Publish to PyPI` skipped and with it whatever is guarded on
   its success, and `documented` skipped on its own account, its guard being
   the push. `gh run rerun` does not reach a skipped job, `--failed` rerunning
   `failure` and `--job` refusing a skip outright, so what recovers one is
   doing by hand what it would have done: for `github-release` the script "If
   something goes wrong" gives, for `published` a dispatch of
   `pypi-install.yml`.

   A dispatch of `pypi-install.yml` passes no version, so it waits for
   nothing and installs what the index serves at the time. Read the
   installed version each cell prints in its log, and dispatch again
   where a cell installed the previous release.

   Read the Docs builds a tag on its first push only: a deleted and
   re-pushed tag is rebuilt by hand from the builds page, and `documented`
   stays red until it is.

1. Install what was just published, in an environment of its own rather
   than one that may already hold it, and run something with it.
   `version` is the one the tagging step set:

   ```shell
   uv run --isolated --no-project --with "${dist:?}==${version:?}" \
     --refresh-package "${dist:?}" \
     python -c "${smoke:?}"
   ```

   from a directory that belongs to no checkout of this project: run
   inside one, uv can answer from a cached build of the tree rather than
   from the index. `--refresh-package` makes uv read the index again
   rather than its cache, which can miss a version just published. The
   pin makes the check test this release: unpinned, an index still
   serving the previous release installs that one, and the smoke test
   passes on it. Pinned, uv answers `No solution found` until the index
   serves the version, and the command is run again then.

   then check the attestations — the JSON API answers `null` for
   `provenance` even where they exist; the simple API,
   `https://pypi.org/simple/<dist>/` with `Accept:
   application/vnd.pypi.simple.v1+json`, carries the real link, under
   `/integrity/<project>/<version>/<filename>/provenance`, and
   `pypi-attestations verify pypi <file> --repository
   https://github.com/btclib-org/<repo>` checks the
   signature rather than merely its presence.

1. Read the `published` job of the release run, which needs no dispatch:
   `release.yml` calls that workflow once PyPI has accepted the files, with
   the tag's version, and it waits for the index to serve that version
   before installing anything — so it cannot pass by testing the release
   before this one. It installs from PyPI on every image `os-ubuntu.yml`,
   `os-macos.yml` and `os-windows.yml` run between them, at the floor of
   the supported interpreter range and at its two newest interpreters,
   each of those beside its free-threaded build, and runs its smoke test.
   From then on it runs weekly on its own, and a failure means the outside
   world moved, not this repository — a new runner image, an interpreter
   release, PyPI serving a file that does not match its own hash — which
   is why it is a workflow of its own rather than a job of this one.

1. Check the GitHub release the previous step's workflow run created —
   **ask for the release itself, not for the run's conclusion**, a
   skipped job being what a green run looks like from the Actions page:

   ```shell
   version=<the released version>
   ```

   Split for the reason the tagging step gives.

   ```shell
   gh release view "v${version:?}" --json name,assets,author
   ```

   `release not found` is the failure "If something goes wrong" ends with.
   `author` is the cheap second question: `github-actions[bot]` is the
   workflow having cut it, any other login a release recreated by hand. Its
   notes are the tag's section of RELEASE_NOTES.md, and the distribution files
   are attached, `<tag>.intoto.jsonl` and the bill of materials beside them. A
   run that logs `RELEASE_NOTES.md has no v<version> section` generated the
   notes from the merged pull requests instead — the fallback `version-check`
   exists to make unreachable, not a second way to write release notes — and
   they are worth replacing by hand if it ever fires.

1. Read the bill of materials attached to the release,
   `<dist>-<version>.cdx.json` with the `-` of `dist` written `_`: a
   CycloneDX 1.6 document naming the distribution, its licence, the two
   files with their SHA-256, and one component per dependency the wheel's
   metadata declares. It is read out of the built wheel and not out of
   `pyproject.toml`, which is what lets a rehearsal describe the `.dev`
   version it actually built. A component that is not a dependency
   `pyproject.toml` declares is one this repository did not mean to ship.
   Attested with the distribution files, so `gh attestation verify` below
   covers it too.

1. Verify the provenance of an asset, which is the release's own and not
   the PEP 740 attestations checked two steps up: those cover the copies
   on the index, these the copies attached here. Both forms, the same
   signature read two ways:

   ```shell
   version=<the released version>
   ```

   ```shell
   signer=btclib-org/.github/.github/workflows/reusable-build.yml &&
   id=$(gh api "repos/btclib-org/${repo:?}" --jq .id) &&
   cert='.[].verificationResult.signature.certificate' &&
   : "${dist:?}" &&
   wheel="${dist//-/_}-${version:?}-py3-none-any.whl" &&
   gh release download "v${version:?}" --repo "btclib-org/${repo:?}" &&
   gh attestation verify "${wheel:?}" --owner btclib-org \
     --signer-workflow "${signer:?}" \
     --source-ref "refs/tags/v${version:?}" --format json \
     --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}" &&
   gh attestation verify "${wheel:?}" --owner btclib-org \
     --signer-workflow "${signer:?}" \
     --source-ref "refs/tags/v${version:?}" --format json \
     --bundle "v${version:?}.intoto.jsonl" \
     --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
   ```

   the first asks the attestations API for the signed statement, the
   second reads it from the asset and asks nothing — which is what the
   bundle is attached for, mirroring the releases page being the case it
   answers. One attestation covers every asset the `attest` job was
   given, so the sdist and the bill of materials verify against the same
   bundle.

   Each command is section 12's verifier. Section 12 of the organization
   standard says what its exit code means, why the signer is named without a
   ref, why `--source-ref` names the tag, why the repository is compared by
   its id, and which workflow signed a release made before this repository
   called `reusable-build.yml`. For a signer that is a reusable workflow,
   `gh attestation verify --help` requires `--signer-workflow` or
   `--signer-repo`. `--owner` alone does not pin the signer: without either
   flag, both forms verify the release. Neither form is offline on its own —
   the Sigstore trusted root comes over the network unless `gh attestation
   trusted-root > trusted_root.jsonl` fetched it earlier and
   `--custom-trusted-root` points at it.

1. **Review the bestpractices.dev answers.** Refresh the saved answers
   in btclib-org/.github with its `.github/scripts/bestpractices.py`,
   and use its `--stale` and `--differ` to find what to read (section 10
   of its README). Read `https://www.bestpractices.dev/projects/<bp>`
   against the release, and update every answer it changed: the release
   notes and the vulnerabilities it fixed, signed tags and assets,
   attestation names. Then refresh the saved answers again. An advisory
   this repository publishes is owed the same review.

1. Open the next cycle: set a generic next version without the day (e.g.
   after 2026.8.6, use 2026.9) in `pyproject.toml`, through a pull
   request like any other. That shape is the one nothing tagged can have,
   so a checkout of `main` between releases reports itself as work in
   progress rather than as a release it is not, and `version-check`
   refuses it should it ever reach a tag — which is a second guard behind
   the heading check, not a replacement for it. Re-lock so `uv.lock`
   agrees:

   ```shell
   uv lock
   ```

   No section is opened here: the next release's pull request writes its
   own. The version cannot move earlier: `version-check` compares the tag
   against what `pyproject.toml` declares, so a tree already bumped would
   offer it the next cycle's month instead of the version being released.

A dependent adapts after the release, as section 12 of the organization
standard says.

## Rebuild a release from its tag

`reusable-build.yml`'s `build` job exports `SOURCE_DATE_EPOCH` from the
commit date and normalizes the sdist, so a rebuild of a released tag is
the same bytes as what was published — that job's own upload is what
`publish-pypi` publishes, unchanged, so "what was published" and "what
that job built" are the same files (issue btclib-org/btclib#1166).
Anyone can check that, and the check is one command short of the
provenance one above: verify the *rebuilt* file rather than a downloaded
one, and it can only pass if the digests agree.

```shell
version=<the released version>
```

The placeholder stands in a fence with nothing under it to reach, and the
fence below writes it `${version:?}` and chains, which is the pair the
tagging step of *Release to PyPI* describes. `SOURCE_DATE_EPOCH` is
exported rather than prefixed onto the build: a prefix binds one
command, and both scripts below read the variable out of their own
environment and refuse to run without it.

```shell
git worktree add --detach "/tmp/${repo:?}-rebuild" "v${version:?}" &&
cd "/tmp/${repo:?}-rebuild" &&
python=$(grep -Ev '^[[:space:]]*(#|$)' .python-version) &&
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct) &&
signer=btclib-org/.github/.github/workflows/reusable-build.yml &&
id=$(gh api "repos/btclib-org/${repo:?}" --jq .id) &&
cert='.[].verificationResult.signature.certificate' &&
: "${dist:?}" &&
stem="${dist//-/_}-${version:?}" &&
wheels=$(mktemp -d) &&
gh release download "v${version:?}" --repo "btclib-org/${repo:?}" \
  --dir "$wheels" --pattern '*.whl' &&
gh attestation verify "$wheels"/*.whl --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref "refs/tags/v${version:?}" --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}" &&
uv_version=$(unzip -p "$wheels"/*.whl '*.dist-info/WHEEL' |
  sed -n 's/^Generator: uv //p') &&
[[ $uv_version =~ ^[0-9]+([.][0-9]+)*$ ]] &&
uvx "uv@$uv_version" build &&
uv run --no-project --python "$python" \
  .github/scripts/normalize_sdist.py dist/ &&
served=$(mktemp -d) &&
git clone --depth 1 --filter=blob:none --sparse \
  https://github.com/btclib-org/.github "$served" &&
git -C "$served" sparse-checkout set .github/scripts &&
uv run --no-project --python "$python" \
  "$served"/.github/scripts/generate_sbom.py dist/ sbom/ &&
gh attestation verify "dist/${stem:?}.tar.gz" --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref "refs/tags/v${version:?}" --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}" &&
gh attestation verify "dist/${stem:?}-py3-none-any.whl" --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref "refs/tags/v${version:?}" --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
```

A release with no `.cdx.json` asset has no bill of materials to verify,
and this last command is left out for it:

```shell
gh attestation verify "sbom/${stem:?}.cdx.json" --owner btclib-org \
  --signer-workflow "${signer:?}" \
  --source-ref "refs/tags/v${version:?}" --format json \
  --jq "${cert:?}.sourceRepositoryIdentifier" | grep -qx "${id:?}"
```

Section 12 of the organization standard names the signer of a release
made before this repository called `reusable-build.yml`.

`python` is the interpreter the tag's own `.python-version` pins, its
comment and blank lines dropped, and not the one `main` pins:
`normalize_sdist.py` writes the sdist again through the running
interpreter's `gzip`, so a rebuild under another pin is the published
bytes only where the two interpreters' zlib compress alike (issue
btclib-org/.github#1349).

`uv_version` is the uv the release job ran, read off the published
wheel once its attestation verifies, so that what is read is signed: its
`.dist-info/WHEEL` names it on the `Generator:` line, where the tag holds
only `[tool.uv] required-version`, a floor `setup-uv` resolves to the
newest uv at release time. The `[[ ]]` holds it to digits and dots
before `uvx` sees it, `uvx` taking a URL or a VCS reference in that
place and running what it fetches. That line is written by the
build, so a wheel built under another uv is another digest (issue
btclib-org/btclib-node#1063). The sdist is verified first, it being the
file the rebuild exists to reproduce: a wheel that still disagrees stops
the chain after that check rather than ahead of it.

The bill of materials is rebuilt with them and verified like them: its
timestamp is `SOURCE_DATE_EPOCH` and its serial number is derived from
the two digests, so it is the same bytes as the released copy — which is
the only reason a third `gh attestation verify` can pass at all. It is
no steadier than the files, though: any of the bounds below that moves a
distribution file's digest moves this document's serial number with it,
so the third command fails wherever the first two do.
`generate_sbom.py` comes from btclib-org/.github's `main`, not from
the tag, so once `main` changes what it writes the third command fails
with the files unchanged.

These things bound that guarantee, and each is worth knowing before
reading a mismatch as tampering:

- **the build reads the working directory, not git.** `uv_build` walks
  the tree through the glob patterns of `[tool.uv.build-backend]`, so an
  *untracked* file matching one of them is packed like any other and
  changes the digest. `tests/**` and `docs/**` are the patterns wide
  enough for that to happen by accident, and `source-exclude` beside them
  names what a linter or a type checker is known to leave there — but the
  rule is the directory, not the list. The worktree the command above
  adds is a clean tree whatever the reader's checkout holds: it has only
  the files the tag tracks, and `git worktree add` refuses a target that
  already holds files.
- **the build backend is the uv's own.** `[build-system] requires`
  names a range rather than a version, and for
  the uv the release ran, which the range admits, `uv build` uses the
  backend built into that uv rather than a `uv_build` resolved from the
  range. That is why the command above runs the release's uv rather than
  the reader's, and why it reproduces the wheel only while that uv can
  still be installed. The sdist's member metadata is `normalize_sdist.py`'s
  answer and not the backend's, which is why the command above runs that
  script and why a rebuild that skips it disagrees with the published
  archive on every member's `mtime`.
- **the rehearsal is a different version, by construction.** A TestPyPI
  dispatch appends `.dev<run*100+attempt>` to the version, so its files are not
  a second build of the release's — they are their own artifact, published
  where they say they are. The attestation the rehearsal writes covers
  those, and no digest is shared with the release.

## If something goes wrong

- The workflow failed before the `publish-pypi` job: nothing was
  uploaded. Delete the tag, fix, and tag again:

  ```shell
  git tag -d v<version>
  git push origin :refs/tags/v<version>
  ```

  Both lines, and the local one is the half that is easy to skip: a tag is
  per-repository where a branch is per-worktree, so deleting it in one
  worktree leaves it in every other, and the `git tag -s` that follows
  answers `fatal: tag 'v<version>' already exists` — from a checkout that
  looks uninvolved. Delete locally wherever it is, then re-create.

- `publish-pypi` itself ran and failed at the token exchange
  (`invalid-publisher`), after the matrix had already built everything:
  nothing was uploaded, but retagging would rebuild what was never at
  fault. Fix the registration and re-run the publish job alone against
  what is already built:

  ```shell
  run=<the release.yml run>
  ```

  Split for the reason the tagging step gives.

  ```shell
  gh run rerun "${run:?}" --failed
  ```

  a fresh approval of the `pypi` environment is still required, the
  protection applying per deployment attempt rather than once per run.
  This is a different case from the one above: there, the workflow never
  reached `publish-pypi`, so there is nothing to re-run and no artifact to
  re-run it against.

- The upload succeeded but the release is broken: PyPI never accepts a
  file name twice, even after deletion. Yank the bad release on PyPI and
  publish a new patch version, a fourth number on the day
  (`2026.8.6` → `2026.8.6.1`).

- Only the `github-release` job failed: the PyPI upload is already done;
  re-run the failed job, or recover by hand from the run's `dist`,
  `sbom` **and** `attestation` artifacts, not `dist` alone — the job
  downloads all three before it writes the release, and a release built
  from `dist` only would carry the wheel and the sdist with no signed
  statement beside them, leaving "Verify the provenance of an asset"
  above nothing to `--bundle` against, and no bill of materials for
  "Read the bill of materials attached to the release" to read. The
  by-hand recovery is the same script the `skipped` case spells out
  next; the difference between the two is only that `gh run rerun
  --failed` reaches a job the run marks *failed*, so it is worth trying
  first here and is not an option there at all.

- `github-release` shows **`skipped`** while `publish-pypi` and `build` both
  report `success`. That is a defect in `release.yml`'s `needs:` or `if:`: a
  job behind a skipped ancestor is skipped unless its own `if:` opens with
  `always()`, so the fix is an explicit `if` on the job that shows the
  symptom. The run's conclusion is `success` and no release exists, which is
  why the step above asks `gh release view` rather than reading the run.
  Recovery is by
  hand: `gh run rerun --job` refuses a skipped job outright (`cannot be
  rerun`), unlike a failed one. Re-running the whole workflow is not the
  fix either: `publish-pypi` would attempt the upload a second time, and
  while PyPI would refuse the existing file names rather than accept a
  duplicate, the attempt itself asks for a fresh approval of the `pypi`
  environment and gates the run on nothing this repository controls. Skip
  the workflow entirely and do by hand what the job's own script does,
  from the artifacts already sitting on the run:

  ```shell
  run=<run id>
  version=<the released version>
  ```

  The assignments stand in a fence of their own, and the fence below
  takes the same pair as the tagging step.

  ```shell
  gh run download "${run:?}" -n dist -D dist &&
  gh run download "${run:?}" -n sbom -D sbom &&
  gh run download "${run:?}" -n attestation -D attestation &&
  curl -fsS "https://pypi.org/pypi/${dist:?}/${version:?}/json" \
    -o pypi.json &&
  python3 -c '
  import hashlib, json, os, sys
  with open("pypi.json") as f:
      urls = json.load(f)["urls"]
  pypi = {u["filename"]: u["digests"]["sha256"] for u in urls}
  local = {}
  for path in sys.argv[1:]:
      with open(path, "rb") as f:
          digest = hashlib.sha256(f.read()).hexdigest()
      local[os.path.basename(path)] = digest
  for name in sorted(pypi.keys() | local.keys()):
      if name not in local:
          print("missing from dist/:", name)
      elif name not in pypi:
          print("not on PyPI:", name)
      elif local[name] != pypi[name]:
          print("digest differs:", name)
      else:
          print("same as PyPI:", name)
  sys.exit(not local or local != pypi)
  ' dist/* &&

  git show "v${version:?}:RELEASE_NOTES.md" > tag-notes.md &&
  awk -v tag="v${version:?}" '
    $0 ~ "^## " tag "( |$)" {found=1; next}
    /^## / && found {exit}
    found && NF {text=1}
    found {print}
    END {
      if (!text) print "RELEASE_NOTES.md has no notes for " tag > "/dev/stderr"
      exit !text
    }
  ' tag-notes.md > notes.md &&
  cp attestation/attestation.jsonl "v${version:?}.intoto.jsonl" &&
  gh release create "v${version:?}" dist/* sbom/* \
    "v${version:?}.intoto.jsonl" \
    --title "v${version:?}" --notes-file notes.md
  ```

  Where the read fails or the tag's section has no notes, the script
  stops before the release exists rather than publish an empty body. The
  job creates the release anyway, as the comment on its step in
  `reusable-github-release.yml` says. `version-check` refuses a tag whose
  section is missing or empty before `build`, so after the upload the
  stop means the read failed: check `version` and the tag. The tag
  cannot change after the upload, so where its section is empty all the
  same, write `notes.md` by hand and run the commands after the awk. The
  awk runs only once the Python step has passed, so its message means
  every file matched PyPI.

  The Python step compares the files `gh release create` attaches from
  `dist/` with the files PyPI holds for `version`, by name and SHA-256,
  and prints what it found for each name. A file only one side has, or a
  digest that differs, stops the script before the release exists: a
  wrong `run` would otherwise attach files PyPI never accepted. A failed
  fetch stops it too, `curl -f` exiting non-zero on an HTTP error.

  A script that stopped leaves the downloaded artifacts behind, and `gh
  run download` refuses to write a file that already exists. Remove them
  before running the script again:

  ```shell
  rm -rf dist sbom attestation
  ```

## This repository in particular

Everything above is the same file in every repository that publishes;
everything below is this one's, and the comparison stops at this heading.

The block the steps above read:

```shell
repo=btclib
dist=btclib
test_dist=btclib
pkg=btclib
rtd=btclib
bp=14253
smoke='from btclib.network import NETWORKS; from ecc.curves import CURVES
print(sorted(NETWORKS), CURVES["secp256r1"].n)'
```

`smoke` reads the files the wheel ships under `_data/`. `import btclib`
runs `__init__.py` alone, and `btclib.network` reads those files by path
when it is first imported, so a wheel missing one passes `import btclib`
and fails here.

The job the steps above call `published` is `pypi-install` in this
tree's `release.yml` (issue #2925).

**`deps-latest`'s `suite-bindings-latest` job is the one to read
closely.** It upgrades btclib-secp256k1 alone and runs the suite, so it
asks whether the newest release of the bindings works with this tree
before the release ships against a pin about to be a version behind. A
release this tree cannot import fails its *Assert the bindings are
serving* step, before the suite. A red test after that step is the
bindings importing and answering differently. Either is a reason to
stop. In every `release.yml` run, the `dist` job asks the same question
of the wheel about to be published, in its *Smoke-test the wheel against
the newest bindings (release only)* step.

**A btclib-org dependency is not drift left to Dependabot.** Before the
release pull request, make sure the newest release of each btclib-org
project `pyproject.toml` requires, in `dependencies` and in the extras,
is the one this release should depend on, and that its floor says so.
Whether the floor resolves, the `dist` job's smoke test answers on every
pull request. Whether it should move, nothing automates: only a person
knows what the sibling's release was for. These floors have no ceiling,
and a sibling can publish on the morning of a release.

**A direct reference is not a requirement a release may carry.** PyPI
refuses `<name> @ git+…` in metadata, and nothing before `publish-pypi`
refuses it: the whole matrix builds and the upload fails at the end. So
a floor is written back over it, `>=` the release that carries what this
tree calls, and the sibling is released first.

**griffe's output here has lines of known shapes.** `Attribute value was
changed: Union[X, Y] -> X | Y` is PEP 604 spelling and breaks nobody, and
`__copyright__` reports the same way when its years change. Each is still
a finding and wants its entry, as the public API step above says. A
systemic change, such as one parameter going keyword-only in every class
that takes it, prints once per site and is one entry in
`RELEASE_NOTES.md`, naming each object it reports. Grouped this way, the
output is short enough to check entry by entry.

**The release pull request also moves the changelog window down by
one.** The release below the one just cut leaves `CHANGELOG.md` for
`changelog/v<version>.md`, its section unchanged under a title and a
line pointing back, and the index in `CHANGELOG.md`'s preamble gains a
link to that file at the top of its list. Past a size ceiling, GitHub's
contents API answers a file with an empty `content` at HTTP 200, and one
file per release keeps each under it (issue #2109).
`tests/changelog_immutability_test.py` holds each archived section to its
tag, so the move copies the text rather than retyping it. Where the
section links a root file, the link is corrected for the directory it
lands in, `./RELEASE_NOTES.md` becoming `../RELEASE_NOTES.md`, and that
edit to sealed text takes a `_KNOWN_DRIFT` entry in that module.

The documentation build to run with the other gates before the merge is
the one `docs/README.rst` gives.

**This tree opens the next cycle as soon as `version-check` is green on
the tag**, not after the publish. Once the tag is pushed, every commit
above the release fails `tests/declared_version_test.py` until the
placeholder lands. It waits for `version-check` because a tag that check
refuses may need a new commit on `main`, and a placeholder already there
would make that commit declare the next cycle. Where a tag deleted after
this step is pushed again on a new commit, as *If something goes wrong*
says, that commit sets `pyproject.toml` back to the release's version,
and the next cycle is opened again once `version-check` is green.

btclib-secp256k1 does not bound a rebuild. It is a runtime dependency,
through ecc's `secp256k1` extra, and the distribution files carry it
only as the pin `uv.lock` brings into the sdist, which is text of the
tag. An isolated build installs `[build-system] requires` and no more,
so the rebuild needs no `uv sync` to produce the published bytes.
