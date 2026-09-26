# Tests, code coverage, and profiling

## Install required packages

```shell
uv sync
```

uv takes care of the virtual environment: every command below runs inside
it, thanks to the `uv run` prefix.

## Test and code coverage

Test execution is distributed across multiple cores,
with the number of cores being chosen automatically:
this can be changed in the addopts option of pyproject.toml

`--cov` is in those addopts, so the whole of it is one command:

```shell
uv run pytest
```

That measures what `tool.coverage.run` in pyproject.toml names, reports
how `tool.coverage.report` says, and is gated at the `fail_under` there.
It is the same measurement the `coverage` job makes — the job cannot gate
on a scope a contributor's run does not have — and it is what a change
has to pass before it is pushed rather than after. It costs nothing to
have it there: the suite takes the same time either way on the
interpreter `.python-version` pins, coverage.py using `sys.monitoring`
from 3.12 on.

**A run that selects a subset is not gated.** `fail_under` applies to
every report coverage writes, so `uv run pytest tests/ecc` would fail
on the tree's coverage rather than on anything about that run. A path
that leaves part of the suite behind, `-k`, `-m`, `--deselect`,
`--ignore`, `--ignore-glob` or `--lf` therefore drops the threshold to
zero: `coverage_fail_under` in `tests/conftest.py` is where that
happens, and its docstring is why. The report still prints, which is
what makes it worth reading while iterating on one module. An `-x` that
stops early is outside the set: what cuts that run short is a failure
and not what the invocation asked for. Section 8 of the organization
standard is what names the set.

`uv run pytest tests` is not a selection either. What decides is whether
the paths named contain every `testpaths` entry, so the directory that
*is* the suite — and anything above it — is gated at the ratchet exactly
like the bare command.

Passing `--cov-fail-under` names the threshold yourself, and outranks
both of those.

Coverage results can also be reported as html at htmlcov/index.html:

```shell
uv run coverage html
```

To run the tests without measuring anything, which is the one way to
make them faster:

```shell
uv run pytest --no-cov
```

## The integration tests, and why they are off by default

`tests/integration/` is the only part of the suite that needs something
this repository does not ship: a `bitcoind` to talk to. Each test skips
itself without the switch that asks for it, so an ordinary run reports
them skipped and says which switch was off:

```shell
BTCLIB_INTEGRATION=1 uv run pytest tests/integration
```

That runs `btclib.coinstats` against the node's own `gettxoutsetinfo`, at
the tip of a chain the test builds, and the p2p handshake: a `Version`
this library serialized, sent over a socket straight at the node's p2p
port, and read back against whatever Core answers with, up to and
including `verack`. The node is this session's own: a data directory under
pytest's `tmp_path` and ephemeral rpc and p2p ports, so nothing reaches a
node you are running. Name another binary with
`BTCLIB_BITCOIND=/path/to/bitcoind`.

These tests are outside the coverage ratchet, which `pyproject.toml`
says where it omits them: the ratchet measures what an ordinary run
executes, and a body that skips itself would be an uncovered line at
every commit rather than a defect.

Both run unattended in `integration-bitcoind.yml`, which fails the job if
its tests skipped rather than ran, and downloads a pinned Core release
weekly, on every pull request and on every push to `main`.

## Fuzzing, and replaying a crash it finds

`tests/fuzz_test.py` is Hypothesis over every parser of the public
surface, part of the ordinary `uv run pytest` above. Coverage-guided
fuzzing is a separate job: `fuzz.yml` runs every `fuzz/fuzz_*.py`
harness with `atheris` under ClusterFuzzLite, weekly and on
`workflow_dispatch`, never on `uv run pytest` and never inside the
coverage ratchet. Atheris 3.1.0 ships no wheel for macOS or aarch64, so
the machine writing the code cannot run a harness with `uv run` the way
the rest of the suite does; what it can still do is replay a crash the
workflow already found, in the same images the workflow used —
`base-builder-python` to build the harness, `base-runner` to run it —
which is what makes the missing wheel irrelevant to reproducing a
finding rather than blocking it.

A crash `fuzz.yml` finds is attached to that run as a GitHub Actions
artifact named `crashes-<fuzzer>` (`<fuzzer>` the crashing
`fuzz/fuzz_*.py` file's own stem), holding the input under a
sanitizer-named directory with a `.summary` beside it carrying the
stack trace. The run id is in the run's own URL, so the two are quoted
for the download call beside them and stand in an assignment block of
their own above it, unset being what an unfilled paste of that block
alone supplies:

```shell
run_id=<run-id>
fuzzer=<fuzzer>
```

```shell
gh run download "${run_id:?}" -n "crashes-${fuzzer:?}"
```

Replaying it needs a checkout of
[google/oss-fuzz](https://github.com/google/oss-fuzz), whose
`infra/helper.py` drives the same build `.clusterfuzzlite/Dockerfile`
describes — `gcr.io/oss-fuzz-base/base-builder-python` — for a
project outside its own `projects/` tree via `--external`
(`google/clusterfuzzlite`'s `docs/build_integration.md`, "Testing
locally", which is where `--external` is spelled;
`google/oss-fuzz`'s `docs/advanced-topics/reproducing.md` has the shape
of `reproduce` and not that flag):

```shell
btclib_checkout=<btclib-checkout>
fuzzer=<fuzzer>
crash_file=<path-to-crash-file>
```

`:?` in the commands below is what makes an unfilled paste stop: the
shell refuses to expand a variable left unset and the command never
runs. Filling the block above is what arms them; deleting the `:?`
disarms them.

```shell
git clone --depth=1 https://github.com/google/oss-fuzz.git
```

```shell
python3 oss-fuzz/infra/helper.py build_fuzzers \
    --external "${btclib_checkout:?}" --sanitizer address
```

```shell
python3 oss-fuzz/infra/helper.py reproduce \
    --external "${btclib_checkout:?}" "${fuzzer:?}" "${crash_file:?}"
```

`reproduce` forwards trailing arguments to the fuzzer's own libFuzzer
binary, which is where minimization comes from — the crashing input
shrunk to what still reproduces it, written back to oss-fuzz's own
`build/out/` for this checkout, the directory `reproduce` mounts as
`/out`. Two things about the invocation are not obvious and both are
`helper.py`'s: `fuzzer_args` is declared `nargs='*'` rather than
`argparse.REMAINDER`, so a first token beginning with `-` is read as an
option to `helper.py` itself and refused — `--` is what ends its own
arguments; and `reproduce_impl` prepends `-runs=100`, which is the
whole minimization budget unless a later `-runs` overrides it, libFuzzer
taking the last occurrence of a flag:

```shell
python3 oss-fuzz/infra/helper.py reproduce \
    --external "${btclib_checkout:?}" "${fuzzer:?}" "${crash_file:?}" \
    -- -minimize_crash=1 -runs=100000
```

What to do with the minimized input from there is `fuzz.yml`'s own
comment and `fuzz/fuzz_*.py`'s: a regression test naming it and the
exception the parser is expected to raise on it.

Not `fuzz/corpus/<name>/`, which is a seed corpus checked into the
tree and asserted still valid by `tests/fuzz_corpus_test.py`; `fuzz.yml`'s
own comment is where the reason a crash cannot live there is argued. The
corpus
a batch run accumulates lives the same way a crash does, a GitHub
Actions artifact named `cifuzz-corpus-<fuzzer>`, `fuzz.yml` naming no
`storage-repo` to keep it in a git branch instead. The prefix is the
difference: `GithubActionsFilestore.upload_corpus` goes through
`_upload_directory`, which prepends `cifuzz-`, where `upload_crashes`
calls `_raw_upload_directory` and does not — so the two names are not
the same shape, and a download asking for the wrong one answers
`no artifact matches any of the names or patterns provided`.

## There is no `slow` marker, and that is a measurement

`addopts` in pyproject.toml passes `--strict-markers`, so a marker has to
be registered before it can be used, and pyproject.toml registers none:
the suite applies no marker pytest does not define itself, `parametrize`
with a few `usefixtures` and a `skipif`, so there is nothing to register.
The flag is not idle for that — it is what turns a misspelled `skipif`
into an error instead of into a test that silently stops skipping.

The obvious thing to register would be `slow`, for a `-m "not slow"`
developer loop. Bitcoin Core's vector files are the biggest thing in here
and they are still not the slow part: each vector is its own parametrized
case rather than one loop inside one function, which is what lets
`pytest-xdist` spread them, and run through the bindings they are cheap
enough that `--durations` rounds most of them to zero.

What costs is `tests/script_engine/python_path_test.py`, which re-runs the
same vector sets through the Python implementations of the two functions
the engine takes from the bindings (issue #129). It holds most of the
suite's slowest cases, the `tapscript-bigmulti` ones, and enough of a run
to make the case for a marker a measurement rather than a shrug. The
second run, serial with `-n0`, is the baseline a plain `uv run pytest`'s
parallel workers are worth against:

```shell
uv run pytest --ignore=tests/script_engine/python_path_test.py
uv run pytest -n0
```

What it would cost is why none is registered: a plain `uv run pytest` is
the run that has looked at everything, and the file a `-m "not slow"` loop
would skip is the one whose whole purpose is to catch the Python path and
the bindings disagreeing about a verdict.

Register one when a test earns it, with the measurement in the commit
message. This file states no test count and no wall clock, for the reason
the changelog states none either: a number in prose is a line that every
commit moving it has to edit, and the ones this section carried had all
stopped being true — which test was the slowest included. The commands
above answer with today's, `--durations=8` is in `addopts` so every run
names the current worst offenders, and `--durations=0 --durations-min=0`
prints the whole distribution rather than the tail above five
milliseconds.

## `--dist worksteal`, and the two things that do not help

That lopsidedness is also why `addopts` passes `--dist worksteal` instead
of xdist's default `load`. `load` hands the queue out in chunks, so a
worker that draws several `bigmulti` cases is still going when the others
have nothing left; worksteal lets an idle worker take back what is queued
behind a busy one. Worksteal wins that comparison against the default
`load`, best of three runs each:

```shell
uv run pytest -p no:randomly --dist load
```

`-p no:randomly` is part of the comparison, not decoration: pytest-randomly
reshuffles on every run, and two schedulers timed over two different orders
are not being compared to each other — a lucky order under `load` beats an
unlucky one under worksteal.

Two changes that look like they should help and do not, neither of them in
the configuration:

- **scheduling the slow module first**, with a
  `pytest_collection_modifyitems` hook that moves that one file's items to
  the front of `items`. Stealing already balances the tail, and
  front-loading the heavy tests only denies it the small work it needs to
  fill the gaps with. The hook is a handful of lines as a `-p` plugin,
  which is how to put the question again to a suite that has grown.
- **a different `-n`**: every value tried, below the core count and above
  it, is slower than `auto`. Fewer workers than cores leaves throughput
  unused; more than cores adds interpreters that only compete for the same
  cores.

Two things make a wall clock here worth less than it looks. The cores are
not equivalent: the same file takes far longer pinned to a machine's
efficiency cores with `taskpolicy -b` than it does at normal QoS, so the
workers `auto` counts are worth fewer cores than they number. And whatever
else runs on the machine takes exactly the difference these comparisons
are about — a `pre-commit` run in another checkout of this repository is
enough to double the baseline. Best of three with nothing else running, or
the number describes the machine rather than pytest.

## Profiling

The second command's interactive browser takes `sort time`, `stats 30`
and `callers add_jac` once it opens:

```shell
uv run python -m cProfile -o btclib.prof -m pytest \
    -n0 --no-cov -p no:randomly
uv run python -m pstats btclib.prof
```

Every flag after `-m pytest` undoes something `addopts` asked for, and
none of them is decoration. `-n0` because xdist runs the tests in child
processes while cProfile measures the parent, which then reports the
suite as time spent waiting on them. `--no-cov` because coverage's
callback is charged to whichever function is running under it. `-p
no:randomly` because two profiles are comparable only if the order that
produced them was.

`-s time` and `-s cumtime` in place of `-o` sort the run and keep
nothing. Saving the file answers both sorts from one run, and answers
what neither of them asks — who called the expensive function, which is
the browser's `callers` on the second line.

What to know before reading one:

- **the point arithmetic of btclib_ecc's `curves/curve_group.py`
  dominates the self time**, and it runs where a test asks for the
  arithmetic the bindings do not do: `python_path_test.py` turns the
  delegation off on purpose, and so does every test comparing the two
  arms. The profile therefore ranks the fallback, and a change meant for what
  a user's secp256k1 call reaches has to be measured on a run that is
  not denying it the bindings.
- **a wrapper is billed for being called.** `double_jac` does nothing but
  call the helper beneath it, and every one of those calls is charged to
  it; `isinstance`, `len` and `list.append` are the same entry from the
  other side, large because everything calls them.
- **`time.sleep` high in the self time is not work**: it is
  `subprocess._wait`, the tests that shell out, and `callers` is what
  says so rather than guesswork.
- **cost per call is a sort the profile does not offer**, and the sort by
  self time buries it: something called a handful of times can be
  expensive in each of them and rank nowhere. Read `ncalls` beside
  `tottime`, or divide one by the other.

## Convention tests

Section 7 of the [organization standard][std] lists conventions a suite
can turn into a red test, and says a repository needs the ones its own
prose states rather than all of them. That escape clause is right and it
costs something: an absent convention test reads exactly like a
convention this repository does not have, and a `grep` over `tests/`
cannot tell the two apart — the suites of the organization name the same
idea three different ways, and one of them folds several checks into the
file that is about its single module.

So which of section 7's conventions this repository tests is **declared
here**, in two halves that together account for every one of them: the
table below and the "Not tested here" line under it.
`conventions_test.py` asserts the declaration is true, and what its
assertions catch is written in that module's docstring, a second list
here being the statement section 9 refuses. One row per module, so a
convention answered by more than one file is named once per file rather
than in a row too wide for eighty columns.

| convention | tested in |
| --- | --- |
| the public surface | `all_test.py` |
| the copyright header | `copyright_test.py` |
| the documentation | `docs_test.py` |
| the import graph | `imports_test.py` |
| the changelog | `release_notes_test.py` |
| the build system | `build_system_test.py` |
| the calling convention | `keyword_only_test.py` |
| the calling convention | `name_contract_test.py` |
| the calling convention | `private_defaults_test.py` |
| input validation | `input_validation_test.py` |

Not tested here: the suite opens no socket.

The calling convention takes three modules because it is three rules —
a keyword-only parameter stays keyword-only, a private signature carries
no default, and a public name promises what the call answers — and
section 7 states it as one bullet. What must not be aligned across the
organization is where these live or what they are called; only which
conventions are tested, and that each tree says which.

[std]: https://github.com/btclib-org/.github/blob/main/README.md
