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
have it there: the suite takes the same time either way on the 3.14
`.python-version` pins, coverage.py using `sys.monitoring` from 3.12 on.

**A run that selects a subset is not gated.** `fail_under` applies to
every report coverage writes, so `uv run pytest tests/bip32` would fail
on the tree's coverage rather than on anything about that run. Naming
paths, `-k` or `-m` therefore drops the threshold to zero:
`coverage_fail_under` in `tests/conftest.py` is where that happens, and
its docstring is why. The report still prints, which is what makes it
worth reading while iterating on one module. Ways of shortening a run
that are not a selection — `--lf`, `--deselect`, an `-x` that stops
early — keep the full threshold and will report a shortfall the tree
does not have.

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
this repository does not ship: a `bitcoind` to talk to, an `hwi` to run,
a device to press a button on. Each test skips itself without the switch
that asks for it, so an ordinary run reports them skipped and says which
switch was off:

```shell
BTCLIB_INTEGRATION=1 uv run pytest tests/integration
```

That runs the regtest flow — btclib exports an account, Core imports it,
Core pays it, btclib builds and signs the spend, and the node accepts the
transaction or the test fails. The node is this session's own: a data
directory under pytest's `tmp_path` and an ephemeral port, so nothing
reaches a node you are running. Name another binary with
`BTCLIB_BITCOIND=/path/to/bitcoind`.

The HWI tests need a device as well, and a second switch for the one that
asks it to sign:

```shell
BTCLIB_INTEGRATION=1 BTCLIB_HWI=hwi BTCLIB_HWI_SIGN=1 \
    uv run pytest tests/integration/hwi_device_test.py -n0
```

`BTCLIB_HWI` is the executable, split on spaces, so an emulator is
reached with `BTCLIB_HWI="hwi --emulators"`. Nothing there is
destructive: enumerate, an xpub, an address on a screen, a signature.

`-n0` because there is one device. `addopts` passes `-n auto`, which is
right for the rest of the suite and wrong here: three workers are three
HWI processes on one device, and the one that reaches it mid-exchange
waits for an answer to somebody else's command until btclib's timeout
ends it.

These tests are outside the coverage ratchet, which `pyproject.toml`
says where it omits them: the ratchet measures what an ordinary run
executes, and a body that skips itself would be an uncovered line at
every commit rather than a defect.

Both halves run unattended, in three jobs across two workflows, and each
job fails if its tests skipped rather than ran. The regtest one is
`integration.yml`'s, and downloads a pinned Core release on every pull
request and weekly. The other two are this module against an emulator,
one vendor each, in `hwi-integration.yml` — a workflow with no
`pull_request` trigger at all, so a firmware release or an emulator that
stopped starting headless never shows up as a check on a review that has
nothing to do with it. They run weekly, on a push to `main`, and on
demand:

```shell
gh workflow run hwi-integration.yml --ref <branch>
```

`HWI against a Trezor emulator` downloads a pinned Model T binary and a
pinned HWI, loads the seed HWI's own suite uses, and sets both switches:
an emulator reached over udp is driven through DebugLink, which answers
the confirmation a person would press, so even the signing test needs
nobody.

`HWI against a Ledger emulator` builds the Bitcoin app from a pinned tag
in Ledger's own builder image and runs it under Speculos. It is the same
module twice, because a Ledger app has its coin compiled in and this
module asks about two: the mainnet build answers the xpub and the
address on the screen, the testnet one signs the regtest spend. What
presses the buttons there is `--automation`, matching the text the app
draws, since Speculos has no DebugLink — the fragile part of that job,
and why its Speculos logs are uploaded with the reports.

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
to make the case for a marker a measurement rather than a shrug:

```shell
uv run pytest --ignore=tests/script_engine/python_path_test.py
uv run pytest -n0                       # what the cores are worth
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
behind a busy one. Worksteal wins that comparison, best of three runs each:

```shell
uv run pytest -p no:randomly --dist load   # the default, to compare with
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

```shell
uv run python -m cProfile -o btclib.prof -m pytest \
    -n0 --no-cov -p no:randomly
uv run python -m pstats btclib.prof   # sort time, stats 30, callers add_jac
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

- **the point arithmetic of `curves/curve_group.py` dominates the self
  time**, and what drives it is the two places that ask for the
  arithmetic the bindings do not do: `python_path_test.py` turns the
  delegation off on purpose, and the low-cardinality tests of `dsa` and
  `ssa` run toy curves `_libsecp256k1_serves` refuses by definition.
  The profile therefore ranks the fallback, and a change meant for what
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

Section 7 of the [organization standard][std] lists eight conventions a
suite can turn into a red test, and says a repository needs the ones its
own prose states rather than all of them. That escape clause is right and
it costs something: an absent convention test reads exactly like a
convention this repository does not have, and a `grep` over `tests/`
cannot tell the two apart — the suites of the organization name the same
idea three different ways, and one of them folds several checks into the
file that is about its single module.

So which of the eight this repository tests is **declared here**, and
`conventions_test.py` asserts the declaration is true: every convention
named below is one of section 7's, every module named exists and holds at
least one test, and the two halves together account for all eight. One
row per module, so a convention answered by more than one file is named
once per file rather than in a row too wide for eighty columns.

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

Not tested here: none.

The calling convention takes three modules because it is three rules —
a keyword-only parameter stays keyword-only, a private signature carries
no default, and a public name promises what the call answers — and
section 7 states it as one bullet. What must not be aligned across the
organization is where these live or what they are called; only which
conventions are tested, and that each tree says which.

[std]: https://github.com/btclib-org/.github/blob/main/README.md
