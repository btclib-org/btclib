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

The ultimate comprehensive way of running the tests is

```shell
uv run pytest --cov-report term-missing:skip-covered --cov=btclib --cov=tests
```

If you want to contribute to btclib, please ensure that it succeeds.

Coverage results can also be reported as html at htmlcov/index.html:

```shell
uv run coverage html
```

Finally, the fastest test execution can be accomplished running pytest only

```shell
uv run pytest
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
BTCLIB_INTEGRATION=1 BTCLIB_HWI=hwi BTCLIB_HWI_SIGN=1 uv run pytest tests/integration
```

`BTCLIB_HWI` is the executable, split on spaces, so an emulator is
reached with `BTCLIB_HWI="hwi --emulators"`. Nothing there is
destructive: enumerate, an xpub, an address on a screen, a signature.

These tests are outside the coverage ratchet, which `pyproject.toml`
says where it omits them: the ratchet measures what an ordinary run
executes, and a body that skips itself would be an uncovered line at
every commit rather than a defect.

The regtest flow does run unattended: the `integration` workflow
downloads a pinned Core release weekly and on demand, and fails if a
regtest test skipped rather than ran. The HWI half does not — a device
or an emulator is a thing to keep working rather than a tarball to
download, which is issue #529.

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

Profiling can be obtained with:

```shell
uv run python -m cProfile -s time -m pytest
uv run python -m cProfile -s cumtime -m pytest
uv run python -m cProfile -o btclib.prof -m pytest
```
