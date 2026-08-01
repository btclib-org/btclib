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

## There is no `slow` marker, and that is a measurement

`addopts` in pyproject.toml passes `--strict-markers`, so a marker has to
be registered before it can be used, and pyproject.toml registers none:
the suite applies no marker of its own, only `parametrize`, 54 times. The
flag is not idle for that — it is what turns a misspelled `skipif` into an
error instead of into a test that silently stops skipping.

The obvious thing to register would be `slow`, for a `-m "not slow"`
developer loop. Measured on this tree: 14681 tests in 17.2 s across the
cores and 79.3 s on one, best of three runs each. The Bitcoin Core vector
files are the biggest thing in here and they are still not the slow part —
8917 of those tests run in 6.8 s — because each vector is its own
parametrized case rather than one loop inside one function, which is what
lets `pytest-xdist` spread them.

What costs is `tests/script_engine/test_python_path.py`, which re-runs the
vector sets through the python implementations of the two functions the
engine takes from the bindings (issue #129). It holds the slowest tests in
the suite — the `tapscript-bigmulti` cases, 3 s each — and 5185 tests
taking 11.2 s on their own: `--ignore` that one file and the remaining
9496 run in 8.8 s. So the saving is no longer "a couple of seconds", and
the case for the marker is a number rather than a shrug. What it would
cost has not changed, and is why none is registered: a plain `uv run
pytest` is the run that has looked at everything, and the file a
`-m "not slow"` loop would skip is the one whose whole purpose is to catch
the python path and the bindings disagreeing about a verdict.

Register one when a test earns it, with the number in the commit message.
The numbers above are this tree's, and they move: `--durations=8` is in
`addopts`, so every run prints the current worst offenders.

## `--dist worksteal`, and the two things that do not help

That lopsidedness is also why `addopts` passes `--dist worksteal` instead
of xdist's default `load`. `load` hands the queue out in chunks, so a
worker that draws several `bigmulti` cases is still going when the others
have nothing left; worksteal lets an idle worker take back what is queued
behind a busy one. Best of three each: **17.2 s against 23.3 s**, the same
14681 tests in the same order.

Two changes that look like they should help, measured rather than assumed,
and neither is in the configuration:

- **scheduling the slow module first**, with a
  `pytest_collection_modifyitems` hook: 22.2 s under worksteal and 32.7 s
  under `load`, both *worse* than leaving collection order alone. Stealing
  already balances the tail, and moving the heavy tests to the front only
  denies it the small work it needs to fill the gaps with.
- **a different `-n`**: 6 → 22.6 s, 8 → 19.9, 12 → 20.7, 16 → 23.4,
  against `auto` (10 on this machine) at 17.2. Fewer workers than cores
  leaves throughput unused; more than cores adds interpreters that only
  compete for the same cores.

One number to keep in mind before reading too much into a wall clock: the
cores are not equivalent. On a 4+6 machine the same 413-test file takes
3.3 s at normal QoS and 15.1 s pinned to the efficiency cores with
`taskpolicy -b`, so ten workers are worth about five performance cores,
not ten.

## Profiling

Profiling can be obtained with:

```shell
uv run python -m cProfile -s time -m pytest
uv run python -m cProfile -s cumtime -m pytest
uv run python -m cProfile -o btclib.prof -m pytest
```
