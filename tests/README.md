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
developer loop. Measured on this tree: 12449 tests in 21.9 s across the
cores and 85.3 s on one, best of three runs each. The Bitcoin Core vector
files are the biggest thing in here and they are still not the slow part —
7709 of those tests run in 4.4 s — because each vector is its own
parametrized case rather than one loop inside one function, which is what
lets `pytest-xdist` spread them.

What costs is `tests/script_engine/test_python_path.py`, which re-runs the
vector sets through the python implementations of the two functions the
engine takes from the bindings (issue #129). It holds the slowest six
tests in the suite — `tapscript-bigmulti`, 3 to 5 s each — and 4169 tests
taking 13.2 s on their own, which is half the wall clock: `--ignore` that
one file and the remaining 8280 run in 10.4 s. So the saving is no longer
"a couple of seconds", and the case for the marker is now a number rather
than a shrug. What it would cost has not changed, and is why none is
registered: a plain `uv run pytest` is the run that has looked at
everything, and the file a `-m "not slow"` loop would skip is the one
whose whole purpose is to catch the python path and the bindings
disagreeing about a verdict.

Register one when a test earns it, with the number in the commit message.
The numbers above are this tree's, and they move: `--durations=8` is in
`addopts`, so every run prints the current worst offenders.

## Profiling

Profiling can be obtained with:

```shell
uv run python -m cProfile -s time -m pytest
uv run python -m cProfile -s cumtime -m pytest
uv run python -m cProfile -o btclib.prof -m pytest
```
