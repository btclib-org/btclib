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
the suite applies no marker of its own, only `parametrize`, 37 times. The
flag is not idle for that — it is what turns a misspelled `skipif` into an
error instead of into a test that silently stops skipping.

The obvious thing to register would be `slow`, for a `-m "not slow"`
developer loop. Measured on this tree, there is nothing to put behind it:
7936 tests in 10.6 s across the cores, 21 s on one, and the slowest single
test is `test_low_cardinality` at 1.4 s. The Bitcoin Core vector files are
the biggest thing in here and they are not the slow part — 4420 of those
tests run in 3 s — because each vector is its own parametrized case rather
than one loop inside one function, which is what lets `pytest-xdist`
spread them. A marker excluding them would save a couple of seconds and
cost the guarantee that a plain `uv run pytest` ran everything.

Register one when a test earns it, with the number in the commit message.

## Profiling

Profiling can be obtained with:

```shell
uv run python -m cProfile -s time -m pytest
uv run python -m cProfile -s cumtime -m pytest
uv run python -m cProfile -o btclib.prof -m pytest
```
