# Tests, code coverage, and profiling

## Required packages

```shell
pip install coverage pytest pytest-cov pytest-xdist
```

## Tests

Test execution is distributed across multiple cores,
with the default number of cores being four:
this can be changed in setup.cfg

```shell
pytest
```

## Tests with Coverage

```shell
pytest --cov-report term-missing:skip-covered --cov=btclib
```

Coverage results can also be reported as html at htmlcov/index.html:

```shell
coverage html
```

## Test with tox

The ultimate comprehensive way of running the tests is to use tox

```shell
tox
```

## Profile

```shell
python -m cProfile -s time setup.py test
```

```shell
python -m cProfile -s cumtime setup.py test
```

```shell
python -m cProfile -o btclib.prof setup.py test
```
