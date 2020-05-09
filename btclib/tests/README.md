# Tests, code coverage, and profiling

## Required packages

```shell
pip install coverage pytest pytest-cov pytest-xdist
```

## Tests

Test execution is distributed across multiple cores,
with the default number of cores being four:
change it in tox.ini to your preferences

```shell
pytest
```

## Tests with Coverage

```shell
pytest --cov=btclib
```

Coverage results are available as report:

```shell
coverage html
```

and/or html report at htmlcov/index.html:

```shell
coverage html
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
