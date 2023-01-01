# Tests, code coverage, and profiling

## Install required packages

```shell
python -m pip install -r requirements-dev.txt
```

Consider installing the required packages in a dedicated virtual environment.

## Test and code coverage

Test execution is distributed across multiple cores,
with the default number of cores being eight:
this can be changed in setup.cfg

The ultimate comprehensive way of running the tests is to use tox:

```shell
tox
```

If you want to contribute to btclib, please ensure that tox succeeds.

Alternatively, one can run pytest with coverage

```shell
pytest --cov-report term-missing:skip-covered --cov=btclib
```

Coverage results can also be reported as html at htmlcov/index.html:

```shell
coverage html
```

Finally, the fastest test execution can be accomplished running pytest only

```shell
pytest
```

## Profiling

Profiling can be obtained with:

```shell
python -m cProfile -s time setup.py test
python -m cProfile -s cumtime setup.py test
python -m cProfile -o btclib.prof setup.py test
```
