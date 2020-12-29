# Tests, code coverage, and profiling

## Required packages

btclib has no required packages, but btclib tests do:
consider installing the required packages in a dedicated virtual environment.

    python -m pip install -r requirements-dev.txt

## Test

Test execution is distributed across multiple cores,
with the default number of cores being eight:
this can be changed in setup.cfg

The ultimate comprehensive way of running the tests is to use tox:

    tox

If you want to contribute to btclib, please ensure that tox succeeds.

Alternatively, one can run pytest with coverage

    pytest --cov-report term-missing:skip-covered --cov=btclib

Coverage results can also be reported as html at htmlcov/index.html:

    coverage html

Finally, the fastest test execution can be accomplished running pytest only

    pytest

Profiling can be obtained with:

    python -m cProfile -s time setup.py test

    python -m cProfile -s cumtime setup.py test

    python -m cProfile -o btclib.prof setup.py test
