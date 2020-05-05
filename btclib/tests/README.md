# Tests, code coverage, and profiling

## Tests

```shell
python -m unittest discover
```

## Coverage

```shell
python -m pip install --upgrade pip setuptools coverage

coverage run -m unittest discover
coverage report -m
```

if you prefer to see the report in a webpage, also add:

```shell
coverage html
```

then see htmlcov/index.html

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
