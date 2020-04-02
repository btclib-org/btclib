# Code coverage and profiling

## Coverage

```shell
python -m pip install --upgrade pip
python -m pip install --upgrade setuptools coverage

coverage run --source=btclib setup.py test
coverage report -m
```

if you prefer to see the report in a webpage, also add:

```shell
coverage html
```

then see htmlcov/index.html

## Profile

```shell
 python -m cProfile -s tottime setup.py test
```

```shell
 python -m cProfile -s time setup.py test
```

```shell
 python -m cProfile -o btclib.prof setup.py test
```
