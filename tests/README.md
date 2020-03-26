# Coverage

```shell
python -m pip install --upgrade pip
python -m pip install --upgrade setuptools coverage

coverage run --source=btclib setup.py test
coverage report -m
coverage html
```

if you prefer to see the report in a webpage, also add:

```shell
coverage html
```

then see htmlcov/index.html
