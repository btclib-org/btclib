# btclib: a bitcoin cryptography library

[![Build Status](https://travis-ci.org/dginst/btclib.svg)](https://travis-ci.org/dginst/btclib)
[![Coverage Status](https://coveralls.io/repos/github/dginst/btclib/badge.svg)](https://coveralls.io/github/dginst/btclib)

[![PyPI status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI version shields.io](https://img.shields.io/pypi/v/btclib.svg)](https://pypi.python.org/pypi/btclib/)

btclib is a python3 type annotated library intended for teaching and demonstration of the cryptography used in bitcoin.

To install (and upgrade) `btclib`:

```shell
python3 -m pip install --upgrade btclib
```

Algorithms are not to be used in production environments: they could be broken using side-channel attacks. Moreover, they will probably have major refactorings without care for backward compatibility.
