# btclib: a 'bitcoin cryptography' library

<http://github.com/dginst/btclib>

[![Build Status](https://travis-ci.org/dginst/btclib.svg)](https://travis-ci.org/dginst/btclib)
[![Coverage Status](https://coveralls.io/repos/github/dginst/btclib/badge.svg)](https://coveralls.io/github/dginst/btclib)
[![PyPI status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![GitHub License](https://img.shields.io/github/license/dginst/btclib.svg)](https://github.com/dginst/btclib/blob/master/LICENSE)

btclib is a python3 type annotated library intended for teaching and demonstration of the elliptic curve cryptography used in bitcoin.

It does not have external requirements or dependencies; to install (and upgrade) it:

```shell
python3 -m pip install --upgrade btclib
```

Originally developed for the [_Bitcoin and Blockchain Technology Course_](https://www.ametrano.net/bbt/) at Milano Bicocca and Politecnico di Milano, its algorithms are not intended for production environments: they could be broken using side-channel attacks; moreover, they might be subjected to major refactoring without care for backward compatibility.

The library includes:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octet / integer / point conversion functions
- elliptic curve class
  - fast algebra implemented using Jacobian coordinates
  - double scalar multiplication (Straus's algorithm, also known as Shamir's trick)
  - multi scalar multiplication (Bos-coster's algorithm)
  - point simmetry solution: odd/even, high/low, and quadratic residue
  - available curves: SEC 1 v1 and v2, NIST, Brainpool, and low cardinality test curves
- DSA signature and DER encoding
- Schnorr signature (according to bip-schnorr bitcoin standardization)
  - batch validation
  - threshold signature
  - MuSig multi-signature
- Borromean ring signature
- RFC-6979 to make signature schemes deterministic
- sign-to-contract notarization
- Diffie-Hellman
- Pedersen Committment
- base58 encoding, addresses, WIFs
- BIP32 hierarchical deterministic wallets
- BIP39 mnemonic code for generating deterministic keys
- [Electrum](https://electrum.org/#home) standard for mnemonic code

A very extensive test suite reproduces results from major official sources and covers basically 100% of the library code base.
