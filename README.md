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

Algorithms are not to be used in production environments: they could be broken using side-channel attacks. Moreover, they might be subjected to major refactoring without care for backward compatibility.

The library includes:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octet / integer / point conversion functions
- elliptic curve class
  - fast algebra implemented using Jacobian coordinates
  - double scalar multiplication (Shamir's trick)
  - point simmetry solution: odd/even, high/low, and quadratic residue
  - SEC 1 v1 and v2 curves
  - NIST curves
  - low cardinality test curves
- ECDSA signature and DER encoding
- Sign-to-contract notarization
- Schnorr signature (according to bip-schnorr bitcoin standardization)
  - batch validation
  - threshold signature
  - MuSig multi-signature
- Borromean ring signature
- RFC-6979 to make signature schemes deterministic
- base58 encoding, addresses, WIFs
- BIP32 hierarchical deterministic wallets
- BIP39 mnemonic code for generating deterministic keys
- Electrum standard for mnemonic code
- EC Diffie-Hellman
- Pedersen Committment

A very extensive test suite reproduces results from major official sources and cover basically 100% of the library code base.
