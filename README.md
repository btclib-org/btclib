# btclib: a python3 library for 'bitcoin cryptography'

[![Build Status](https://travis-ci.org/btclib-org/btclib.svg)](https://travis-ci.org/btclib-org/btclib)
[![ReadtheDocs](https://img.shields.io/readthedocs/btclib.svg)](https://btclib.readthedocs.io)
[![Coverage Status](https://coveralls.io/repos/github/btclib-org/btclib/badge.svg?branch=master)](https://coveralls.io/github/btclib-org/btclib?branch=master)
[![PyPI status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![GitHub License](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/master/LICENSE)

[![btclib logo](https://github.com/btclib-org/btclib/blob/master/img/btclib-logo-40.jpg)](https://github.com/btclib-org)
btclib is a python3 (>=3.8) type annotated library intended for
teaching/learning/using bitcoin, its blockchain,
and the associated elliptic curve cryptography.

It does not have external requirements or dependencies;
to install (and upgrade) it:

```shell
python -m pip install --upgrade btclib
```

Originally developed for the
[_Bitcoin and Blockchain Technology_](https://www.ametrano.net/bbt/)
course at the University of Milano-Bicocca,
the library is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility;
moreover, some of its algorithms could be broken using side-channel attacks.

The library includes:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octets / integer / varint / point conversion functions
- elliptic curve class
  - fast algebra implemented using Jacobian coordinates
  - double scalar multiplication (Straus's algorithm, also known as
    Shamir's trick)
  - multi scalar multiplication (Bos-coster's algorithm)
  - point simmetry solution: odd/even, low/high, and quadratic residue
- elliptic curves: SEC 1 v1 and v2, NIST, Brainpool, and
  low cardinality test curves
- ECDSA signature with (transaction) DER encoding
- ECDSA signature with (message) compact encoding: standard p2pkh and
  [BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)/[Electrum](https://electrum.org/#home)
  extensions to p2wpkh and p2wpkh-p2sh
- EC Schnorr signature (according to
  [bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki)
  bitcoin standardization)
  - batch validation
  - threshold signature (see test-suite)
  - MuSig multi-signature (see test-suite)
- Borromean ring signature
- [RFC 6979](https://tools.ietf.org/html/rfc6979:) to make signature
  schemes deterministic
- Sign-to-contract commitment
- Diffie-Hellman
- Pedersen committment
- Base58 encoding/decoding
- p2pkh/p2sh addresses and WIFs
- Bech32 encoding/decoding
- p2wpkh/p2wsh native SegWit addresses and their legacy p2sh-wrapped versions
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  hierarchical deterministic wallets
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  wordlists and mnemonic for generating deterministic keys
- [Electrum](https://electrum.org/#home) standard for mnemonic
- Script encoding/decoding
- nulldata, p2pk, p2pkh, multi-sig, p2sh, p2wpkh, and p2wsh ScriptPubKeys

A very extensive test suite reproduces results from major official sources
and [covers 100%](https://coveralls.io/github/btclib-org/btclib)
of the library code base.

The library development is actively supported by the [Digital Gold Institute](http://dgi.io)

[![DGI logo](https://dgi.io/img/logo/dgi-logo.png)](http://dgi.io)
