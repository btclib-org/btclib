
[![Build Status](https://travis-ci.org/btclib-org/btclib.svg)](https://travis-ci.org/btclib-org/btclib)
[![ReadtheDocs](https://img.shields.io/readthedocs/btclib.svg)](https://btclib.readthedocs.io)
[![Coverage Status](https://coveralls.io/repos/github/btclib-org/btclib/badge.svg?branch=master)](https://coveralls.io/github/btclib-org/btclib?branch=master)
[![PyPI status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI pyversions](https://img.shields.io/pypi/pyversions/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![GitHub License](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/master/LICENSE)

* * *

[btclib](https://btclib.org) is a
Python3 [type annotated](https://docs.python.org/3/library/typing.html)
library intended for teaching, learning, and using bitcoin,
its blockchain, and the associated elliptic curve cryptography.

Originally developed for the
[_Bitcoin and Blockchain Technology_](https://www.ametrano.net/bbt/)
course at the University of Milano-Bicocca,
btclib is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility; moreover,
some of its algorithms could be broken using side-channel attacks.

* * *

btclib does not have external requirements or dependencies;
to install (and upgrade) it:

```shell
python -m pip install --upgrade btclib
```

The library is rigorously and extensively tested: the test suite
[covers 100%](https://coveralls.io/github/btclib-org/btclib)
of the code base and reproduces results from both informal
and major reference sources. Included features are:

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
  [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
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
  hierarchical deterministic key chains
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  wordlists and mnemonic for generating deterministic keys
- [Electrum](https://electrum.org/#home) standard for mnemonic
- Script encoding/decoding
- nulldata, p2pk, p2ms, p2pkh, p2sh, p2wpkh, and p2wsh ScriptPubKeys
