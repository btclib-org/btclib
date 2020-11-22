
# A Python library for 'bitcoin cryptography'

[![PyPI pyversions](https://img.shields.io/pypi/pyversions/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-%231674b1.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/imports-isort-%231674b1)](https://timothycrosley.github.io/isort/)
[![Linted with flake8](https://img.shields.io/badge/lint-flake8-%231674b1)](https://flake8.pycqa.org)
[![Linted with pylint](https://img.shields.io/badge/lint-pylint-%231674b1)](https://pylint.pycqa.org)
[![Checked with mypy](https://img.shields.io/badge/type--check-mypy-%231674b1)](http://mypy-lang.org/)
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![Build Status](https://travis-ci.org/btclib-org/btclib.svg)](https://travis-ci.org/btclib-org/btclib)
[![ReadtheDocs](https://img.shields.io/readthedocs/btclib.svg)](https://btclib.readthedocs.io)
[![Coverage Status](https://coveralls.io/repos/github/btclib-org/btclib/badge.svg?branch=master)](https://coveralls.io/github/btclib-org/btclib?branch=master)
[![PyPI status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![GitHub License](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/master/LICENSE)
[![Follow on Twitter](https://img.shields.io/twitter/follow/btclib?style=social&logo=twitter)](https://twitter.com/intent/follow?screen_name=btclib)

[btclib](https://btclib.org) is a
Python3 [type annotated](https://docs.python.org/3/library/typing.html)
library intended for teaching, learning, and using bitcoin,
its blockchain, and the associated elliptic curve cryptography.

It is rigorously and extensively tested: the test suite
[covers 100%](https://coveralls.io/github/btclib-org/btclib)
of the code base and reproduces results from both informal
and major reference sources.

Originally developed for the
[_Bitcoin and Blockchain Technology_](https://www.ametrano.net/bbt/)
course at the University of Milano-Bicocca,
btclib is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility; moreover,
some of its algorithms could be broken using side-channel attacks.

Included features are:

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
- [SLIP132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
  key versions (xprv, yprv, zprv, Yprv, Zprv, tprv, uprv, vprv, and Uprv)
  with corresponding mapping to
  p2pkh/p2sh, p2wpkh-p2sh, p2wpkh, p2wsh-p2sh, and p2wsh addresses
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  wordlists and mnemonic for generating deterministic keys
- [Electrum](https://electrum.org/#home) standard for mnemonic
- Script encoding/decoding
- nulldata, p2pk, p2ms, p2pkh, p2sh, p2wpkh, and p2wsh ScriptPubKeys
- BlockHeader and Block data classes
- OutPoint, TxIn, TxOut, and TX data classes
- legacy and segwit_v0 sighash
- [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
  partially signed bitcoin transactions (PSBT):
  PsbtIn, PbstOut, and Psbt data classes

* * *

To install (and/or upgrade) btclib:

    python -m pip install --upgrade btclib

You might want to install btclib into a
python virtual environment; e.g. from the root folder:

Bash shell

    python -m venv venv
    source ./venv/bin/activate
    pip install --upgrade btclib

Windows CMD or PowerShell:

    python -m venv venv
    .\venv\Scripts\activate
    pip install --upgrade btclib

Windows Git bash shell:

    python -m venv venv
    cd ./venv/Scripts
    . activate
    cd ../..
    pip install --upgrade btclib

Some development tools are required to develop and test btclib;
they can be installed with:

    python -m pip install --upgrade -r requirements-dev.txt

Developers might also consider to install btclib in editable way:

    python -m pip install --upgrade -e ./
