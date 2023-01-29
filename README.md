# A Python library for 'bitcoin cryptography'

<!-- markdownlint-disable MD013 -->
| | |
| --- | --- |
| Project | [![status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/) [![license](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/master/LICENSE) |
| Package | [![calver: yyy.m.d](https://img.shields.io/badge/cal_ver-yyyy.m.d-1674b1.svg?logo=calver)](https://calver.org/) [![pypi](https://img.shields.io/pypi/v/btclib.svg?logo=pypi)](https://pypi.python.org/pypi/btclib/) [![downloads](https://static.pepy.tech/badge/btclib)](https://pepy.tech/project/btclib) |
| Supported platforms | [![python](https://img.shields.io/pypi/pyversions/btclib.svg?logo=python)](https://pypi.python.org/pypi/btclib/) |
| Formatting standards | [![lint: isort](https://img.shields.io/badge/lint-isort-yellowgreen.svg?logo=isort)](https://github.com/PyCQA/isort) [![lint: black](https://img.shields.io/badge/lint-black-yellowgreen.svg?logo=black)](https://github.com/psf/black) [![lint: flake8](https://img.shields.io/badge/lint-flake8-yellowgreen.svg?logo=flake8)](<https://github.com/PyCQA/flake8>) [![lint: yesqa](https://img.shields.io/badge/lint-yesqa-yellowgreen.svg?logo=yesqa)](<https://github.com/asottile/yesqa>) [![lint: markdownlint-cli2](https://img.shields.io/badge/lint-markdownlint--cli2-yellowgreen.svg?logo=sourcery)](https://github.com/DavidAnson/markdownlint-cli2) |
| Coding standards | [![lint: pylint](https://img.shields.io/badge/lint-pylint-yellowgreen.svg?logo=pylint)](https://github.com/PyCQA/pylint) [![lint: autoflake](https://img.shields.io/badge/lint-autoflake-yellowgreen.svg?logo=autoflake)](https://github.com/PyCQA/autoflake) [![lint: pyupgrade](https://img.shields.io/badge/lint-pyupgrade-yellowgreen.svg?logo=pyupgrade)](https://github.com/asottile/pyupgrade)  [![lint: sourcery](https://img.shields.io/badge/lint-sourcery-yellowgreen.svg?logo=sourcery)](https://sourcery.ai) [![security: bandit](https://img.shields.io/badge/security-bandit-yellowgreen.svg?logo=bandit)](https://github.com/PyCQA/bandit) |
| Type checking | [![type check: mypy](https://img.shields.io/badge/type_check-mypy-yellowgreen.svg?logo=mypy)](http://mypy-lang.org/) [![type check: pyright](https://img.shields.io/badge/type_check-pyright-yellowgreen.svg)](https://github.com/microsoft/pyright)  |
| Documentation | [![docs](https://readthedocs.org/projects/btclib/badge/?version=latest)](https://btclib.readthedocs.io) [![lint: docformatter](https://img.shields.io/badge/lint-docformatter-yellowgreen.svg?logo=docformatter)](https://github.com/PyCQA/docformatter) [![lint: pydocstringformatter](https://img.shields.io/badge/lint-pydocstringformatter-yellowgreen.svg?logo=pydocstringformatter)](https://github.com/DanielNoord/pydocstringformatter) [![lint: pydocstyle](https://img.shields.io/badge/lint-pydocstyle-yellowgreen.svg?logo=pydocstyle)](https://github.com/PyCQA/pydocstyle)|
| CI/CD | [![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit) [![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib/master.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib/master) [![lint](https://github.com/btclib-org/btclib/actions/workflows/lint.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/lint.yml) [![test](https://github.com/btclib-org/btclib/actions/workflows/test.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/test.yml) [![test-py312](https://github.com/btclib-org/btclib/actions/workflows/test-pydev.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/test-pydev.yml) [![coverage](https://coveralls.io/repos/github/btclib-org/btclib/badge.svg?logo=coveralls)](https://coveralls.io/github/btclib-org/btclib) |
| Conversations | [![slack](https://img.shields.io/badge/slack-btclib_dev-white.svg?logo=slack)](https://bbt-training.slack.com/messages/C01CCJ85AES) [![Follow on Twitter](https://img.shields.io/twitter/follow/btclib?style=social&logo=twitter)](https://twitter.com/intent/follow?screen_name=btclib)|

[Browse GitHub Code Repository](https://github.com/btclib-org/btclib/)

---
<!-- markdownlint-enable MD013 -->

[btclib](https://btclib.org) is a
Python3 [type annotated](https://docs.python.org/3/library/typing.html)
library intended for teaching, learning, and using bitcoin;
the focus is on elliptic curve cryptography and bitcoin's blockchain.

It is rigorously and extensively tested: the test suite
[covers 100%](https://coveralls.io/github/btclib-org/btclib)
of the code base and reproduces results from both informal
and major reference sources.

Originally developed for the
_[Bitcoin and Blockchain Technology](https://www.ametrano.net/bbt/)_
course at the University of Milano-Bicocca,
btclib is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility; moreover,
some of its algorithms could be broken using side-channel attacks.

The library is not limited to the bitcon elliptic curve secp256k1;
anyway, FFI bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
(the optimized C library used by Bitcoin Core)
are available for this curve and used by default.

Included features are:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octets / integer / point / var_int / var_bytes helper functions
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
- [RFC 6979](https://tools.ietf.org/html/rfc6979) for deterministic signature
  schemes
- EC Schnorr signature (according to
  [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki)
  bitcoin standardization)
    - batch validation
    - threshold signature (see test-suite)
    - MuSig multi-signature (see test-suite)
- Borromean ring signature
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
  p2pkh/p2sh, p2wpkh-p2sh, p2wpkh, p2wsh-p2sh, p2wsh and p2tr addresses
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  wordlists and mnemonic for generating deterministic keys
- [Electrum](https://electrum.org/#home) standard for mnemonic
- Script encoding/decoding
- nulldata, p2pk, p2ms, p2pkh, p2sh, p2wpkh, p2wsh and p2tr ScriptPubKeys
- BlockHeader and Block data classes
- OutPoint, TxIn, TxOut, and TX data classes
- legacy, segwit_v0 and taproot transaction hash signatures
- [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
  partially signed bitcoin transactions (PSBT):
  PsbtIn, PbstOut, and Psbt data classes

---

To install (and/or upgrade) btclib:

```shell
python -m pip install --upgrade btclib
```

You might want to install btclib into a
python virtual environment; e.g. from the root folder:

Shell:

```shell
python -m venv venv_btclib
source ./venv_btclib/bin/activate
python -m pip install --upgrade btclib
```

Windows CMD or PowerShell:

```powershell
python -m venv venv_btclib
.\venv_btclib\Scripts\activate
python -m pip install --upgrade btclib
```

Windows Git bash shell:

```bash
python -m venv venv_btclib
cd ./venv_btclib/Scripts
. activate
cd ../..
python -m pip install --upgrade btclib
```

See [CONTRIBUTING](./CONTRIBUTING.md) if you are interested
in btclib develoment.

See [SECURITY](./SECURITY.md) if you have found a security vulnerability.
