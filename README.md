# A Python library for 'bitcoin cryptography'

<!-- markdownlint-disable MD013 -->
| | |
| --- | --- |
| Project | [![status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/) [![license](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/master/LICENSE) |
| Package | [![uv](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/uv/main/assets/badge/v0.json)](https://github.com/astral-sh/uv) [![calver: yyy.m.d](https://img.shields.io/badge/cal_ver-yyyy.m.d-1674b1.svg?logo=calver)](https://calver.org/) [![pypi](https://img.shields.io/pypi/v/btclib.svg?logo=pypi)](https://pypi.python.org/pypi/btclib/) [![downloads](https://static.pepy.tech/badge/btclib)](https://pepy.tech/project/btclib) |
| Supported platforms | [![python](https://img.shields.io/pypi/pyversions/btclib.svg?logo=python)](https://pypi.python.org/pypi/btclib/) |
| Formatting standards | [![format: ruff](https://img.shields.io/badge/format-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/formatter/) [![lint: markdownlint-cli2](https://img.shields.io/badge/lint-markdownlint--cli2-yellowgreen.svg?logo=markdown)](https://github.com/DavidAnson/markdownlint-cli2) |
| Coding standards | [![lint: ruff](https://img.shields.io/badge/lint-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/) |
| Type checking | [![type check: mypy](https://img.shields.io/badge/type_check-mypy-yellowgreen.svg?logo=mypy)](https://mypy-lang.org/) |
| Documentation | [![docs](https://readthedocs.org/projects/btclib/badge/?version=latest)](https://btclib.readthedocs.io) [![lint: ruff](https://img.shields.io/badge/docstrings-ruff-yellowgreen.svg?logo=ruff)](https://docs.astral.sh/ruff/rules/#pydocstyle-d) |
| CI/CD | [![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://github.com/pre-commit/pre-commit) [![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib/master.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib/master) [![lint](https://github.com/btclib-org/btclib/actions/workflows/lint.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/lint.yml) [![test](https://github.com/btclib-org/btclib/actions/workflows/test.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/test.yml) |
| Conversations | [![slack](https://img.shields.io/badge/slack-btclib_dev-white.svg?logo=slack)](https://bbt-training.slack.com/messages/C01CCJ85AES) [![Follow on Twitter](https://img.shields.io/twitter/follow/btclib?style=social&logo=twitter)](https://twitter.com/intent/follow?screen_name=btclib) |

[Browse GitHub Code Repository](https://github.com/btclib-org/btclib/)

---
<!-- markdownlint-enable MD013 -->

[btclib](https://btclib.org) is a
Python3 [type annotated](https://docs.python.org/3/library/typing.html)
library intended for teaching, learning, and using bitcoin;
the focus is on elliptic curve cryptography and bitcoin's blockchain.

It is rigorously and extensively tested: the test suite covers
virtually the whole code base, a floor the build enforces, and
reproduces results from both informal and major reference sources.

Originally developed for the
_[Bitcoin and Blockchain Technology](https://www.ametrano.net/bbt/)_
course at the University of Milano-Bicocca,
btclib is not intended for production environments:
it is often refactored for improved clarity,
without care for backward compatibility; moreover,
some of its algorithms could be broken using side-channel attacks.

The library is not limited to the bitcoin elliptic curve secp256k1;
for that curve, though, it always relies on
[btclib_libsecp256k1](https://github.com/btclib-org/btclib_libsecp256k1),
FFI bindings to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1)
(the optimized C library used by Bitcoin Core):
they are a required dependency, not an optional accelerator, so
installing btclib needs either one of their wheels or a C toolchain to
build them. The python implementation is what every other curve uses,
and the test suite validates it against the bindings: it is libsecp256k1
that says what the right answer is, being the implementation bitcoin
consensus itself relies on.

Included features are:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octets / integer / point / var_int / var_bytes helper functions
- elliptic curve class
    - fast algebra implemented using Jacobian coordinates
    - double scalar multiplication (Straus's algorithm, also known as
      Shamir's trick)
    - multi scalar multiplication (Bos-coster's algorithm)
    - point symmetry solution: odd/even, low/high, and quadratic residue
    - elliptic curves: SEC 1 v1 and v2, NIST, Brainpool, and
      low cardinality test curves
- ECDSA signature with (transaction) DER encoding
- ECDSA signature with (message) compact encoding: standard p2pkh and
  [BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)/[Electrum](https://electrum.org/#home)
  extensions to p2wpkh and p2wpkh-p2sh
- [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) for deterministic signature
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
- Pedersen commitment
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

## Module layout

Three pairs of modules are one idea split in two, and each split runs one
way only. Knowing which half is which is most of finding your way around:

| the codec / the arithmetic | the bitcoin semantics on top |
| --- | --- |
| `btclib.curves` — `Curve`, `mult` | `btclib.ecc` — `dsa`, `ssa`, `bms` |
| `btclib.base58` — the encoding | `btclib.b58` — WIF, p2pkh, p2sh |
| `btclib.bech32` — the encoding | `btclib.b32` — p2wpkh, p2wsh, p2tr |

The right column imports the left one; the left never imports the right.

So `from btclib.ecc import dsa` for a signature and
`from btclib.curves import mult` for a point multiplication; `btclib.b58`
for an address and `btclib.base58` only if you want the encoding on its
own. It is the split the standard library draws between `base64` and
whatever uses it. Each of the six modules repeats the rule in its own
docstring.

`btclib.curves` was `btclib.ec` up to and including 2023.7.12 — one
character from `btclib.ecc`, which is why it was renamed. Nothing else
about it changed: every name it exports is the name it exported before.

The rest, roughly bottom-up: `to_prv_key` and `to_pub_key` accept any key
representation and hand back one; `bip32` and `mnemonic` derive keys;
`script`, `tx`, `block` and `psbt` build and validate what goes on the
chain. `bip21` parses and builds `bitcoin:` payment URIs, and sits on top
of everything: it imports `b58`, `b32`, `amount` and `network`, and nothing
in the library imports it.

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
in btclib development.

See [SECURITY](./SECURITY.md) if you have found a security vulnerability.
