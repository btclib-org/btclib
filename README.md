# A Python library for 'bitcoin cryptography'

<!-- The badges are what the reader decides with: the first line says what
this is and whether it can be used, the second whether it works. A badge
that reports no state -- "we use ruff", "we use uv" -- reports a choice
instead, and those are in CONTRIBUTING.md, beside the prose that says how
the choice is enforced. One badge per line keeps a change to one line and
every line inside MD013; the site renders the line break as a space, its
kramdown having hard_wrap off. -->
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg?logo=pypi)](https://pypi.python.org/pypi/btclib/)
[![downloads](https://static.pepy.tech/badge/btclib)](https://pepy.tech/project/btclib)
[![development status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![license](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/master/LICENSE)
[![supported Python versions](https://img.shields.io/pypi/pyversions/btclib.svg?logo=python)](https://pypi.python.org/pypi/btclib/)

[![test workflow status](https://github.com/btclib-org/btclib/actions/workflows/test.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/test.yml)
[![lint workflow status](https://github.com/btclib-org/btclib/actions/workflows/lint.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/lint.yml)
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib/master.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib/master)
[![documentation build](https://readthedocs.org/projects/btclib/badge/?version=latest)](https://btclib.readthedocs.io)

[![GitHub repository: btclib-org/btclib](https://img.shields.io/badge/GitHub-btclib--org%2Fbtclib-181717?logo=github)](https://github.com/btclib-org/btclib/)
[![slack: btclib_dev](https://img.shields.io/badge/slack-btclib_dev-white.svg?logo=slack)](https://bbt-training.slack.com/messages/C01CCJ85AES)

---

[btclib](https://btclib.org) is a Python3
[type annotated](https://docs.python.org/3/library/typing.html) library
for teaching, learning and using bitcoin, focused on elliptic curve
cryptography and bitcoin's blockchain. It started as a teaching tool for
Ferdinando Ametrano's
*[Bitcoin and Blockchain Technology](https://www.ametrano.net/bbt/)*
course, it is used in production today (still marked as beta
because it is often refactored for improved clarity).

The test suite covers virtually the whole code base, a floor the build
enforces, and it answers to vectors their authors publish: the BIPs' and
the SLIPs' own, Bitcoin Core's script, transaction, sighash and
key-encoding files, HWI's, trezor's for BIP39 and SLIP39, and Appendix A.2
of RFC 6979. `tests/_data/README.md` pins each vendored file to the
upstream commit it was copied from, and says whether the two still match —
including the few vectors that are btclib's own, having no upstream.

The library is not limited to secp256k1, and for that curve it always
calls
[btclib_libsecp256k1](https://github.com/btclib-org/btclib-libsecp256k1),
FFI bindings to Bitcoin Core's optimized C library
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). They are a
required dependency and not an optional accelerator, so installing btclib
needs one of their wheels or a C toolchain. The Python arithmetic serves
every other curve, and the suite validates it against the bindings:
libsecp256k1 says what the right answer is, being what bitcoin consensus
relies on.

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
    - [MuSig2](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki)
      multi-signature: key aggregation with plain and x-only tweaking,
      nonce aggregation, partial signatures and their aggregation, one
      primitive per round of the protocol
- Borromean ring signature
- Sign-to-contract commitment
- Diffie-Hellman, and the x-only ECDH on the
  [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki)
  ElligatorSwift encoding of a public key
- ECIES in the BIE1 layout, the block cipher supplied by the caller
- Pedersen commitment
- Base58 encoding/decoding
- p2pkh/p2sh addresses and WIFs
- Bech32 encoding/decoding
- p2wpkh/p2wsh native segwit addresses and their legacy p2sh-wrapped versions
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  hierarchical deterministic key chains
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  mnemonic for generating deterministic keys, in the twelve wordlists of
  the reference implementation, with the language read off the words
- [Electrum](https://electrum.org/#home) standard for mnemonic, in the
  five wordlists Electrum reads
- [SLIP39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
  Shamir backup: a master secret split into mnemonic shares, of which a
  threshold number recovers it
- [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
  address from an extended key and a
  `m/purpose'/coin_type'/account'/change/address_index` path, the purpose
  selecting the encoding: 44 p2pkh, 49 p2wpkh-p2sh, 84 p2wpkh (BIP84),
  86 p2tr (BIP86)
- [SLIP132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
  key versions (xprv, yprv, zprv, Yprv, Zprv, tprv, uprv, vprv, and Uprv)
  with corresponding mapping to
  p2pkh/p2sh, p2wpkh-p2sh, p2wpkh, p2wsh-p2sh, p2wsh and p2tr addresses
- Script encoding/decoding
- nulldata, p2pk, p2ms, p2pkh, p2sh, p2wpkh, p2wsh and p2tr ScriptPubKeys
- a script engine: a transaction verified against the consensus rules,
  legacy, segwit and tapscript, with Bitcoin Core's own vectors behind it
- [BIP380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
  output descriptors: the checksum, the parser, the scripts a descriptor
  names, and the spend
- [BIP379](https://github.com/bitcoin/bips/blob/master/bip-0379.md)
  miniscript, read, written and spent: the expression compiled to a script,
  a script read back into the expression it is, the type system that says
  an expression is well formed, the bounds a spend of it is analysed by,
  and the non-malleable witness that satisfies it
- OutPoint, TxIn, TxOut, and TX data classes
- legacy, segwit_v0 and taproot transaction hash signatures
- BlockHeader and Block data classes
- merkle proofs verified against a header's merkle root
- proof-of-work arithmetic: compact targets, retargeting, work, hash rate
- [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
  partially signed bitcoin transactions (PSBT):
  PsbtIn, PsbtOut, and Psbt data classes, with the taproot fields of
  [BIP371](https://github.com/bitcoin/bips/blob/master/bip-0371.mediawiki)
  and the MuSig2 ones of
  [BIP373](https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki)
- [BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
  PSBT version 2, the unsigned transaction computed from the fields rather
  than carried as one: the lock time its inputs require, the identifier
  that ignores their sequences, the modifiable flags a Constructor must
  obey, and conversion either way
- [BIP21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
  `bitcoin:` payment URIs
- fee rates carrying their unit (sat/kvB and sat/vB), the fee a virtual
  size owes at one, and the dust threshold of any output type, computed as
  Bitcoin Core computes it rather than tabulated
- keystore: the addresses an extended key or a set of individual keys has
  handed out, the derivation path of each, and the private key that signs
  for one — what `sign(address, msg)` needs
- an external signer behind one contract, with Bitcoin Core's
  [HWI](https://github.com/bitcoin-core/HWI) behind it for a hardware
  wallet
- a chain backend behind one interface — a transaction by id, the output
  an outpoint names, the chain tip — over a full node's JSON-RPC or a
  block explorer's HTTP api

---

## Module layout

Three pairs of modules are one idea split in two, and each split runs one
way only:

| the codec / the arithmetic | the bitcoin semantics on top |
| --- | --- |
| `btclib.curves` — `Curve`, `mult` | `btclib.ecc` — `dsa`, `ssa`, `bms` |
| `btclib.base58` — the encoding | `btclib.b58` — WIF, p2pkh, p2sh |
| `btclib.bech32` — the encoding | `btclib.b32` — p2wpkh, p2wsh, p2tr |

The right column imports the left one; the left never imports the right.

So `from btclib.ecc import dsa` for a signature,
`from btclib.curves import mult` for a point multiplication, `btclib.b58`
for an address, `btclib.base58` for the encoding on its own. Each of the
six modules says the same in its own docstring.

The rest, roughly bottom-up. `alias` holds the types the public API
accepts, much of it taking anything convertible rather than one type, and
`exceptions` the errors it raises. `to_prv_key` and `to_pub_key` accept
any key representation and hand back one. `bip32` and `mnemonic` derive
keys. `script`, `tx`, `block` and `psbt` build and validate what goes on
the chain, and `script.engine` runs a transaction against the consensus
rules.

Above them, `bip44` composes `bip32`, `script.taproot` and both address
encodings into an address from an extended key and a derivation path, and
`descriptors` reads the BIP380 grammar and hands back the scripts a
descriptor names -- with `descriptors.miniscript` reading BIP379's
language, which is a script written as a tree of fragments, and
satisfying one. `psbt_signer`
is the contract an external signer answers; `hwi` is that contract over
Bitcoin Core's HWI.

Nothing in the library imports `bip21`, `slip132`, `fee`, `keystore`,
`hwi` or `fetch`: they are the top of the stack, and `fetch` is the only
one that goes out to the network. `keystore` remembers which addresses
`bip44` has handed out and signs for one with `ecc.bms`.

The rpc client `fetch` speaks through is not in that stack: it is
[bitcoin-core-rpc](https://github.com/btclib-org/bitcoin-core-rpc), a
package of its own that btclib depends on — one file, standard library
only, installable or copyable, and usable by anyone who wants a node
client and no bitcoin library. `btclib.fetch` turns its answers into `Tx`
and `TxOut`, and checks the chain the node reports against the network
those are labelled for.

The dependency stops at `btclib/fetch/`. bitcoin-core-rpc declares its own
`FetchError`, importing nothing of btclib's being what lets its file be
vendored, and `btclib.fetch.fetcher.client_errors` re-raises it as
`btclib.exceptions`' own, with the `status` and the `code` carried across:
an `except FetchError` written against btclib catches what a fetcher
raises, and no module outside that package loads `urllib.request`.
Constructing a client opens no socket; the first call does.

---

To install, or upgrade:

```shell
python -m pip install --upgrade btclib
```

In a virtual environment:

```shell
python -m venv venv_btclib
source venv_btclib/bin/activate
python -m pip install --upgrade btclib
```

On Windows the second line is `venv_btclib\Scripts\activate` in CMD and
PowerShell, `source venv_btclib/Scripts/activate` in Git bash.

[CONTRIBUTING](./CONTRIBUTING.md) is for development,
[SECURITY](./SECURITY.md) for reporting a vulnerability.
