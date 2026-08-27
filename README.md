# A Python library for 'bitcoin cryptography'

<!-- The badges are what the reader decides with, in three groups: what the
software is and whether it can be used, whether it works, and how it is
run as a project. At the end, the OpenSSF badges.

Inside the second group the gates come first, in the order a commit meets
them, and the sentinels follow in the order section 10 of the
organization standard schedules them -- the badge order *is* the calendar
order over that subset, which is why the two move together or not at all.
The day and hour each sentinel owns live in that section and are not
copied here: a reader wanting the schedule reads it there, where it is
still true.

One badge per line keeps a change to one line and every line inside MD013,
whose 80 columns bind only where a space follows them.

A badge that reports no state -- "we use ruff", "we use uv" -- reports a
choice instead, and those are in CONTRIBUTING.md, beside the prose that
says how the choice is enforced.
-->
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg?logo=pypi)](https://pypi.python.org/pypi/btclib/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/releases)
[![development status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![license](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/btclib)](https://pepy.tech/project/btclib)
[![supported Python versions](https://img.shields.io/pypi/pyversions/btclib.svg?logo=python)](https://pypi.python.org/pypi/btclib/)
[![implementation](https://img.shields.io/pypi/implementation/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![wheel](https://img.shields.io/pypi/wheel/btclib.svg)](https://pypi.python.org/pypi/btclib/)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib/main)
[![lint workflow status](https://github.com/btclib-org/btclib/actions/workflows/lint.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/lint.yml)
[![test workflow status](https://github.com/btclib-org/btclib/actions/workflows/test.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/test.yml)
[![docs workflow status](https://github.com/btclib-org/btclib/actions/workflows/docs.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/docs.yml)
[![documentation build](https://app.readthedocs.org/projects/btclib/badge/?version=latest)](https://btclib.readthedocs.io)
[![vendored-vectors workflow status](https://github.com/btclib-org/btclib/actions/workflows/vendored-vectors.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/vendored-vectors.yml)
[![mutation workflow status](https://github.com/btclib-org/btclib/actions/workflows/mutation.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/mutation.yml)
[![fuzz workflow status](https://github.com/btclib-org/btclib/actions/workflows/fuzz.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/fuzz.yml)
[![integration-bitcoind workflow status](https://github.com/btclib-org/btclib/actions/workflows/integration-bitcoind.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/integration-bitcoind.yml)
[![integration-hwi workflow status](https://github.com/btclib-org/btclib/actions/workflows/integration-hwi.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/integration-hwi.yml)
[![deps-latest workflow status](https://github.com/btclib-org/btclib/actions/workflows/deps-latest.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/deps-latest.yml)
[![pypi-install workflow status](https://github.com/btclib-org/btclib/actions/workflows/pypi-install.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/pypi-install.yml)
[![py-arm-authority workflow status](https://github.com/btclib-org/btclib/actions/workflows/py-arm-authority.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/py-arm-authority.yml)
[![os-macos workflow status](https://github.com/btclib-org/btclib/actions/workflows/os-macos.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/os-macos.yml)
[![os-ubuntu workflow status](https://github.com/btclib-org/btclib/actions/workflows/os-ubuntu.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/os-ubuntu.yml)
[![os-windows workflow status](https://github.com/btclib-org/btclib/actions/workflows/os-windows.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/os-windows.yml)
[![links workflow status](https://github.com/btclib-org/btclib/actions/workflows/links.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/links.yml)
[![codeql workflow status](https://github.com/btclib-org/btclib/actions/workflows/codeql.yml/badge.svg)](https://github.com/btclib-org/btclib/actions/workflows/codeql.yml)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/btclib/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/btclib)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14253/badge)](https://www.bestpractices.dev/projects/14253)

---

[btclib](https://btclib.org) is a Python
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
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1),
FFI bindings to Bitcoin Core's optimized C library
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). They are the
recommended install and what `pip install "btclib[secp256k1]"` asks for,
needing one of their wheels or a C toolchain; without them btclib still
answers, on the Python arithmetic, tens of times more slowly and not in
constant time — `SECURITY.md` publishes both. That Python arithmetic
serves every other curve anyway, and the suite validates it against the
bindings: libsecp256k1 says what the right answer is, being what bitcoin
consensus relies on.

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
- [BIP322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
  signed messages, where the address is a script to satisfy rather than a
  key to recover: the simple, full and proof-of-funds variants, verified
  by the script engine, so multisig, taproot and time locks sign as well
  as p2pkh does
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
- [BIP374](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
  discrete logarithm equality proofs: 64 bytes proving that an ECDH shared
  secret was computed from the key that signed, without revealing that key,
  over an arbitrary generator and an optional message
- ECIES in the BIE1 layout, the block cipher supplied by the caller
- Pedersen commitment
- Base58 encoding/decoding
- p2pkh/p2sh addresses and WIFs
- Bech32 encoding/decoding
- p2wpkh/p2wsh native segwit addresses and their legacy p2sh-wrapped versions
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  hierarchical deterministic key chains
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  mnemonic for generating deterministic keys, in the wordlists of the
  reference implementation, with the language read off the words
- [Electrum](https://electrum.org/#home) standard for mnemonic, reading
  the same wordlists as BIP39 except for Portuguese, which is Electrum's
  own list
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
- [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
  deterministic entropy: one root key behind many wallets, a hardened
  path saying which, and each application taking what it needs of the 512
  bits it reaches — a BIP39 mnemonic, the Bitcoin Core `hdseed` WIF, an
  xprv, raw bytes, a base64 or base85 password, dice rolls, and the
  SHAKE256 stream an RSA key generator reads
- [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
  silent payments: one reusable bech32m address, and a different taproot
  output for every payment to it — the sender's outputs, the receiver's
  scan, the labels that give one wallet many published addresses, and the
  tweak data a light client scans from
- Script encoding/decoding
- nulldata, p2pk, p2ms, p2pkh, p2sh, p2wpkh, p2wsh and p2tr ScriptPubKeys
- a script engine: a transaction verified against the consensus rules,
  legacy, segwit and tapscript, with Bitcoin Core's own vectors behind it
- [BIP380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
  output descriptors: the checksum, the parser, the scripts a descriptor
  names, and the spend
- [BIP379](https://github.com/bitcoin/bips/blob/master/bip-0379.md)
  miniscript, read, written and spent, inside `wsh()` and as a `tr()` leaf:
  the expression compiled to a script, a script read back into the
  expression it is, the type system that says an expression is well formed,
  the bounds a spend of it is analysed by, and the non-malleable witness
  that satisfies it
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
- PsbtView, the same psbt read a map at a time out of a stream, for a
  signer with less memory than the psbt takes: the maps it is asked for,
  the transaction being built, the outputs being spent and both sig_hashes
- [BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
  PSBT version 2, the unsigned transaction computed from the fields rather
  than carried as one: the lock time its inputs require, the identifier
  that ignores their sequences, the modifiable flags a Constructor must
  obey, and conversion either way
- [BIP375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)
  silent payments in a PSBT: the six fields that carry an ECDH share, its
  BIP374 proof and the address being paid, the output script that may not
  exist yet, and the identifier that reads the address in its place — with
  both roles the BIP adds, the Signer that writes the shares and derives
  the scripts and the Transaction Extractor that recomputes every one of
  them before the transaction goes out
- [BIP21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
  `bitcoin:` payment URIs
- fee rates carrying their unit (sat/kvB, sat/vB, and the BTC/kvB Bitcoin
  Core quotes one in), the fee a virtual size owes at one, what a child
  owes for the unconfirmed ancestors it is mined with, and the dust
  threshold of any output type, computed as Bitcoin Core computes it
  rather than tabulated
- wallets, several sources of addresses behind one vocabulary: an extended
  key at a BIP44 account or a set of individual keys, which also answer
  the private key that signs for an address — what `sign(address, msg)`
  needs — an output descriptor per chain, and a script template with
  multisig quorums in it, for the pre-descriptor wallets no descriptor
  states — and, for the ones that turn out to have a descriptor after all,
  the ranged descriptor lifted out of the script itself, confirmed against
  the addresses it derives. Each answers `address(branch, index)`,
  `script_pub_key(branch, index)` and `position_of(script_pub_key)`, the
  last being "is this output mine", compared whole and never on a key
  origin's fingerprint
- an external signer behind one contract, with Bitcoin Core's
  [HWI](https://github.com/bitcoin-core/HWI) behind it for a hardware
  wallet
- a chain backend behind one interface — a transaction by id, the output
  an outpoint names, the chain tip — over a full node's JSON-RPC or a
  block explorer's HTTP api

---

## Secrets, and where constant time ends

btclib is used to teach and to prototype as much as to build, and the two
uses want different things of it. What follows is the boundary between
them, before a private key is handed to any of the above.

A Python object carrying secret material cannot be reliably zeroized: it
stays in the process memory until garbage collection, and the interpreter
may have copied it meanwhile. The constant-time properties are
libsecp256k1's, and they hold on the C side of the call — not before it,
and not after.

Not every operation crosses that call. `dsa.sign`, `ssa.sign` and
`silent_payments.output_keys` reach the bindings for secp256k1 with sha256
and no nonce of the caller's; another curve, another hash function, or a
nonce you supply runs the Python arithmetic instead, which the suite
validates against the bindings but which is not constant-time. So a caller
whose threat model includes timing should stay on the delegated paths, or
keep the key out of the process altogether: `btclib.hwi` drives a hardware
wallet through HWI, behind the same `PsbtSigner` contract a software
signer answers. `silent_payments.scan_outputs`, BIP352's light-client
scan, is Python-only regardless: it accepts the shared secret already
reduced, the shape a light client has and the bindings have no entry
point for. `scan_transaction_outputs`, its full-node sibling, is not:
where the bindings serve secp256k1 it reaches them with `b_scan`, the
recipient's scan private key, the same as `output_keys` above — a
caller holding the transaction itself gets the delegated path a light
client cannot reach.

What that path does about it is in the names, and it is worth knowing
before calling one. **A function whose duration follows the value it is
given ends in `_var`, and the plain name beside it is the one a secret may
be handed**: `mod_inv` draws a random blinding factor where `mod_inv_var`
is the bare extended Euclid, and `mult` makes the same additions for every
scalar where `double_mult_var` does not. It is libsecp256k1's own
convention, and forgetting to choose gives the safer call rather than the
faster one.

The suffix is not a safety label, and no name here promises constant time.
It says which of two spellings to reach for, and each one was measured
rather than assumed — including the ones that kept a plain name, which
CONTRIBUTING lists with the figure that earned it.

<!-- The link is to the file and not to its section: the documentation
build renders this README with myst, which mints no heading ids, so a
fragment naming one is an unresolved reference and fails sphinx-build -W.
The section is named in the prose instead, which costs the reader one
scroll and the build nothing. -->
[SECURITY](./SECURITY.md)'s "Limitations, not vulnerabilities" states each
condition exactly — which arguments delegate, which do not, and what the
Python path does hide — and is the canonical text; this section is the
pointer to it.

---

## Module layout

Each pair of modules below is one idea split in two, and each split runs
one way only:

| the codec / the arithmetic | the bitcoin semantics on top |
| --- | --- |
| `btclib.curves` — `Curve`, `mult` | `btclib.ecc` — `dsa`, `ssa`, `bms` |
| `btclib.base58` — the encoding | `btclib.b58` — WIF, p2pkh, p2sh |
| `btclib.bech32` — the encoding | `btclib.b32` — p2wpkh, p2wsh, p2tr |

The right column imports the left one; the left never imports the right.

So `from btclib.ecc import dsa` for a signature,
`from btclib.curves import mult` for a point multiplication, `btclib.b58`
for an address, `btclib.base58` for the encoding on its own. Each of
these modules says the same in its own docstring.

The rest, roughly bottom-up. `alias` holds the types the public API
accepts, much of it taking anything convertible rather than one type, and
`exceptions` the errors it raises. `to_prv_key` and `to_pub_key` accept
any key representation and hand back one. `bip32` and `mnemonic` derive
keys. `script`, `tx`, `block` and `psbt` build and validate what goes on
the chain, and `script.engine` runs a transaction against the consensus
rules. `p2p` is the wire format peers speak — the message envelope, its
framing, the message start each network begins with, and the payloads a
connection opens with — and it opens no socket: `fetch` is the one
package that goes and asks, and neither imports the other.

Above them, `bip44` composes `bip32`, `script.taproot` and both address
encodings into an address from an extended key and a derivation path, and
`descriptors` reads the BIP380 grammar and hands back the scripts a
descriptor names -- with `descriptors.miniscript` reading BIP379's
language, which is a script written as a tree of fragments, and
satisfying one. `psbt_signer`
is the contract an external signer answers; `hwi` is that contract over
Bitcoin Core's HWI.

Nothing in the library imports `bip21`, `bip322`, `bip85`, `slip132`,
`fee`, `wallet`, `hwi`, `p2p` or `fetch`: they are the top of the stack,
and `fetch` is the only one that goes out to the network. `wallet` remembers
which addresses it has handed out — over `bip44`, over `descriptors` or
over a script template of its own — and its key wallets sign for one with
`ecc.bms`.
`bip322` is the other message signing, and it is at the top rather than
beside `ecc.bms` because it needs everything below it: a script, a
transaction, a psbt and the engine that runs them. `bip85` derives the
entropy behind another wallet's seed from one root key, and is up here
because a BIP39 sentence and a WIF are two of the formats it hands
back.

The rpc client `fetch` speaks through is not in that stack: it is
[bitcoin-core-rpc](https://github.com/btclib-org/bitcoin-core-rpc), a
package of its own that btclib depends on — one file, standard library
only, installable or copyable, and usable by anyone who wants a node
client and no bitcoin library. `btclib.fetch` turns its answers into `Tx`
and `TxOut`, and checks the chain the node reports against the network
those are labelled for.

The dependency stops at `src/btclib/fetch/` and at `src/btclib/p2p/magic.py`,
which is where the p2p message start is — that package's table, not a
second copy of it. bitcoin-core-rpc declares its own `FetchError`,
importing nothing of btclib's being what lets its file be vendored, and
`btclib.fetch.fetcher.client_errors` re-raises it as `btclib.exceptions`'
own, with the `status` and the `code` carried across: an `except
FetchError` written against btclib catches what a fetcher raises. No
module loads `urllib.request` on its way to anything else: importing it
is what reaching that package costs, so `btclib.p2p` publishes the
message start without importing it and a caller who parses messages pays
nothing for a client it never uses. Constructing a client opens no
socket; the first call does.

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
[REVIEWING](./REVIEWING.md) for what a pull request is answered against,
[SECURITY](./SECURITY.md) for reporting a vulnerability.

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
