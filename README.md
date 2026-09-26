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

Every workflow-status badge carries `?branch=main` on its image and
`?query=branch%3Amain` on its link: section 2 of the organization
standard is where that is decided and why. The two spellings are not
interchangeable -- the runs page ignores the image's and renders
unfiltered. The pre-commit.ci badge is outside it, being the service's
own with its branch already in its path.
-->
[![PyPI version](https://img.shields.io/pypi/v/btclib.svg?logo=pypi)](https://pypi.python.org/pypi/btclib/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/releases)
[![development status](https://img.shields.io/pypi/status/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![license](https://img.shields.io/github/license/btclib-org/btclib.svg)](https://github.com/btclib-org/btclib/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/btclib)](https://pepy.tech/projects/btclib)
[![supported Python versions](https://img.shields.io/pypi/pyversions/btclib.svg?logo=python)](https://pypi.python.org/pypi/btclib/)
[![implementation](https://img.shields.io/pypi/implementation/btclib.svg)](https://pypi.python.org/pypi/btclib/)
[![wheel](https://img.shields.io/pypi/wheel/btclib.svg)](https://pypi.python.org/pypi/btclib/)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib/main)
[![lint workflow status](https://github.com/btclib-org/btclib/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/lint.yml?query=branch%3Amain)
[![test workflow status](https://github.com/btclib-org/btclib/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/test.yml?query=branch%3Amain)
[![docs workflow status](https://github.com/btclib-org/btclib/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/docs.yml?query=branch%3Amain)
[![documentation build](https://app.readthedocs.org/projects/btclib/badge/?version=latest)](https://btclib.readthedocs.io)
[![vendored-vectors workflow status](https://github.com/btclib-org/btclib/actions/workflows/vendored-vectors.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/vendored-vectors.yml?query=branch%3Amain)
[![mutation workflow status](https://github.com/btclib-org/btclib/actions/workflows/mutation.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/mutation.yml?query=branch%3Amain)
[![fuzz workflow status](https://github.com/btclib-org/btclib/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/fuzz.yml?query=branch%3Amain)
[![integration-bitcoind workflow status](https://github.com/btclib-org/btclib/actions/workflows/integration-bitcoind.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/integration-bitcoind.yml?query=branch%3Amain)
[![deps-latest workflow status](https://github.com/btclib-org/btclib/actions/workflows/deps-latest.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/deps-latest.yml?query=branch%3Amain)
[![pypi-install workflow status](https://github.com/btclib-org/btclib/actions/workflows/pypi-install.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/pypi-install.yml?query=branch%3Amain)
[![deps-oldest workflow status](https://github.com/btclib-org/btclib/actions/workflows/deps-oldest.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/deps-oldest.yml?query=branch%3Amain)
[![py-arm-authority workflow status](https://github.com/btclib-org/btclib/actions/workflows/py-arm-authority.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/py-arm-authority.yml?query=branch%3Amain)
[![os-macos workflow status](https://github.com/btclib-org/btclib/actions/workflows/os-macos.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/os-macos.yml?query=branch%3Amain)
[![os-ubuntu workflow status](https://github.com/btclib-org/btclib/actions/workflows/os-ubuntu.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/os-ubuntu.yml?query=branch%3Amain)
[![os-windows workflow status](https://github.com/btclib-org/btclib/actions/workflows/os-windows.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/os-windows.yml?query=branch%3Amain)
[![links workflow status](https://github.com/btclib-org/btclib/actions/workflows/links.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/links.yml?query=branch%3Amain)
[![sdist-rebuild workflow status](https://github.com/btclib-org/btclib/actions/workflows/sdist-rebuild.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/sdist-rebuild.yml?query=branch%3Amain)
[![codeql workflow status](https://github.com/btclib-org/btclib/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib/actions/workflows/codeql.yml?query=branch%3Amain)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/btclib/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/btclib)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/14253/badge)](https://www.bestpractices.dev/projects/14253)

---

[btclib](https://btclib.readthedocs.io/) is a Python
[type annotated](https://docs.python.org/3/library/typing.html) library
for teaching, learning and using bitcoin, focused on elliptic curve
cryptography and bitcoin's blockchain. It started as a teaching tool for
Ferdinando Ametrano's
*[Bitcoin and Blockchain Technology](https://www.ametrano.net/bbt/)*
course, it is used in production today (still marked as beta
because it is often refactored for improved clarity — [CONTRIBUTING.md's
*Breaking a caller is not an
argument*](./CONTRIBUTING.md#breaking-a-caller-is-not-an-argument) says
what that promises a caller and what it does not).

The test suite covers virtually the whole code base, a floor the build
enforces, and it answers to vectors their authors publish: the BIPs' own,
Bitcoin Core's script, transaction, sighash and key-encoding files, and
Appendix A.2 of RFC 6979. `tests/_data/README.md` pins each vendored file to the
upstream commit it was copied from, and says whether the two still match —
including the few vectors that are btclib's own, having no upstream.

The library is not limited to secp256k1, and for that curve it delegates
to
[btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1),
FFI bindings to Bitcoin Core's optimized C library
[libsecp256k1](https://github.com/bitcoin-core/secp256k1), wherever a
call's own guard admits them. They are the recommended install and what
`pip install "btclib[secp256k1]"` asks for, needing one of their wheels
or a C toolchain; without them, or with the delegation turned off in a
process that has them, btclib still answers, on the Python arithmetic,
tens of times more slowly and not in constant time — `SECURITY.md`
publishes both. That Python arithmetic serves every other curve anyway,
and the suite validates it against the bindings: libsecp256k1 says what
the right answer is, being what bitcoin consensus relies on.

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
- Script encoding/decoding
- nulldata, p2pk, p2ms, p2pkh, p2sh, p2wpkh, p2wsh and p2tr ScriptPubKeys
- a script engine: a transaction verified against the consensus rules,
  legacy, segwit and tapscript, with Bitcoin Core's own vectors behind it
- OutPoint, TxIn, TxOut, and TX data classes
- legacy, segwit_v0 and taproot transaction hash signatures
- BlockHeader and Block data classes
- merkle proofs verified against a header's merkle root
- proof-of-work arithmetic: compact targets, retargeting, work, hash rate
- fee rates carrying their unit (sat/kvB, sat/vB, and the BTC/kvB Bitcoin
  Core quotes one in), the fee a virtual size owes at one, what a child
  owes for the unconfirmed ancestors it is mined with, and the dust
  threshold of any output type, computed as Bitcoin Core computes it
  rather than tabulated

The wallet side — key derivation, mnemonics, PSBTs, output descriptors,
signers and chain backends — is the `btclib-wallet` distribution, imported
as `btclib_wallet`, which depends on this one.

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

Not every operation crosses that call, and what decides is one
predicate — a process-wide dispatch switch, secp256k1 as the curve,
and sha256 or no hash function at all — with whatever further
conditions the call site ands onto it. Those conditions differ from
one function to the next, and `SECURITY.md` states each of them, for
`dsa.sign` and `ssa.sign` alike.
Whatever that conjunction declines runs the Python arithmetic, which
the suite validates against the bindings but which is not
constant-time. A process that has the bindings turns that switch off
with `curves.set_libsecp256k1_serving(serving=False)`, or with
`ELLIPTICCURVES_NO_LIBSECP256K1` in the environment, and every operation here
is then the Python arithmetic. So a caller whose threat model includes
timing should stay on the delegated paths, or keep the key out of the
process altogether: `btclib_wallet.hwi` drives a hardware wallet through
HWI, behind the same `PsbtSigner` contract a software signer answers.

Crossing that call is not the same as constant time. A `mult` of a
point you supplied, the shared point of a key agreement among them,
crosses into libsecp256k1's constant-time multiplication;
`double_mult_var` and `multi_mult_var` cross into the variable-time one
their suffix names, so a secret handed to them carries no timing
guarantee on the delegated path either. `SECURITY.md` has the
accounting, and which call a multiplication takes is part of it.

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

[ARCHITECTURE](./ARCHITECTURE.md) is the design: which module holds what,
the import edges the tests hold, and the two arithmetic paths behind
secp256k1.

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

How the organization decides, and who holds which role, is its
[GOVERNANCE.md](https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md);
what it intends to do, and what it deliberately does not, is its
[ROADMAP.md](https://github.com/btclib-org/.github/blob/main/ROADMAP.md).

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
