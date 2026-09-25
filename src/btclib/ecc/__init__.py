# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.ecc.

**The schemes.** btclib.ecc holds what is built *on* an elliptic curve:
dsa, ssa, bms and borromean signatures, the MuSig2 aggregation of many
ssa signers into one, the FROST threshold signing in which a subset of
a group sharing one key signs for all of it, pedersen commitments, the
Confidential Transactions rangeproof built over one and the rewind that
reads a value, a blinding factor and a message back out of it, the
Diffie-Hellman key agreement, the BIE1 ECIES built on top of it, the
ElligatorSwift encoding of a public key with the x-only ECDH on it, the
BIP374 proof that two points share one discrete logarithm, and the
RFC6979, BIP340 and sign-to-contract nonces. The curve arithmetic underneath is
btclib.curves, and the rule between the two is that direction: ecc
imports curves, never the other way round. The key derivation functions
the agreement uses are btclib.kdf: a KDF is a hash construction with no
curve in it, and its own module says why it is not here.

The two names are easy to conflate -- everything here is also about
curves -- so the anchor is worth stating: `from btclib.curves import mult`,
`from btclib.ecc import dsa`.

The schemes are what this package is for, so ``__all__`` names them and
the import below binds each as a package attribute: without it, `import
btclib.ecc` followed by `btclib.ecc.dsa.sign(...)` would raise
AttributeError until something else in the process happened to import the
submodule, and the package would advertise the loose helpers alone
instead of the schemes behind them.

The three nonces are named the same way, as modules. A nonce derivation
is a scheme of its own -- RFC6979 has test vectors, BIP340's auxiliary
randomness is part of the signing standard, and sign-to-contract has its
commitment and its opening -- so `btclib.ecc.rfc6979_nonce` is the
spelling, as `btclib.ecc.dsa` is.

What is *not* here is a module's own functions, plain or prepared:
`dsa.sign` and `dsa.sign_` are both in `dsa.__all__` and neither is in
this one, and nor are `musig2.key_agg`, `ecies.encrypt` or
`ellswift.xdh`. The loose helpers ``__all__`` names above are the whole
of the exception. So the trailing underscore is no part of the
decision, and for four names there is no decision to make: dsa and ssa
both define `sign_`, `verify_` and `assert_as_valid_`, ssa and
rfc6979_nonce both define `challenge_`, and a package-level export of
any of the four would collide -- as one of `sign` would, which five of
these modules define, or of `gen_keys`, which three do.

**bms is imported on demand, and it is the one scheme that is.** It
names its signer by an address, so it reaches `b32`, `b58`, `key` and
`network`, where every other module here imports only what sits at the
curve's layer and below it (issue #2282). Importing it eagerly below
would put those modules behind `import btclib.ecc`; `__getattr__` at the
bottom answers `btclib.ecc.bms` instead, the first time it is asked for.
`from btclib.ecc import bms` is answered there too, a from-import asking
for the attribute before it imports a submodule. tests/imports_test.py
holds the rest of the package to that layer, and leaves this module out.

**Secrets.** This is the package a private key is handed to, and what
holds around it is conditional. What decides whether an operation here
is one libsecp256k1 call is `curves.curve._libsecp256k1_serves` -- the
process-wide dispatch switch, the curve and the hash function -- with
the conditions of the call site anded onto it; whatever the conjunction
declines runs the Python arithmetic, which the suite validates against
the bindings but which is not constant-time. Nor is a Python object
holding a secret zeroized, on either path. SECURITY.md's limitations
section states each condition, argument by argument, and README.md
carries the short form.
"""

from importlib import import_module
from types import ModuleType

from btclib.ecc import (
    bip340_nonce,
    borromean,
    commit_nonce,
    dh,
    dleq,
    dsa,
    ecies,
    ellswift,
    frost,
    musig2,
    pedersen,
    rangeproof,
    rfc6979_nonce,
    ssa,
)
from btclib.ecc.dh import diffie_hellman
from btclib.ecc.pedersen import second_generator

__all__ = [
    "bip340_nonce",
    "bms",
    "borromean",
    "commit_nonce",
    "dh",
    "diffie_hellman",
    "dleq",
    "dsa",
    "ecies",
    "ellswift",
    "frost",
    "musig2",
    "pedersen",
    "rangeproof",
    "rfc6979_nonce",
    "second_generator",
    "ssa",
]


def __getattr__(published: str) -> ModuleType:
    """Import `bms` the first time it is asked for.

    PEP 562, as `btclib/__init__.py` does it: this answers `btclib.ecc.bms`
    on a package that has not imported it, which is how a walker reading
    `__all__` descends and how `from btclib.ecc import *` binds.
    """
    if published == "bms":
        return import_module(f"{__name__}.bms")
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with `bms` beside what the package already has.

    `dir()` reads the namespace, so without this `bms` is missing from it
    until first touched, as `btclib/script/__init__.py` says of its own.
    """
    return sorted({*__all__, *globals()})
