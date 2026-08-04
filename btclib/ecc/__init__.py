#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Module btclib.ecc.

**The schemes.** btclib.ecc holds what is built *on* an elliptic curve:
dsa, ssa, bms and borromean signatures, the MuSig2 aggregation of many
ssa signers into one, pedersen commitments, the Diffie-Hellman key
agreement, the BIE1 ECIES built on top of it, the ElligatorSwift encoding
of a public key with the x-only ECDH on it, and the RFC6979, BIP340 and
sign-to-contract nonces. The curve arithmetic underneath is
btclib.curves, and the rule between the two is that direction: ecc
imports curves, never the other way round.

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
spelling, as `btclib.ecc.dsa` is. What is *not* here is any name ending
in an underscore: `bip340_nonce_`, `rfc6979_nonce_`, `commit_nonce_` and
`challenge_` take a message already reduced to a scalar and an explicit
curve, which is the expert door of the module that defines them, and
`dsa.sign_` and `ssa.sign_` are not exported either.

bms does `from btclib.ecc import dsa`, i.e. it imports a name from the
package that is importing it, and the order of the line below does not
have to work around it: a `from package import name` whose name is not
yet an attribute falls back to importing package.name as a submodule,
which is what happens here. tests/imports_test.py imports every module of
the library with nothing else in sys.modules, which is the order that
would find it if it did not.
"""

from btclib.ecc import (
    bip340_nonce,
    bms,
    borromean,
    commit_nonce,
    dh,
    dsa,
    ecies,
    ellswift,
    musig2,
    pedersen,
    rfc6979_nonce,
    ssa,
)
from btclib.ecc.dh import ansi_x9_63_kdf, diffie_hellman
from btclib.ecc.pedersen import second_generator

__all__ = [
    "ansi_x9_63_kdf",
    "bip340_nonce",
    "bms",
    "borromean",
    "commit_nonce",
    "dh",
    "diffie_hellman",
    "dsa",
    "ecies",
    "ellswift",
    "musig2",
    "pedersen",
    "rfc6979_nonce",
    "second_generator",
    "ssa",
]
