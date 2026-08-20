# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.ecc.

**The schemes.** btclib.ecc holds what is built *on* an elliptic curve:
dsa, ssa, bms and borromean signatures, the MuSig2 aggregation of many
ssa signers into one, pedersen commitments, the Diffie-Hellman key
agreement with the two key derivation functions beside it, the BIE1 ECIES
built on top of it, the ElligatorSwift encoding of a public key with the
x-only ECDH on it, the BIP374 proof that two points share one discrete
logarithm, and the RFC6979, BIP340 and sign-to-contract nonces. The curve
arithmetic underneath is btclib.curves, and the rule between the two is
that direction: ecc imports curves, never the other way round.

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

bms does `from btclib.ecc import dsa`, i.e. it imports a name from the
package that is importing it, and the order of the line below does not
have to work around it: a `from package import name` whose name is not
yet an attribute falls back to importing package.name as a submodule,
which is what happens here. tests/imports_test.py imports every module of
the library with nothing else in sys.modules, which is the order that
would find it if it did not.

**Secrets.** This is the package a private key is handed to, and what
holds around it is conditional. A signature of secp256k1 with sha256 and
a nonce btclib derives is one libsecp256k1 call; another curve, another
hash function or a nonce of the caller's runs the Python arithmetic,
which the suite validates against the bindings but which is not
constant-time. Nor is a Python object holding a secret zeroized, on
either path. SECURITY.md's limitations section states each condition,
argument by argument, and README.md carries the short form.
"""

from btclib.ecc import (
    bip340_nonce,
    bms,
    borromean,
    commit_nonce,
    dh,
    dleq,
    dsa,
    ecies,
    ellswift,
    musig2,
    pedersen,
    rfc6979_nonce,
    ssa,
)
from btclib.ecc.dh import (
    ansi_x9_63_kdf,
    diffie_hellman,
    hkdf,
    hkdf_expand,
    hkdf_extract,
)
from btclib.ecc.pedersen import second_generator

__all__ = [
    "ansi_x9_63_kdf",
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
    "hkdf",
    "hkdf_expand",
    "hkdf_extract",
    "musig2",
    "pedersen",
    "rfc6979_nonce",
    "second_generator",
    "ssa",
]
