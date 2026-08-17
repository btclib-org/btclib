# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Everything btclib asks of libsecp256k1, imported in one place.

Eleven modules delegate to the bindings and none of them imports them:
they import from here, so the question "are the bindings installed" is
asked once, at one import, and answered by `AVAILABLE` rather than by
eleven `try` blocks that could drift apart. `curves.curve` reads that
answer into `_libsecp256k1_available`, which is the seam every dispatch
in the package consults, so an absent binding is a dispatch that declines
rather than an `ImportError` raised before any dispatch is reached.

A module that imports nothing of btclib, and is therefore below every
package that reads it -- the placement `consensus.py` has and for its
reason. What it does import is the whole of the surface btclib uses, so
this file is also the answer to "what does btclib need these bindings
for", which was previously spread over the eleven import blocks.

The names are re-exported under the bindings' own spelling and the caller
aliases them as it always did: a caller holding `keys` and reaching
through it, and a caller naming `pubkey_sum` directly, both keep the call
they had. Neither shape costs an attribute lookup it did not cost before,
which matters where `curves.curve` counts tenths of a microsecond.

With the bindings absent every name here is None. Nothing may call one:
`_libsecp256k1_serves` is False in that configuration, and it is the
predicate in front of every delegation -- which is a rule about the
package rather than about this file, and is what `tests/no_bindings_test.py`
checks by importing btclib with the bindings out of reach.
"""

from __future__ import annotations

__all__ = [
    "AVAILABLE",
    "PubkeyTweakChain",
    "dsa",
    "dsa_verify",
    "ellswift",
    "keys",
    "pubkey_from_prvkey",
    "pubkey_sum",
    "pubkey_tweak_add",
    "pubkey_tweak_mul",
    "pubkey_tweak_mul_sum",
    "pubkey_verify",
    "recovery",
    "ssa",
    "ssa_verify",
    "xonly",
    "xonly_pubkey_verify",
    "xonly_to_pubkey",
]

try:
    from btclib_secp256k1 import dsa, ellswift, keys, recovery, ssa, xonly
    from btclib_secp256k1.dsa import verify as dsa_verify
    from btclib_secp256k1.keys import (
        PubkeyTweakChain,
        pubkey_from_prvkey,
        pubkey_sum,
        pubkey_tweak_add,
        pubkey_tweak_mul,
        pubkey_tweak_mul_sum,
        pubkey_verify,
    )
    from btclib_secp256k1.ssa import verify as ssa_verify
    from btclib_secp256k1.xonly import pubkey_verify as xonly_pubkey_verify
    from btclib_secp256k1.xonly import to_pubkey as xonly_to_pubkey

    AVAILABLE = True
except ImportError:  # pragma: no cover
    # None and not a callable that raises: what would raise is never
    # called, so the object would be a second thing to keep true. The
    # ignore is on the assignment and not on the module: every other
    # name here keeps the type the try branch gave it
    dsa = ellswift = keys = recovery = ssa = xonly = None  # type: ignore[assignment]
    # a class rather than a function, so mypy calls it an assignment to
    # a type and wants the second code as well
    PubkeyTweakChain = None  # type: ignore[misc, assignment]
    dsa_verify = pubkey_from_prvkey = None  # type: ignore[assignment]
    pubkey_sum = pubkey_tweak_add = pubkey_tweak_mul = None  # type: ignore[assignment]
    pubkey_tweak_mul_sum = pubkey_verify = ssa_verify = None  # type: ignore[assignment]
    xonly_pubkey_verify = xonly_to_pubkey = None  # type: ignore[assignment]

    AVAILABLE = False
