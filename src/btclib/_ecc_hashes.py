# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The hashing btclib.ecc's schemes do, kept below btclib.hashes.

BIP340's tagged hash, SEC 1's reduction of a message to one digest, and
the check that a hash function is a constructor. Each is `hashlib` and
nothing else. btclib.hashes imports `var_int` and `_ripemd160`, which nothing
in btclib.ecc needs, so a scheme importing these from there would reach
above the substrate that tests/imports_test.py holds btclib.ecc to
(issue #2282).

Private: btclib.hashes publishes `tagged_hash` and `reduce_to_hlen` as
the same objects, and that is the spelling a caller names.
"""

from __future__ import annotations

import hashlib

from btclib.alias import HashF, Octets
from btclib.exceptions import BTClibTypeError
from btclib.utils import bytes_from_octets

__all__ = [
    "reduce_to_hlen",
    "tagged_hash",
]


def _assert_valid_hf(hf: HashF) -> None:
    """Refuse an hf that is not a hash constructor.

    The mistake it catches is `sha256()` written where `sha256` belongs --
    the digest object instead of the class that makes one -- which is a
    caller's own error and not a statement about the message or the
    signature it was passed with.

    `callable` and not a trial call: a digest object is not callable, so
    the check is a slot lookup rather than the hash it would otherwise
    have to build, which matters where it sits in front of a verification
    the bindings answer fast enough for that hash to show.

    So it is not exhaustive, and does not need to be: a callable of the
    wrong shape -- `hashes.hash256`, which takes the message rather than
    making a digest -- still fails at the `hf()` that follows, with the
    plain TypeError `tests/alias_test.py` pins there on purpose. What
    matters for the verifications is not the class but that neither one is
    a ValueError, so neither is mistaken for a signature that does not
    verify.

    A `BTClibTypeError` for the reason the class exists, and with a
    consequence the boolean verifications depend on: it is a `TypeError`,
    so their `except (ValueError, BTClibRuntimeError)` does not catch it
    and a caller's mistake reaches the caller instead of being reported as
    a signature that does not verify.
    """
    if not callable(hf):
        raise BTClibTypeError(f"not a hash function: {hf!r} is not callable")


def reduce_to_hlen(msg: Octets, hf: HashF = hashlib.sha256) -> bytes:
    """Return the message digested by hf, one digest long.

    Step 4 of SEC 1 v.2 section 4.1.3: what the un-underscored
    signing and verifying spellings do to a message before handing it
    to their trailing-underscore twins.
    """
    # here as well as in the verifications this feeds, and not only there:
    # they take the message already reduced, so this is where an hf of
    # theirs is first called and where a bad one would otherwise leave as
    # the bare TypeError of `hf()`
    _assert_valid_hf(hf)
    msg = bytes_from_octets(msg)
    # Step 4 of SEC 1 v.2 section 4.1.3
    h = hf()
    h.update(msg)
    return h.digest()


def tagged_hash(tag: bytes, m: bytes, hf: HashF = hashlib.sha256) -> bytes:
    """Return BIP340's tagged hash: hf(hf(tag) || hf(tag) || m).

    The doubled tag digest is what makes a hash under one tag invalid
    under every other.
    """
    # libsecp256k1 computes exactly this in hashes.tagged_sha256, and the
    # binding is not called because it is slower at every size, and by
    # more the larger the message: hashlib's SHA256 is OpenSSL's,
    # hardware-accelerated, where libsecp256k1 compiles its own portable
    # C. This path also has to stay for hf != sha256, so delegating would
    # buy neither speed nor one implementation less.
    h1 = hf()
    h1.update(tag)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate

    h2.update(m)
    return h2.digest()
