#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Commitment-tweaked ephemeral key (nonce): sign-to-contract.

A signature commits to a value by tweaking its nonce with it, at no cost
in size: what comes out is an ordinary DSA or SSA signature, and only
whoever is shown the committed value and the receipt can tell that it
commits to anything.

Let commit_hash be the commitment value and R a curve point, then

e = hash(R||commit_hash)

is a commitment operation.

When signing, an ephemeral secret key k is generated and its
corresponding curve point R = kG is used. Here, instead of using (k, R),
compute the commitment to commit_hash

e = hash(R||commit_hash),

tweak k with e and consequently substitute R with W = (k+e)G = R+eG, then
proceed signing in the standard way, using (k+e, W).

When the committer/signer will reveal R and commit_hash, the verifier
will check that

W.x = (R+eG).x

with e = hash(R||commit_hash)) and W.x being known from the signature.

R is the receipt, and it is the signer's to keep: nothing in the
signature says what it was. `dsa.sign` and `ssa.sign` take the commitment
as a parameter and return the receipt beside the signature, `dsa.verify`
and `ssa.verify` take the two back to open the commitment, and this
module is the nonce derivation behind all four -- beside the RFC6979 and
BIP340 ones, which answer the same question when nothing is committed.
"""

from __future__ import annotations

from hashlib import sha256

from btclib.alias import HashF, Octets, Point
from btclib.curves import Curve, bytes_from_point, mult, secp256k1
from btclib.exceptions import BTClibRuntimeError
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.utils import bytes_from_octets, int_from_bits


def _tweak(commit_hash: Octets, receipt: Point, ec: Curve, hf: HashF) -> int:
    """Return the hash(receipt||commit_hash) tweak for the provided receipt."""
    t = bytes_from_point(receipt, ec) + bytes_from_octets(commit_hash)
    while True:
        h = hf()
        h.update(t)
        t = h.digest()
        # reducing the hash mod n -- whether the whole of it or its
        # leftmost nlen bits -- would introduce a bias, which is why
        # neither is done here
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        tweak = int_from_bits(t, ec.nlen)  # candidate tweak
        if 0 < tweak < ec.n:  # acceptable value for tweak
            return tweak  # successful candidate


def commit_nonce_(
    commit_hash: Octets,
    nonce: PrvKey,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[int, Point]:
    """Return the commitment-tweaked nonce, and the receipt to reveal.

    The receipt is the point of the nonce as it came in: it is what the
    tweak hashes, so a verifier given the committed value can recompute
    the tweak and reach the point the signature carries.
    """
    nonce = int_from_prv_key(nonce, ec)
    receipt = mult(nonce, ec.G, ec)
    tweaked_nonce = (nonce + _tweak(commit_hash, receipt, ec, hf)) % ec.n
    # the tweak is uniform in 1..n-1, so a zero sum is a one-in-n event
    # and not a rejection to loop over: the nonce is either the caller's
    # or the deterministic derivation's, and neither has a next candidate
    # to offer. Refused here, because a nonce of zero has no point to sign
    # with and mod_inv(0) is the error the caller would see instead
    if tweaked_nonce == 0:
        raise BTClibRuntimeError("failed to sign: zero tweaked nonce")
    return tweaked_nonce, receipt


def commit_point_(
    commit_hash: Octets,
    receipt: Point,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Point:
    """Return W = R + hash(R||commit_hash)G, the point the nonce became.

    Its x-coordinate is what the signature's r was built from -- dsa
    reduces that coordinate modulo the group order and ssa keeps the field
    element -- so the comparison against r belongs to each scheme and not
    here.
    """
    return ec.add(receipt, mult(_tweak(commit_hash, receipt, ec, hf), ec.G, ec))
