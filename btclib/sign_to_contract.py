#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Include a commitment inside an elliptic curve DSA/SSA signature.

Let c be the commitment value and R a curve point, then

    e = hash(R||c)

is a commitment operation.

When signing, an ephemeral secret key k is generated and its
corresponding curve point R = kG is used. Here, instead of
using (k, R), compute the commitment to c

    e = hash(R||c),

tweak k with e and consequently substitute R with W = (k+e)G = R+eG,
the proceed signing in the standard way, using (k+e, W).

When the committer/signer will reveal R and c,
the verifier will check that

    W.x = (R+eG).x

with e = hash(R||c)) and W.x being known from the signature.
"""

from hashlib import sha256
from typing import Optional, Tuple

from . import dsa, ssa
from .alias import HashF, Octets, Point, String
from .curve import Curve, mult, secp256k1
from .hashes import reduce_to_hlen
from .rfc6979 import _rfc6979
from .sec_point import bytes_from_point
from .to_prv_key import PrvKey, int_from_prv_key
from .utils import bytes_from_octets, int_from_bits


def _tweak(c: Octets, R: Point, ec: Curve, hf: HashF) -> int:
    "Return the hash(R||c) tweak for the provided R."

    t = bytes_from_point(R, ec) + bytes_from_octets(c)
    while True:
        h = hf()
        h.update(t)
        t = h.digest()
        # The following lines would introduce a bias
        # nonce = int.from_bytes(t, 'big') % ec.n
        # nonce = int_from_bits(t, ec.nlen) % ec.n
        # In general, taking a uniformly random integer (like those
        # obtained from a hash function in the random oracle model)
        # modulo the curve order n would produce a biased result.
        # However, if the order n is sufficiently close to 2^hf_len,
        # then the bias is not observable: e.g.
        # for secp256k1 and sha256 1-n/2^256 it is about 1.27*2^-128
        tweak = int_from_bits(t, ec.nlen)  # candidate tweak
        if 0 < tweak < ec.n:  # acceptable value for tweak
            return tweak  # successful candidate


def _dsa_commit_sign(
    c: Octets,
    m: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[dsa.Sig, Point]:
    """Include a commitment c inside an ECDSA signature."""

    nonce = (
        _rfc6979(m, prv_key, ec, hf) if nonce is None else int_from_prv_key(nonce, ec)
    )
    R = mult(nonce, ec.G, ec)

    tweaked_nonce = (nonce + _tweak(c, R, ec, hf)) % ec.n
    tweaked_sig = dsa._sign(m, prv_key, tweaked_nonce, low_s=True, ec=ec, hf=hf)

    return tweaked_sig, R


def dsa_commit_sign(
    commit_msg: String,
    msg: String,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[dsa.Sig, Point]:
    """Include a commitment c inside an ECDSA signature."""

    c = reduce_to_hlen(commit_msg, hf)
    m = reduce_to_hlen(msg, hf)
    return _dsa_commit_sign(c, m, prv_key, nonce, ec, hf)


def _dsa_verify_commit(
    c: Octets,
    R: Point,
    m: Octets,
    key: dsa.Key,
    sig: dsa.Sig,
    hf: HashF = sha256,
) -> bool:
    "Open the commitment c inside an EC DSA signature."

    tweak = _tweak(c, R, sig.ec, hf)
    W = sig.ec.add(R, mult(tweak, sig.ec.G, sig.ec))

    # sig.r is in [1..n-1]
    return (sig.r == W[0] % sig.ec.n) and dsa._verify(m, key, sig, hf)


def dsa_verify_commit(
    commit_msg: String,
    receipt: Point,
    msg: String,
    key: dsa.Key,
    sig: dsa.Sig,
    hf: HashF = sha256,
) -> bool:
    c = reduce_to_hlen(commit_msg, hf)
    m = reduce_to_hlen(msg, hf)
    return _dsa_verify_commit(c, receipt, m, key, sig, hf)


def _ssa_commit_sign(
    c: Octets,
    m: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[ssa.Sig, Point]:
    """Include a commitment c inside an ECSSA signature."""

    nonce = (
        ssa._det_nonce(m, prv_key, aux=None, ec=ec, hf=hf)
        if nonce is None
        else int_from_prv_key(nonce, ec)
    )
    R = mult(nonce, ec.G, ec)

    tweaked_nonce = (nonce + _tweak(c, R, ec, hf)) % ec.n
    tweaked_sig = ssa._sign(m, prv_key, tweaked_nonce, ec, hf)

    return tweaked_sig, R


def ssa_commit_sign(
    commit_msg: String,
    msg: String,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[ssa.Sig, Point]:
    """Include a commitment c inside an ECSSA signature."""

    c = reduce_to_hlen(commit_msg, hf)
    m = reduce_to_hlen(msg, hf)
    return _ssa_commit_sign(c, m, prv_key, nonce, ec, hf)


def _ssa_verify_commit(
    c: Octets,
    R: Point,
    m: Octets,
    pub_key: ssa.BIP340PubKey,
    sig: ssa.Sig,
    hf: HashF = sha256,
) -> bool:
    "Open the commitment c inside an EC SSA signature."

    tweak = _tweak(c, R, sig.ec, hf)
    W = sig.ec.add(R, mult(tweak, sig.ec.G, sig.ec))

    # sig.r is in [1..p-1]
    return (sig.r == W[0]) and ssa._verify(m, pub_key, sig, hf)


def ssa_verify_commit(
    commit_msg: String,
    receipt: Point,
    msg: String,
    pub_key: ssa.BIP340PubKey,
    sig: ssa.Sig,
    hf: HashF = sha256,
) -> bool:
    c = reduce_to_hlen(commit_msg, hf)
    m = reduce_to_hlen(msg, hf)
    return _ssa_verify_commit(c, receipt, m, pub_key, sig, hf)
