#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Include a commitment inside an elliptic curve DSA/SSA signature.

Let commit_hash be the commitment value and R a curve point, then

    e = hash(R||commit_hash)

is a commitment operation.

When signing, an ephemeral secret key k is generated and its
corresponding curve point R = kG is used. Here, instead of
using (k, R), compute the commitment to commit_hash

    e = hash(R||commit_hash),

tweak k with e and consequently substitute R with W = (k+e)G = R+eG,
the proceed signing in the standard way, using (k+e, W).

When the committer/signer will reveal R and commit_hash,
the verifier will check that

    W.x = (R+eG).x

with e = hash(R||commit_hash)) and W.x being known from the signature.
"""

from hashlib import sha256
from typing import Optional, Tuple

from btclib.alias import HashF, Octets, Point
from btclib.ecc import dsa, ssa
from btclib.ecc.curve import Curve, mult, secp256k1
from btclib.ecc.rfc6979 import rfc6979_
from btclib.ecc.sec_point import bytes_from_point
from btclib.hashes import reduce_to_hlen
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.utils import bytes_from_octets, int_from_bits


def _tweak(commit_hash: Octets, R: Point, ec: Curve, hf: HashF) -> int:
    "Return the hash(R||commit_hash) tweak for the provided R."

    t = bytes_from_point(R, ec) + bytes_from_octets(commit_hash)
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


def dsa_commit_sign_(
    commit_hash: Octets,
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    lower_s: bool = True,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[dsa.Sig, Point]:
    "Include a commitment inside an EC DSA signature."

    nonce = (
        rfc6979_(msg_hash, prv_key, ec, hf)
        if nonce is None
        else int_from_prv_key(nonce, ec)
    )
    R = mult(nonce, ec.G, ec)

    tweaked_nonce = (nonce + _tweak(commit_hash, R, ec, hf)) % ec.n
    tweaked_sig = dsa.sign_(msg_hash, prv_key, tweaked_nonce, lower_s, ec=ec, hf=hf)

    return tweaked_sig, R


def dsa_commit_sign(
    commit: Octets,
    msg: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[dsa.Sig, Point]:
    "Include a commitment inside an EC DSA signature."

    commit_hash = reduce_to_hlen(commit, hf)
    msg_hash = reduce_to_hlen(msg, hf)
    return dsa_commit_sign_(
        commit_hash, msg_hash, prv_key, nonce, lower_s=True, ec=ec, hf=hf
    )


def dsa_verify_commit_(
    commit_hash: Octets,
    R: Point,
    msg_hash: Octets,
    key: dsa.Key,
    sig: dsa.Sig,
    lower_s: bool = True,
    hf: HashF = sha256,
) -> bool:
    "Open the commitment associated to an EC DSA signature."

    tweak = _tweak(commit_hash, R, sig.ec, hf)
    W = sig.ec.add(R, mult(tweak, sig.ec.G, sig.ec))

    # sig.r is in [1..n-1]
    return (sig.r == W[0] % sig.ec.n) and dsa.verify_(msg_hash, key, sig, lower_s, hf)


def dsa_verify_commit(
    commit: Octets,
    receipt: Point,
    msg: Octets,
    key: dsa.Key,
    sig: dsa.Sig,
    lower_s: bool = True,
    hf: HashF = sha256,
) -> bool:
    "Open the commitment associated to an EC DSA signature."
    commit_hash = reduce_to_hlen(commit, hf)
    msg_hash = reduce_to_hlen(msg, hf)
    return dsa_verify_commit_(commit_hash, receipt, msg_hash, key, sig, lower_s, hf)


def ssa_commit_sign_(
    commit_hash: Octets,
    msg_hash: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[ssa.Sig, Point]:
    "Include a commitment inside an EC SSA signature."

    nonce = (
        ssa.det_nonce_(msg_hash, prv_key, aux=None, ec=ec, hf=hf)
        if nonce is None
        else int_from_prv_key(nonce, ec)
    )
    R = mult(nonce, ec.G, ec)

    tweaked_nonce = (nonce + _tweak(commit_hash, R, ec, hf)) % ec.n
    tweaked_sig = ssa.sign_(msg_hash, prv_key, tweaked_nonce, ec, hf)

    return tweaked_sig, R


def ssa_commit_sign(
    commit: Octets,
    msg: Octets,
    prv_key: PrvKey,
    nonce: Optional[PrvKey] = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> Tuple[ssa.Sig, Point]:
    "Include a commitment inside an EC SSA signature."

    commit_hash = reduce_to_hlen(commit, hf)
    msg_hash = reduce_to_hlen(msg, hf)
    return ssa_commit_sign_(commit_hash, msg_hash, prv_key, nonce, ec, hf)


def ssa_verify_commit_(
    commit_hash: Octets,
    R: Point,
    msg_hash: Octets,
    pub_key: ssa.BIP340PubKey,
    sig: ssa.Sig,
    hf: HashF = sha256,
) -> bool:
    "Open the commitment associated to an EC SSA signature."

    tweak = _tweak(commit_hash, R, sig.ec, hf)
    W = sig.ec.add(R, mult(tweak, sig.ec.G, sig.ec))

    # sig.r is in [1..p-1]
    return (sig.r == W[0]) and ssa.verify_(msg_hash, pub_key, sig, hf)


def ssa_verify_commit(
    commit: Octets,
    receipt: Point,
    msg: Octets,
    pub_key: ssa.BIP340PubKey,
    sig: ssa.Sig,
    hf: HashF = sha256,
) -> bool:
    "Open the commitment associated to an EC SSA signature."
    commit_hash = reduce_to_hlen(commit, hf)
    msg_hash = reduce_to_hlen(msg, hf)
    return ssa_verify_commit_(commit_hash, receipt, msg_hash, pub_key, sig, hf)
