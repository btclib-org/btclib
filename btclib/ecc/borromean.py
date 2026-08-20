# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Borromean ring signature functions.

References:
    - https://github.com/ElementsProject/borromean-signatures-writeup
    - https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

Both are also cited inside `sign`, which is not where a reader looks
first; they are here because the module is what one arrives at.

"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from hashlib import sha256

from btclib.alias import HashF, Octets, Point
from btclib.curves import Curve, bytes_from_point, double_mult_var, mult, secp256k1
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.utils import bytes_from_octets, int_from_bits

__all__ = [
    "PubkeyRing",
    "SValues",
    "assert_as_valid",
    "sign",
    "verify",
]

# the curve and the hash function are parameters, as they are in dsa, ssa
# and pedersen -- not module globals: selecting either through a global
# would mean rebinding an attribute of this module, which changes the
# algorithm for every other caller in the process
#
# ec has to be passed to mult and double_mult_var too, and that is easy to
# miss: both take the curve as their *last* argument and default it to
# secp256k1, so `mult(k)` and `double_mult_var(-e, Q, s, ec.G)` type check,
# read as if they honoured ec, and compute on secp256k1 -- every point
# then encoded against ec, so the first bytes_from_point rejects it and
# no curve but secp256k1 can sign at all (issue 183)


def _hash(m: bytes, R: bytes, i: int, j: int, hf: HashF) -> bytes:
    temp = b"".join(
        [m, R, i.to_bytes(4, "big", signed=False), j.to_bytes(4, "big", signed=False)]
    )
    hasher = hf()
    hasher.update(temp)
    return hasher.digest()


PubkeyRing = Sequence[Point]


def _get_msg_format(
    msg: bytes, pubk_rings: Sequence[PubkeyRing], ec: Curve, hf: HashF
) -> bytes:
    t = b"".join(
        b"".join(bytes_from_point(Q, ec) for Q in pubk_ring) for pubk_ring in pubk_rings
    )
    hasher = hf()
    hasher.update(msg + t)
    return hasher.digest()


SValues = Sequence[list[int]]


def _initialize(
    msg: Octets, pubk_rings: Sequence[PubkeyRing], ec: Curve, hf: HashF
) -> tuple[bytes, bytes, SValues]:
    msg_ = bytes_from_octets(msg)
    m = _get_msg_format(msg_, pubk_rings, ec, hf)
    e = [[0] * len(pubk_ring) for pubk_ring in pubk_rings]
    return msg_, m, e


def sign(
    msg: Octets,
    ks: Sequence[int],
    sign_key_idx: Sequence[int],
    sign_keys: Sequence[int],
    pubk_rings: Sequence[PubkeyRing],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> tuple[bytes, SValues]:
    """Borromean ring signature - signing algorithm.

    https://github.com/ElementsProject/borromean-signatures-writeup
    https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

    inputs:
    - msg: message to be signed (bytes)
    - sign_key_idx: list of indexes representing each signing key per ring
    - sign_keys: list containing the whole set of signing keys (one per ring)
    - pubk_rings: dictionary of sequences representing single rings of pub_keys
    """
    msg, m, e = _initialize(msg, pubk_rings, ec, hf)
    e0bytes = m
    # drawn uniformly in [0, ec.n), the same distribution the real
    # s-value has once step 2 reduces it: randbits(256) is uniform over
    # [0, 2**256), not over the scalars, and the two ranges diverge by
    # more than a 2**-127 fraction on a low-cardinality curve -- one
    # forged this way and the real one reduced would then disagree in
    # the same distinguishing way the unreduced real value used to
    s = [
        [secrets.randbelow(ec.n) for _ in range(len(pubk_ring))]
        for pubk_ring in pubk_rings
    ]

    # one entry per ring in each of the three, checked here rather than
    # left to the `strict=True` of the two loops below: a short ks would
    # truncate them silently and sign a subset of the rings -- a signature
    # over fewer rings than the caller asked for, which is the one thing a
    # ring signature must not do quietly. zip's own message is a
    # BTClibValueError's class with none of its content, naming "argument
    # 3" and no parameter of this function; strict=True stays, as the
    # assertion that this check and those loops cannot drift apart
    if not len(pubk_rings) == len(sign_key_idx) == len(ks):
        err_msg = f"{len(pubk_rings)} rings, {len(sign_key_idx)} signing indexes"
        err_msg += f" and {len(ks)} nonces"
        raise BTClibValueError(err_msg)

    # step 1
    for i, (pubk_ring, j_star, k) in enumerate(
        zip(pubk_rings, sign_key_idx, ks, strict=True)
    ):
        keys_size = len(pubk_ring)
        start_idx = (j_star + 1) % keys_size
        r = bytes_from_point(mult(k, ec.G, ec), ec)
        if start_idx != 0:
            for j in range(start_idx, keys_size):
                e[i][j] = int_from_bits(_hash(m, r, i, j, hf), ec.nlen) % ec.n
                # e is already reduced mod n, so only zero can trip this,
                # and for secp256k1 with sha256 zero is a 2**-255
                # accident: exactly two of the 256-bit outputs (0 and n)
                # are 0 mod n. On a low-cardinality curve it is one message
                # in n -- one in eleven on ec13_11 -- which is the corner
                # case issue 183 asked for and what makes ec a parameter
                # worth having: tests/ecc/borromean_test.py reaches this
                # raise, and the three below it, on that curve
                if not 0 < e[i][j] < ec.n:
                    err_msg = "implausible signature failure"
                    raise BTClibRuntimeError(err_msg)
                t = double_mult_var(-e[i][j], pubk_ring[j], s[i][j], ec.G, ec)
                r = bytes_from_point(t, ec)
        e0bytes += r
    hasher = hf()
    hasher.update(e0bytes)
    e0 = hasher.digest()
    # step 2
    # strict=True: see step 1
    for i, (j_star, k) in enumerate(zip(sign_key_idx, ks, strict=True)):
        e[i][0] = int_from_bits(_hash(m, e0, i, 0, hf), ec.nlen) % ec.n
        # zero e again: the same accident documented above
        if not 0 < e[i][0] < ec.n:
            err_msg = "implausible signature failure"
            raise BTClibRuntimeError(err_msg)
        for j in range(1, j_star + 1):
            s[i][j - 1] = secrets.randbelow(ec.n)
            t = double_mult_var(
                -e[i][j - 1], pubk_rings[i][j - 1], s[i][j - 1], ec.G, ec
            )
            r = bytes_from_point(t, ec)
            e[i][j] = int_from_bits(_hash(m, r, i, j, hf), ec.nlen) % ec.n
            # zero e again, and the one guard of the four that stays
            # unreachable from a test: this e hashes an r built from
            # s[i][j-1], drawn from secrets two lines up, so a
            # low-cardinality curve makes it a one-in-n *accident* rather
            # than something a chosen message can arrange
            if not 0 < e[i][j] < ec.n:
                err_msg = "implausible signature failure"  # pragma: no cover
                raise BTClibRuntimeError(err_msg)  # pragma: no cover
        # reduced mod n, like every forged value above: unreduced, this
        # is about twice the bit length of the others -- k and
        # sign_keys[i] * e[i][j_star] are each near n, so their sum is
        # about 512 bits where a forged s stays at 256 -- and the real
        # signer's ring position is then the longest s in the ring, with
        # no computation needed to read it off a published signature.
        # Every consumer already reduces mod n (`mult`, `double_mult_var`),
        # so this changes no signature, only what it discloses.
        s[i][j_star] = (k + sign_keys[i] * e[i][j_star]) % ec.n
    return e0, s


def verify(
    msg: Octets,
    e0: bytes,
    s: SValues,
    pubk_rings: Sequence[PubkeyRing],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> bool:
    """Borromean ring signature - verification algorithm.

    inputs:

    - msg: message to be signed
    - e0: pinned e-value needed to start the verification algorithm
    - s: s-values, both real (one per ring) and forged
    - pubk_rings: sequence of PubKey rings
    """
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states
    try:
        assert_as_valid(msg, e0, s, pubk_rings, ec, hf)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def assert_as_valid(
    msg: Octets,
    e0: bytes,
    s: SValues,
    pubk_rings: Sequence[PubkeyRing],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> None:
    """Refuse an invalid borromean ring signature.

    The rings are walked forward from e0 and must close on the e0 they
    started from; errors carry the reason, verify being the boolean
    answer.
    """
    msg, m, e = _initialize(msg, pubk_rings, ec, hf)
    e0bytes = m

    for i, pubk_ring in enumerate(pubk_rings):
        keys_size = len(pubk_ring)
        e[i][0] = int_from_bits(_hash(m, e0, i, 0, hf), ec.nlen) % ec.n
        # a zero e: the same accident documented in sign, and here
        # nothing is random -- the whole signature is an argument -- so a
        # chosen e0 reaches it on a low-cardinality curve
        if e[i][0] == 0:
            err_msg = "implausible signature failure"
            raise BTClibRuntimeError(err_msg)
        r = b"\0x00"
        for j in range(keys_size):
            t = double_mult_var(-e[i][j], pubk_ring[j], s[i][j], ec.G, ec)
            r = bytes_from_point(t, ec)
            if j != keys_size - 1:
                h = _hash(m, r, i, j + 1, hf)
                e[i][j + 1] = int_from_bits(h, ec.nlen) % ec.n
                # a zero e: the same accident, one ring position later
                if e[i][j + 1] == 0:
                    err_msg = "implausible signature failure"
                    raise BTClibRuntimeError(err_msg)
            else:
                e0bytes += r
    hasher = hf()
    hasher.update(e0bytes)
    e0_prime = hasher.digest()
    if e0_prime != e0:
        raise BTClibRuntimeError("signature verification failed")
