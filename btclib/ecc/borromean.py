#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Borromean signature functions."""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from hashlib import sha256

from btclib.alias import HashF, Octets, Point
from btclib.ec import Curve, bytes_from_point, double_mult, mult, secp256k1
from btclib.exceptions import BTClibRuntimeError
from btclib.utils import bytes_from_octets, int_from_bits

# the curve and the hash function are parameters, as they are in dsa, ssa
# and pedersen, and as the two FIXMEs here asked. They used to be module
# globals -- "ec = secp256k1" and "from hashlib import sha256 as hf" -- so
# selecting either meant rebinding an attribute of this module, which
# changes the algorithm for every other caller in the process

# TODO test corner case on low-cardinality curves


def _hash(m: bytes, R: bytes, i: int, j: int, hf: HashF) -> bytes:
    temp = b"".join(
        [m, R, i.to_bytes(4, "big", signed=False), j.to_bytes(4, "big", signed=False)]
    )
    # hf() then update(), which is how HashF is spelled everywhere else in
    # the package: the alias is Callable[[], Any], a constructor, so hf(temp)
    # does not type check even though hashlib.sha256 accepts it
    hasher = hf()
    hasher.update(temp)
    return bytes(hasher.digest())


PubkeyRing = Sequence[Point]


def _get_msg_format(
    msg: bytes, pubk_rings: Sequence[PubkeyRing], ec: Curve, hf: HashF
) -> bytes:
    t = b"".join(
        b"".join(bytes_from_point(Q, ec) for Q in pubk_ring) for pubk_ring in pubk_rings
    )
    hasher = hf()
    hasher.update(msg + t)
    return bytes(hasher.digest())


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
    s = [
        [secrets.randbits(256) for _ in range(len(pubk_ring))]
        for pubk_ring in pubk_rings
    ]

    # step 1
    for i, (pubk_ring, j_star, k) in enumerate(zip(pubk_rings, sign_key_idx, ks)):
        keys_size = len(pubk_ring)
        start_idx = (j_star + 1) % keys_size
        r = bytes_from_point(mult(k), ec)
        if start_idx != 0:
            for j in range(start_idx, keys_size):
                e[i][j] = int_from_bits(_hash(m, r, i, j, hf), ec.nlen) % ec.n
                # e is already reduced mod n, so only zero can trip this,
                # and for secp256k1 with sha256 zero is a 2**-255
                # accident: exactly two of the 256-bit outputs (0 and n)
                # are 0 mod n. A low-cardinality curve is a different
                # matter, which is what the TODO at the top of the module
                # is about, and what made ec a parameter worth having
                if not 0 < e[i][j] < ec.n:
                    err_msg = "implausible signature failure"  # pragma: no cover
                    raise BTClibRuntimeError(err_msg)  # pragma: no cover
                t = double_mult(-e[i][j], pubk_ring[j], s[i][j], ec.G)
                r = bytes_from_point(t, ec)
        e0bytes += r
    hasher = hf()
    hasher.update(e0bytes)
    e0 = bytes(hasher.digest())
    # step 2
    for i, (j_star, k) in enumerate(zip(sign_key_idx, ks)):
        e[i][0] = int_from_bits(_hash(m, e0, i, 0, hf), ec.nlen) % ec.n
        # zero e again: the same 2**-255 accident documented above
        if not 0 < e[i][0] < ec.n:
            err_msg = "implausible signature failure"  # pragma: no cover
            raise BTClibRuntimeError(err_msg)  # pragma: no cover
        for j in range(1, j_star + 1):
            s[i][j - 1] = secrets.randbits(256)
            t = double_mult(-e[i][j - 1], pubk_rings[i][j - 1], s[i][j - 1], ec.G)
            r = bytes_from_point(t, ec)
            e[i][j] = int_from_bits(_hash(m, r, i, j, hf), ec.nlen) % ec.n
            # zero e again: the same 2**-255 accident documented above
            if not 0 < e[i][j] < ec.n:
                err_msg = "implausible signature failure"  # pragma: no cover
                raise BTClibRuntimeError(err_msg)  # pragma: no cover
        s[i][j_star] = k + sign_keys[i] * e[i][j_star]
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
    # ValueError and BTClibRuntimeError, not Exception: an input that is not
    # a valid signature is False, and so is a verification that failed, but
    # a TypeError is neither -- an hf passed as sha256() instead of sha256
    # is a caller error, and it used to be reported as an invalid signature.
    # BTClibRuntimeError by name and not RuntimeError, because
    # RecursionError is one and is not an answer about a signature
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
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False
    msg, m, e = _initialize(msg, pubk_rings, ec, hf)
    e0bytes = m

    for i, pubk_ring in enumerate(pubk_rings):
        keys_size = len(pubk_ring)
        e[i][0] = int_from_bits(_hash(m, e0, i, 0, hf), ec.nlen) % ec.n
        # a zero e: the same 2**-255 accident documented in sign
        if e[i][0] == 0:
            err_msg = "implausible signature failure"  # pragma: no cover
            raise BTClibRuntimeError(err_msg)  # pragma: no cover
        r = b"\0x00"
        for j in range(keys_size):
            t = double_mult(-e[i][j], pubk_ring[j], s[i][j], ec.G)
            r = bytes_from_point(t, ec)
            if j != keys_size - 1:
                h = _hash(m, r, i, j + 1, hf)
                e[i][j + 1] = int_from_bits(h, ec.nlen) % ec.n
                # a zero e: the same 2**-255 accident documented in sign
                if e[i][j + 1] == 0:
                    err_msg = "implausible signature failure"  # pragma: no cover
                    raise BTClibRuntimeError(err_msg)  # pragma: no cover
            else:
                e0bytes += r
    hasher = hf()
    hasher.update(e0bytes)
    e0_prime = bytes(hasher.digest())
    if e0_prime != e0:
        raise BTClibRuntimeError("signature verification failed")
