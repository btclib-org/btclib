#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.borromean` module."""

import hashlib
import inspect
import secrets
from hashlib import sha256

import pytest

from btclib.alias import Point
from btclib.curves import secp256k1
from btclib.ecc import borromean, dsa
from btclib.exceptions import BTClibRuntimeError


def test_borromean() -> None:
    nring = 4
    # ring_sizes = [1 + random.randrange(7) for _ in range(nring)]
    # sign_key_idx = [random.randrange(size) for size in ring_sizes]
    # derandomize test to ensure code coverage
    ring_sizes = [3, 4, 6, 7]
    sign_key_idx = [2, 1, 0, 5]

    key_rings = [[dsa.gen_keys() for _ in range(ring_sizes[i])] for i in range(nring)]
    sign_keys = [key_rings[i][sign_key_idx[i]][0] for i in range(nring)]
    pubk_rings = [
        [key_rings[i][j][1] for j in range(ring_sizes[i])] for i in range(nring)
    ]

    msg = b"Borromean ring signature"
    sig = borromean.sign(
        msg, list(range(1, nring + 1)), sign_key_idx, sign_keys, pubk_rings
    )

    borromean.assert_as_valid(msg, sig[0], sig[1], pubk_rings)
    assert borromean.verify(msg, sig[0], sig[1], pubk_rings)
    # bytes, not str: a str msg is taken as hex, so "another message"
    # would fail to parse and never reach the ring verification
    assert not borromean.verify(b"another message", sig[0], sig[1], pubk_rings)
    # a msg that is neither bytes nor a hex-str is a caller error, and
    # verify says so instead of answering False: it used to catch Exception,
    # so an int msg was reported as a failed ring signature
    with pytest.raises(TypeError):
        borromean.verify(0, sig[0], sig[1], pubk_rings)  # type: ignore[arg-type]

    # a forged signature must raise, not merely return a falsy value:
    # assert_as_valid is called as a statement, so a return value
    # would be silently discarded
    err_msg = "signature verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        borromean.assert_as_valid(b"another message", sig[0], sig[1], pubk_rings)


def test_the_curve_and_the_hash_function_are_parameters() -> None:
    """They were module globals, so selecting either was process-wide.

    "ec = secp256k1  # FIXME any curve" and "from hashlib import sha256 as
    hf  # FIXME any hf": choosing another meant rebinding an attribute of
    btclib.ecc.borromean, which changes the algorithm for every other
    caller in the process. They are arguments now, with the same defaults
    and in the same position as in dsa, ssa and pedersen.
    """
    assert not hasattr(borromean, "ec")
    assert not hasattr(borromean, "hf")

    signature = inspect.signature(borromean.sign)
    assert list(signature.parameters)[-2:] == ["ec", "hf"]
    assert signature.parameters["ec"].default is secp256k1
    assert signature.parameters["hf"].default is sha256
    for func in (borromean.verify, borromean.assert_as_valid):
        parameters = inspect.signature(func).parameters
        assert list(parameters)[-2:] == ["ec", "hf"]
        assert parameters["ec"].default is secp256k1
        assert parameters["hf"].default is sha256


def test_another_hash_function_gives_another_signature() -> None:
    """The hf argument is threaded all the way down, not merely accepted."""
    msg = "0f" * 32
    nring = 2
    ring_sizes = [2, 2]
    sign_key_idx = [0, 1]

    prv_keys: list[list[int]] = [[] for _ in range(nring)]
    pub_keys: list[list[Point]] = [[] for _ in range(nring)]
    sign_keys = []
    for i in range(nring):
        for _j in range(ring_sizes[i]):
            prv_key, pub_key = dsa.gen_keys()
            prv_keys[i].append(prv_key)
            pub_keys[i].append(pub_key)
        sign_keys.append(prv_keys[i][sign_key_idx[i]])
    ks = [1 + secrets.randbelow(secp256k1.n - 1) for _ in range(nring)]

    sig_256 = borromean.sign(msg, ks, sign_key_idx, sign_keys, pub_keys)
    sig_512 = borromean.sign(
        msg, ks, sign_key_idx, sign_keys, pub_keys, hf=hashlib.sha512
    )
    assert sig_256[0] != sig_512[0]

    # each verifies under its own hash function and under no other
    assert borromean.verify(msg, sig_256[0], sig_256[1], pub_keys)
    assert borromean.verify(msg, sig_512[0], sig_512[1], pub_keys, hf=hashlib.sha512)
    assert not borromean.verify(
        msg, sig_256[0], sig_256[1], pub_keys, hf=hashlib.sha512
    )
    assert not borromean.verify(msg, sig_512[0], sig_512[1], pub_keys)
