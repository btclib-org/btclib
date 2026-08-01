#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Tests for the `btclib.ecc.commit_nonce` module.

The commitment is a parameter of `dsa.sign` and `ssa.sign`, so what is
exercised here is those two: a signature carrying a commitment verifies as
an ordinary one, opens against the value committed to, and opens against
nothing else.

The dsa construction is libsecp256k1-zkp's `ecdsa_s2c`, and the fixed
vectors of that module's test suite are below. There is no upstream
schnorr sign-to-contract, so the ssa side has no vector to match and is
tested against itself and against the properties the scheme needs.
"""

import random
from hashlib import sha1, sha256

import pytest

from btclib.curves import bytes_from_point, mult, secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import dsa, ssa
from btclib.ecc.bip340_nonce import bip340_nonce_
from btclib.ecc.commit_nonce import (
    _tweak,
    commit_entropy_,
    commit_nonce_,
    commit_point_,
)
from btclib.ecc.dsa import _S2C_DATA_TAG, _S2C_POINT_TAG
from btclib.ecc.rfc6979_nonce import rfc6979_nonce_
from btclib.ecc.ssa import _S2C_POINT_TAG as _SSA_POINT_TAG
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.hashes import reduce_to_hlen
from tests.curves.curve_test import low_card_curves

random.seed(42)

_COMMIT = b"to be committed"
_MSG = b"to be signed"

# a key valid on every curve tested here, so that a signature is a
# deterministic function of the arguments and a parity that shows up once
# shows up always
_PRV_KEY = 12345678901234567890


def test_dsa_commitment() -> None:
    for hf in (sha256, sha1):
        for ec in (secp256k1, CURVES["secp160r1"]):
            pub_key = mult(_PRV_KEY, ec.G, ec)
            for lower_s in (True, False):
                sig, receipt = dsa.sign(
                    _MSG, _PRV_KEY, None, lower_s, ec, hf, commit=_COMMIT
                )
                # an ordinary signature, whether or not it commits
                dsa.assert_as_valid(_MSG, pub_key, sig, lower_s, hf)
                dsa.assert_as_valid(
                    _MSG, pub_key, sig, lower_s, hf, commit=_COMMIT, receipt=receipt
                )
                # to that value and to no other
                assert not dsa.verify(
                    _MSG,
                    pub_key,
                    sig,
                    lower_s,
                    hf,
                    commit=b"not this",
                    receipt=receipt,
                )
                # and with the receipt the signer kept, not another point
                assert not dsa.verify(
                    _MSG,
                    pub_key,
                    sig,
                    lower_s,
                    hf,
                    commit=_COMMIT,
                    receipt=mult(2, receipt, ec),
                )


def test_ssa_commitment() -> None:
    # the tweak moves the nonce's point, so BIP340's even-y normalization
    # has to be applied to the moved one: both parities are collected
    # here, the odd ones being the signatures that fail without it
    parities = set()
    for hf in (sha256, sha1):
        for ec in (secp256k1, CURVES["secp160r1"]):
            prv_key, x_Q = ssa.gen_keys(_PRV_KEY, ec)
            commit_hash = reduce_to_hlen(_COMMIT, hf)
            for i in range(4):
                aux = i.to_bytes(hf().digest_size, "big")
                sig, receipt = ssa.sign(_MSG, prv_key, aux, ec, hf, commit=_COMMIT)
                ssa.assert_as_valid(_MSG, x_Q, sig, hf)
                ssa.assert_as_valid(_MSG, x_Q, sig, hf, commit=_COMMIT, receipt=receipt)
                assert not ssa.verify(
                    _MSG, x_Q, sig, hf, commit=b"not this", receipt=receipt
                )
                assert not ssa.verify(
                    _MSG, x_Q, sig, hf, commit=_COMMIT, receipt=mult(2, receipt, ec)
                )
                # the receipt is the even-y point the tweak hashed
                assert receipt[1] % 2 == 0
                W = commit_point_(commit_hash, receipt, _SSA_POINT_TAG, ec, hf)
                parities.add(W[1] % 2)

    assert parities == {0, 1}


def test_the_python_path_is_the_committing_one() -> None:
    """A commitment is entropy the bindings cannot take, as a nonce is.

    The libsecp256k1 fast path derives the nonce itself and its `sign`
    exposes no ndata, so it cannot be the path that commits. What says it
    took the other path is the signature: the one the committed nonce
    produces, derived here a second time out of the parts.
    """
    ec, hf = secp256k1, sha256
    commit_hash = reduce_to_hlen(_COMMIT, hf)
    msg_hash = reduce_to_hlen(_MSG, hf)

    sig, receipt = dsa.sign_(msg_hash, _PRV_KEY, commit_hash=commit_hash)

    entropy = commit_entropy_(commit_hash, _S2C_DATA_TAG, hf)
    nonce = rfc6979_nonce_(msg_hash, _PRV_KEY, ec, hf, entropy)
    assert receipt == mult(nonce, ec.G, ec)
    tweaked_nonce, tweaked_receipt = commit_nonce_(
        commit_hash, nonce, _S2C_POINT_TAG, ec, hf
    )
    assert tweaked_receipt == receipt
    assert sig == dsa.sign_(msg_hash, _PRV_KEY, tweaked_nonce)
    # and the point a verifier recomputes is the tweaked nonce's
    assert commit_point_(commit_hash, receipt, _S2C_POINT_TAG, ec, hf) == mult(
        tweaked_nonce, ec.G, ec
    )


# src/modules/ecdsa_s2c/tests_impl.h, test_ecdsa_s2c_fixed_vectors: the
# key and the message of that fixture, and its two (s2c_data, opening)
# pairs. The opening is the compressed original nonce point, which is
# btclib's receipt, and reproducing it pins every step of the derivation
# at once -- the s2c/ecdsa/data tag, RFC6979's additional data, and the
# seed layout key||msg||data that libsecp256k1's nonce function uses
_ZKP_PRV_KEY = bytes.fromhex("55" * 32)
_ZKP_MSG_HASH = bytes.fromhex("88" * 32)
_ZKP_VECTORS = [
    pytest.param(
        "1bf6fb42f41eb876c4d7aa0d67242b00baab99dc2084493e4e63277fa1f77f22",
        "03f030def3188c0f56fcea87435b307643f45dafe22cbc82fd56034fae97417d3a",
        id="zkp-0",
    ),
    pytest.param(
        "35199a8fbf84ad6ef69a184c1b19285befbe06e60b6264e6d373893f6855e24a",
        "03901717ce7c7484a2ce1b7dc7403b14e0354971393ec092a7f3e0c8e4e2d2639d",
        id="zkp-1",
    ),
]


@pytest.mark.parametrize(("commit_hash", "opening"), _ZKP_VECTORS)
def test_libsecp256k1_zkp_fixed_vectors(commit_hash: str, opening: str) -> None:
    """The receipt is the opening libsecp256k1-zkp's own fixture expects."""
    sig, receipt = dsa.sign_(_ZKP_MSG_HASH, _ZKP_PRV_KEY, commit_hash=commit_hash)
    assert bytes_from_point(receipt, secp256k1).hex() == opening

    # and the commitment opens, which is what the fixture asserts next
    pub_key = mult(int.from_bytes(_ZKP_PRV_KEY, "big"), secp256k1.G, secp256k1)
    assert dsa.verify_(
        _ZKP_MSG_HASH, pub_key, sig, commit_hash=commit_hash, receipt=receipt
    )


def test_the_commitment_reaches_the_nonce() -> None:
    """Two commitments over one message must not share an untweaked nonce.

    Sharing one is the whole vulnerability: the tweaked nonces then
    differ by a value the two openings make public, and two signatures
    over one message with a known nonce difference are two equations in
    the two unknowns k and the private key. The receipt *is* the
    untweaked nonce's point, so distinct receipts are the property, and
    a plain signature's nonce must be a third value again.
    """
    hf = sha256
    _, receipt_a = dsa.sign(_MSG, _PRV_KEY, commit=b"contract A")
    _, receipt_b = dsa.sign(_MSG, _PRV_KEY, commit=b"contract B")
    plain_nonce = rfc6979_nonce_(reduce_to_hlen(_MSG, hf), _PRV_KEY)
    plain_point = mult(plain_nonce, secp256k1.G, secp256k1)
    assert receipt_a != receipt_b
    assert plain_point not in (receipt_a, receipt_b)

    # ssa keeps its aux and mixes the commitment into it, so the same
    # holds there with the aux held fixed -- random aux would hide it
    prv_key, _ = ssa.gen_keys(_PRV_KEY)
    aux = bytes(32)
    _, receipt_a = ssa.sign(_MSG, prv_key, aux, commit=b"contract A")
    _, receipt_b = ssa.sign(_MSG, prv_key, aux, commit=b"contract B")
    plain_k, _, _, _ = bip340_nonce_(reduce_to_hlen(_MSG, hf), prv_key, aux)
    assert receipt_a != receipt_b
    assert mult(plain_k, secp256k1.G, secp256k1) not in (receipt_a, receipt_b)


def test_a_commitment_derives_its_own_nonce() -> None:
    """dsa refuses a nonce beside a commitment; ssa's aux is not a nonce."""
    with pytest.raises(BTClibValueError, match="commitment derives its own nonce"):
        dsa.sign(_MSG, _PRV_KEY, 1234, commit=_COMMIT)
    with pytest.raises(BTClibValueError, match="commitment derives its own nonce"):
        dsa.sign_(
            reduce_to_hlen(_MSG, sha256), _PRV_KEY, 1234, commit_hash=b"\x00" * 32
        )


def test_a_plain_signature_opens_no_commitment() -> None:
    """The r of a signature that committed to nothing is not W.x."""
    ec = secp256k1
    nonce = 1 + random.randrange(ec.n - 1)
    receipt = mult(nonce, ec.G, ec)
    pub_key = mult(_PRV_KEY, ec.G, ec)
    sig = dsa.sign(_MSG, _PRV_KEY, nonce)
    with pytest.raises(BTClibRuntimeError, match="commitment verification failed"):
        dsa.assert_as_valid(_MSG, pub_key, sig, commit=_COMMIT, receipt=receipt)

    prv_key, x_Q = ssa.gen_keys(_PRV_KEY, ec)
    ssa_sig = ssa.sign(_MSG, prv_key)
    with pytest.raises(BTClibRuntimeError, match="commitment verification failed"):
        ssa.assert_as_valid(_MSG, x_Q, ssa_sig, commit=_COMMIT, receipt=receipt)


def test_commitment_needs_the_receipt() -> None:
    """A commitment without its receipt, or a receipt alone, is a caller error.

    A TypeError and not a False: `verify` answers about a signature, and
    "nothing here opens this" is not an answer about one.
    """
    pub_key = mult(_PRV_KEY, secp256k1.G, secp256k1)
    sig, receipt = dsa.sign(_MSG, _PRV_KEY, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="commitment without the receipt"):
        dsa.verify(_MSG, pub_key, sig, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="receipt without the commitment"):
        dsa.verify(_MSG, pub_key, sig, receipt=receipt)

    prv_key, x_Q = ssa.gen_keys(_PRV_KEY)
    ssa_sig, receipt = ssa.sign(_MSG, prv_key, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="commitment without the receipt"):
        ssa.verify(_MSG, x_Q, ssa_sig, commit=_COMMIT)
    with pytest.raises(BTClibTypeError, match="receipt without the commitment"):
        ssa.verify(_MSG, x_Q, ssa_sig, receipt=receipt)


def test_zero_tweaked_nonce() -> None:
    """A tweak that cancels the nonce has no next candidate to try.

    One in n, so it is searched for rather than waited for, on a curve
    where one in n is one in eleven: the commitment is the free argument,
    the tweak being a hash of the other two.
    """
    ec, hf = low_card_curves["ec13_11"], sha256
    nonce = 1
    receipt = mult(nonce, ec.G, ec)
    commit_hash = next(
        h
        for h in (i.to_bytes(4, "big") for i in range(1000))
        if _tweak(h, receipt, _S2C_POINT_TAG, ec, hf) == ec.n - nonce
    )
    with pytest.raises(BTClibRuntimeError, match="zero tweaked nonce"):
        commit_nonce_(commit_hash, nonce, _S2C_POINT_TAG, ec, hf)
