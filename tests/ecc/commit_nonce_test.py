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
"""

import random
from hashlib import sha1, sha256

import pytest

from btclib.curves import mult, secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import dsa, ssa
from btclib.ecc.commit_nonce import _tweak, commit_nonce_, commit_point_
from btclib.ecc.rfc6979_nonce import rfc6979_nonce_
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError
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
            for nonce in (None, 1 + random.randrange(ec.n - 1)):
                sig, receipt = dsa.sign(
                    _MSG, _PRV_KEY, nonce, True, ec, hf, commit=_COMMIT
                )
                # an ordinary signature, whether or not it commits
                dsa.assert_as_valid(_MSG, pub_key, sig, True, hf)
                dsa.assert_as_valid(
                    _MSG, pub_key, sig, True, hf, commit=_COMMIT, receipt=receipt
                )
                # to that value and to no other
                assert not dsa.verify(
                    _MSG, pub_key, sig, True, hf, commit=b"not this", receipt=receipt
                )
                # and with the receipt the signer kept, not another point
                assert not dsa.verify(
                    _MSG,
                    pub_key,
                    sig,
                    True,
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
                parities.add(commit_point_(commit_hash, receipt, ec, hf)[1] % 2)

    assert parities == {0, 1}


def test_the_python_path_is_the_committing_one() -> None:
    """A commitment is a nonce the bindings cannot take, as a nonce is.

    The libsecp256k1 fast path derives the nonce itself, so it cannot be
    the path that signs with a tweaked one. What says it took the other
    path is the signature: the one the tweaked nonce produces.
    """
    ec, hf = secp256k1, sha256
    commit_hash = reduce_to_hlen(_COMMIT, hf)
    msg_hash = reduce_to_hlen(_MSG, hf)

    sig, receipt = dsa.sign_(msg_hash, _PRV_KEY, commit_hash=commit_hash)

    nonce = rfc6979_nonce_(msg_hash, _PRV_KEY, ec, hf)
    assert receipt == mult(nonce, ec.G, ec)
    tweaked_nonce, tweaked_receipt = commit_nonce_(commit_hash, nonce, ec, hf)
    assert tweaked_receipt == receipt
    assert sig == dsa.sign_(msg_hash, _PRV_KEY, tweaked_nonce)
    # and the point a verifier recomputes is the tweaked nonce's
    assert commit_point_(commit_hash, receipt, ec, hf) == mult(tweaked_nonce, ec.G, ec)


def test_dsa_commitment_vector() -> None:
    """The scheme is the one it was, checked against a signature it made.

    Nothing in a signature says that it commits, so a regression here is
    invisible to a verifier that was handed the receipt of the same run:
    the vectors are the answers of the implementation this replaced.
    """
    prv_key = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    nonce = 0x0FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA987654321

    sig, receipt = dsa.sign(_MSG, prv_key, nonce, commit=_COMMIT)
    assert sig.r == 0xC696D81308C12BED41C65B0DCFC7A6245BE7FA9FB21EF4F16501C5CE2958032F
    assert sig.s == 0x7A617D5D11F3E80F88169E11247361807EF9CB2048D08E6FD0859D970C6A57B8
    assert receipt == (
        0xFD1B7DE8C449EECDA5E5E2F3B4D7DCB5C241D0BB727D1C2098A4D3F423857B62,
        0xF53E2185247B1AD26F62049A7CF51ECA19E071947257B46FC3F8E6374783C59B,
    )

    # and with the RFC6979 nonce, which the commitment does not replace
    sig, receipt = dsa.sign(_MSG, prv_key, commit=_COMMIT)
    assert sig.r == 0xE7A2FF506BFFA4E086CEA910214F7D707B85E348EB5A8C754765E046F0366D21
    assert sig.s == 0x6FE9CADCED3B6BCD2D3EF1FEB300BA4A4FFE1E75E90D47E984D86B7903059114
    assert receipt == (
        0xD7F052C5EB79E90264FABB4B66C7BDA7D1265A39DF8065F842F530BB28D7AA25,
        0xD8CDB86D6FE2284B12D4E23D07D4B8695BC872CA4B53D6B88877012EF348C1B1,
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
        if _tweak(h, receipt, ec, hf) == ec.n - nonce
    )
    with pytest.raises(BTClibRuntimeError, match="zero tweaked nonce"):
        commit_nonce_(commit_hash, nonce, ec, hf)
