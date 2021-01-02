#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Tests for the `btclib.pedersen` module."

from hashlib import sha256, sha384

import pytest

from btclib.ecc import pedersen
from btclib.ecc.curve import CURVES, secp256k1

secp256r1 = CURVES["secp256r1"]
secp384r1 = CURVES["secp384r1"]


def test_second_generator() -> None:
    """
    important remarks on secp256-zkp prefix for
    compressed encoding of the second generator:
    https://github.com/garyyu/rust-secp256k1-zkp/wiki/Pedersen-Commitment
    """

    H = (
        0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0,
        0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904,
    )
    assert H == pedersen.second_generator(secp256k1, sha256)

    _ = pedersen.second_generator(secp256r1, sha256)
    _ = pedersen.second_generator(secp384r1, sha384)


def test_commitment() -> None:

    ec = secp256k1
    hf = sha256

    r_1 = 0xDEADBEEF
    v1 = 0xBAADCAFE
    # r_1*G + v1*H
    C1 = pedersen.commit(r_1, v1, ec, hf)
    assert pedersen.verify(r_1, v1, C1, ec, hf)

    r_2 = 0xBAADBAAD
    v2 = 0xBAADBEEF
    # r_2*G + v2*H
    C2 = pedersen.commit(r_2, v2, ec, hf)
    assert pedersen.verify(r_2, v2, C2, ec, hf)

    # Pedersen Commitment is additively homomorphic
    # Commit(r_1, v1) + Commit(r_2, v2) = Commit(r_1+r_2, v1+r_2)
    R = pedersen.commit(r_1 + r_2, v1 + v2, ec, hf)
    assert ec.add(C1, C2) == R

    # commit does not verify (with catched exception)
    assert not pedersen.verify(sha256, v1, C2, ec, hf)  # type: ignore
    with pytest.raises(TypeError):
        pedersen.commit(sha256, v1, ec, hf)  # type: ignore
