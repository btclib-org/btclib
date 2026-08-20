# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.pedersen` module."""

from hashlib import sha256, sha384

import pytest

from btclib.curves import secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import pedersen
from btclib.exceptions import BTClibRuntimeError

secp256r1 = CURVES["secp256r1"]
secp384r1 = CURVES["secp384r1"]


def test_second_generator() -> None:
    """Pin H for (secp256k1, sha256): it is Elements' and CT's H.

    `second_generator`'s docstring says what the constant is and why
    only this one `(ec, hf)` pair is pinned; the two other pairs below
    are only exercised, not pinned, for that same reason.
    """
    H = (
        0x50929B74C1A04954B78B4B6035E97A5E078A5A0F28EC96D547BFEE9ACE803AC0,
        0x31D3C6863973926E049E637CB1B5F40A36DAC28AF1766968C30C2313F3A38904,
    )
    assert pedersen.second_generator(secp256k1, sha256) == H

    _ = pedersen.second_generator(secp256r1, sha256)
    _ = pedersen.second_generator(secp384r1, sha384)


def test_second_generator_is_cached() -> None:
    """Issue #287: (ec, hf) is the cache key, not ec alone.

    A cache hit answers with the very object the first call built --
    fine here, since a Point is a tuple and so cannot be mutated back
    into the cache -- and a different hf is a different entry rather
    than a collision with the one secp256k1/sha256 already filled.
    """
    pedersen.second_generator.cache_clear()

    H1 = pedersen.second_generator(secp256k1, sha256)
    H2 = pedersen.second_generator(secp256k1, sha256)
    assert H1 is H2
    assert pedersen.second_generator.cache_info().hits == 1

    H3 = pedersen.second_generator(secp256k1, sha384)
    assert H3 != H1
    assert pedersen.second_generator.cache_info().hits == 1


def test_commitment() -> None:
    """Verify commit/verify round-trips and the additive homomorphism."""
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
    assert ec.add_var(C1, C2) == R

    pedersen.assert_as_valid(r_1, v1, C1, ec, hf)

    # a commitment that opens to something else must raise, not merely
    # return a falsy value: assert_as_valid is called as a statement, so
    # a return value would be silently discarded
    err_msg = "commitment verification failed"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        pedersen.assert_as_valid(r_1, v1, C2, ec, hf)
    assert not pedersen.verify(r_1, v1, C2, ec, hf)

    # a hash function where a blinding factor goes is a caller error, and
    # verify says so instead of answering False: catching Exception would
    # answer "the commitment does not open" to passing sha256
    with pytest.raises(TypeError):
        pedersen.verify(sha256, v1, C2, ec, hf)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        pedersen.commit(sha256, v1, ec, hf)  # type: ignore[arg-type]


def test_commit_to_infinity() -> None:
    """Refuse r and v both zero mod n: the commitment is INF.

    Any other opening of INF would need the discrete log of H.
    """
    err_msg = r"invalid \(INF\) key"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        pedersen.commit(0, 0, secp256k1, sha256)
