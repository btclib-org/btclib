# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.pedersen` module.

The `zkp`-marked tests at the end are issue #1679's third oracle. H for
(secp256k1, sha256) is the generator libsecp256k1-zkp calls
`secp256k1_generator_h`, and `commit` is the rG + vH that library's
`secp256k1_pedersen_commit` computes, so both are asked of
`btclib_secp256k1.zkp` and compared; a commitment btclib computed then
goes to `zkp.rangeproof`, which proves it, verifies the proof and
rewinds it back to the value and the blinding factor btclib chose.

That gives this tree no rangeproof. The proof, its verification and its
rewind are libsecp256k1-zkp's throughout, and what btclib contributes is
the commitment they are about: nothing here builds or reads a proof.
"""

import secrets
from hashlib import sha256, sha384

import pytest

from btclib.alias import Point
from btclib.curves import mult, secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import pedersen
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from tests import needs_zkp

# guarded module scope, the same shape `btclib._libsecp256k1` uses: this
# file is collected in every job, including the no-bindings one where
# `btclib_secp256k1` does not exist at all, and pytest imports every
# module it collects before `tests.needs_zkp` can skip anything in it
try:
    from btclib_secp256k1.zkp import generator as zkp_generator
    from btclib_secp256k1.zkp import rangeproof as zkp_rangeproof
except ImportError:  # pragma: no cover -- only the no-bindings job reaches this
    zkp_generator = None  # type: ignore[assignment]
    zkp_rangeproof = None  # type: ignore[assignment]

secp256r1 = CURVES["secp256r1"]
secp384r1 = CURVES["secp384r1"]


def test_second_generator() -> None:
    """Pin H for (secp256k1, sha256): it is Elements' and CT's H.

    `second_generator`'s docstring says what the constant is and why
    only this one `(ec, hf)` pair is pinned; the two other pairs below
    are only exercised, not pinned, for that same reason.

    This holds the literal; `test_second_generator_matches_zkp` at the
    end of this file asks libsecp256k1-zkp itself for the same value,
    wherever the flagged extension is built.
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

    # r and v take every spelling `Integer` does, octets included
    r_hex = "00" * 31 + "03"
    assert pedersen.commit(r_hex, v1, ec, hf) == pedersen.commit(3, v1, ec, hf)


def test_commit_unblinded() -> None:
    """Refuse r = 0 mod n: the commitment then carries no blinding at all.

    v is not checked on its own: commit(0, 0) is refused by this same
    check, being the r = 0 mod n case of an unblinded commitment.
    """
    err_msg = r"invalid \(unblinded\) commitment"
    with pytest.raises(BTClibValueError, match=err_msg):
        pedersen.commit(0, 5, secp256k1, sha256)
    with pytest.raises(BTClibValueError, match=err_msg):
        pedersen.commit(secp256k1.n, 5, secp256k1, sha256)
    with pytest.raises(BTClibValueError, match=err_msg):
        pedersen.commit(0, 0, secp256k1, sha256)

    assert not pedersen.verify(0, 5, pedersen.commit(5, 5, secp256k1, sha256))


def test_commit_blinding_factor_sum() -> None:
    """A range check on r would break the additive homomorphism.

    r_1 + r_2 lands past ec.n and is still a valid blinding factor for
    the summed commitment; only a sum landing on 0 mod n -- the second
    factor chosen to cancel the first -- is the unblinded case.
    """
    ec = secp256k1
    r_1, r_2 = ec.n - 3, 10
    C1, C2 = pedersen.commit(r_1, 4, ec), pedersen.commit(r_2, 5, ec)

    assert not 1 <= r_1 + r_2 < ec.n
    R = pedersen.commit(r_1 + r_2, 9, ec)
    assert ec.add_var(C1, C2) == R
    assert pedersen.verify(r_1 + r_2, 9, R, ec)

    err_msg = r"invalid \(unblinded\) commitment"
    with pytest.raises(BTClibValueError, match=err_msg):
        pedersen.commit(r_1 + 3, 9, ec)  # r_1 + 3 == ec.n


# libsecp256k1-zkp's own serializations, both in
# `src/modules/generator/main_impl.h`: `secp256k1_generator_serialize`
# writes `11 ^ secp256k1_fe_is_square_var(y)` and then the 32 bytes of x,
# and `secp256k1_pedersen_commitment_serialize` hands back what
# `secp256k1_pedersen_commitment_save` stored the same way, `9 ^` the same
# bit. So the leading octet says whether y is a quadratic residue, where a
# SEC compressed point's says whether y is even: `bytes_from_point` is not
# the bridge, and `_zkp_octets` below is.
_ZKP_GENERATOR_TAG = 11
_ZKP_COMMITMENT_TAG = 9


def _zkp_octets(
    point: Point, tag: int
) -> bytes:  # pragma: no cover -- only the marked tests below call this
    """Write a point the way libsecp256k1-zkp serializes one.

    Euler's criterion is what reads the bit the two serializations
    share: y is a quadratic residue exactly where y**((p-1)/2) is 1.

    Called from the `zkp`-marked tests below alone, hence the pragma.
    """
    x, y = point
    p = secp256k1.p
    return bytes([tag ^ int(pow(y, (p - 1) // 2, p) == 1)]) + x.to_bytes(32, "big")


# `pragma: no cover` on every `@needs_zkp` below, that marker being the
# reason: `ZKP_AVAILABLE` is False in every job that measures coverage,
# `.github/workflows/zkp-oracle.yml` being the one job where it is True,
# and that job's own `pytest -m zkp --no-cov` collects no coverage data
# for any report to combine. The marker's line and not the `def` under
# it: `ruff format` reflows a `def` line a comment carries past 88
# columns, splitting `-> None:` across three lines to hang it, and
# leaves a decorator line alone.
#
# `secrets` and not a seeded `random`, as `tests/ecc/musig2_test.py`'s own
# zkp tests: what the loops below have to reach is a sample of each
# leading octet, and each asserts that at its end rather than arranging
# it with a seed.
@needs_zkp  # pragma: no cover -- no zkp.generator.h() to compare H against
def test_second_generator_matches_zkp() -> None:
    """H is the `secp256k1_generator_h` the library itself holds.

    `test_second_generator` above pins H against a constant transcribed
    from libsecp256k1-zkp's source; this asks that library for it, so the
    two agree about a value neither of them copied from the other.

    It settles nothing about the leading octet: H's y is neither a
    quadratic residue nor odd, so `11 ^ is_square(y)` and the SEC-shaped
    `11 ^ (y & 1)` write the same octet for it.
    `test_commit_matches_zkp` below is where the two conventions part.
    """
    H = pedersen.second_generator(secp256k1, sha256)
    assert _zkp_octets(H, _ZKP_GENERATOR_TAG) == zkp_generator.h()
    # and not a bridge that answers h() for whatever it is handed
    assert _zkp_octets(secp256k1.G, _ZKP_GENERATOR_TAG) != zkp_generator.h()


@needs_zkp  # pragma: no cover -- no zkp.generator.pedersen_commit to compare against
def test_commit_matches_zkp() -> None:
    """`commit` is `zkp.generator.pedersen_commit`: rG + vH over one H.

    Sampled inside what both sides accept, a blinding factor in [1, n)
    and a value below 2**64; `test_commit_outside_the_zkp_intersection`
    below is what each does at the edges and why they are left out.

    A bridge reading `y & 1` instead writes the same octet as the real
    one wherever y's parity and its quadratic residuosity agree, so a
    sample carrying only those cases would report agreement about the
    wrong convention. Both octets have to turn up, which is what the
    assertion after the loop asks for.
    """
    octets_seen = set()
    for _ in range(64):
        r = 1 + secrets.randbelow(secp256k1.n - 1)
        v = secrets.randbelow(2**64)
        commitment = zkp_generator.pedersen_commit(r, v)
        assert _zkp_octets(pedersen.commit(r, v), _ZKP_COMMITMENT_TAG) == commitment
        octets_seen.add(commitment[0])
        # another value under the same blinding factor is another point:
        # the agreement above is not a comparison against a constant
        assert zkp_generator.pedersen_commit(r, v ^ 1) != commitment
    assert octets_seen == {_ZKP_COMMITMENT_TAG, _ZKP_COMMITMENT_TAG ^ 1}


@needs_zkp  # pragma: no cover -- no zkp side to hold each edge against
def test_commit_outside_the_zkp_intersection() -> None:
    """Each edge belongs to one side alone, which is why neither is sampled.

    r = 0 mod n: `commit` refuses the unblinded commitment its own
    docstring names, and libsecp256k1-zkp answers v*H, the very point
    anyone who guesses v recomputes. r past n: `commit` takes it, a sum
    of blinding factors being a blinding factor, and the C call refuses
    the scalar overflow. v past 2**64: `commit` takes it, and zkp's value
    is a uint64.
    """
    n = secp256k1.n
    H = pedersen.second_generator(secp256k1, sha256)

    err_msg = r"invalid \(unblinded\) commitment"
    with pytest.raises(BTClibValueError, match=err_msg):
        pedersen.commit(0, 7)
    assert zkp_generator.pedersen_commit(0, 7) == _zkp_octets(
        mult(7, H, secp256k1), _ZKP_COMMITMENT_TAG
    )

    assert pedersen.verify(n + 5, 7, pedersen.commit(n + 5, 7))
    with pytest.raises(RuntimeError, match="Pedersen commitment failed"):
        zkp_generator.pedersen_commit(n + 5, 7)

    assert pedersen.verify(7, 2**64, pedersen.commit(7, 2**64))
    with pytest.raises(ValueError, match=r"value must be an int in \[0, 2\*\*64\)"):
        zkp_generator.pedersen_commit(7, 2**64)


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to prove and rewind with
def test_zkp_rangeproof_over_a_btclib_commitment() -> None:
    """Prove, verify and rewind a commitment `commit` computed.

    All three are libsecp256k1-zkp's, and the rewind is what makes them
    a comparison rather than a round trip inside that library: the value
    and the blinding factor it hands back are the ones btclib chose,
    recovered from a proof about a point btclib computed.

    Both leading octets again, for the reason `test_commit_matches_zkp`
    gives: a proof rides on the commitment's serialization, so a bridge
    right on one octet and wrong on the other verifies here and fails
    there.
    """
    octets_seen = set()
    for _ in range(64):
        r = 1 + secrets.randbelow(secp256k1.n - 1)
        v = secrets.randbelow(2**64)
        commitment = _zkp_octets(pedersen.commit(r, v), _ZKP_COMMITMENT_TAG)
        octets_seen.add(commitment[0])
        nonce = secrets.token_bytes(32)
        proof = zkp_rangeproof.sign(commitment, r, nonce, v)

        proven_range = zkp_rangeproof.verify(commitment, proof)
        assert proven_range is not None
        min_value, max_value = proven_range
        assert min_value <= v <= max_value

        blind, value, _message, rewound_min, rewound_max = zkp_rangeproof.rewind(
            commitment, proof, nonce
        )
        assert int.from_bytes(blind, "big") == r
        assert value == v
        assert (rewound_min, rewound_max) == (min_value, max_value)
    assert octets_seen == {_ZKP_COMMITMENT_TAG, _ZKP_COMMITMENT_TAG ^ 1}


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to put a wrong opening to
def test_zkp_rangeproof_refuses_a_wrong_opening() -> None:
    """Each half of the agreement above can fail, and is made to.

    A proof is bound to the value and to the blinding factor the
    commitment was built from, and the rewind to the nonce as well.
    Flipping the leading octet is the control on the bridge itself: the
    flipped octets name the other of the two points sharing that x, and
    no proof of this commitment is a proof of that one -- so a bridge
    writing the wrong octet would be verifying a proof about a point
    `commit` never returned.

    `sign` answers a proof in each of these: what refuses them is
    `verify`, which returns None where a proof does not open its
    commitment, that being a verdict and not an exception.
    """
    r = 1 + secrets.randbelow(secp256k1.n - 1)
    v = secrets.randbelow(2**64)
    commitment = _zkp_octets(pedersen.commit(r, v), _ZKP_COMMITMENT_TAG)
    nonce = secrets.token_bytes(32)
    proof = zkp_rangeproof.sign(commitment, r, nonce, v)
    assert zkp_rangeproof.verify(commitment, proof) is not None

    flipped = bytes([commitment[0] ^ 1]) + commitment[1:]
    assert zkp_rangeproof.verify(flipped, proof) is None

    other_value = zkp_rangeproof.sign(commitment, r, nonce, v ^ 1)
    assert zkp_rangeproof.verify(commitment, other_value) is None

    other_r = 1 + secrets.randbelow(secp256k1.n - 1)
    other_blind = zkp_rangeproof.sign(commitment, other_r, nonce, v)
    assert zkp_rangeproof.verify(commitment, other_blind) is None

    err_msg = "proof does not verify, or rewind failed"
    with pytest.raises(ValueError, match=err_msg):
        zkp_rangeproof.rewind(commitment, proof, secrets.token_bytes(32))
