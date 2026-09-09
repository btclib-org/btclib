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

The codec is asked three things wherever the suite runs: the fixed
vectors libsecp256k1-zkp's own C tests hold for each of the two
serializations; the commitments vendored in
`tests/ecc/_data/zkp_rangeproof_vectors.json`, which that library wrote
and which have to go back out as they came in; and the refusals
`secp256k1_pedersen_commitment_parse` makes. What only the marked tests
add is that library answering now rather than in a recording:
`zkp.generator.pedersen_commit` over freshly drawn `(r, v)`, and
`zkp.generator.h()`.
"""

import secrets
from collections.abc import Callable
from hashlib import sha256, sha384
from typing import Any

import pytest

from btclib.alias import INF, Point
from btclib.curves import mult, point_from_octets, secp256k1
from btclib.curves.curve import CURVES
from btclib.ecc import pedersen
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from tests import load, needs_zkp, vector_id

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

# the commitments `zkp.generator.pedersen_commit` wrote for the entries
# `tests/ecc/rangeproof_test.py` reads: that file records a proof beside
# the commitment it is about, and the commitment is this module's.
# `tests/_data/README.md` has how it was recorded
_VECTORS = load("ecc", "_data", "zkp_rangeproof_vectors.json")
_IDS = [vector_id(i, v["id"]) for i, v in enumerate(_VECTORS)]

# libsecp256k1-zkp's own fixed vectors for the two serializations, both
# in `src/modules/generator/tests_impl.h`: `test_generator_fixed_vector`
# holds the first and `test_pedersen_commitment_fixed_vector` the
# second, and each parses it, writes it back and compares. They carry
# one x and one residuosity bit at two tags, so they name one point
_ZKP_GENERATOR_VECTOR = (
    "0bc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)
_ZKP_COMMITMENT_VECTOR = (
    "09c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

# the pair of leading octets a serialized commitment has, written here
# rather than read off the module: an assertion that both of them turned
# up would otherwise move with what it is testing
_COMMITMENT_OCTETS = {0x08, 0x09}


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


def test_the_upstream_fixed_vectors_name_one_point_at_two_tags() -> None:
    """libsecp256k1-zkp's own vectors, each read and written back.

    The x is 2G's and the point is not 2G: the y of 2G is a quadratic
    residue, asserted here rather than stated, and both leading octets
    report a y that is not one.
    """
    two_g = mult(2, secp256k1.G, secp256k1)
    assert secp256k1.y_quadratic_residue_var(two_g[0]) == two_g[1]
    minus_two_g = secp256k1.negate(two_g)

    generator = bytes.fromhex(_ZKP_GENERATOR_VECTOR)
    assert pedersen.generator_from_octets(generator) == minus_two_g
    assert pedersen.bytes_from_generator(minus_two_g) == generator

    commitment = bytes.fromhex(_ZKP_COMMITMENT_VECTOR)
    assert pedersen.commitment_from_octets(commitment) == minus_two_g
    assert pedersen.bytes_from_commitment(minus_two_g) == commitment


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_a_vendored_commitment_goes_back_out_as_it_came_in(
    vector: dict[str, Any],
) -> None:
    """Octets libsecp256k1-zkp wrote, read here and written back.

    Each is that library's own answer to
    `zkp.generator.pedersen_commit`, recorded with the blinding factor
    and the value that produced it, so the round trip is against a
    serialization this tree did not write.
    """
    octets = bytes.fromhex(vector["commitment"])
    commitment = pedersen.commitment_from_octets(octets)
    assert secp256k1.is_on_curve(commitment)
    assert pedersen.bytes_from_commitment(commitment) == octets


def test_the_leading_octet_is_residuosity_and_not_parity() -> None:
    """The vendored commitments are what says the two readings are two.

    Bit 0 read as the parity of y -- the `02`/`03` a SEC compressed
    point carries -- lifts some of these commitments to the point
    residuosity lifts them to and the rest to its negation. What
    decides is the parity of the y that is a square, a property of the
    commitment's own x and not of the proof recorded beside it, which
    is the assertion inside the loop.

    Both outcomes are asserted: it is the agreements that make the
    wrong reading worth a test, since there the two answer one point
    and nothing in the octets says which was read.
    """
    agreements = set()
    for vector in _VECTORS:
        octets = bytes.fromhex(vector["commitment"])
        by_parity = point_from_octets(bytes([0x02 | octets[0] & 1]) + octets[1:])
        commitment = pedersen.commitment_from_octets(octets)
        assert by_parity[0] == commitment[0]
        agrees = by_parity == commitment
        assert agrees == (secp256k1.y_quadratic_residue_var(commitment[0]) % 2 == 0)
        agreements.add(agrees)
    assert agreements == {True, False}


@pytest.mark.parametrize("prefix", [0x00, 0x02, 0x03, 0x04, 0x07, 0x0A, 0x0B, 0x0C])
def test_a_commitment_refuses_a_leading_octet_outside_its_pair(prefix: int) -> None:
    """`(input[0] & 0xFE) != 8` is the whole of what the format admits.

    `0a` and `0b` are the generator's own pair, and `0c` is what
    `test_pedersen_commitment_fixed_vector` puts to
    `secp256k1_pedersen_commitment_parse`; `02` and `03` are the SEC
    prefixes for the same x, which is the confusion this codec is here
    to end.
    """
    octets = bytes([prefix]) + bytes.fromhex(_ZKP_COMMITMENT_VECTOR)[1:]
    with pytest.raises(BTClibValueError, match="not a Pedersen commitment"):
        pedersen.commitment_from_octets(octets)


@pytest.mark.parametrize("prefix", [0x02, 0x03, 0x08, 0x09, 0x0C])
def test_a_generator_refuses_a_leading_octet_outside_its_pair(prefix: int) -> None:
    """`(input[0] & 0xFE) != 10`, and `08` is the case zkp's own test makes.

    `test_generator_fixed_vector` flips that vector's leading octet to
    a commitment's and checks `secp256k1_generator_parse` returns zero.
    """
    octets = bytes([prefix]) + bytes.fromhex(_ZKP_GENERATOR_VECTOR)[1:]
    with pytest.raises(BTClibValueError, match="not a generator"):
        pedersen.generator_from_octets(octets)


def test_a_commitment_refuses_an_x_no_point_of_the_curve_has() -> None:
    """`secp256k1_fe_set_b32_limit` and `secp256k1_ge_x_on_curve_var`.

    p itself is not a field element, and zero is one that names no
    point: 7 is not a square modulo p, so nothing squares to 0**3 + 7.
    """
    err_msg = r"x-coordinate not in 0\.\.p-1"
    with pytest.raises(BTClibValueError, match=err_msg):
        pedersen.commitment_from_octets(b"\x08" + secp256k1.p.to_bytes(32, "big"))

    with pytest.raises(BTClibValueError, match="invalid x-coordinate: 0"):
        pedersen.commitment_from_octets(b"\x08" + bytes(32))


def test_a_commitment_is_as_many_octets_as_it_is() -> None:
    """One tag and one x, and `bytes_from_octets` is what says so."""
    octets = bytes.fromhex(_ZKP_COMMITMENT_VECTOR)
    with pytest.raises(BTClibValueError, match="invalid size: 32 bytes instead of 33"):
        pedersen.commitment_from_octets(octets[:-1])


@pytest.mark.parametrize(
    "write", [pedersen.bytes_from_commitment, pedersen.bytes_from_generator]
)
def test_writing_refuses_what_has_no_x_to_write(
    write: Callable[[Point], bytes],
) -> None:
    """A pair that is no point of secp256k1, and the infinity point.

    `secp256k1_pedersen_commit` does not save the second either: it
    answers zero where the sum lands there, rather than serializing a
    point with no x.
    """
    with pytest.raises(BTClibValueError, match="point not on curve"):
        write((1, 2))

    with pytest.raises(BTClibValueError, match="no bytes representation"):
        write(INF)


# `pragma: no cover` on every `@needs_zkp` below, that marker being the
# reason: `tests/conftest.py` turns it into a skip in an unflagged
# build, and excluding what a build cannot execute is what leaves the
# floor a measurement of the suite rather than of the build the machine
# has (issue #1885). The marker's line and not the `def` under
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
    assert pedersen.bytes_from_generator(H) == zkp_generator.h()
    assert pedersen.generator_from_octets(zkp_generator.h()) == H
    # and not a codec that answers h() for whatever it is handed
    assert pedersen.bytes_from_generator(secp256k1.G) != zkp_generator.h()


@needs_zkp  # pragma: no cover -- no zkp.generator.pedersen_commit to compare against
def test_commit_matches_zkp() -> None:
    """`commit` is `zkp.generator.pedersen_commit`: rG + vH over one H.

    Sampled inside what both sides accept, a blinding factor in [1, n)
    and a value below 2**64; `test_commit_outside_the_zkp_intersection`
    below is what each does at the edges and why they are left out.

    A writer reading `y & 1` instead answers the same octet as
    `bytes_from_commitment` wherever y's parity and its quadratic
    residuosity agree, so a sample carrying only those cases would
    report agreement about the wrong convention. Both octets have to
    turn up, which is what the assertion after the loop asks for.
    """
    octets_seen = set()
    for _ in range(64):
        r = 1 + secrets.randbelow(secp256k1.n - 1)
        v = secrets.randbelow(2**64)
        commitment = zkp_generator.pedersen_commit(r, v)
        assert pedersen.bytes_from_commitment(pedersen.commit(r, v)) == commitment
        assert pedersen.commitment_from_octets(commitment) == pedersen.commit(r, v)
        octets_seen.add(commitment[0])
        # another value under the same blinding factor is another point:
        # the agreement above is not a comparison against a constant
        assert zkp_generator.pedersen_commit(r, v ^ 1) != commitment
    assert octets_seen == _COMMITMENT_OCTETS


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
    assert zkp_generator.pedersen_commit(0, 7) == pedersen.bytes_from_commitment(
        mult(7, H, secp256k1)
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
    gives: a proof rides on the commitment's serialization, so a codec
    right on one octet and wrong on the other verifies here and fails
    there.
    """
    octets_seen = set()
    for _ in range(64):
        r = 1 + secrets.randbelow(secp256k1.n - 1)
        v = secrets.randbelow(2**64)
        commitment = pedersen.bytes_from_commitment(pedersen.commit(r, v))
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
    assert octets_seen == _COMMITMENT_OCTETS


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to put a wrong opening to
def test_zkp_rangeproof_refuses_a_wrong_opening() -> None:
    """Each half of the agreement above can fail, and is made to.

    A proof is bound to the value and to the blinding factor the
    commitment was built from, and the rewind to the nonce as well.
    Flipping the leading octet is the control on the codec itself: the
    flipped octets name the other of the two points sharing that x, and
    no proof of this commitment is a proof of that one -- so a writer
    that put the wrong octet there would be verifying a proof about a
    point `commit` never returned.

    `sign` answers a proof in each of these: what refuses them is
    `verify`, which returns None where a proof does not open its
    commitment, that being a verdict and not an exception.
    """
    r = 1 + secrets.randbelow(secp256k1.n - 1)
    v = secrets.randbelow(2**64)
    commitment = pedersen.bytes_from_commitment(pedersen.commit(r, v))
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
