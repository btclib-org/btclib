# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.dleq` module.

The vectors are BIP374's own, both csv files of
https://github.com/bitcoin/bips/tree/master/bip-0374, vendored under
`tests/ecc/_data/`; `tests/_data/README.md` pins the revision. Every
case of both files is exercised, the failure cases included, and a
generated proof is checked byte for byte against the file rather than
only verified -- the nonce being deterministic, a proof that verifies but
differs from BIP374's is a proof no other implementation would have
produced.
"""

import pytest

from btclib.curves import mult, point_from_pub_key, secp256k1
from btclib.ecc import dleq
from btclib.exceptions import BTClibValueError
from tests import load_csv, vector_id

# what the generation file writes in the proof column of a case that must
# fail; the point at infinity, in its B column, is spelled INFINITY and
# needs no name here -- it is no public key, and btclib refuses it as the
# unparsable string it is
_INVALID = "INVALID"

_GENERATE_VECTORS = load_csv("ecc", "_data", "test_vectors_generate_proof.csv")
_VERIFY_VECTORS = load_csv("ecc", "_data", "test_vectors_verify_proof.csv")


@pytest.mark.parametrize(
    "G,a,B,aux,msg,proof",
    [row[1:-1] for row in _GENERATE_VECTORS],
    ids=[vector_id(int(row[0]), row[-1]) for row in _GENERATE_VECTORS],
)
def test_generate_proof_vectors(
    G: str, a: str, B: str, aux: str, msg: str, proof: str
) -> None:
    """BIP374's generation vectors, the three failure cases included."""
    # an empty message column is no message at all, which is a different
    # input to the hashes than a 32-byte one
    m = msg or None
    if proof == _INVALID:
        # a = 0, a = n, and B at infinity: the conditions BIP374 fails on
        # before any arithmetic, and none of the three is expressible as a
        # btclib private key or public key in the first place
        with pytest.raises(BTClibValueError):
            dleq.generate_proof(a, B, aux, G, m)
        return

    assert dleq.generate_proof(a, B, aux, G, m).hex() == proof
    # and the proof the file holds is the proof that verifies, under the A
    # and C the scalar, the point and the generator of the same row produce
    A = mult(a, point_from_pub_key(G))
    C = mult(a, point_from_pub_key(B))
    assert dleq.verify_proof(A, B, C, proof, G, m)


@pytest.mark.parametrize(
    "G,A,B,C,proof,msg,success",
    [row[1:-1] for row in _VERIFY_VECTORS],
    ids=[vector_id(int(row[0]), row[-1]) for row in _VERIFY_VECTORS],
)
def test_verify_proof_vectors(
    G: str, A: str, B: str, C: str, proof: str, msg: str, success: str
) -> None:
    """BIP374's verification vectors, the seven failure cases included."""
    m = msg or None
    expected = success == "TRUE"
    assert dleq.verify_proof(A, B, C, proof, G, m) is expected
    if expected:
        dleq.assert_proof_as_valid(A, B, C, proof, G, m)
    else:
        with pytest.raises(BTClibValueError):
            dleq.assert_proof_as_valid(A, B, C, proof, G, m)


def test_the_round_trip_on_the_default_generator() -> None:
    """No vector omits the generator; a caller ordinarily does.

    And none omits the auxiliary randomness either, every proof in the
    file being reproducible byte for byte. Both defaults are exercised
    here: what a fresh-randomness proof can be held to is that it
    verifies, and that it is not the proof the previous call returned.
    """
    a = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9
    b = 0x25FCA0B0A1D2FEC6A62E3E1E8CEDAAF1F72F5FEA2B87D4E28D33D0E0B4C6B4F1
    A = mult(a)
    B = mult(b)
    C = mult(a, B)

    proof = dleq.generate_proof(a, B)
    assert dleq.verify_proof(A, B, C, proof)
    assert proof != dleq.generate_proof(a, B)

    # and the shared secret is the one B's holder computes, which is the
    # equivalence the proof is about rather than an aside: b*A == a*B
    assert mult(b, A) == C


def test_the_message_is_32_bytes_or_absent() -> None:
    """BIP374's own restriction, unlike the ssa message of any size.

    Asked of the verification as well as of the generation since issue
    2170: BIP374 asserts the length in `dleq_challenge`, which
    `dleq_verify_proof` reaches at its last step, so the restriction is
    one the verifier holds to and not only the prover.
    """
    a = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9
    B = mult(2)
    A, C = mult(a), mult(a, B)
    good = dleq.generate_proof(a, B, msg="00" * 32)
    for msg in ("", "00" * 31, "00" * 33):
        with pytest.raises(BTClibValueError, match="invalid size"):
            dleq.generate_proof(a, B, msg=msg)
        with pytest.raises(BTClibValueError, match="invalid size"):
            dleq.verify_proof(A, B, C, good, msg=msg)
        with pytest.raises(BTClibValueError, match="invalid size"):
            dleq.assert_proof_as_valid(A, B, C, good, msg=msg)

    # b"" cannot stand in for "no message": an empty message would hash
    # to the same input as an absent one, so the size check refuses it
    # and `None` is the only spelling
    proof = dleq.generate_proof(a, B, msg=None)
    assert dleq.verify_proof(mult(a), B, mult(a, B), proof) is True
    assert dleq.verify_proof(mult(a), B, mult(a, B), proof, msg="00" * 32) is False


def test_a_proof_is_64_bytes() -> None:
    """Anything else is refused, by both spellings (issue 2170).

    BIP374's own reference opens `dleq_verify_proof` with
    `assert len(proof) == 64`, ahead of every condition it answers
    `False` for, and this draws the same line: a buffer of another
    length carries no `e` and no `s` to compare, so the proof does not
    fail to hold -- it is not a proof.
    """
    a = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9
    B = mult(2)
    A, C = mult(a), mult(a, B)
    proof = dleq.generate_proof(a, B)

    for damaged in (proof[:-1], proof + b"\x00", b""):
        for call in (dleq.verify_proof, dleq.assert_proof_as_valid):
            with pytest.raises(BTClibValueError, match="invalid size"):
                call(A, B, C, damaged)


def test_an_s_of_n_or_more_is_refused() -> None:
    """The one BIP374 failure condition neither vector file reaches.

    A proof carrying such an s cannot be generated -- s is computed mod n
    -- so upstream's generator produces none and the pair of files has no
    case for it. Refused all the same, and not because the arithmetic
    would go wrong: s and s + n multiply a point to the same result, so
    an unchecked verifier would accept two encodings of every proof it
    accepts one of. n itself and the largest 32-byte value are the two
    ends of the range that names.

    The check is what makes the encoding canonical rather than what makes
    it safe, and the asymmetry with e says which: e is compared to a hash
    and is left unreduced, so there is exactly one e that verifies.
    """
    a = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9
    B = mult(2)
    A, C = mult(a), mult(a, B)
    e = dleq.generate_proof(a, B)[:32]

    for s in (secp256k1.n, 2**256 - 1):
        forged = e + s.to_bytes(32, "big")
        with pytest.raises(BTClibValueError, match="s not in 0..n-1"):
            dleq.assert_proof_as_valid(A, B, C, forged)
        assert dleq.verify_proof(A, B, C, forged) is False


def test_a_nonce_point_at_infinity_is_refused() -> None:
    """R1 and R2 at infinity, the two conditions no vector reaches either.

    s*G - e*A is infinity exactly when s == e mod n and A == G, and
    s*B - e*C likewise for B == C: two proofs nobody generates, and two
    branches of the verification that a permutation of the vectors above
    happens never to hit. Refused for the reason BIP374 gives them: an
    infinite R has no compressed serialization for the challenge to hash.
    """
    e = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    proof = e.to_bytes(32, "big") + e.to_bytes(32, "big")

    # A == G and s == e: R1 = (s - e)*G
    with pytest.raises(BTClibValueError, match="invalid \\(INF\\) R1"):
        dleq.assert_proof_as_valid(secp256k1.G, mult(3), mult(5), proof)

    # A == 2*G leaves R1 alone, and B == C sends R2 to infinity instead
    with pytest.raises(BTClibValueError, match="invalid \\(INF\\) R2"):
        dleq.assert_proof_as_valid(mult(2), mult(3), mult(3), proof)


def test_a_generator_that_is_no_point_is_refused() -> None:
    """The generator is an argument, so it is an argument to validate."""
    a = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9
    B = mult(2)
    for G in ("02" + "00" * 32, "not a point", (1, 2)):
        with pytest.raises(BTClibValueError):
            dleq.generate_proof(a, B, G=G)
        # and refused by the verification too, rather than reported as a
        # proof that does not hold: the generator is a point of the
        # curve or it is nothing, `point_from_pub_key` proving it while
        # reading it (issue 2170)
        with pytest.raises(BTClibValueError):
            dleq.verify_proof(mult(a), B, mult(a, B), "00" * 64, G)


def test_verify_proof_tells_a_malformed_argument_from_one_that_fails() -> None:
    """Issue 2170's two sides, over the four points and the proof.

    The points arrive as `GE` objects in BIP374's reference, already
    parsed, and a proof is asserted 64 octets long there; what it
    answers `False` for is `s >= GE.ORDER`, an `R` at infinity and a
    challenge that does not match. Here `point_from_pub_key` is that
    parse and `bytes_from_octets` that assertion, both ahead of the try.
    """
    a = 0xC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9
    B = mult(2)
    A, C = mult(a), mult(a, B)
    proof = dleq.generate_proof(a, B)
    assert dleq.verify_proof(A, B, C, proof)

    # a spelling no conversion reads as a point, in each of the four
    # positions a point occupies -- the generator among them, BIP374
    # passing it in
    no_point = "not a point"
    for arguments in (
        (no_point, B, C, proof),
        (A, no_point, C, proof),
        (A, B, no_point, proof),
        (A, B, C, proof, no_point),
    ):
        with pytest.raises(BTClibValueError):
            dleq.verify_proof(*arguments)

    # and a proof of any other length, which is BIP374's own assertion
    with pytest.raises(BTClibValueError, match="invalid size"):
        dleq.verify_proof(A, B, C, proof[:-1])

    # well formed, and merely not the proof of this triple: another
    # point of the curve in C, a 32-octet message the proof was not
    # bound to, and an s at or above the group order
    assert dleq.verify_proof(A, B, mult(3), proof) is False
    assert dleq.verify_proof(A, B, C, proof, msg="00" * 32) is False
    forged = proof[:32] + secp256k1.n.to_bytes(32, "big")
    assert dleq.verify_proof(A, B, C, forged) is False

    # a message of any other length is refused, not answered about:
    # BIP374's `dleq_challenge` opens with
    # `if m is not None: assert len(m) == 32`, reached from
    # `dleq_verify_proof`'s last step, so another size is an
    # AssertionError there rather than a proof that does not hold. An
    # absent message is not a wrong one and stays the default
    for size in (31, 33, 0):
        with pytest.raises(BTClibValueError, match="invalid size"):
            dleq.verify_proof(A, B, C, proof, msg="00" * size)
