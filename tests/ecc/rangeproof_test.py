# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.rangeproof` module.

The vectors are proofs libsecp256k1-zkp signed, recorded with the
arguments that produced them and with what `zkp.rangeproof.info`
answers for each -- `tests/_data/README.md` has the recording and how
to make another. They are here so that the parser is exercised
wherever the suite runs: the flagged extension exists in
`.github/workflows/zkp-oracle.yml`'s job alone, so a test that can only
ask the library leaves the parser unmeasured in every ordinary run.

What the vectors are asked: that a parse of the header says what `info`
said about the same octets, field for field; that `serialize` writes
those octets back byte for byte, which is what pins the fields `info`
is silent about -- the sign bits, the ring commitments and the
signature; and that the length the mantissa implies is the length zkp
wrote.

The `zkp`-marked tests at the end put the same questions to the library
itself, and one more the recording needs: that signing again with the
recorded arguments answers the very octets vendored here.
"""

from io import BytesIO
from typing import Any

import pytest

from btclib.curves import secp256k1
from btclib.ecc.borromean import BorromeanSig
from btclib.ecc.rangeproof import RangeProof
from btclib.exceptions import BTClibValueError
from tests import load, needs_zkp, replace_unchecked, vector_id

# guarded module scope, the same shape `tests/ecc/pedersen_test.py` uses:
# this file is collected in every job, including the no-bindings one where
# `btclib_secp256k1` does not exist at all
try:
    from btclib_secp256k1.zkp import generator as zkp_generator
    from btclib_secp256k1.zkp import rangeproof as zkp_rangeproof
except ImportError:  # pragma: no cover -- only the no-bindings job reaches this
    zkp_generator = None  # type: ignore[assignment]
    zkp_rangeproof = None  # type: ignore[assignment]

_VECTORS = load("ecc", "_data", "zkp_rangeproof_vectors.json")
_IDS = [vector_id(i, v["id"]) for i, v in enumerate(_VECTORS)]

_HAS_NZ_RANGE = 64
_HAS_MIN = 32


def _octets(id_: str) -> bytes:
    return bytes.fromhex(next(v for v in _VECTORS if v["id"] == id_)["proof"])


def _header_size(octets: bytes) -> int:
    # computed from the flags here rather than asked of the parser: an
    # offset the module supplied would move with what is being tested
    return 1 + bool(octets[0] & _HAS_NZ_RANGE) + 8 * bool(octets[0] & _HAS_MIN)


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_parse_reads_the_header_zkp_reads(vector: dict[str, Any]) -> None:
    """Field for field, a parse says what `zkp.rangeproof.info` said.

    `info` answers zero for a proof that carries no `min_value` field
    and for one that carries eight zero octets, so the comparison is
    against `min_value or 0`; which of the two a proof is stays in the
    round trip below.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    info = vector["info"]
    assert proof.exp == info["exp"]
    assert proof.mantissa == info["mantissa"]
    assert (proof.min_value or 0) == info["min value"]
    assert proof.max_value == info["max value"]


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_serialize_writes_back_what_zkp_signed(vector: dict[str, Any]) -> None:
    """The round trip, which is what pins every field `info` is silent on.

    The sign bits, the ring commitments and the borromean signature
    have no oracle of their own: nothing outside the proof states them,
    and the only thing that says they were read as the format writes
    them is that they go back where they came from.
    """
    octets = bytes.fromhex(vector["proof"])
    assert RangeProof.parse(octets).serialize() == octets


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_mantissa_accounts_for_every_octet(vector: dict[str, Any]) -> None:
    """The length the mantissa implies is the length zkp wrote.

    `secp256k1_rangeproof_verify_impl` derives the ring structure from
    the mantissa and never reads it out of the proof, so a proof is
    only as self-describing as that derivation is right: one x per ring
    but the last, one sign bit each, and one `s` per public key.
    """
    octets = bytes.fromhex(vector["proof"])
    proof = RangeProof.parse(octets)
    rings = len(proof.rsizes)
    assert len(proof.signs) == rings - 1
    assert len(proof.ring_commitments) == rings - 1
    assert tuple(len(ring) for ring in proof.sig.s) == proof.rsizes
    body = ((rings + 6) >> 3) + 32 * (rings - 1) + 32 + 32 * sum(proof.rsizes)
    assert len(octets) == _header_size(octets) + body


def test_the_sign_bit_is_residuosity_and_not_parity() -> None:
    """The vectors are what says the two conventions are not one.

    `secp256k1_rangeproof_serialize_point` writes
    `!secp256k1_fe_is_square_var(&point->y)`, and the y that is a
    square has the parity it happens to have: on the ring commitments
    vendored here the bit a parity reading would write is sometimes the
    same and sometimes not. Both outcomes are asserted, and it is the
    agreements that make the wrong convention worth a test -- there the
    two write the same octet, and nothing says which was read.
    """
    seen = set()
    for vector in _VECTORS:
        proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
        for sign, x in zip(proof.signs, proof.ring_commitments, strict=True):
            y_residue = secp256k1.y_quadratic_residue_var(x)
            y = secp256k1.p - y_residue if sign else y_residue
            seen.add(bool(y & 1) == sign)
    assert seen == {True, False}


def test_parse_refuses_a_reserved_bit() -> None:
    """Bit 7 of the flags is held at zero, and is not a field to carry."""
    octets = _octets("one ring")
    with pytest.raises(BTClibValueError, match="bit 7 set in the rangeproof flags"):
        RangeProof.parse(bytes([octets[0] | 128]) + octets[1:])


def test_parse_refuses_a_mantissa_past_the_cap() -> None:
    """A mantissa past 64 is refused where it is read, `check_validity` or not.

    It is what says how many rings follow, so an octet naming one this
    format has no rings for is a field boundary rather than a value:
    `read_exactly`'s own rule, and
    `secp256k1_rangeproof_getheader_impl` returns zero on it as soon as
    it has read the octet.
    """
    octets = _octets("one ring")
    err_msg = "rangeproof mantissa not in 1..64: 65"
    for check_validity in (True, False):
        with pytest.raises(BTClibValueError, match=err_msg):
            RangeProof.parse(
                octets[:1] + b"\x40" + octets[2:], check_validity=check_validity
            )


def test_parse_refuses_an_exponent_past_the_cap() -> None:
    """An exponent past 18 is a value, so `check_validity` decides it.

    The octets are the same either way -- five bits hold 19 as readily
    as 18 -- which is what makes the refusal `assert_valid`'s and the
    parse with the check off a parse that round-trips.
    """
    octets = _octets("one ring")
    mutated = bytes([octets[0] | 19]) + octets[1:]
    with pytest.raises(BTClibValueError, match="exponent not in 0..18: 19"):
        RangeProof.parse(mutated)
    assert (
        RangeProof.parse(mutated, check_validity=False).serialize(check_validity=False)
        == mutated
    )


def test_parse_refuses_a_range_that_overflows_its_own_width() -> None:
    """Scaling by the exponent is where zkp checks `UINT64_MAX`, and so is this.

    The mantissa's ceiling times ten, once per exponent, has to stay
    inside the width the format states its range in;
    `secp256k1_rangeproof_getheader_impl` compares before each
    multiplication rather than after.
    """
    octets = _octets("odd mantissa")
    mutated = bytes([octets[0] | 18]) + octets[1:]
    with pytest.raises(BTClibValueError, match="max value overflows at exponent 18"):
        RangeProof.parse(mutated)


def test_a_min_value_of_zero_is_not_the_absence_of_one() -> None:
    """Two proofs mean the same range and are not the same octets.

    `zkp.rangeproof.info` answers zero for both, so `min_value` is None
    where the header carries no field and an integer where it does --
    the eight zero octets below being a header this parse has to write
    back as it found them.
    """
    octets = _octets("padded sign bits")
    zeroed = octets[:2] + bytes(8) + octets[10:]
    proof = RangeProof.parse(zeroed)
    assert proof.min_value == 0
    assert proof.max_value == RangeProof.parse(octets).max_value - 1000
    assert proof.serialize() == zeroed


def test_parse_refuses_a_set_bit_above_the_last_sign_bit() -> None:
    """Padding is not a field either, and zkp refuses it as mutation.

    Nothing hashes those bits -- the challenge covers the header, then
    each sign bit with the x beside it -- so a proof would otherwise
    have as many spellings as the padding has values.
    `secp256k1_rangeproof_verify_impl` says so where it forces them to
    zero.
    """
    octets = _octets("padded sign bits")
    signs_at = _header_size(octets)
    mutated = bytearray(octets)
    mutated[signs_at + 1] |= 2
    with pytest.raises(BTClibValueError, match="sign bit padding is not zero"):
        RangeProof.parse(bytes(mutated))


def test_parse_refuses_trailing_octets() -> None:
    """A proof is one whole octet string, `utils.assert_no_trailing`'s rule."""
    octets = _octets("one ring")
    with pytest.raises(BTClibValueError, match="1 bytes after the rangeproof"):
        RangeProof.parse(octets + b"\x00")


def test_parse_leaves_a_caller_s_stream_where_the_proof_ends() -> None:
    """What follows in a stream is the caller's, as everywhere else here."""
    octets = _octets("one ring")
    stream = BytesIO(octets + b"tail")
    proof = RangeProof.parse(stream)
    assert proof.serialize() == octets
    assert stream.read() == b"tail"


@pytest.mark.parametrize(
    "id_, size, err_msg",
    [
        ("one ring", 0, "rangeproof flags"),
        ("one ring", 1, "rangeproof mantissa"),
        ("public value", 1, "rangeproof min value"),
        ("odd mantissa", 2, "rangeproof sign bits"),
        ("odd mantissa", 3, "rangeproof ring commitment 0"),
        ("odd mantissa", 3 + 32 * 8, "borromean e0"),
        ("odd mantissa", 3 + 32 * 9, "borromean s"),
    ],
)
def test_parse_refuses_a_truncated_proof(id_: str, size: int, err_msg: str) -> None:
    """Each field boundary in turn, named by the field that ran out.

    The whole of the header parse zkp reaches by asking for at least 65
    octets first: a proof shorter than that has no room for the `e0`
    and the one `s` even the smallest ring structure needs, so reading
    field by field refuses the same buffers and says which field.
    """
    with pytest.raises(BTClibValueError, match=f"not enough data for the {err_msg}"):
        RangeProof.parse(_octets(id_)[:size])


def test_assert_valid_refuses_a_body_the_mantissa_does_not_describe() -> None:
    """Every field is against the mantissa, that being what says the shape."""
    proof = RangeProof.parse(_octets("odd mantissa"))

    err_msg = "rangeproof has 7 sign bits for 8 ring commitments"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(proof, signs=proof.signs[:-1]).assert_valid()

    err_msg = "rangeproof has 7 ring commitments where the mantissa asks for 8"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(
            proof, ring_commitments=proof.ring_commitments[:-1]
        ).assert_valid()

    err_msg = "ring commitment 0 does not fit in 32 octets"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(
            proof, ring_commitments=(2**256, *proof.ring_commitments[1:])
        ).assert_valid()

    smaller = BorromeanSig(proof.sig.e0, [list(ring) for ring in proof.sig.s[:-1]])
    with pytest.raises(BTClibValueError, match="are not the mantissa's"):
        replace_unchecked(proof, sig=smaller).assert_valid()


def test_assert_valid_refuses_a_header_no_proof_carries() -> None:
    """The exponent and the mantissa are one flag, so they move together."""
    proof = RangeProof.parse(_octets("odd mantissa"))

    err_msg = "rangeproof exponent not in 0..18: -1"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(proof, exp=-1).assert_valid()

    public = RangeProof.parse(_octets("public value"))
    err_msg = "rangeproof exponent of a public value is not -1: 3"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(public, exp=3).assert_valid()

    # the cap `parse` refuses where it reads the octet, which leaves
    # this the state of an object built rather than parsed
    err_msg = "rangeproof mantissa not in 1..64: 65"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(proof, mantissa=65).assert_valid()

    err_msg = "rangeproof min value not in 0..2\\*\\*64-1: 18446744073709551616"
    with pytest.raises(BTClibValueError, match=err_msg):
        replace_unchecked(public, min_value=2**64).assert_valid()


def test_assert_valid_refuses_a_range_that_overflows_its_min_value() -> None:
    """The sum is the second place zkp compares against `UINT64_MAX`.

    Built rather than parsed: the widest mantissa there is, over a
    `min_value` of one, is a header no `sign` call produces and
    `secp256k1_rangeproof_getheader_impl` returns zero on.
    """
    sig = BorromeanSig(bytes(32), [[0] * 4] * 32)
    err_msg = "max value overflows past min value 1"
    with pytest.raises(BTClibValueError, match=err_msg):
        RangeProof(0, 64, 1, (False,) * 31, (0,) * 31, sig)


def test_rsizes_are_the_digits_the_mantissa_asks_for() -> None:
    """Two bits are one base-4 digit, and an odd bit is a ring of its own.

    The public-value proof is the degenerate case: no mantissa, one
    ring, and the single key the commitment itself gives.
    """
    shapes = {
        "public value": (1,),
        "one ring": (2,),
        "odd mantissa": (4,) * 8 + (2,),
        "padded sign bits": (4,) * 10,
        "scaled exponent": (4,) * 5,
    }
    for id_, rsizes in shapes.items():
        assert RangeProof.parse(_octets(id_)).rsizes == rsizes


# `pragma: no cover` on every `@needs_zkp` below, the marker being the
# reason: `ZKP_AVAILABLE` is False in every job that measures coverage,
# and `zkp-oracle.yml`'s own `pytest -m zkp --no-cov` collects none. The
# marker's line and not the `def` under it, as `tests/ecc/pedersen_test.py`
# does and for the reason it gives there
@needs_zkp  # pragma: no cover -- no zkp.rangeproof to sign the vectors again
def test_the_vectors_are_what_zkp_signs_today() -> None:
    """Signing again with the recorded arguments answers the recorded octets.

    A rangeproof draws nothing: its nonces are the hash chain
    `rangeproof_genrand` derives from the caller's, so the arguments in
    the file are the whole of what produced it. That is what makes this
    a recording anybody can take again rather than a blob.
    """
    for vector in _VECTORS:
        blind = bytes.fromhex(vector["blind"])
        commitment = zkp_generator.pedersen_commit(blind, vector["value"])
        assert commitment.hex() == vector["commitment"]
        proof = zkp_rangeproof.sign(
            commitment,
            blind,
            bytes.fromhex(vector["nonce"]),
            vector["value"],
            **vector["sign arguments"],
        )
        assert proof.hex() == vector["proof"]


@needs_zkp  # pragma: no cover -- no zkp.rangeproof.info to compare a parse against
def test_parse_agrees_with_zkp_info_over_proofs_it_signs() -> None:
    """The header comparison the vectors record, made against the library.

    Asked over every exponent the format allows, which is not what gets
    written: `secp256k1_range_proveparams` lowers an exponent whose
    range would not fit the value, so this value at this `min_bits`
    writes 16 for everything above it. The assertion after the loop is
    what says so, rather than the loop being trusted to have varied
    anything.
    """
    blind = bytes(31) + b"\x07"
    exps_seen = set()
    for exp in range(-1, 19):
        value = 100000
        commitment = zkp_generator.pedersen_commit(blind, value)
        proof_octets = zkp_rangeproof.sign(
            commitment, blind, bytes(31) + bytes([exp + 2]), value, exp=exp, min_bits=8
        )
        exp_, mantissa, min_value, max_value = zkp_rangeproof.info(proof_octets)
        proof = RangeProof.parse(proof_octets)
        assert (proof.exp, proof.mantissa) == (exp_, mantissa)
        assert (proof.min_value or 0, proof.max_value) == (min_value, max_value)
        assert proof.serialize() == proof_octets
        exps_seen.add(exp_)
    assert exps_seen == set(range(-1, 17))


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to put the mutations to
def test_zkp_refuses_what_this_parse_refuses() -> None:
    """The header refusals above, put to the library that wrote the octets.

    `info` answers for the header and for nothing else: it reads a
    prefix of a proof, and a proof with an octet appended, as readily
    as it reads the whole one, so truncation and trailing octets are
    refusals of this parse and of `verify` rather than of `info`. The
    padding bits go the other way -- nothing hashes them, so `info`
    reads a mutated proof and `verify` is what has to turn it down for
    a proof to have one spelling.
    """
    octets = _octets("padded sign bits")
    commitment = bytes.fromhex(
        next(v for v in _VECTORS if v["id"] == "padded sign bits")["commitment"]
    )
    assert zkp_rangeproof.verify(commitment, octets) is not None

    with pytest.raises(ValueError, match="invalid proof"):
        zkp_rangeproof.info(bytes([octets[0] | 128]) + octets[1:])
    with pytest.raises(ValueError, match="invalid proof"):
        zkp_rangeproof.info(octets[:1] + b"\x40" + octets[2:])
    with pytest.raises(ValueError, match="invalid proof"):
        zkp_rangeproof.info(bytes([octets[0] | 18]) + octets[1:])

    mutated = bytearray(octets)
    mutated[_header_size(octets) + 1] |= 2
    assert zkp_rangeproof.info(bytes(mutated)) == zkp_rangeproof.info(octets)
    assert zkp_rangeproof.verify(commitment, bytes(mutated)) is None

    zeroed = octets[:2] + bytes(8) + octets[10:]
    assert zkp_rangeproof.info(zeroed)[2] == 0

    # what `info` does not answer for, and this parse does
    whole = zkp_rangeproof.info(octets)
    assert zkp_rangeproof.info(octets[:65]) == whole
    assert zkp_rangeproof.info(octets + b"\x00") == whole
    assert zkp_rangeproof.verify(commitment, octets[:65]) is None
    assert zkp_rangeproof.verify(commitment, octets + b"\x00") is None
