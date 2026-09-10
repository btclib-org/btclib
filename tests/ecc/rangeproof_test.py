# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.ecc.rangeproof` module.

The vectors are proofs libsecp256k1-zkp signed, recorded with the
arguments that produced them and with what `zkp.rangeproof.info`
answers for each -- `tests/_data/README.md` has the recording and how
to make another. They are here so that the parser is exercised
wherever the suite runs: the flagged extension is what a
btclib-secp256k1 installed from its sdist with `BTCLIB_LIBSECP256K1_ZKP`
has, so a test that can only ask the library leaves the parser
unmeasured in an unflagged build.

What the vectors are asked: that a parse of the header says what `info`
said about the same octets, field for field; that `serialize` writes
those octets back byte for byte, which is what pins the fields `info`
is silent about -- the sign bits, the ring commitments and the
signature; and that the length the mantissa implies is the length zkp
wrote.

Every entry is asked one thing more, and it is the strongest question
in this file: `sign`, given an entry's own `blind`, `value`, `nonce`
and `sign arguments`, has to answer its octets. A rangeproof draws
nothing, so those are the whole of what produced the recording, and an
implementation that agrees with zkp at every step is the only one that
lands on the same octets. The entries reach the shapes the header can
take: a blinded range at an exponent the signer kept, one at an
exponent it raised the mantissa for, an odd mantissa whose last ring
holds two keys, a `min_value` field with sign bits padded above it, and
both shapes of the proof that states its value in the clear.

What the recording does not reach is the header a request does not
get -- an exponent lowered, a `min_bits` clamped, a range refused --
and those are put to `_prove_params` against numbers
`secp256k1_range_proveparams` can be read for, with the `zkp`-marked
tests at the end holding the same arguments to the library.

Every entry is asked something further still, and this one needs no
signature at all: `pubk_rings` and `sign_key_idx`, given the entry's own
commitment and value, have to name keys that add up to the blinding
factor the entry records. Nothing in a proof states that sum, and the
published ring commitments cannot be asked to state it -- each carries a
blinding factor drawn from the nonce chain, so the value, the exponent
and the mantissa do not determine them.

The `nonce` is what determines them, and every entry is asked that too:
`nonce_chain` has to write the ring commitments the proof states, x and
sign bit, and every `s` the signature did not overwrite. That is the
whole of `secp256k1_rangeproof_genrand` held to octets zkp wrote, its
two acceptance rules apart: a chain that redrew no ring blinding factor
and refused no ring member's draw answers every entry here, and each of
those draws is reached at one in about 2**128. What puts them is a
chain a test writes.

And every entry is verified and rewound, which the nonce on file is
what makes possible: `verify` walks the rings `pubk_rings` rebuilds
back to the `e0` zkp wrote, and `rewind` answers the blinding factor
and the value the entry records from that nonce alone.
These are the proofs this tree asked zkp to write;
`tests/ecc/rangeproof_fixed_vectors_test.py` puts the same question to
the ones zkp published on its own.

The refusals a rewind has are constructed rather than waited for. A
value encoding for a value the proof was not written for is put in by
monkeypatching `_prep`, which decides the forged `s` values and nothing
else, so each such proof is a valid signature that a rewind has to turn
down: at the last ring's own digit, at a digit an odd mantissa's last
ring has no key for, and at one that opens no commitment.

The `zkp`-marked tests at the end put the same questions to the library
itself, and more the recording cannot answer: that signing again with
the recorded arguments answers the very octets vendored here, that
values and headers no entry carries are written the same way, and that
over a grid of `value`, `min_value`, `exp`, `min_bits` and `message`
the two implementations write the same octets, refuse the same
arguments, and each read what the other wrote.
"""

from inspect import Parameter, signature
from io import BytesIO
from typing import Any

import pytest

from btclib.alias import INF
from btclib.curves import mult, secp256k1
from btclib.ecc import rangeproof
from btclib.ecc.borromean import BorromeanSig
from btclib.ecc.pedersen import (
    _RANGEPROOF_TAG,
    _bytes_from_point,
    _point_from_x,
    commit,
    second_generator,
)
from btclib.ecc.rangeproof import RangeProof, sign, sign_public_value
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
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


def _vector(id_: str) -> dict[str, Any]:
    return next(v for v in _VECTORS if v["id"] == id_)


def _octets(id_: str) -> bytes:
    return bytes.fromhex(_vector(id_)["proof"])


# every entry a writer here can be asked for, read out of the file
# rather than repeated as literals, so the tests below that build a
# proof instead of reading one ask with arguments the recording names.
# `sign` takes an entry whose arguments are its own keyword ones, and
# `sign_public_value` one whose `exp` of -1 is the whole of them. The
# names are asked of the signature rather than written out, an argument
# gained there being one an entry may then be recorded with
_SIGN_KEYWORDS = {
    name
    for name, parameter in signature(sign).parameters.items()
    if parameter.kind is Parameter.KEYWORD_ONLY
}
_WRITABLE = [v for v in _VECTORS if set(v["sign arguments"]) <= _SIGN_KEYWORDS]
_WRITABLE_IDS = [vector_id(i, v["id"]) for i, v in enumerate(_WRITABLE)]
_PUBLIC_VALUES = [v for v in _VECTORS if v["sign arguments"] == {"exp": -1}]
_PUBLIC_VALUE_IDS = [vector_id(i, v["id"]) for i, v in enumerate(_PUBLIC_VALUES)]
_BLIND = _vector("public value")["blind"]
_NONCE = _vector("public value")["nonce"]


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
        for sign_bit, x in zip(proof.signs, proof.ring_commitments, strict=True):
            y_residue = secp256k1.y_quadratic_residue_var(x)
            y = secp256k1.p - y_residue if sign_bit else y_residue
            seen.add(bool(y & 1) == sign_bit)
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


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_pubk_rings_open_at_the_recorded_blinding_factor(
    vector: dict[str, Any],
) -> None:
    """The keys a proof's signature is over, checked with no signature read.

    Each ring's key at the value's own digit is that ring's blinding
    factor times G: `secp256k1_rangeproof_genrand` draws all but the
    last and answers the last with minus their sum, and
    `secp256k1_rangeproof_sign_impl` adds the caller's blinding factor
    to it. So the keys `sign_key_idx` names add up to `blind * G`, which
    the recording states and no octet of the proof does.

    That sum is what pins the derivation before there is a verifier to
    pin it. The published ring commitments cannot do it: each is
    `sec * G` plus its digit's own multiple of the generator, and `sec`
    comes from the chain the caller's nonce seeds, so the value, the
    exponent and the mantissa do not determine them.

    What the sum does not say is where a point sits. It reduces to
    `sum(digit * weight) == value - min_value`, a scalar equation that
    survives any permutation of the ring commitments across rings, the
    recovered one included, so each stated commitment's placement is
    asserted directly rather than inferred from it. The recovered one
    needs no assertion beside them: with the stated heads, the digits
    and the weights fixed, the sum leaves it a single group element.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    # the entry's own commitment octets, which zkp writes under the same
    # residuosity bit at another tag: `9 ^ is_square(y)` for a Pedersen
    # commitment, `1 ^` it at `_RANGEPROOF_TAG`
    recorded = bytes.fromhex(vector["commitment"])
    assert _bytes_from_point(commitment, _RANGEPROOF_TAG) == (
        bytes([recorded[0] ^ 8]) + recorded[1:]
    )

    rings = proof.pubk_rings(commitment)
    assert tuple(len(ring) for ring in rings) == proof.rsizes
    stated = tuple(
        _point_from_x(x, sign)
        for x, sign in zip(proof.ring_commitments, proof.signs, strict=True)
    )
    assert tuple(ring[0] for ring in rings[: len(stated)]) == stated
    total = None
    for ring, j in zip(rings, proof.sign_key_idx(vector["value"]), strict=True):
        total = ring[j] if total is None else secp256k1.add_aff_var(total, ring[j])
    assert total == mult(vector["blind"], secp256k1.G, secp256k1)


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_sign_key_idx_is_the_value_s_own_base_four_digits(
    vector: dict[str, Any],
) -> None:
    """Digit by digit, least significant ring first, back to the value.

    `secp256k1_range_proveparams` writes `secidx[i] = (v >> (i*2)) & 3`
    over the value less `min_value` and divided by ten as many times as
    the exponent says, so weighing each digit by its own ring and
    summing is what says the decomposition is that one. Each digit is a
    position the ring it names has, the ring of two an odd mantissa ends
    with included.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    sign_key_idx = proof.sign_key_idx(vector["value"])
    v = sum(digit << 2 * i for i, digit in enumerate(sign_key_idx))
    assert v * 10 ** max(proof.exp, 0) + (proof.min_value or 0) == vector["value"]
    assert all(j < size for j, size in zip(sign_key_idx, proof.rsizes, strict=True))


def test_a_ring_commitment_x_resolves_against_residuosity() -> None:
    """The rangeproof's tag read the other way, over every x vendored here.

    `secp256k1_ge_set_xquad` answers the y that is a square and
    `secp256k1_rangeproof_verify_impl` negates it where the sign bit is
    set, so the round trip back to the octets is what says the
    resolution is that serialization's own inverse. Reading the bit as
    parity would answer a different point wherever the two conventions
    disagree, and `test_the_sign_bit_is_residuosity_and_not_parity` is
    where the vendored proofs are shown to carry both cases.
    """
    for vector in _VECTORS:
        proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
        for x, sign_bit in zip(proof.ring_commitments, proof.signs, strict=True):
            point = _point_from_x(x, sign_bit)
            octets = bytes([sign_bit]) + x.to_bytes(secp256k1.p_size, "big")
            assert _bytes_from_point(point, _RANGEPROOF_TAG) == octets


def test_sign_key_idx_refuses_a_value_this_proof_has_no_digit_for() -> None:
    """Outside the range the header states, or between two of its steps."""
    proof = RangeProof.parse(_octets("padded sign bits"))
    err_msg = f"rangeproof value not in 1000..{proof.max_value}: "
    with pytest.raises(BTClibValueError, match=f"{err_msg}999"):
        proof.sign_key_idx(999)
    with pytest.raises(BTClibValueError, match=f"{err_msg}{proof.max_value + 1}"):
        proof.sign_key_idx(proof.max_value + 1)

    # an exponent of 2, so the proof steps by a hundred and says nothing
    # about what lies between two steps
    scaled = RangeProof.parse(_octets("scaled exponent"))
    err_msg = "rangeproof value 100001 is not the exponent's own multiple"
    with pytest.raises(BTClibValueError, match=err_msg):
        scaled.sign_key_idx(100001)


def test_pubk_rings_refuses_what_names_no_public_key() -> None:
    """A commitment off the curve, an x on no point, and a ring at infinity.

    The last is the one zkp checks by name: a commitment equal to
    `min_value` times the generator leaves the single ring of a
    public-value proof at infinity, and
    `secp256k1_rangeproof_verify_impl` returns zero where its own
    `pubs[npub]` lands there.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    with pytest.raises(BTClibValueError, match="point not on curve"):
        proof.pubk_rings((1, 2))

    # 7 is no x-coordinate of this curve, and it is a ring commitment
    # `assert_valid` takes: what a proof states there is an integer of
    # the field's width and this is where it has to name a point
    with pytest.raises(BTClibValueError, match="invalid x-coordinate: 7"):
        replace_unchecked(
            proof, ring_commitments=(7, *proof.ring_commitments[1:])
        ).pubk_rings(commitment)

    public = RangeProof.parse(_octets("public value"))
    min_value = public.min_value
    # the entry whose value is not zero, so the field is there to read
    assert min_value is not None
    err_msg = "last ring commitment is the point at infinity"
    with pytest.raises(BTClibValueError, match=err_msg):
        public.pubk_rings(mult(min_value, second_generator(), secp256k1))


def test_pubk_rings_does_not_check_the_proof_twice() -> None:
    """`check_validity` is `serialize`'s flag and means the same here.

    The derivation reads no field `assert_valid` has not already held
    against the mantissa, so a caller that has checked the object once
    says so and gets the same rings.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    assert proof.pubk_rings(commitment, check_validity=False) == proof.pubk_rings(
        commitment
    )


def _seed(vector: dict[str, Any]) -> bytes:
    # what `secp256k1_rangeproof_sign_impl` hands the chain, built from
    # the recording rather than asked of the module: the header octets
    # are the proof's own prefix, so nothing under test supplies them
    octets = bytes.fromhex(vector["proof"])
    return (
        bytes.fromhex(vector["nonce"])
        + _bytes_from_point(commit(vector["blind"], vector["value"]), _RANGEPROOF_TAG)
        + _bytes_from_point(second_generator(), _RANGEPROOF_TAG)
        + octets[: _header_size(octets)]
    )


class _FixedDraws:
    """A `_HmacDrbg` whose chain the test wrote, block by block.

    The blocks come back in the order they were given, which is what
    lets a test put a draw at one step of `_genrand` and a different one
    at the next: refused draws are reached at one in about 2**128 and
    cannot be had by choosing a nonce.
    """

    def __init__(self, *blocks: bytes) -> None:
        self.blocks = list(blocks)

    def generate(self, size: int) -> bytes:
        return self.blocks.pop(0)[:size]

    def reseed(self) -> None:
        """Advance nothing: what the chain answers is the list above."""


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_nonce_chain_writes_the_ring_commitments_a_proof_states(
    vector: dict[str, Any],
) -> None:
    """Every ring commitment, rebuilt from the nonce that drew its factor.

    A ring commitment is its ring's blinding factor times G plus the
    digit that ring proves times the generator, and every blinding
    factor but the last comes off the chain the caller's nonce seeds.
    So the x coordinates and sign bits a proof states are a function of
    the recording's `nonce`, which is what
    `test_pubk_rings_open_at_the_recorded_blinding_factor` cannot ask:
    that sum holds for any assignment of factors adding up to `blind`.

    The last ring's factor is minus the sum of the others, and
    `secp256k1_rangeproof_sign_impl` adds the caller's own to it, which
    is the head `pubk_rings` recovers rather than reads.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    chain = proof.nonce_chain(commitment, vector["value"], vector["nonce"])
    sign_key_idx = proof.sign_key_idx(vector["value"])
    scale = 10 ** max(proof.exp, 0)

    heads = []
    factors = list(chain.blinding_factors)
    factors[-1] = (factors[-1] + int(vector["blind"], 16)) % secp256k1.n
    for i, (sec, digit) in enumerate(zip(factors, sign_key_idx, strict=True)):
        heads.append(
            secp256k1.add_aff_var(
                mult(sec, secp256k1.G, secp256k1),
                mult(digit * scale << 2 * i, second_generator(), secp256k1),
            )
        )

    stated = [_bytes_from_point(head, _RANGEPROOF_TAG) for head in heads[:-1]]
    assert tuple(int.from_bytes(o[1:], "big") for o in stated) == proof.ring_commitments
    assert tuple(bool(o[0]) for o in stated) == proof.signs
    assert tuple(ring[0] for ring in proof.pubk_rings(commitment)) == tuple(heads)


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_the_nonce_chain_answers_every_s_the_signature_did_not_write(
    vector: dict[str, Any],
) -> None:
    """The draws, against the `s` values the proof carries.

    `secp256k1_rangeproof_sign_impl` moves the draw at the key the
    value's own digit names into the nonce that closes the ring and
    writes a signature there, and leaves every other draw where it is.
    So the two agree at exactly the keys `sign_key_idx` does not name,
    which is what makes the whole chain -- the discarded block of every
    ring but the last included -- answerable to octets zkp wrote.
    """
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    chain = proof.nonce_chain(commitment, vector["value"], vector["nonce"])
    sign_key_idx = proof.sign_key_idx(vector["value"])

    for i, (drawn, written) in enumerate(zip(chain.draws, proof.sig.s, strict=True)):
        for j, (a, b) in enumerate(zip(drawn, written, strict=True)):
            assert (a == b) == (j != sign_key_idx[i])


def test_nonce_chain_refuses_a_commitment_that_is_no_point() -> None:
    """The commitment is required on the curve, before any seed exists.

    The refusal is the explicit one, `pubk_rings`' on the argument of
    the same name. `_bytes_from_point` would turn the same pair down
    where the seed is written, so what the explicit check fixes is
    where the refusal happens rather than whether it happens.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    with pytest.raises(BTClibValueError, match="point not on curve"):
        proof.nonce_chain((1, 2), vector["value"], vector["nonce"])


def test_nonce_chain_refuses_a_commitment_at_infinity() -> None:
    """Infinity has no x, and the seed is written from one.

    `is_on_curve` answers `True` for any `(x, 0)`, that being how a
    point at infinity is spelled in affine coordinates, so the
    `require_on_curve` above the seed lets it through and
    `_bytes_from_point` is what turns it down. `match` is on that
    refusal's own message, the off-curve one above raising a different
    one from the same method.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    assert secp256k1.is_on_curve(INF)
    with pytest.raises(BTClibValueError, match="no bytes representation"):
        proof.nonce_chain(INF, vector["value"], vector["nonce"])


def test_nonce_chain_does_not_check_the_proof_twice() -> None:
    """`check_validity` is `pubk_rings`' flag and means the same here.

    The chain reads the mantissa, the exponent and `min_value`, which
    `assert_valid` has already held against each other, so a caller
    that has checked the object once says so and gets the same scalars.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    commitment = commit(vector["blind"], vector["value"])
    assert proof.nonce_chain(
        commitment, vector["value"], vector["nonce"], check_validity=False
    ) == proof.nonce_chain(commitment, vector["value"], vector["nonce"])


def test_a_ring_but_the_last_spends_a_block_before_the_one_it_keeps() -> None:
    """The draw `secp256k1_rangeproof_genrand` makes and does not read.

    It draws into the buffer it overwrites before testing it, so the
    blinding factor of every ring but the last is the second block of
    its pair and the first is spent on the chain's advance alone. A
    derivation taking the first is off by a block from that ring
    onward, which no proof of a single ring can show.
    """
    vector = _vector("scaled exponent")
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    chain = proof.nonce_chain(
        commit(vector["blind"], vector["value"]), vector["value"], vector["nonce"]
    )

    blocks = rangeproof._blocks(_seed(vector))
    discarded, tested, member = (int.from_bytes(next(blocks), "big") for _ in range(3))
    assert chain.blinding_factors[0] == tested
    assert chain.blinding_factors[0] != discarded
    assert chain.draws[0][0] == member


@pytest.mark.parametrize(
    "id_, key",
    [("padded sign bits", 3), ("scaled exponent", 2)],
    ids=["the last key of the ring", "the one before the digit's own"],
)
def test_the_last_ring_carries_the_value_in_one_of_its_draws(
    id_: str, key: int
) -> None:
    """`prep`'s value encoding, which is one draw of one ring and no more.

    `secp256k1_rangeproof_sign_impl` writes the value into the octets
    it hands the chain, and `secp256k1_rangeproof_rewind_inner` reads
    it back out of the `s` the proof states there. The key is the
    ring's last, or the one before it where the value's own digit is
    that one, since the draw at the digit's key is spent as a nonce.

    Fold nothing in and every other draw is what it was: the chain
    advances on the blocks alone, so what this costs is one `s` of one
    ring, in a proof that is otherwise byte for byte the same.
    """
    vector = _vector(id_)
    proof = RangeProof.parse(bytes.fromhex(vector["proof"]))
    value = vector["value"]
    sign_key_idx = proof.sign_key_idx(value)
    v = proof._mantissa_value(value)

    prep = rangeproof._prep(proof.rsizes, v, sign_key_idx[-1], b"")
    seed = _seed(vector)
    written = rangeproof._genrand(seed, proof.rsizes, prep)
    plain = rangeproof._genrand(seed, proof.rsizes, bytes(len(prep)))

    moved = [
        (i, j)
        for i, ring in enumerate(plain.draws)
        for j, drawn in enumerate(ring)
        if drawn != written.draws[i][j]
    ]
    assert moved == [(len(proof.rsizes) - 1, key)]
    assert written.blinding_factors == plain.blinding_factors

    i, j = moved[0]
    assert written.draws[i][j] == proof.sig.s[i][j]
    encoding = b"\x80" + bytes(7) + v.to_bytes(8, "big") * 3
    assert plain.draws[i][j] ^ written.draws[i][j] == int.from_bytes(encoding, "big")


def test_a_ring_blinding_factor_that_is_no_scalar_is_redrawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Genrand's other acceptance rule, the one a single ring never meets.

    A ring blinding factor at or past n, or zero, sends
    `secp256k1_rangeproof_genrand` back to the chain for another block,
    where the same draw for a ring member fails the proof outright --
    which is `test_a_draw_that_is_no_scalar_is_refused_and_not_redrawn`
    below. The factor of the last ring is drawn from nothing: it is
    minus the sum of the others, so two rings answer with a pair
    summing to zero.
    """
    accepted = bytes(31) + b"\x07"
    members = [bytes(31) + bytes([j]) for j in range(1, 5)]
    monkeypatch.setattr(
        rangeproof,
        "_HmacDrbg",
        lambda *_: _FixedDraws(
            b"\x11" * 32,
            bytes(32),
            secp256k1.n.to_bytes(32, "big"),
            accepted,
            *members,
        ),
    )

    rsizes = (2, 2)
    zeroed = bytes(rangeproof._RING_STRIDE * secp256k1.n_size * len(rsizes))
    chain = rangeproof._genrand(b"", rsizes, zeroed)
    assert chain.blinding_factors[0] == int.from_bytes(accepted, "big")
    assert chain.blinding_factors[1] == secp256k1.n - chain.blinding_factors[0]
    assert chain.draws == ((1, 2), (3, 4))


@pytest.mark.parametrize("vector", _WRITABLE, ids=_WRITABLE_IDS)
def test_sign_writes_the_octets_zkp_signed(vector: dict[str, Any]) -> None:
    """The recording asked of the writer, over every shape it holds.

    An entry's `blind`, `value`, `nonce` and `sign arguments` are the
    whole of what produced its proof, so writing them again here has to
    answer those octets -- the header, the sign bits, the ring
    commitments and the borromean signature alike.
    `zkp.rangeproof.verify` accepting the result would say only that it
    is *a* proof, where this says it is the same one.

    Selected on the `sign arguments` being keyword ones `sign` takes:
    an entry recorded with an argument it has no parameter for -- a
    `gen_bytes`, which names the generator -- is not one it can be
    held to.
    """
    proof = sign(
        vector["blind"], vector["value"], vector["nonce"], **vector["sign arguments"]
    )
    assert proof.serialize().hex() == vector["proof"]


@pytest.mark.parametrize("vector", _PUBLIC_VALUES, ids=_PUBLIC_VALUE_IDS)
def test_sign_public_value_writes_the_octets_zkp_signed(
    vector: dict[str, Any],
) -> None:
    """The vendored entries, asked of this module rather than of the library.

    A rangeproof draws nothing, so an entry's `blind`, `value` and
    `nonce` are the whole of what produced its proof: writing them again
    here has to answer those octets. `zkp.rangeproof.verify` accepting
    the result would say only that it is *a* proof, where this says it
    is the same one.

    Selected on the `sign arguments` rather than by name, so an entry
    recorded later with exactly an `exp` of -1 is asked this too. Exact
    equality and not the `exp` alone: `sign_public_value` takes a
    blinding factor, a value and a nonce, so an entry recorded with any
    further argument -- an `extra_commit`, which enters the challenge --
    is not one it can be held to.
    """
    proof = sign_public_value(vector["blind"], vector["value"], vector["nonce"])
    assert proof.serialize().hex() == vector["proof"]


def test_the_proof_written_carries_no_ring_commitment() -> None:
    """One ring, so there is nothing for a squareness bit to be written on.

    A proof carries one ring commitment per ring but the last, one sign
    bit each, and the public-value proof has a single ring. So what
    `sign_public_value` writes exercises neither the digit
    decomposition nor the residuosity convention on a ring commitment,
    and the tests above reach both through a proof this module reads
    rather than one it writes.
    """
    proof = sign_public_value(_BLIND, 100000, _NONCE)
    assert proof.rsizes == (1,)
    assert proof.signs == ()
    assert proof.ring_commitments == ()
    assert tuple(len(ring) for ring in proof.sig.s) == (1,)


def test_a_public_value_of_zero_carries_no_min_value_field() -> None:
    """`min_value ? 32 : 0` is zkp's own flag, and here the value is the min.

    So a public value of zero writes the flags octet, the `e0` and the
    one `s` with no eight-octet field between them, which is also the
    shortest buffer `secp256k1_rangeproof_sign_impl` accepts. That zkp
    writes those octets is the `public value, zero` entry's to say, and
    the test above is where it says it; what is here is the shape, read
    off the object rather than off the recording.
    """
    vector = _vector("public value, zero")
    proof = sign_public_value(vector["blind"], vector["value"], vector["nonce"])
    octets = proof.serialize()
    assert proof.min_value is None
    assert octets[0] == 0
    assert len(octets) == 1 + 32 + 32
    assert RangeProof.parse(octets).serialize() == octets


def test_sign_public_value_refuses_what_it_has_no_octets_for() -> None:
    """Each argument against what the format and the curve allow."""
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        sign_public_value(0, 1, _NONCE)

    err_msg = "rangeproof value not in 0..2\\*\\*64-1: "
    with pytest.raises(BTClibValueError, match=f"{err_msg}-1"):
        sign_public_value(_BLIND, -1, _NONCE)
    with pytest.raises(BTClibValueError, match=f"{err_msg}18446744073709551616"):
        sign_public_value(_BLIND, 2**64, _NONCE)

    with pytest.raises(BTClibValueError, match="invalid size: 31 bytes instead of 32"):
        sign_public_value(_BLIND, 1, _NONCE[:-2])


@pytest.mark.parametrize(
    "draw",
    [bytes(32), secp256k1.n.to_bytes(32, "big")],
    ids=["zero", "at n"],
)
def test_a_draw_that_is_no_scalar_is_refused_and_not_redrawn(
    draw: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`genrand`'s rule and not RFC6979's, which is why they are two rules.

    `secp256k1_scalar_set_b32` flags a draw at or past n, refuses zero
    beside it, and `secp256k1_rangeproof_sign_impl` returns zero on
    either -- where `rfc6979_nonce` asks the same chain for its next
    candidate. A proof written from that next block is one zkp does not
    write.
    """
    monkeypatch.setattr(rangeproof, "_HmacDrbg", lambda *_: _FixedDraws(draw))
    with pytest.raises(BTClibRuntimeError, match="nonce is not a scalar"):
        sign_public_value(_BLIND, 1, _NONCE)


@pytest.mark.parametrize(
    "challenge",
    [bytes(32), secp256k1.n.to_bytes(32, "big")],
    ids=["zero", "at n"],
)
def test_a_challenge_that_is_no_scalar_is_refused(
    challenge: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same refusal a step later, where `ecc.borromean` makes none.

    `secp256k1_borromean_sign` reads its challenge through
    `secp256k1_scalar_set_b32` too and returns zero on the flag, where
    `borromean.sign` takes the hash modulo n and carries on. Reducing
    here would write a proof `secp256k1_borromean_verify_impl` refuses.
    """
    monkeypatch.setattr(rangeproof, "_hash", lambda *_: challenge)
    with pytest.raises(BTClibRuntimeError, match="challenge is not a scalar"):
        sign_public_value(_BLIND, 1, _NONCE)


def test_a_zero_signature_value_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """There is one challenge that makes k - e*blind vanish, and zkp refuses it.

    Both halves are handed in, that challenge being k over the blinding
    factor: `secp256k1_borromean_sign` returns zero rather than write
    the s, and `secp256k1_borromean_verify_impl` refuses one it is handed.
    """
    k = 5
    e = k * pow(int(_BLIND, 16), -1, secp256k1.n) % secp256k1.n
    monkeypatch.setattr(
        rangeproof, "_HmacDrbg", lambda *_: _FixedDraws(k.to_bytes(32, "big"))
    )
    monkeypatch.setattr(rangeproof, "_hash", lambda *_: e.to_bytes(32, "big"))
    with pytest.raises(BTClibRuntimeError, match="signature value is zero"):
        sign_public_value(_BLIND, 1, _NONCE)


# what `secp256k1_range_proveparams` answers, argument by argument: each
# row is `(value, min_value, exp, min_bits)` asked for, the
# `(exp, mantissa, min_value, max_value)` written, and why the two
# differ. The written column is what that function computes and not
# what `_prove_params` answered for it, and the `zkp`-marked test at
# the end asks the library for the same headers
_Header = tuple[int, int, int, int]
_HEADER_CASES: list[tuple[_Header, _Header, str]] = [
    ((0, 0, 0, 0), (0, 1, 0, 1), "value zero"),
    ((3, 0, 0, 2), (0, 2, 0, 3), "a single ring"),
    ((5000, 0, 0, 13), (0, 13, 0, 8191), "odd mantissa"),
    ((100000, 0, 0, 0), (0, 17, 0, 131071), "mantissa from the value"),
    ((100000, 0, 5, 0), (5, 1, 0, 100000), "exponent takes the value"),
    (
        (100000, 0, 18, 20),
        (13, 20, 100000, 10485750000000100000),
        "exponent lowered",
    ),
    ((100000, 0, 3, 62), (0, 62, 0, 4611686018427387903), "min bits past 61"),
    ((2**63, 0, 5, 0), (0, 64, 0, 2**64 - 1), "value past 2**63-1"),
    ((2**40 + 7, 2**40, 0, 64), (0, 23, 2**40, 1099520016383), "min bits clamped"),
    ((2**40, 2**40 - 1, 0, 0), (0, 1, 2**40 - 1, 2**40), "a range of one step"),
    (
        (2**64 - 1, 2**64 - 1, 0, 0),
        (-1, 0, 2**64 - 1, 2**64 - 1),
        "min value at the ceiling",
    ),
    ((2**64 - 1, 0, 0, 0), (0, 64, 0, 2**64 - 1), "the whole field"),
]
_HEADERS = [
    pytest.param(arguments, header, id=why) for arguments, header, why in _HEADER_CASES
]


def _written(arguments: _Header) -> RangeProof:
    value, min_value, exp, min_bits = arguments
    return sign(_BLIND, value, _NONCE, min_value=min_value, exp=exp, min_bits=min_bits)


@pytest.mark.parametrize("arguments, header", _HEADERS)
def test_the_header_is_what_the_format_has_room_for(
    arguments: _Header, header: _Header
) -> None:
    """What a caller asks for is a request, and the header is the answer.

    `secp256k1_range_proveparams` lowers the exponent until the range
    it would prove fits a uint64, lowers `min_bits` to the precision
    the floor leaves, raises the mantissa to that precision where the
    value needs fewer bits than it, and rewrites `min_value` to what
    the rescaled value no longer reaches.
    A `min_value` at the ceiling of the field is where no range can be
    coded at all, and what comes back there is the proof of an exact
    value.
    """
    proof = _written(arguments)
    assert (proof.exp, proof.mantissa) == header[:2]
    assert (proof.min_value or 0, proof.max_value) == header[2:]


@pytest.mark.parametrize("arguments, header", _HEADERS)
def test_a_proof_written_here_opens_at_its_own_blinding_factor(
    arguments: _Header, header: _Header
) -> None:
    """The proof read back against the commitment it was written for.

    Nothing outside the octets states the ring commitments, so what
    says they are the ones the digits ask for is that the keys
    `sign_key_idx` names across the rings sum to `blind * G` -- the
    same question `tests/ecc/rangeproof_fixed_vectors_test.py` puts to
    proofs zkp published, put here to proofs this module wrote. The
    value has to lie in the range the header states for those digits to
    exist at all, which is the first assertion below.
    """
    value = arguments[0]
    proof = _written(arguments)
    assert header[2] <= value <= proof.max_value

    rings = proof.pubk_rings(commit(_BLIND, value))
    stated = tuple(
        _point_from_x(x, sign_bit)
        for x, sign_bit in zip(proof.ring_commitments, proof.signs, strict=True)
    )
    assert tuple(ring[0] for ring in rings[: len(stated)]) == stated

    total = None
    for ring, j in zip(rings, proof.sign_key_idx(value), strict=True):
        total = ring[j] if total is None else secp256k1.add_aff_var(total, ring[j])
    assert total == mult(_BLIND, secp256k1.G, secp256k1)


def test_sign_refuses_what_it_has_no_octets_for() -> None:
    """Each argument against what the format and the curve allow.

    The bounds on the exponent and on `min_bits` are the ones
    `secp256k1_rangeproof_sign_impl` reads before it asks for a header
    at all, and so is `min_value` above the value: a floor over the
    thing it is a floor of proves nothing.
    """
    with pytest.raises(BTClibValueError, match="private key not in 1..n-1"):
        sign(0, 1, _NONCE)

    err_msg = "rangeproof value not in 0..2\\*\\*64-1: "
    with pytest.raises(BTClibValueError, match=f"{err_msg}-1"):
        sign(_BLIND, -1, _NONCE)
    with pytest.raises(BTClibValueError, match=f"{err_msg}18446744073709551616"):
        sign(_BLIND, 2**64, _NONCE)

    with pytest.raises(BTClibValueError, match="min value not in 0..7: 8"):
        sign(_BLIND, 7, _NONCE, min_value=8)
    with pytest.raises(BTClibValueError, match="exponent not in -1..18: 19"):
        sign(_BLIND, 7, _NONCE, exp=19)
    with pytest.raises(BTClibValueError, match="exponent not in -1..18: -2"):
        sign(_BLIND, 7, _NONCE, exp=-2)
    with pytest.raises(BTClibValueError, match="min bits not in 0..64: 65"):
        sign(_BLIND, 7, _NONCE, min_bits=65)

    with pytest.raises(BTClibValueError, match="invalid size: 31 bytes instead of 32"):
        sign(_BLIND, 1, _NONCE[:-2])


@pytest.mark.parametrize(
    "value, min_value",
    [(2**63, 1), (2**63 - 1, 2**63 - 1)],
    ids=["value past the sign bit", "min value at it"],
)
def test_a_range_leaving_its_other_end_no_room_is_refused(
    value: int, min_value: int
) -> None:
    """`secp256k1_range_proveparams`' own refusal, and it has two arms.

    The digits prove `value - min_value` and the header states the
    floor, so the largest a proof can assert is the sum of the two, and
    zkp answers zero rather than write a maximum that would wrap. The
    arms are a nonzero floor under a value past `2**63-1` and a nonzero
    value over a floor at or past it, which are not one rule: the
    control below is a value exactly at that ceiling, which is proven,
    where the same value a step higher is not.
    """
    with pytest.raises(BTClibValueError, match="does not fit 2\\*\\*64"):
        sign(_BLIND, value, _NONCE, min_value=min_value)

    proof = sign(_BLIND, 2**63 - 1, _NONCE, min_value=1)
    assert (proof.exp, proof.mantissa, proof.min_value) == (0, 63, 1)


def test_a_last_ring_blinding_factor_of_zero_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The caller's blinding factor cancelling the chain's own.

    `secp256k1_rangeproof_sign_impl` adds the caller's to the last
    ring's and returns zero on a sum of zero: that ring's commitment
    would then be the digit alone, with nothing blinding it. The chain
    answers the last factor as minus the sum of the others, so the sum
    is zero exactly where the caller's blinding factor is that sum, and
    a chain the test wrote is what puts it -- a nonce whose chain
    reached it is a one-in-n accident and cannot be chosen.
    """
    chain = rangeproof.NonceChain((-int(_BLIND, 16) % secp256k1.n,), ((1, 2, 3, 4),))
    monkeypatch.setattr(rangeproof, "_genrand", lambda *_: chain)
    with pytest.raises(BTClibRuntimeError, match="last ring blinding factor is zero"):
        sign(_BLIND, 3, _NONCE, min_bits=2)


def test_a_ring_commitment_at_infinity_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`secp256k1_pedersen_ecmult` landing on infinity, which is no key.

    A ring commitment is its blinding factor times G plus its digit at
    the weight of its place, and the two cancel only for a blinding
    factor that is the discrete logarithm of the digit's point. Nobody
    has one for the generator this module uses -- `second_generator` is
    derived precisely so that nobody does -- so the generator is put on
    a known multiple of G here and the blinding factor read off it.
    """
    log_of_generator = 12345
    monkeypatch.setattr(
        rangeproof,
        "second_generator",
        lambda: mult(log_of_generator, secp256k1.G, secp256k1),
    )
    # the single ring of a mantissa of two, whose digit is the value
    blind = -3 * log_of_generator % secp256k1.n
    err_msg = "ring commitment is the point at infinity"
    with pytest.raises(BTClibRuntimeError, match=err_msg):
        sign(blind, 3, _NONCE, min_bits=2)


# --------------------------------------------------------------------------
# Verification, and the rewind built on it
# --------------------------------------------------------------------------


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_a_recorded_proof_holds_for_its_own_commitment(vector: dict[str, Any]) -> None:
    """Every entry verified against the commitment its arguments make.

    The proof is octets zkp signed and the commitment is built here from
    the entry's own blinding factor and value, so what this asks is
    whether the walk over the rings `pubk_rings` rebuilds closes on the
    `e0` those octets carry. A commitment to another value is asked
    beside it: the last ring commitment is recovered from the
    commitment, so every ring's message changes with it and nothing
    closes.
    """
    commitment = commit(vector["blind"], vector["value"])
    octets = bytes.fromhex(vector["proof"])
    rangeproof.assert_as_valid(commitment, octets)
    assert rangeproof.verify(commitment, octets)
    assert rangeproof.verify(commitment, RangeProof.parse(octets))

    other = commit(vector["blind"], vector["value"] + 1)
    assert not rangeproof.verify(other, octets)
    with pytest.raises(BTClibRuntimeError, match="signature verification failed"):
        rangeproof.assert_as_valid(other, octets)


@pytest.mark.parametrize("vector", _VECTORS, ids=_IDS)
def test_rewind_reads_a_recorded_proof_back(vector: dict[str, Any]) -> None:
    """The blinding factor and the value the entry states, from its nonce.

    Every entry carries the nonce it was signed under, which is what
    makes a rewind a question the suite can put wherever it runs rather
    than one the flagged extension has to answer.

    Nothing was embedded in these, so what the rings carry past the
    value encoding is the zeros `_prep` left.
    """
    commitment = commit(vector["blind"], vector["value"])
    rewound = rangeproof.rewind(
        commitment, bytes.fromhex(vector["proof"]), vector["nonce"]
    )
    assert rewound.blind == int(vector["blind"], 16)
    assert rewound.value == vector["value"]
    assert not any(rewound.message)


def test_verify_refuses_a_turned_octet_of_the_signature() -> None:
    """One bit of the last `s`, which is the mutation a proof has to fail on."""
    octets = bytearray(_octets("odd mantissa"))
    commitment = commit(
        _vector("odd mantissa")["blind"], _vector("odd mantissa")["value"]
    )
    assert rangeproof.verify(commitment, bytes(octets))
    octets[-1] ^= 1
    assert not rangeproof.verify(commitment, bytes(octets))


def test_verify_refuses_a_signature_value_of_zero() -> None:
    """The one `s` zkp writes none of, and `BorromeanSig` holds.

    `secp256k1_borromean_sign` answers zero rather than put a zero `s`
    in a proof, and `secp256k1_borromean_verify_impl` turns one down
    where it is handed it. `BorromeanSig.assert_valid` reads `s` against
    0..n-1 and so accepts it, which is what leaves the refusal to the
    walk.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(_octets("odd mantissa"))
    zeroed = [list(ring) for ring in proof.sig.s]
    zeroed[0][0] = 0
    mutated = replace_unchecked(proof, sig=replace_unchecked(proof.sig, s=zeroed))
    commitment = commit(vector["blind"], vector["value"])
    with pytest.raises(BTClibRuntimeError, match="signature value is zero"):
        rangeproof.assert_as_valid(commitment, mutated)
    assert not rangeproof.verify(commitment, mutated)


def test_verify_refuses_a_ring_key_at_infinity() -> None:
    """The key `secp256k1_borromean_verify_impl` turns down before its ecmult.

    A ring's key at position j is that ring's commitment less j times
    the weight of the digit the ring proves, so a stated commitment
    sitting exactly on one of those multiples leaves a key at infinity.
    The first ring's second key is the cheapest of them: at an exponent
    of zero the weight is the generator itself, so the commitment whose
    octets are the generator's puts it there.

    Nothing later in the walk would turn it down. The point a walk
    reaches at that key is `e*Q + s*G`, which is `s*G` for a `Q` at
    infinity -- an ordinary point, and one the prover picks by picking
    `s`.
    """
    vector = _vector("odd mantissa")
    proof = RangeProof.parse(_octets("odd mantissa"))
    assert proof.exp == 0
    octets = _bytes_from_point(second_generator(), _RANGEPROOF_TAG)
    holed = replace_unchecked(
        proof,
        signs=(bool(octets[0]), *proof.signs[1:]),
        ring_commitments=(
            int.from_bytes(octets[1:], "big"),
            *proof.ring_commitments[1:],
        ),
    )
    commitment = commit(vector["blind"], vector["value"])
    rings = holed.pubk_rings(commitment)
    assert rings[0][1] == INF
    with pytest.raises(BTClibRuntimeError, match="ring key is the point at infinity"):
        rangeproof.assert_as_valid(commitment, holed)
    assert not rangeproof.verify(commitment, holed)


def test_rewind_refuses_a_nonce_that_is_not_the_proof_s() -> None:
    """A wrong nonce draws a different chain, and no key then reads as a value.

    `_value_encoding` looks at two keys of the last ring and takes
    neither: the xor of a proof's own `s` with a draw that never wrote
    it opens with bit 7 clear, or repeats none of its three eight-octet
    runs. The proof still verifies -- a rewind is what the nonce is for,
    and nothing else in it depends on one.
    """
    vector = _vector("odd mantissa")
    commitment = commit(vector["blind"], vector["value"])
    octets = _octets("odd mantissa")
    assert rangeproof.verify(commitment, octets)
    with pytest.raises(BTClibRuntimeError, match="reads no value encoding"):
        rangeproof.rewind(commitment, octets, bytes(32))


def _with_encoded_value(monkeypatch: pytest.MonkeyPatch, v: int) -> None:
    # `_prep` writing an encoding for a value the proof is not written
    # for, at the key the true value's own digit would have put it at.
    # A rewind reads that value back and is refused on it; the octets
    # are a valid signature either way, the buffer deciding only what
    # the forged `s` values are
    real_prep = rangeproof._prep

    def fake_prep(rsizes: Any, _v: int, sign_key_idx: int, message: bytes) -> bytes:
        return real_prep(rsizes, v, sign_key_idx, message)

    monkeypatch.setattr(rangeproof, "_prep", fake_prep)


def test_rewind_refuses_a_value_encoding_at_the_last_ring_s_digit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`secp256k1_rangeproof_rewind_inner`'s "value is in wrong position".

    `_prep` writes the encoding at whichever of the last ring's two
    candidate keys the ring's own digit does not take, so a value whose
    top digit names the key the encoding was found at is a value the
    proof was not written for. A mantissa of four gives two rings of
    four keys: the value three has digits three and zero, so the
    encoding goes at the last key and a rewind reading a value whose top
    digit is three lands on it.
    """
    _with_encoded_value(monkeypatch, 12)
    proof = sign(_BLIND, 3, _NONCE, min_bits=4)
    commitment = commit(_BLIND, 3)
    assert rangeproof.verify(commitment, proof)
    with pytest.raises(BTClibRuntimeError, match="reads the value at the digit"):
        rangeproof.rewind(commitment, proof, _NONCE)


def test_rewind_refuses_a_digit_the_last_ring_has_no_key_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An odd mantissa ends in a ring of two, which proves one bit.

    A value whose top digit is two or three names a position that ring
    does not have. zkp indexes its own arrays at that position anyway,
    and they end before it: `secp256k1_rangeproof_genrand` fills as many
    as the rings hold keys, and `secp256k1_borromean_verify_impl` saves
    as many challenges.
    """
    _with_encoded_value(monkeypatch, 8)
    proof = sign(_BLIND, 3, _NONCE, min_bits=3)
    commitment = commit(_BLIND, 3)
    assert proof.rsizes == (4, 2)
    assert rangeproof.verify(commitment, proof)
    with pytest.raises(BTClibRuntimeError, match="has no key for"):
        rangeproof.rewind(commitment, proof, _NONCE)


def test_rewind_refuses_what_does_not_open_the_commitment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check `secp256k1_rangeproof_verify_impl` makes after the rewind.

    A value encoding naming a digit that is neither the key it sits at
    nor the ring's own passes both refusals above, and what comes back
    is a blinding factor recovered at a key nobody signed at: the pair
    is arithmetic on forged scalars, and rebuilding the commitment from
    it is what says so.
    """
    _with_encoded_value(monkeypatch, 4)
    proof = sign(_BLIND, 3, _NONCE, min_bits=4)
    commitment = commit(_BLIND, 3)
    assert rangeproof.verify(commitment, proof)
    with pytest.raises(BTClibRuntimeError, match="does not open the commitment"):
        rangeproof.rewind(commitment, proof, _NONCE)


def test_a_public_value_proof_rewinds_to_its_blinding_factor_alone() -> None:
    """One ring of one key, and only the blinding factor is recoverable.

    There is no digit to read and no second key to carry a message: the
    value is the header's own `min_value`, stated in the clear, and what
    the rewind adds is that whoever holds the nonce also holds the
    factor the commitment was written under.
    """
    proof = sign_public_value(_BLIND, 100000, _NONCE)
    commitment = commit(_BLIND, 100000)
    rewound = rangeproof.rewind(commitment, proof, _NONCE)
    assert rewound == (int(_BLIND, 16), 100000, b"")


@pytest.mark.parametrize(
    "value, min_bits",
    [(3, 4), (100000, 8), (100000, 20), (2**32, 33)],
    ids=["two rings", "odd mantissa", "padded sign bits", "wide mantissa"],
)
def test_sign_embeds_a_message_rewind_reads_back(value: int, min_bits: int) -> None:
    """The message written into the draws, and read back out of them.

    What comes back is every octet the rings before the last carry, and
    whatever the last ring has left once the value encoding and the key
    its own digit opens are taken out of it -- two keys where it holds
    four, none where an odd mantissa leaves it holding two: the message
    first and the zeros `_prep` left after it. Nothing in a proof says
    where the message ends, which is what makes the padding the
    caller's to know the length of.
    """
    message = b"btclib reads what it writes"
    proof = sign(_BLIND, value, _NONCE, min_bits=min_bits, message=message)
    commitment = commit(_BLIND, value)
    rewound = rangeproof.rewind(commitment, proof, _NONCE)
    assert rewound.blind == int(_BLIND, 16)
    assert rewound.value == value
    assert rewound.message[: len(message)] == message
    assert not any(rewound.message[len(message) :])

    keys = sum(proof.rsizes)
    assert len(rewound.message) == secp256k1.n_size * (keys - 2)
    # the octets are a proof carrying no message everywhere else
    plain = sign(_BLIND, value, _NONCE, min_bits=min_bits)
    assert (plain.exp, plain.mantissa, plain.min_value) == (
        proof.exp,
        proof.mantissa,
        proof.min_value,
    )
    assert plain.ring_commitments == proof.ring_commitments
    assert plain.serialize() != proof.serialize()


def test_the_nonce_chain_answers_the_draws_of_a_proof_carrying_a_message() -> None:
    """A message is in the draws, so the chain needs it to answer them.

    Every `s` the signature did not overwrite is the chain's own draw,
    with the message folded into it at the keys the message reaches,
    which is the same question that
    `test_the_nonce_chain_answers_every_s_the_signature_did_not_write`
    puts to a proof carrying none. The message here is shorter than one
    scalar, so it reaches the first key of the first ring and no other,
    and the assertion is over every key either way.
    """
    message = b"in the draws"
    value = 100000
    proof = sign(_BLIND, value, _NONCE, min_bits=8, message=message)
    commitment = commit(_BLIND, value)
    chain = proof.nonce_chain(commitment, value, _NONCE, message)
    plain = proof.nonce_chain(commitment, value, _NONCE)
    reached = [
        (i, j)
        for i, (a, b) in enumerate(zip(plain.draws, chain.draws, strict=True))
        for j, (x, y) in enumerate(zip(a, b, strict=True))
        if x != y
    ]
    assert reached == [(0, 0)]

    sign_key_idx = proof.sign_key_idx(value)
    for i, (drawn, written) in enumerate(zip(chain.draws, proof.sig.s, strict=True)):
        for j, (a, b) in enumerate(zip(drawn, written, strict=True)):
            assert (a == b) == (j != sign_key_idx[i])


def test_a_message_longer_than_the_rings_hold_is_refused() -> None:
    """`secp256k1_rangeproof_sign_impl`'s own bound, `128 * (rings - 1)`.

    The last ring carries the value encoding and the key a rewind
    recovers the blinding factor at, so what is left is every ring
    before it -- and a proof of a single ring has none, which is what a
    small `min_bits` and the public-value proof both give.
    """
    err_msg = "message is longer than the"
    with pytest.raises(BTClibValueError, match=err_msg):
        sign(_BLIND, 1, _NONCE, min_bits=1, message=b"x")
    with pytest.raises(BTClibValueError, match=err_msg):
        sign(_BLIND, 3, _NONCE, min_bits=4, message=bytes(129))
    # the same bound reached through the chain rather than through `sign`
    proof = sign(_BLIND, 3, _NONCE, min_bits=4)
    with pytest.raises(BTClibValueError, match=err_msg):
        proof.nonce_chain(commit(_BLIND, 3), 3, _NONCE, bytes(129))
    # and what it does hold
    filled = sign(_BLIND, 3, _NONCE, min_bits=4, message=bytes(128))
    assert filled.rsizes == (4, 4)


@pytest.mark.parametrize(
    "value, kwargs",
    [
        (100000, {"exp": -1}),
        (3, {"min_bits": 4}),
        (100000, {"min_bits": 8, "message": b"bound and carried"}),
    ],
    ids=["public value", "odd mantissa", "message too"],
)
def test_extra_commit_binds_a_proof_to_octets_it_does_not_carry(
    value: int, kwargs: dict[str, Any]
) -> None:
    """A proof holds under the octets it was written under, and not others.

    They are the caller's own and the proof carries none of them, so a
    verifier is handed them again or walks the rings to an `e0` the
    signature does not state. `assert_as_valid` raises the borromean
    walk's own refusal, `verify` answers False, and `rewind` refuses
    before it reads anything, the verification being what it opens
    with.

    Nothing else about the proof moves: the header and the ring
    commitments are those of a proof written under no `extra_commit`,
    the signature over them is not, and a rewind under the right
    octets answers the same blinding factor, value and message. That
    is `secp256k1_rangeproof_genrand` taking no such argument, so the
    draws it derives are the same and only the message the rings are
    signed over changes.
    """
    extra_commit = b"the output this belongs to"
    commitment = commit(_BLIND, value)
    bound = sign(_BLIND, value, _NONCE, extra_commit=extra_commit, **kwargs)
    plain = sign(_BLIND, value, _NONCE, **kwargs)

    assert rangeproof.verify(commitment, bound, extra_commit=extra_commit)
    rewound = rangeproof.rewind(commitment, bound, _NONCE, extra_commit=extra_commit)
    assert rewound == rangeproof.rewind(commitment, plain, _NONCE)

    assert (bound.exp, bound.mantissa, bound.min_value) == (
        plain.exp,
        plain.mantissa,
        plain.min_value,
    )
    assert bound.signs == plain.signs
    assert bound.ring_commitments == plain.ring_commitments
    assert bound.sig != plain.sig

    err_msg = "rangeproof signature verification failed"
    for wrong in (b"", extra_commit + b"!", extra_commit[:-1]):
        assert not rangeproof.verify(commitment, bound, extra_commit=wrong)
        with pytest.raises(BTClibRuntimeError, match=err_msg):
            rangeproof.assert_as_valid(commitment, bound, extra_commit=wrong)
        with pytest.raises(BTClibRuntimeError, match=err_msg):
            rangeproof.rewind(commitment, bound, _NONCE, extra_commit=wrong)
    # and the proof written under none is refused under these
    assert not rangeproof.verify(commitment, plain, extra_commit=extra_commit)


def test_extra_commit_is_read_as_octets_wherever_it_is_taken() -> None:
    """A hex string says what the same octets say, `Octets` being the type.

    `verify` catches the `ValueError` a spelling that is no octets
    raises, as it catches a parse's, where the three that raise their
    reason let it out.
    """
    value = 100000
    commitment = commit(_BLIND, value)
    proof = sign(_BLIND, value, _NONCE, min_bits=8, extra_commit="cafe")
    assert (
        proof.serialize()
        == sign(_BLIND, value, _NONCE, min_bits=8, extra_commit=b"\xca\xfe").serialize()
    )
    assert rangeproof.verify(commitment, proof, extra_commit=b"\xca\xfe")
    assert rangeproof.rewind(commitment, proof, _NONCE, extra_commit="cafe").value == (
        value
    )
    assert not rangeproof.verify(commitment, proof, extra_commit="not hex")
    with pytest.raises(ValueError, match="non-hexadecimal number found"):
        rangeproof.assert_as_valid(commitment, proof, extra_commit="not hex")


# `pragma: no cover` on every `@needs_zkp` below, the marker being the
# reason: `tests/conftest.py` turns it into a skip in an unflagged
# build, and excluding what a build cannot execute is what leaves the
# floor a measurement of the suite rather than of the build the machine
# has (issue #1885). The marker's line and not the `def` under it, as
# `tests/ecc/pedersen_test.py` does and for the reason it gives there
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


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to sign the same arguments
def test_zkp_signs_and_verifies_the_proof_this_module_writes() -> None:
    """The library asked for the octets `sign_public_value` answers.

    Four values under one blinding factor and one nonce: 100000, which
    the recording fixes under these same arguments; zero, which it fixes
    under others; and one and the widest the eight-octet field holds,
    which no entry fixes at this exponent. `verify` is asked beside
    `sign` because the two are different questions -- the first says zkp
    writes these octets, the second that zkp reads them as the range
    they state.
    """
    blind = bytes.fromhex(_BLIND)
    nonce = bytes.fromhex(_NONCE)
    for value in (0, 1, 100000, 2**64 - 1):
        commitment = zkp_generator.pedersen_commit(blind, value)
        octets = sign_public_value(_BLIND, value, _NONCE).serialize()
        assert octets == zkp_rangeproof.sign(commitment, blind, nonce, value, exp=-1)
        assert zkp_rangeproof.verify(commitment, octets) == (value, value)


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to sign at other arguments
def test_the_nonce_chain_answers_proofs_zkp_signs_at_other_shapes() -> None:
    """The derivation put to rings the recording does not fix.

    Each entry fixes one mantissa, where the library signs at any of
    them: the mantissas here are none of the entries', so the ring
    count varies, and with it the digit of the last ring and the key
    its value encoding lands on.
    Each proof is asked what an entry is asked -- that the chain writes
    the ring commitments it states, x and sign bit, and every `s` its
    signature did not overwrite.
    """
    blind = bytes(31) + b"\x0b"
    for min_bits, exp, value in (
        (2, 0, 3),
        (13, 0, 5000),
        (16, 2, 123400),
        (52, 0, 2**51),
    ):
        nonce = bytes(31) + bytes([min_bits])
        octets = zkp_rangeproof.sign(
            zkp_generator.pedersen_commit(blind, value),
            blind,
            nonce,
            value,
            exp=exp,
            min_bits=min_bits,
        )
        proof = RangeProof.parse(octets)
        chain = proof.nonce_chain(commit(blind, value), value, nonce)
        sign_key_idx = proof.sign_key_idx(value)
        scale = 10 ** max(proof.exp, 0)

        for i, x in enumerate(proof.ring_commitments):
            head = secp256k1.add_aff_var(
                mult(chain.blinding_factors[i], secp256k1.G, secp256k1),
                mult(sign_key_idx[i] * scale << 2 * i, second_generator(), secp256k1),
            )
            assert _bytes_from_point(head, _RANGEPROOF_TAG) == bytes(
                [proof.signs[i]]
            ) + x.to_bytes(secp256k1.p_size, "big")

        for i, (drawn, written) in enumerate(
            zip(chain.draws, proof.sig.s, strict=True)
        ):
            for j, (a, b) in enumerate(zip(drawn, written, strict=True)):
                assert (a == b) == (j != sign_key_idx[i])


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to sign the same headers
def test_zkp_signs_and_verifies_the_proofs_this_module_writes() -> None:
    """The library asked for the octets `sign` answers, header by header.

    The rows of `_HEADERS`, which are where a request and what the
    format has room for come apart: an exponent lowered, a `min_bits`
    clamped, a range that swallows the value into its floor. Each is
    asked three things, and they are three different questions. `sign`
    says zkp writes these very octets; `verify` says zkp reads them as
    the range they state, and answers that range; and the same call
    over a proof with one octet of the signature turned says it is not
    reading them as a range whatever they are.
    """
    blind = bytes.fromhex(_BLIND)
    nonce = bytes.fromhex(_NONCE)
    for arguments, header, _ in _HEADER_CASES:
        value, min_value, exp, min_bits = arguments
        commitment = zkp_generator.pedersen_commit(blind, value)
        octets = _written(arguments).serialize()
        assert octets == zkp_rangeproof.sign(
            commitment,
            blind,
            nonce,
            value,
            min_value=min_value,
            exp=exp,
            min_bits=min_bits,
        )
        assert zkp_rangeproof.info(octets) == header
        assert zkp_rangeproof.verify(commitment, octets) == header[2:]

        turned = bytearray(octets)
        turned[-1] ^= 1
        assert zkp_rangeproof.verify(commitment, bytes(turned)) is None


# The grid the two `@needs_zkp` sweeps below are taken over, and it is a
# product rather than a list of interesting cases: what a header comes
# out as is `secp256k1_range_proveparams`' answer to four arguments at
# once, so the combinations that matter are the ones nobody would think
# to write down. Most of the grid is refused by both implementations --
# a floor above the value, a message longer than the rings hold, a
# range that would wrap -- and the sweeps assert that agreement rather
# than skipping past it
_GRID_VALUES = (
    0,
    1,
    3,
    42,
    255,
    5000,
    100000,
    2**32,
    2**40 + 7,
    2**63 - 1,
    2**63,
    2**64 - 1,
)
_GRID = [
    (min_value, exp, min_bits, message)
    for min_value in (0, 1000, 2**40, 2**64 - 1)
    for exp in (-1, 0, 2, 18)
    for min_bits in (0, 8, 13, 64)
    for message in (b"", b"btclib embeds this")
]


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to write the proofs read here
@pytest.mark.parametrize("value", _GRID_VALUES)
def test_this_module_reads_what_zkp_writes(value: int) -> None:
    """Proofs the library signed, verified and rewound here.

    Each is asked three things. `verify` says the rings close on the
    `e0` zkp wrote, over a commitment built here rather than parsed
    from zkp's octets; the range the header states is the one
    `zkp.rangeproof.verify` answers; and `rewind` answers the blinding
    factor, the value and the message `zkp.rangeproof.rewind` answers
    for the same proof and nonce.

    The message is compared to zkp's own where the two buffers can
    differ in length: zkp fills a caller's, which
    `btclib_secp256k1.zkp.rangeproof` sizes at `MAX_MESSAGE_LEN`, where
    a rewind here answers every octet the rings carry -- 32 for each
    key that is neither the value encoding nor the one the last ring's
    digit opens. Only the widest mantissa has more of them than that
    constant allows, and the assertion says which case is which rather
    than comparing prefixes and calling it agreement.
    """
    blind = bytes.fromhex(_BLIND)
    nonce = bytes.fromhex(_NONCE)
    commitment = zkp_generator.pedersen_commit(blind, value)
    point = commit(_BLIND, value)
    read = 0
    for min_value, exp, min_bits, message in _GRID:
        why = (min_value, exp, min_bits, message)
        try:
            octets = zkp_rangeproof.sign(
                commitment,
                blind,
                nonce,
                value,
                min_value=min_value,
                exp=exp,
                min_bits=min_bits,
                message=message,
            )
        except ValueError:
            continue
        read += 1
        assert rangeproof.verify(point, octets), why
        proof = RangeProof.parse(octets)
        assert zkp_rangeproof.verify(commitment, octets) == (
            proof.min_value or 0,
            proof.max_value,
        ), why

        blind_out, value_out, message_out, _, _ = zkp_rangeproof.rewind(
            commitment, octets, nonce
        )
        rewound = rangeproof.rewind(point, octets, nonce)
        assert rewound.blind == int.from_bytes(blind_out, "big"), why
        assert rewound.value == value_out, why
        assert len(message_out) == min(
            len(rewound.message), zkp_rangeproof.MAX_MESSAGE_LEN
        ), why
        assert rewound.message[: len(message_out)] == message_out, why
        assert rewound.message[: len(message)] == message, why
    assert read


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to read the proofs written here
@pytest.mark.parametrize("value", _GRID_VALUES)
def test_zkp_reads_what_this_module_writes(value: int) -> None:
    """Proofs written here, handed back to the library over the same grid.

    `sign` says zkp writes these very octets, `zkp.rangeproof.verify`
    that it reads them as the range the header states, and
    `zkp.rangeproof.rewind` that it recovers from them the blinding
    factor, the value and the message they were written with -- padded
    with the zeros `_prep` left, which is what the library answers a
    caller's buffer with.

    Where the two refuse is asserted rather than skipped: an argument
    zkp turns down is one this module has to turn down as well, which
    is most of the grid and is the half a sweep of accepted cases
    cannot see.
    """
    blind = bytes.fromhex(_BLIND)
    nonce = bytes.fromhex(_NONCE)
    commitment = zkp_generator.pedersen_commit(blind, value)
    written = refused = 0
    for min_value, exp, min_bits, message in _GRID:
        why = (min_value, exp, min_bits, message)
        try:
            octets = zkp_rangeproof.sign(
                commitment,
                blind,
                nonce,
                value,
                min_value=min_value,
                exp=exp,
                min_bits=min_bits,
                message=message,
            )
        except ValueError:
            refused += 1
            with pytest.raises((BTClibValueError, BTClibRuntimeError)):
                sign(
                    _BLIND,
                    value,
                    _NONCE,
                    min_value=min_value,
                    exp=exp,
                    min_bits=min_bits,
                    message=message,
                )
            continue
        written += 1
        proof = sign(
            _BLIND,
            value,
            _NONCE,
            min_value=min_value,
            exp=exp,
            min_bits=min_bits,
            message=message,
        )
        assert proof.serialize() == octets, why
        assert zkp_rangeproof.verify(commitment, octets) == (
            proof.min_value or 0,
            proof.max_value,
        ), why

        blind_out, value_out, message_out, _, _ = zkp_rangeproof.rewind(
            commitment, octets, nonce
        )
        assert blind_out == blind, why
        assert value_out == value, why
        assert message_out[: len(message)] == message, why
        assert not any(message_out[len(message) :]), why
    assert written and refused


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to put the crafted proofs to
def test_zkp_refuses_the_rewinds_this_module_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The three crafted proofs above, and a nonce that is not the proof's.

    Each carries a value encoding for a value it was not written for,
    and each is a valid signature: `zkp.rangeproof.verify` answers the
    range, which is what says the refusal is the rewind's and not the
    verification's.
    """
    blind = bytes.fromhex(_BLIND)
    nonce = bytes.fromhex(_NONCE)
    for encoded, min_bits, header in (
        (12, 4, (0, 15)),
        (8, 3, (0, 7)),
        (4, 4, (0, 15)),
    ):
        _with_encoded_value(monkeypatch, encoded)
        octets = sign(_BLIND, 3, _NONCE, min_bits=min_bits).serialize()
        monkeypatch.undo()
        commitment = zkp_generator.pedersen_commit(blind, 3)
        assert zkp_rangeproof.verify(commitment, octets) == header
        with pytest.raises(ValueError, match="rewind failed"):
            zkp_rangeproof.rewind(commitment, octets, nonce)

    octets = _octets("odd mantissa")
    vector = _vector("odd mantissa")
    commitment = bytes.fromhex(vector["commitment"])
    assert zkp_rangeproof.verify(commitment, octets) is not None
    with pytest.raises(ValueError, match="rewind failed"):
        zkp_rangeproof.rewind(commitment, octets, bytes(32))


@needs_zkp  # pragma: no cover -- no zkp.rangeproof to bind the same octets
@pytest.mark.parametrize(
    "value, kwargs",
    [
        (100000, {"exp": -1}),
        (3, {"min_bits": 4}),
        (100000, {"min_bits": 8, "message": b"bound and carried"}),
    ],
    ids=["public value", "odd mantissa", "message too"],
)
def test_a_nonempty_extra_commit_crosses_in_both_directions(
    value: int, kwargs: dict[str, Any]
) -> None:
    """The same octets bound here and there, and refused where they differ.

    A proof written here under a nonempty `extra_commit` is the one
    `zkp.rangeproof.sign` writes for those arguments, and
    `zkp.rangeproof.verify` and `zkp.rangeproof.rewind` answer for it
    when handed the same octets. The other direction is the same
    proof read back: `verify` here says the rings close, and `rewind`
    answers the blinding factor and the value zkp's own rewind
    answers.

    The control is a second value of the argument, since a proof that
    verified under the octets it was written with would say nothing
    about whether either implementation reads them at all. Both refuse
    it, and zkp's refusal is `None` from `verify` and `rewind failed`
    from `rewind`.
    """
    extra_commit = b"the output this belongs to"
    blind = bytes.fromhex(_BLIND)
    nonce = bytes.fromhex(_NONCE)
    commitment = zkp_generator.pedersen_commit(blind, value)
    point = commit(_BLIND, value)

    octets = zkp_rangeproof.sign(
        commitment, blind, nonce, value, extra_commit=extra_commit, **kwargs
    )
    proof = sign(_BLIND, value, _NONCE, extra_commit=extra_commit, **kwargs)
    assert proof.serialize() == octets

    blind_out, value_out, message_out, _, _ = zkp_rangeproof.rewind(
        commitment, octets, nonce, extra_commit
    )
    assert blind_out == blind
    assert value_out == value
    assert zkp_rangeproof.verify(commitment, octets, extra_commit) == (
        proof.min_value or 0,
        proof.max_value,
    )

    assert rangeproof.verify(point, octets, extra_commit=extra_commit)
    rewound = rangeproof.rewind(point, octets, nonce, extra_commit=extra_commit)
    assert rewound.blind == int.from_bytes(blind_out, "big")
    assert rewound.value == value_out
    assert len(rewound.message) >= len(message_out)
    assert rewound.message[: len(message_out)] == message_out

    other = extra_commit + b"!"
    assert zkp_rangeproof.verify(commitment, octets, other) is None
    with pytest.raises(ValueError, match="rewind failed"):
        zkp_rangeproof.rewind(commitment, octets, nonce, other)
    assert not rangeproof.verify(point, octets, extra_commit=other)
    with pytest.raises(BTClibRuntimeError, match="verification failed"):
        rangeproof.rewind(point, octets, nonce, extra_commit=other)
