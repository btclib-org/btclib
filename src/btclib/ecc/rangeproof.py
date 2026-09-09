# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Confidential Transactions rangeproof, read from its octets.

`RangeProof.parse` reads what secp256k1-zkp's `rangeproof` module
writes -- `secp256k1_rangeproof_sign_impl`,
`src/modules/rangeproof/rangeproof_impl.h` -- and `RangeProof.serialize`
writes those octets back. Reading is the whole of what is here: nothing
in this module proves a range, verifies a proof or rewinds one, and the
pieces those need -- the digit decomposition, `rangeproof_pub_expand`'s
rings and `rangeproof_genrand`'s nonce chain -- have no counterpart in
this tree yet. Issue #1072 is where the rest of that distance is
tracked.

Elements and Liquid use this format, and a design starting today would
choose bulletproofs, which zkp carries as its `bppp` module.

Reading before writing, because reading is the direction with an
oracle: every header field here is one `zkp.rangeproof.info` answers
for over the same octets, and what that call is silent about -- the
sign bits, the ring commitments and the signature -- is pinned by the
octets going back out unchanged. The first artefact a writer could be
judged by is a whole proof.

`secp256k1_rangeproof_sign_impl` writes, in order:

- one octet of flags and exponent: bit 7 zero, bit 6 `has_nz_range`,
  bit 5 `has_min`, bits 0-4 the exponent;
- the mantissa less one, one octet, where `has_nz_range` is set;
- `min_value`, eight octets big-endian, where `has_min` is set;
- the sign bit of every ring commitment, packed `signs[i >> 3] |=
  quadness << (i & 7)`, padded to an octet;
- the x coordinate of every ring commitment but the last, thirty-two
  octets each;
- `e0` and one `s` per public key, ring-major, thirty-two octets each.

The last row is a `BorromeanSig`, which is why one is a field here
rather than an `e0` and an `s` of this module's own: `ecc.borromean`
already writes and reads that layout. What the rangeproof adds is
`rsizes` -- how the mantissa decides the ring structure -- which
`secp256k1_rangeproof_verify_impl` computes and hands to
`secp256k1_borromean_verify` rather than reading out of the proof, and
which `_rsizes` below computes the same way.

**The sign bit is quadratic residuosity, not parity.**
`secp256k1_rangeproof_serialize_point` writes
`data[0] = !secp256k1_fe_is_square_var(&point->y)`, so a set bit says
the ring commitment's y is not a square. That is not the even/odd
convention `curves.bytes_from_point`, BIP340 and the `02`/`03` SEC
prefix carry, and the two disagree on the vectors
`tests/ecc/rangeproof_test.py` reads. Nothing here computes the bit --
a parse reads it and a serialize writes it back -- so what a
`RangeProof` holds is the octets' own answer; a stage that resolves an
x to a point computes against this convention and not the familiar
one.

Which points those are, and whether the signature over them verifies,
this module does not ask: an x here is an integer of the width the
format fixes. `assert_valid` refuses the headers
`secp256k1_rangeproof_getheader_impl` refuses, and a body this object
could not write the octets of; an x that names no point on the curve
is neither, and a verifier is what turns it down.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from btclib.alias import BinaryData
from btclib.curves import secp256k1
from btclib.ecc.borromean import BorromeanSig
from btclib.exceptions import BTClibValueError
from btclib.utils import assert_no_trailing, bytesio_from_binarydata, read_exactly

__all__ = ["RangeProof"]

# the flags octet, as secp256k1_rangeproof_getheader_impl reads it
_RESERVED = 128
_HAS_NZ_RANGE = 64
_HAS_MIN = 32
_EXP_MASK = 31

# secp256k1_rangeproof_getheader_impl's own two caps, and the width every
# value in this format is bounded by
_MAX_EXP = 18
_MAX_MANTISSA = 64
_UINT64_MAX = 2**64 - 1

# what a min_value field occupies: zkp writes it at a fixed width rather
# than behind a length, and reads it back the same way
_MIN_VALUE_SIZE = 8


def _rsizes(mantissa: int) -> tuple[int, ...]:
    """Return how many public keys each ring holds, from the mantissa alone.

    Two bits of the mantissa are one base-4 digit, so a ring of four
    covers each pair and a last ring of two covers the odd bit left
    over. A mantissa of zero is the public-value proof, whose one ring
    has the single key the commitment itself gives -- `exp` is then -1
    and there is nothing blinded to choose between.

    `secp256k1_rangeproof_verify_impl` computes this and passes it to
    `secp256k1_borromean_verify`, so a `BorromeanSig` inside a proof is
    read against the mantissa where a free-standing one is read against
    a caller's `rsizes`.
    """
    if mantissa == 0:
        return (1,)
    return (4,) * (mantissa >> 1) + ((2,) if mantissa & 1 else ())


def _sign_octets(rings: int) -> int:
    """Return how many octets the sign bits of that many rings occupy.

    One bit per ring but the last, rounded up: `(rings + 6) >> 3`, which
    is zkp's own spelling of it and answers zero for the single-ring
    proof that has no ring commitment to sign.
    """
    return (rings + 6) >> 3


def _max_value(exp: int, mantissa: int, min_value: int) -> int:
    """Return the largest value the header proves for, in zkp's arithmetic.

    The mantissa's own ceiling, scaled by ten as many times as `exp`
    says and offset by `min_value`. Both steps are where zkp refuses a
    header rather than wrapping: `secp256k1_rangeproof_getheader_impl`
    compares against `UINT64_MAX` before each multiplication and before
    the sum, so a header naming a range this format cannot express is
    not a proof of anything.
    """
    value = _UINT64_MAX >> (64 - mantissa) if mantissa else 0
    for _ in range(max(exp, 0)):
        if value > _UINT64_MAX // 10:
            err_msg = f"rangeproof max value overflows at exponent {exp}"
            raise BTClibValueError(err_msg)
        value *= 10
    if value > _UINT64_MAX - min_value:
        err_msg = f"rangeproof max value overflows past min value {min_value}"
        raise BTClibValueError(err_msg)
    return value + min_value


def _assert_valid_header(exp: int, mantissa: int, min_value: int | None) -> None:
    """Refuse a header this format has no octets for.

    The exponent and mantissa caps and the `max_value` arithmetic are
    `secp256k1_rangeproof_getheader_impl`'s own refusals; the
    `min_value` bound is the field's, eight octets carrying no more.
    The exponent and the mantissa are checked together because one flag
    carries both: bit 6 of the first octet says the range is blinded,
    and a public value has neither a mantissa nor an exponent of its
    own. `_max_value` runs here for its raising alone, the value it
    answers being the caller's to ask for.
    """
    if mantissa:
        if not 0 <= exp <= _MAX_EXP:
            raise BTClibValueError(f"rangeproof exponent not in 0..18: {exp}")
        if not 1 <= mantissa <= _MAX_MANTISSA:
            raise BTClibValueError(f"rangeproof mantissa not in 1..64: {mantissa}")
    elif exp != -1:
        err_msg = f"rangeproof exponent of a public value is not -1: {exp}"
        raise BTClibValueError(err_msg)

    if min_value is not None and not 0 <= min_value <= _UINT64_MAX:
        err_msg = f"rangeproof min value not in 0..2**64-1: {min_value}"
        raise BTClibValueError(err_msg)

    _ = _max_value(exp, mantissa, min_value or 0)


@dataclass(frozen=True, init=False)
class RangeProof:
    """A Confidential Transactions rangeproof, as its octets state it.

    `exp` is -1 exactly where the proof states its value in the clear,
    and `mantissa` is 0 there and in [1, 64] everywhere else: the two
    move together because one flag carries both, bit 6 of the first
    octet being what says the range is blinded at all.

    `min_value` is None where that octet's bit 5 is clear and the
    proven range therefore starts at zero, and an integer -- zero
    included -- where the field is present. The two are not the same
    octets and `zkp.rangeproof.info` answers zero for both, so an
    integer of its own is what lets `serialize` write back what `parse`
    read.

    `signs` and `ring_commitments` are aligned, one entry each per ring
    but the last: the wire packs the bits together ahead of the x
    coordinates, which is why they are two fields rather than pairs.
    `sig` is the borromean signature over the rings the mantissa
    describes, and it is where this proof's curve is: an x is written
    at `sig.ec.p_size` octets, which generalizes zkp's hardcoded
    thirty-two the way `BorromeanSig.serialize` generalizes its scalar
    width, the two agreeing wherever the curve is secp256k1.
    """

    exp: int
    mantissa: int
    min_value: int | None
    signs: tuple[bool, ...]
    ring_commitments: tuple[int, ...]
    sig: BorromeanSig

    # written out rather than an InitVar[bool] field and a __post_init__:
    # see the comment on dsa.Sig.__init__
    def __init__(
        self,
        exp: int,
        mantissa: int,
        min_value: int | None,
        signs: Sequence[bool],
        ring_commitments: Sequence[int],
        sig: BorromeanSig,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "exp", exp)
        object.__setattr__(self, "mantissa", mantissa)
        object.__setattr__(self, "min_value", min_value)
        object.__setattr__(self, "signs", tuple(signs))
        object.__setattr__(self, "ring_commitments", tuple(ring_commitments))
        object.__setattr__(self, "sig", sig)

        if check_validity:
            self.assert_valid()

    @property
    def rsizes(self) -> tuple[int, ...]:
        """Return how many public keys each of this proof's rings holds."""
        return _rsizes(self.mantissa)

    @property
    def max_value(self) -> int:
        """Return the largest value this proof's header proves for."""
        return _max_value(self.exp, self.mantissa, self.min_value or 0)

    def assert_valid(self) -> None:
        """Refuse a header no proof carries, or a body it does not describe.

        The header is `_assert_valid_header`'s, which is zkp's own
        refusals. The rest is this object against itself: a sign bit
        with no ring commitment beside it, an x wider than the field it
        is written in, or a signature whose rings are not the ones the
        mantissa describes -- each of them a state `serialize` could
        not write the octets of.
        """
        _assert_valid_header(self.exp, self.mantissa, self.min_value)

        rings = len(self.rsizes)
        if len(self.signs) != rings - 1:
            err_msg = f"rangeproof has {len(self.signs)} sign bits"
            err_msg += f" for {rings - 1} ring commitments"
            raise BTClibValueError(err_msg)
        if len(self.ring_commitments) != rings - 1:
            err_msg = f"rangeproof has {len(self.ring_commitments)} ring commitments"
            err_msg += f" where the mantissa asks for {rings - 1}"
            raise BTClibValueError(err_msg)

        p_size = self.sig.ec.p_size
        for i, x in enumerate(self.ring_commitments):
            if not 0 <= x < 256**p_size:
                err_msg = f"ring commitment {i} does not fit in {p_size} octets"
                raise BTClibValueError(err_msg)

        self.sig.assert_valid()
        sig_rsizes = tuple(len(ring) for ring in self.sig.s)
        if sig_rsizes != self.rsizes:
            err_msg = f"borromean rings {sig_rsizes} are not the mantissa's"
            err_msg += f" {self.rsizes}"
            raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the header, the sign bits, the commitments and the signature.

        `secp256k1_rangeproof_sign_impl`'s own order, and its own two
        conditions: the mantissa octet where the range is blinded, the
        `min_value` octets where the header carries one.
        """
        if check_validity:
            self.assert_valid()

        flags = _HAS_NZ_RANGE | self.exp if self.mantissa else 0
        if self.min_value is not None:
            flags |= _HAS_MIN
        out = bytes([flags])
        if self.mantissa:
            out += bytes([self.mantissa - 1])
        if self.min_value is not None:
            out += self.min_value.to_bytes(_MIN_VALUE_SIZE, byteorder="big")

        signs = bytearray(_sign_octets(len(self.rsizes)))
        for i, sign in enumerate(self.signs):
            signs[i >> 3] |= sign << (i & 7)
        out += bytes(signs)

        p_size = self.sig.ec.p_size
        for x in self.ring_commitments:
            out += x.to_bytes(p_size, byteorder="big")
        # check_validity=False whatever was asked here: assert_valid
        # above already ran the signature's own, so passing the flag on
        # would run it a second time over every scalar
        return out + self.sig.serialize(check_validity=False)

    @classmethod
    def parse(
        cls: type[RangeProof], data: BinaryData, *, check_validity: bool = True
    ) -> RangeProof:
        """Build a RangeProof from the octets zkp's rangeproof module writes.

        secp256k1 and sha256, as `BorromeanSig.parse` reads its own
        layout and for the same reason: the encoding names neither, and
        both widths are what zkp fixes for the one curve it has.

        Three of zkp's refusals do not wait on `check_validity`. Bit 7
        of the first octet, which the format holds at zero, and a set
        bit above the last sign bit, which
        `secp256k1_rangeproof_verify_impl` refuses as mutation, are
        neither of them a field: a parse that accepted either would
        build an object serializing back to different octets. A
        mantissa past 64 is the third, and for `read_exactly`'s own
        reason -- it is what says how many rings follow, so it makes
        the field boundary rather than states a value.

        The exponent's cap and the `max_value` arithmetic decide no
        length, and are `assert_valid`'s as everywhere else.
        """
        stream = bytesio_from_binarydata(data)

        flags = read_exactly(stream, 1, "rangeproof flags")[0]
        if flags & _RESERVED:
            raise BTClibValueError("bit 7 set in the rangeproof flags")
        exp, mantissa = -1, 0
        if flags & _HAS_NZ_RANGE:
            exp = flags & _EXP_MASK
            mantissa = read_exactly(stream, 1, "rangeproof mantissa")[0] + 1
            if mantissa > _MAX_MANTISSA:
                err_msg = f"rangeproof mantissa not in 1..64: {mantissa}"
                raise BTClibValueError(err_msg)
        min_value = None
        if flags & _HAS_MIN:
            octets = read_exactly(stream, _MIN_VALUE_SIZE, "rangeproof min value")
            min_value = int.from_bytes(octets, byteorder="big")

        rings = len(_rsizes(mantissa))
        octets = read_exactly(stream, _sign_octets(rings), "rangeproof sign bits")
        signs = tuple(bool(octets[i >> 3] & 1 << (i & 7)) for i in range(rings - 1))
        padding = (rings - 1) & 7
        if padding and octets[-1] >> padding:
            raise BTClibValueError("rangeproof sign bit padding is not zero")

        p_size = secp256k1.p_size
        ring_commitments = tuple(
            int.from_bytes(
                read_exactly(stream, p_size, f"rangeproof ring commitment {i}"),
                byteorder="big",
            )
            for i in range(rings - 1)
        )

        sig = BorromeanSig.parse(
            stream, _rsizes(mantissa), check_validity=check_validity
        )
        assert_no_trailing(data, stream, "rangeproof")

        return cls(
            exp,
            mantissa,
            min_value,
            signs,
            ring_commitments,
            sig,
            check_validity=check_validity,
        )
