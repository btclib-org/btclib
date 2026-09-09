# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Confidential Transactions rangeproof, and the one shape btclib writes.

`RangeProof.parse` reads what secp256k1-zkp's `rangeproof` module
writes -- `secp256k1_rangeproof_sign_impl`,
`src/modules/rangeproof/rangeproof_impl.h` -- and `RangeProof.serialize`
writes those octets back.

`sign_public_value` writes one proof, and it is the one that proves no
range: `exp` is -1, the value is stated in the clear, and the single
ring holds the key the commitment itself gives. `RangeProof.pubk_rings`
rebuilds, from a proof and the value commitment it was written against,
the rings `secp256k1_borromean_verify` is handed, and
`RangeProof.sign_key_idx` says which key of each ring a value's own
digit names. `RangeProof.nonce_chain` derives what
`secp256k1_rangeproof_genrand` draws for those rings: each ring's
blinding factor, and the scalar behind each of its keys. Nothing here
verifies a proof or rewinds one. Issue #1072
is where the rest of that distance is tracked.

Elements and Liquid use this format, and a design starting today would
choose bulletproofs, which zkp carries as its `bppp` module.

Each direction is held to what can hold it. A parse answers to
`zkp.rangeproof.info`, field for field over the same octets, and what
that call is silent about -- the sign bits, the ring commitments and
the signature -- to the octets going back out unchanged. The writer
answers to something stronger, and that is what makes this the shape to
write first: a rangeproof draws nothing, its nonce being the hash chain
`rangeproof_genrand` derives from the caller's, so the octets are a
function of the arguments and the proof zkp signs for those same
arguments is the answer, byte for byte.

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
`tests/ecc/rangeproof_test.py` reads. No ring commitment's bit is
computed here -- a parse reads it and a serialize writes it back, so
what a `RangeProof` holds is the octets' own answer -- while
`_serialize_point` is that function of zkp's, and what
`sign_public_value` hashes the value commitment and the generator
under. Resolving an x back to a point is the same convention read the
other way, and `_point_from_ring_commitment` is where this module does
it: `secp256k1_ge_set_xquad` takes the y that is a square, and
`secp256k1_rangeproof_verify_impl` negates it where the sign bit says
the y is not one.

The digit decomposition is `rangeproof_pub_expand`: a ring's keys step
down from the ring commitment by the weight of the digit that ring
proves, `10**exp` for the first and four times its predecessor for each
ring after it. The last ring states no commitment of its own --
`secp256k1_rangeproof_verify_impl` recovers it as the value commitment
less `min_value` times the generator and less every ring commitment
before it, which is the digit a prover does not have to send. So the
value commitment is what the whole structure hangs from, and it is
`pubk_rings`'s argument.

An x is an integer of the width the format fixes wherever a proof is
parsed, serialized or held against itself: `assert_valid` refuses the
headers `secp256k1_rangeproof_getheader_impl` refuses, and a body this
object could not write the octets of, and an x naming no point on the
curve is neither. `pubk_rings` is where an x has to name a point, and
is what turns down one that does not. Whether the signature over those
rings verifies, this module does not ask.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import NamedTuple

from btclib.alias import INF, BinaryData, Integer, Octets, Point
from btclib.curves import bytes_from_point, mult, scalar_from_prv_key, secp256k1
from btclib.ecc.borromean import BorromeanSig, PubkeyRing, _hash
from btclib.ecc.pedersen import commit, second_generator
from btclib.ecc.rfc6979_nonce import _HmacDrbg
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.number_theory import legendre_symbol_var
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    int_from_bits,
    read_exactly,
)

__all__ = ["NonceChain", "RangeProof", "sign_public_value"]

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

# what a nonce occupies, and it is zkp's own 32 rather than the scalar
# width every other length here generalizes: `rangeproof_genrand` copies
# that many octets of the caller's nonce into its seed
_NONCE_SIZE = 32

# how far apart two rings sit in the octets `sign_impl` hands the nonce
# chain, which is the widest a ring gets rather than the width of the
# ring in hand: `genrand` indexes that buffer by `i * 4 + j`
_RING_STRIDE = 4


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


def _header_octets(exp: int, mantissa: int, min_value: int | None) -> bytes:
    """Return the flags octet and the fields its own bits say follow it.

    A function of the header alone, because `sign_public_value` needs
    these octets before it has a signature to put after them:
    `secp256k1_rangeproof_sign_impl` writes the header first and then
    hashes it, into the nonce chain's seed and into the message the ring
    is signed over.
    """
    flags = _HAS_NZ_RANGE | exp if mantissa else 0
    if min_value is not None:
        flags |= _HAS_MIN
    out = bytes([flags])
    if mantissa:
        out += bytes([mantissa - 1])
    if min_value is not None:
        out += min_value.to_bytes(_MIN_VALUE_SIZE, byteorder="big")
    return out


def _serialize_point(Q: Point) -> bytes:
    """Return the encoding a rangeproof hashes a point under.

    `secp256k1_rangeproof_serialize_point`: one octet saying the y is
    not a square, then the x. The octet is the residuosity the module
    docstring above distinguishes from parity, so this is not
    `curves.bytes_from_point` with another name: a proof hashed under
    the parity convention verifies nowhere, and nothing in the octets
    says which of the two wrote them.
    """
    residue = legendre_symbol_var(Q[1], secp256k1.p) == 1
    return bytes([0 if residue else 1]) + Q[0].to_bytes(secp256k1.p_size, "big")


def _point_from_ring_commitment(x: int, sign: bool) -> Point:
    """Return the point a ring commitment's x and sign bit name.

    `secp256k1_rangeproof_verify_impl` reads its x through
    `secp256k1_ge_set_xquad`, which is the y that is a square, and
    negates the result where the sign bit is set. The parity convention
    coincides with this one only where the square y is also the even
    one, so reading the bit that way answers a different point on some x
    coordinates and the same point on others, with nothing in the octets
    saying which was read.
    """
    y = secp256k1.y_quadratic_residue_var(x)
    return x, secp256k1.p - y if sign else y


def _pub_expand(
    ring_commitments: Sequence[Point], exp: int, rsizes: Sequence[int]
) -> tuple[PubkeyRing, ...]:
    """Return each ring's keys, from the commitment that ring opens at.

    `secp256k1_rangeproof_pub_expand`. A ring's key at position j is its
    commitment less j times the weight of the digit that ring proves, so
    the position the prover knows the key of is the digit itself.

    zkp reaches the first weight by doubling: it negates the generator
    and multiplies by ten as many times as `exp` says, three doublings
    and an addition each. One scalar multiplication is the same group
    element, and this tree has one that libsecp256k1 answers where the
    doubling chain would be Python arithmetic. The quadrupling between
    rings stays as zkp writes it, needing no scalar at all.
    """
    # zkp holds a negative exponent at zero here, `pub_expand` being
    # reached with the -1 of a proof that states its value
    base = secp256k1.negate(mult(10 ** max(exp, 0), second_generator(), secp256k1))
    rings: list[PubkeyRing] = []
    for i, size in enumerate(rsizes):
        ring = [ring_commitments[i]]
        for _ in range(size - 1):
            ring.append(secp256k1.add_aff_var(ring[-1], base))
        rings.append(tuple(ring))
        if i < len(rsizes) - 1:
            base = secp256k1.double_aff_var(secp256k1.double_aff_var(base))
    return tuple(rings)


class NonceChain(NamedTuple):
    """What `secp256k1_rangeproof_genrand` answers for one proof's rings.

    `blinding_factors` is one scalar per ring, the one that ring's
    commitment is written under. Every ring but the last draws its own
    and the last is minus the sum of those, so once
    `secp256k1_rangeproof_sign_impl` has added the caller's own to that
    last one they sum to it -- which is what lets a verifier recover
    the ring commitment the proof leaves out. What is here is the
    chain's answer, before that addition.

    `draws` is one scalar per public key, ring-major, the shape
    `BorromeanSig.s` carries. At the key the value's own digit names,
    `sign_impl` moves the draw into the nonce it closes that ring with;
    at every other key the draw is the `s` the proof states.
    """

    blinding_factors: tuple[int, ...]
    draws: tuple[tuple[int, ...], ...]


def _blocks(seed: bytes) -> Iterator[bytes]:
    """Yield the blocks of the chain that seed starts, one scalar wide.

    `secp256k1_rfc6979_hmac_sha256_generate` raises a retry flag at the
    end of every call and performs the K and V update at the start of
    the next, so every block after the first opens with a reseed. That
    update is `_HmacDrbg.reseed`, the same two HMACs in the same order
    that `_rfc6979_nonce_` performs on a rejected candidate.
    """
    drbg = _HmacDrbg(seed, sha256)
    yield drbg.generate(secp256k1.n_size)
    while True:
        drbg.reseed()
        yield drbg.generate(secp256k1.n_size)


def _prep(rsizes: Sequence[int], v: int, sign_key_idx: int) -> bytes:
    """Return the octets `secp256k1_rangeproof_sign_impl` folds into the draws.

    zkp's `prep`, which is where a message a proof embeds would sit.
    Nothing here embeds one, so the buffer is zero but for one key of
    the last ring, and that key is written whether there is a message
    or not: an octet of 128, seven of zero, and the value the mantissa
    carries big-endian three times, at the eight octets a `min_value`
    field occupies and for the same reason, both being a uint64. That
    is what makes the value readable from the proof by whoever holds
    the nonce, which is `secp256k1_rangeproof_rewind_inner`.

    A last ring of one key has no such position, and the public-value
    proof is the one shaped that way -- it states its value in the
    clear anyway. Anywhere else the key is the ring's last, or the one
    before it where the value's own digit is that one, since the draw
    at the digit's key is spent as a nonce rather than written into
    the proof.
    """
    prep = bytearray(_RING_STRIDE * secp256k1.n_size * len(rsizes))
    if rsizes[-1] > 1:
        j = rsizes[-1] - 1 - (sign_key_idx == rsizes[-1] - 1)
        offset = ((len(rsizes) - 1) * _RING_STRIDE + j) * secp256k1.n_size
        prep[offset : offset + secp256k1.n_size] = (
            bytes([128]) + bytes(7) + v.to_bytes(_MIN_VALUE_SIZE, "big") * 3
        )
    return bytes(prep)


def _genrand(seed: bytes, rsizes: Sequence[int], prep: bytes) -> NonceChain:
    """Return the chain `secp256k1_rangeproof_genrand` derives from that seed.

    Two acceptance rules, one per kind of draw. A ring blinding factor
    at or past n, or zero, sends the chain on for another block, which
    is what `_rfc6979_nonce_` does with a rejected candidate and by the
    same two HMACs. A ring member's draw there fails the proof instead:
    zkp accumulates that into the `ret` it answers with and abandons
    the proof after the loop, which is the raise here.

    Every ring but the last spends a block before the one it tests, the
    chain drawing into a buffer it overwrites before reading it. So the
    value of that block is discarded and the advance it made is not.
    Skipping it puts the derivation off by a block from the first ring
    onward, in scalars that are well formed: what says so is a proof
    zkp signed.
    """
    blocks = _blocks(seed)
    blinding_factors: list[int] = []
    draws: list[tuple[int, ...]] = []
    acc = 0
    for i, size in enumerate(rsizes):
        if i < len(rsizes) - 1:
            next(blocks)
            while True:
                sec = int.from_bytes(next(blocks), "big")
                if 0 < sec < secp256k1.n:
                    break
            blinding_factors.append(sec)
            acc = (acc + sec) % secp256k1.n
        else:
            blinding_factors.append(-acc % secp256k1.n)

        ring: list[int] = []
        for j in range(size):
            offset = (i * _RING_STRIDE + j) * secp256k1.n_size
            block = zip(
                next(blocks),
                prep[offset : offset + secp256k1.n_size],
                strict=True,
            )
            s = int.from_bytes(bytes(a ^ b for a, b in block), "big")
            if not 0 < s < secp256k1.n:
                raise BTClibRuntimeError("rangeproof nonce is not a scalar")
            ring.append(s)
        draws.append(tuple(ring))
    return NonceChain(tuple(blinding_factors), tuple(draws))


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

    def pubk_rings(
        self, commitment: Point, *, check_validity: bool = True
    ) -> tuple[PubkeyRing, ...]:
        """Return the rings of keys this proof's signature is over.

        `secp256k1_rangeproof_verify_impl` up to the point where it hands
        those rings to `secp256k1_borromean_verify`: every ring
        commitment the proof states, resolved against the residuosity
        convention the module docstring gives; the one it does not state,
        recovered from `commitment`; and `_pub_expand` over all of them.
        Nothing here reads `e0` or an `s`, so a proof whose signature is
        wrong answers the same rings as one whose signature is right.

        `commitment` is the Pedersen commitment the proof was written
        against, `ecc.pedersen.commit`'s own point rather than octets --
        the ones `secp256k1_pedersen_commitment_serialize` hands back
        carry the residuosity bit too, `secp256k1_pedersen_commitment_save`
        writing it at `9 ^ is_square(y)` where `_serialize_point` writes
        `1 ^ is_square(y)`.

        A commitment that leaves the last ring at infinity is refused,
        as `secp256k1_rangeproof_verify_impl` refuses it where its own
        `pubs[npub]` lands there: infinity is no public key. So is an x
        at or past the field prime, which is
        `secp256k1_fe_set_b32_limit`'s refusal and `Curve.y_var`'s own.
        """
        if check_validity:
            self.assert_valid()
        secp256k1.require_on_curve(commitment)

        stated = [
            _point_from_ring_commitment(x, sign)
            for x, sign in zip(self.ring_commitments, self.signs, strict=True)
        ]
        # zkp's own order: the offset and the stated commitments are
        # accumulated, the sum negated, and the commitment added to it
        acc = (
            mult(self.min_value, second_generator(), secp256k1)
            if self.min_value
            else INF
        )
        for point in stated:
            acc = secp256k1.add_aff_var(acc, point)
        last = secp256k1.add_aff_var(commitment, secp256k1.negate(acc))
        if last == INF:
            err_msg = "rangeproof last ring commitment is the point at infinity"
            raise BTClibValueError(err_msg)

        return _pub_expand([*stated, last], self.exp, self.rsizes)

    def nonce_chain(
        self,
        commitment: Point,
        value: int,
        nonce: Octets,
        *,
        check_validity: bool = True,
    ) -> NonceChain:
        """Return the scalars this proof's nonce derives.

        `secp256k1_rangeproof_genrand`, seeded as
        `secp256k1_rangeproof_sign_impl` seeds it: the caller's nonce,
        then the value commitment and the generator under
        `_serialize_point`, then the header octets this proof's own
        exponent, mantissa and `min_value` write. So whoever holds the
        nonce answers every ring commitment the proof states -- each is
        its ring's blinding factor times G plus that ring's own digit
        times the generator -- and every `s` the signature left as the
        chain drew it.

        `commitment` is the Pedersen commitment the proof was written
        against, `pubk_rings`'s argument of that name, and `value` what
        it commits to. The value is read for more than the digits:
        wherever the last ring holds more than one key, one of them
        carries the value inside its own draw, so the chain is not a
        function of the header alone. A value this proof has no digit
        for is refused, `sign_key_idx`'s own refusal.
        """
        if check_validity:
            self.assert_valid()
        secp256k1.require_on_curve(commitment)
        sign_key_idx = self.sign_key_idx(value)
        seed = bytes_from_octets(nonce, _NONCE_SIZE)
        seed += _serialize_point(commitment) + _serialize_point(second_generator())
        seed += _header_octets(self.exp, self.mantissa, self.min_value)

        v = self._mantissa_value(value)
        return _genrand(seed, self.rsizes, _prep(self.rsizes, v, sign_key_idx[-1]))

    def _mantissa_value(self, value: int) -> int:
        """Return that value in the units the mantissa's digits count.

        `secp256k1_range_proveparams`' `v`: the value less `min_value`,
        over ten as many times as the exponent says. The value the
        proof was written for is what this answers for. A value outside
        that range, or one the exponent's own scaling cannot reach, is
        no value of this proof and is refused.
        """
        min_value = self.min_value or 0
        if not min_value <= value <= self.max_value:
            err_msg = f"rangeproof value not in {min_value}..{self.max_value}: {value}"
            raise BTClibValueError(err_msg)
        # mypy reads `int ** int` as `Any`, a negative exponent being
        # what makes that operator answer a float
        scale: int = 10 ** max(self.exp, 0)
        v, remainder = divmod(value - min_value, scale)
        if remainder:
            err_msg = f"rangeproof value {value} is not the exponent's own multiple"
            raise BTClibValueError(err_msg)
        return v

    def sign_key_idx(self, value: int) -> tuple[int, ...]:
        """Return where in each ring the key of that value sits.

        `secp256k1_range_proveparams`' `secidx`, and
        `ecc.borromean.sign`'s argument of this name: the base-4 digits
        of the value less `min_value` over `10**exp`, least significant
        ring first. A ring of two takes the odd bit an odd mantissa
        leaves over, and the digit there is below two because the value
        is within the range the header states.

        A value this proof has no digit for is refused.
        """
        v = self._mantissa_value(value)
        return tuple((v >> 2 * i) & 3 for i in range(len(self.rsizes)))

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the header, the sign bits, the commitments and the signature.

        `secp256k1_rangeproof_sign_impl`'s own order, and its own two
        conditions: the mantissa octet where the range is blinded, the
        `min_value` octets where the header carries one.
        """
        if check_validity:
            self.assert_valid()

        out = _header_octets(self.exp, self.mantissa, self.min_value)

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


def sign_public_value(blind: Integer, value: int, nonce: Octets) -> RangeProof:
    """Return the proof that states its value in the clear.

    `secp256k1_rangeproof_sign_impl` with an `exp` of -1, which
    `secp256k1_range_proveparams` answers with one ring holding the
    single key the commitment itself gives. So this proof asserts no
    range: it says what the commitment commits to, and that whoever
    wrote it knows the blinding factor. The mantissa, the digit
    decomposition, `rangeproof_pub_expand` and the sign bits are all
    absent from it, a proof carrying one ring commitment per ring but
    the last and this one having a single ring.

    A value of zero writes the flags octet and nothing after it; any
    other writes `min_value` in the eight octets behind bit 5.

    secp256k1 and sha256, which `parse` fixes for the reason it gives.
    `blind` is a scalar, read through `curves.scalar_from_prv_key`;
    `value` is what those eight octets carry; `nonce` is the 32 octets
    `rangeproof_genrand` seeds its chain with.

    Deterministic in all three, so what comes back is the octets
    `zkp.rangeproof.sign` answers for the same arguments -- which is
    what `tests/ecc/rangeproof_test.py` asks of it, against a vendored
    proof where the flagged extension is absent and against the library
    where it is.
    """
    blind_int = scalar_from_prv_key(blind, secp256k1)
    if not 0 <= value <= _UINT64_MAX:
        raise BTClibValueError(f"rangeproof value not in 0..2**64-1: {value}")
    nonce_bytes = bytes_from_octets(nonce, _NONCE_SIZE)

    # zkp sets bit 5 from the value, this path's `min_value` being the
    # value itself: `min_value ? 32 : 0`, so zero carries no field
    min_value = value or None
    header = _header_octets(-1, 0, min_value)
    points = _serialize_point(commit(blind_int, value))
    points += _serialize_point(second_generator())

    # the one draw a single ring takes. `rangeproof_genrand` draws
    # nothing for the last ring's blinding factor -- that is minus the
    # sum of the others, and there are no others, so `sec` is zero and
    # the caller's `blind` is the whole of it -- and one block for the
    # ring's one public key, which `sign_impl` then moves into the nonce
    # the ring is closed with. `secp256k1_range_proveparams` answers an
    # `exp` of -1 with a value of zero at digit zero, which is what
    # leaves that ring with nothing of `_prep` written into it
    seed = nonce_bytes + points + header
    k = _genrand(seed, (1,), _prep((1,), 0, 0)).draws[0][0]

    m = sha256(points + header).digest()
    r = bytes_from_point(mult(k, secp256k1.G, secp256k1), secp256k1)
    e0 = sha256(r + m).digest()
    # `secp256k1_borromean_sign` over one ring of one key: `e0` hashes
    # the nonce point and then the message, and the challenge that
    # closes the ring is `e0`'s own at ring 0, position 0, which
    # `borromean._hash` is the preimage of. Not reduced modulo n the
    # way `ecc.borromean` reduces it -- zkp refuses a challenge at or
    # past n here, and a proof it would not have written is a proof its
    # verifier does not take
    e = int_from_bits(_hash(m, e0, 0, 0, sha256), secp256k1.nlen)
    if not 0 < e < secp256k1.n:
        raise BTClibRuntimeError("rangeproof challenge is not a scalar")

    s = (k - e * blind_int) % secp256k1.n
    if s == 0:
        # a zero s is the one `BorromeanSig` holds and zkp does not
        # write: `secp256k1_borromean_sign` returns zero on it, and
        # `secp256k1_borromean_verify` refuses one it is handed
        raise BTClibRuntimeError("rangeproof signature value is zero")
    return RangeProof(-1, 0, min_value, (), (), BorromeanSig(e0, [[s]]))
