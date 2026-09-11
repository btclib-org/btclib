# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Confidential Transactions rangeproof, and what btclib writes of it.

`RangeProof.parse` reads what secp256k1-zkp's `rangeproof` module
writes -- `secp256k1_rangeproof_sign_impl`,
`src/modules/rangeproof/rangeproof_impl.h` -- and `RangeProof.serialize`
writes those octets back.

`sign` writes a proof for a blinded value: `_prove_params` chooses the
header, the mantissa decides the rings and the value's digits which key
of each one the prover opens, and `_borromean_sign` closes them.
`sign_public_value` is that walk at an `exp` of -1, where
the value is stated in the clear and the single ring holds the key the
commitment itself gives. `RangeProof.pubk_rings`
rebuilds, from a proof and the value commitment it was written against,
the rings `secp256k1_borromean_verify_impl` is handed, and
`RangeProof.sign_key_idx` says which key of each ring a value's own
digit names. `RangeProof.nonce_chain` derives what
`secp256k1_rangeproof_genrand` draws for those rings: each ring's
blinding factor, and the scalar behind each of its keys.

`verify` answers whether a proof holds for a commitment, and
`assert_as_valid` is the same question raising its reason; the range
proven is the proof's own `min_value` and `max_value`, which the header
states and a parse reads. `rewind` is what a recipient holding the
nonce calls: it answers the blinding factor, the value and the message
`sign` embedded. Those two are one piece and not two --
`secp256k1_rangeproof_verify_impl` calls
`secp256k1_rangeproof_rewind_inner` from inside itself and hands it the
per-key challenges its own borromean walk produced, commented there as
used during a rewind alone -- so `_verify_rings` answers the challenges
where `verify` answers a bool.

`extra_commit` binds octets of a caller's outside the proof into the
challenge, and it enters the ring message alone:
`secp256k1_rangeproof_sign_impl` and
`secp256k1_rangeproof_verify_impl` write it into their `sha256_m`
after the ring commitments and immediately before finalizing, and hand
`secp256k1_rangeproof_genrand` no such argument. So a proof's octets
change with it and the chain behind them does not.

`gen`, `secp256k1_rangeproof.h`'s own argument of that name and
`zkp.rangeproof`'s `gen_bytes`, is the generator the commitment was
made under, and every entry point below takes it: it enters the
octets hashed into the message every ring is signed over, the weight
each ring's keys step down by in `_pub_expand`, and the `min_value`
offset `pubk_rings` subtracts. `ecc.pedersen.commit` takes it too, so
a caller holding one generator per asset commits and proves under
each of them.

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
`secp256k1_borromean_verify_impl` rather than reading out of the proof,
and which `_rsizes` below computes the same way.

**The sign bit is quadratic residuosity, not parity.**
`secp256k1_rangeproof_serialize_point` writes
`data[0] = !secp256k1_fe_is_square_var(&point->y)`, so a set bit says
the ring commitment's y is not a square. That is not the even/odd
convention `curves.bytes_from_point`, BIP340 and the `02`/`03` SEC
prefix carry, and the two disagree on the vectors
`tests/ecc/rangeproof_test.py` reads. `ecc.pedersen._bytes_from_point`
at `_RANGEPROOF_TAG` is that codec, and every point entering a proof's
hash goes through it: the value commitment, the generator, and each
ring commitment `sign` states. A parse reads those bits back and a
serialize writes them out, so what a `RangeProof` holds is the octets'
own answer. Resolving
an x back to a point is that convention read the other way, and
`ecc.pedersen._point_from_x` is what does it: `secp256k1_ge_set_xquad`
takes the y that is a square, and `secp256k1_rangeproof_verify_impl`
negates it where the sign bit says the y is not one.

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
from btclib.curves import (
    bytes_from_point,
    double_mult_var,
    mult,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.ecc.borromean import BorromeanSig, PubkeyRing, _hash
from btclib.ecc.pedersen import (
    _RANGEPROOF_TAG,
    _bytes_from_point,
    _point_from_x,
    commit,
)
from btclib.ecc.rfc6979_nonce import _HmacDrbg
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    int_from_bits,
    read_exactly,
)

__all__ = [
    "NonceChain",
    "RangeProof",
    "Rewound",
    "assert_as_valid",
    "rewind",
    "sign",
    "sign_public_value",
    "verify",
]

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

# the ceiling `secp256k1_range_proveparams` reads the value and the
# min_value against, and it reads them against it twice: once to refuse
# a range whose proven maximum would wrap, and once to decide that the
# exponent is not worth keeping for a value this large
_INT64_MAX = 2**63 - 1

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
    `secp256k1_borromean_verify_impl`, so a `BorromeanSig` inside a proof is
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

    A function of the header alone, because `sign` needs these octets
    before it has a signature to put after them:
    `secp256k1_rangeproof_sign_impl` writes the header first and then
    hashes it, into the nonce chain's seed and into the message the
    rings are signed over.
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


def _hashed_prefix(
    commitment: Point, gen: Point, exp: int, mantissa: int, min_value: int | None
) -> bytes:
    """Return the octets a proof's message and its nonce chain open with.

    `secp256k1_rangeproof_sign_impl` writes the value commitment, the
    generator and the header into the `sha256_m` the rings are signed
    over, and hands the same three to `secp256k1_rangeproof_genrand`,
    which seeds its chain with the caller's nonce and then with them.
    One function because `sign`, `RangeProof.nonce_chain`, `_ring_message`
    and `rewind` each need exactly these octets, and a proof and the
    chain behind it are bound to the same three.

    `extra_commit` is not among them. `secp256k1_rangeproof_genrand`
    takes no such argument, so what a caller binds into the proof
    reaches the message the rings are signed over and leaves the chain
    where it was.
    """
    return (
        _bytes_from_point(commitment, _RANGEPROOF_TAG)
        + _bytes_from_point(gen, _RANGEPROOF_TAG)
        + _header_octets(exp, mantissa, min_value)
    )


class _ProveParams(NamedTuple):
    """What `secp256k1_range_proveparams` answers for a set of arguments.

    `exp`, `mantissa` and `min_value` are the header the proof carries,
    and none of the three need be what the caller asked for: the
    exponent is lowered until the range fits a uint64, the mantissa is
    raised to the precision asked for, and `min_value` is rewritten to
    whatever the rescaled value leaves under it.

    `v` is the value the mantissa's digits count, `scale` the `10**exp`
    each of them weighs, `rsizes` how many keys each ring holds and
    `sign_key_idx` the digit each ring proves.
    """

    v: int
    rsizes: tuple[int, ...]
    sign_key_idx: tuple[int, ...]
    min_value: int
    mantissa: int
    scale: int
    exp: int


def _prove_params(value: int, min_value: int, exp: int, min_bits: int) -> _ProveParams:
    """Return the header and the ring structure zkp writes for those arguments.

    `secp256k1_range_proveparams`. What the caller asks for is a
    request: an exponent buys range at the cost of precision, so it is
    lowered wherever the range it asks for would not fit a uint64, and
    `min_bits` buys precision inside whatever range is left, so it is
    lowered to what the `min_value` already claims. The two limits meet
    at the exponent, which is why one function answers all of it --
    reading either from the arguments alone would be reading a request
    rather than what the proof states.

    A `min_value` at the ceiling of the field is where no range can be
    coded at all, and the exponent is held at -1 there: what comes back
    is the proof of an exact value, which is `sign_public_value`'s.

    The refusal below has two arms and they are not symmetric: a
    nonzero floor under a value past `2**63-1`, or a nonzero value over
    a floor at or past it. So a value exactly at that ceiling is proven
    where one a step above it is not, and zkp signs the same octets for
    it. What both arms guard is zkp's own comment: either end of the
    range that large leaves the other none, and the maximum the header
    states would overflow the uint64 a verifier reads it as.
    """
    if min_value == _UINT64_MAX:
        exp = -1
    if exp < 0:
        # the exact value, whose one ring holds the single key the
        # commitment itself gives. zkp writes a zero exponent into its
        # own out-parameter here and the header carries none, `rsizes[0]`
        # being 1; -1 is what a `RangeProof` states for that header
        return _ProveParams(0, (1,), (0,), value, 0, 1, -1)

    if (min_value and value > _INT64_MAX) or (value and min_value >= _INT64_MAX):
        err_msg = f"rangeproof range {min_value}..{value} does not fit 2**64"
        raise BTClibValueError(err_msg)

    # precision above what the floor leaves is precision about octets
    # the header already states
    max_bits = 64 - min_value.bit_length() if min_value else 64
    min_bits = min(min_bits, max_bits)
    # ten is not a power of two, so dividing by ten and writing the
    # result in base two times ten widens the range the digits reach,
    # past the 0..2**64 a verifier requires. Rather than work out how
    # much of the exponent survives that, zkp drops it outright for a
    # value in the top half of the field or a precision within a few
    # bits of the whole of it
    if min_bits > 61 or value > _INT64_MAX:
        exp = 0

    v = value - min_value
    # the range the mantissa will have to cover, carried through the
    # same divisions as the value: it is what says how many of the
    # exponent's steps there is room for, and the loop ends at the
    # first one there is not
    v2 = _UINT64_MAX >> (64 - min_bits) if min_bits else 0
    reached = 0
    while reached < exp and v2 <= _UINT64_MAX // 10:
        v //= 10
        v2 *= 10
        reached += 1
    exp = reached

    scale = 10**exp
    # the divisions above are what the floor absorbs: whatever the
    # rescaled value no longer reaches is stated in the clear
    min_value = value - v * scale
    mantissa = max(v.bit_length() or 1, min_bits)
    rsizes = _rsizes(mantissa)
    sign_key_idx = tuple((v >> 2 * i) & 3 for i in range(len(rsizes)))
    return _ProveParams(v, rsizes, sign_key_idx, min_value, mantissa, scale, exp)


def _pub_expand(
    ring_commitments: Sequence[Point],
    gen: Point,
    exp: int,
    rsizes: Sequence[int],
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
    base = secp256k1.negate(mult(10 ** max(exp, 0), gen, secp256k1))
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


def _message_room(rsizes: Sequence[int]) -> int:
    """Return how many octets of message those rings carry.

    `secp256k1_rangeproof_sign_impl`'s own bound. A message rides in
    the draws, one scalar per key at the stride
    `secp256k1_rangeproof_genrand` indexes them by, and the last ring
    is where the value encoding sits and where a rewind recovers the
    blinding factor -- so what is left is every ring before it, and a
    proof of one ring carries no message at all.
    """
    return _RING_STRIDE * secp256k1.n_size * (len(rsizes) - 1)


def _prep(rsizes: Sequence[int], v: int, sign_key_idx: int, message: bytes) -> bytes:
    """Return the octets `secp256k1_rangeproof_sign_impl` folds into the draws.

    zkp's `prep`: the message at the head of the buffer, and the value
    encoding at one key of the last ring, which is written whether
    there is a message or not -- an octet of 128, seven of zero, and
    the value the mantissa carries big-endian three times, at the eight
    octets a `min_value` field occupies and for the same reason, both
    being a uint64. That is what makes the value readable from the
    proof by whoever holds the nonce, which is
    `secp256k1_rangeproof_rewind_inner`.

    A last ring of one key has no such position, and the public-value
    proof is the one shaped that way -- it states its value in the
    clear anyway. Anywhere else the key is the ring's last, or the one
    before it where the value's own digit is that one, since the draw
    at the digit's key is spent as a nonce rather than written into
    the proof.

    The two never share a key: `_message_room` ends where the last ring
    begins, so the value encoding is written over no message octet.
    """
    room = _message_room(rsizes)
    if len(message) > room:
        err_msg = f"rangeproof message is longer than the {room} octets its rings hold"
        raise BTClibValueError(err_msg)
    prep = bytearray(_RING_STRIDE * secp256k1.n_size * len(rsizes))
    prep[: len(message)] = message
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
        self, commitment: Point, gen: Point, *, check_validity: bool = True
    ) -> tuple[PubkeyRing, ...]:
        """Return the rings of keys this proof's signature is over.

        `secp256k1_rangeproof_verify_impl` up to the point where it hands
        those rings to `secp256k1_borromean_verify_impl`: every ring
        commitment the proof states, resolved against the residuosity
        convention the module docstring gives; the one it does not state,
        recovered from `commitment`; and `_pub_expand` over all of them.
        Nothing here reads `e0` or an `s`, so a proof whose signature is
        wrong answers the same rings as one whose signature is right.

        `gen` is the generator that commitment was made under, and both
        the `min_value` offset below and `_pub_expand`'s own weights are
        multiples of it.

        `commitment` is the Pedersen commitment the proof was written
        against, `ecc.pedersen.commit`'s own point rather than octets --
        the ones `secp256k1_pedersen_commitment_serialize` hands back
        carry the residuosity bit too, `secp256k1_pedersen_commitment_save`
        writing it at `9 ^ is_square(y)` where
        `secp256k1_rangeproof_serialize_point` writes `1 ^ is_square(y)`.

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
            _point_from_x(x, sign)
            for x, sign in zip(self.ring_commitments, self.signs, strict=True)
        ]
        # zkp's own order: the offset and the stated commitments are
        # accumulated, the sum negated, and the commitment added to it
        acc = mult(self.min_value, gen, secp256k1) if self.min_value else INF
        for point in stated:
            acc = secp256k1.add_aff_var(acc, point)
        last = secp256k1.add_aff_var(commitment, secp256k1.negate(acc))
        if last == INF:
            err_msg = "rangeproof last ring commitment is the point at infinity"
            raise BTClibValueError(err_msg)

        return _pub_expand([*stated, last], gen, self.exp, self.rsizes)

    def nonce_chain(
        self,
        commitment: Point,
        value: int,
        nonce: Octets,
        gen: Point,
        message: Octets = b"",
        *,
        check_validity: bool = True,
    ) -> NonceChain:
        """Return the scalars this proof's nonce derives.

        `secp256k1_rangeproof_genrand`, seeded as
        `secp256k1_rangeproof_sign_impl` seeds it: the caller's nonce,
        then the value commitment and the generator at
        `_RANGEPROOF_TAG`, then the header octets this proof's own
        exponent, mantissa and `min_value` write. So whoever holds the
        nonce answers every ring commitment the proof states -- each is
        its ring's blinding factor times G plus that ring's own digit
        times the generator -- and every `s` the signature left as the
        chain drew it.

        `commitment` is the Pedersen commitment the proof was written
        against, `pubk_rings`'s argument of that name, `gen` the
        generator it was made under, and `value` what it commits to.
        The value is read for more than the digits: wherever the last
        ring holds more than one key, one of them carries the value
        inside its own draw, so the chain is not a function of the
        header alone. A value this proof has no digit for is refused,
        `sign_key_idx`'s own refusal.

        A commitment at infinity is refused too, where `pubk_rings`
        answers rings for one: the seed carries the octets
        `secp256k1_rangeproof_serialize_point` writes, and infinity
        has no x to write. The `require_on_curve` above lets it through,
        `(x, 0)` being how this library spells infinity in affine
        coordinates.

        `message` is what `sign` embedded, and it belongs here because
        the draws carry it: one scalar per key of every ring before the
        last. `_message_room` bounds it.
        """
        if check_validity:
            self.assert_valid()
        secp256k1.require_on_curve(commitment)
        sign_key_idx = self.sign_key_idx(value)
        seed = bytes_from_octets(nonce, _NONCE_SIZE) + _hashed_prefix(
            commitment, gen, self.exp, self.mantissa, self.min_value
        )

        v = self._mantissa_value(value)
        prep = _prep(self.rsizes, v, sign_key_idx[-1], bytes_from_octets(message))
        return _genrand(seed, self.rsizes, prep)

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


def _challenge(m: bytes, r: bytes, i: int, j: int) -> int:
    """Return the scalar `secp256k1_borromean_sign` hashes at that position.

    `secp256k1_borromean_hash` over the ring's running point and the
    message, read as a scalar the way `secp256k1_scalar_set_b32` reads
    one: a digest at or past n raises the overflow flag and zkp
    abandons the proof, where `ecc.borromean` reduces it and carries
    on. Reducing here would write a proof
    `secp256k1_borromean_verify_impl` refuses.
    """
    e = int_from_bits(_hash(m, r, i, j, sha256), secp256k1.nlen)
    if not 0 < e < secp256k1.n:
        raise BTClibRuntimeError("rangeproof challenge is not a scalar")
    return e


def _borromean_sign(
    m: bytes,
    pubk_rings: Sequence[PubkeyRing],
    ks: Sequence[int],
    secs: Sequence[int],
    sign_key_idx: Sequence[int],
    draws: Sequence[Sequence[int]],
) -> BorromeanSig:
    """Close every ring over that message, as `secp256k1_borromean_sign` does.

    `ecc.borromean.sign_` is the same walk, differing where a
    rangeproof cannot follow it. It draws every forged `s` from
    `secrets`, where here they are `draws` -- what
    `secp256k1_rangeproof_genrand` derived from the caller's nonce, so
    that a proof is a function of its arguments and a recipient holding
    the nonce reads the value back out. And it carries the real
    signer's `s` as `k + e*q` against a ring walked at `-e`, where zkp
    walks at `+e` and answers `k - e*sec`: `ecc.borromean`'s module
    docstring has what one calling `P` where the other calls `-P`
    costs. `_challenge` is a third such difference.

    `ks[i]` is the nonce ring `i` is closed with, `secs[i]` the scalar
    its commitment is written under, and `sign_key_idx[i]` the position
    of the key those two open. The point at every other position is
    forged from the draw already at it, which is why `draws` is the
    signature this returns but for one scalar per ring.
    """
    s = [list(ring) for ring in draws]
    e0_preimage = b""
    for i, (ring, k, j_star) in enumerate(
        zip(pubk_rings, ks, sign_key_idx, strict=True)
    ):
        r = bytes_from_point(mult(k, secp256k1.G, secp256k1), secp256k1)
        for j in range(j_star + 1, len(ring)):
            t = double_mult_var(
                _challenge(m, r, i, j), ring[j], s[i][j], secp256k1.G, secp256k1
            )
            r = bytes_from_point(t, secp256k1)
        e0_preimage += r
    # the message closes the preimage the ring points opened, which is
    # `ecc.borromean.sign_`'s order too
    e0 = sha256(e0_preimage + m).digest()

    for i, (ring, k, j_star) in enumerate(
        zip(pubk_rings, ks, sign_key_idx, strict=True)
    ):
        e = _challenge(m, e0, i, 0)
        for j in range(j_star):
            t = double_mult_var(e, ring[j], s[i][j], secp256k1.G, secp256k1)
            e = _challenge(m, bytes_from_point(t, secp256k1), i, j + 1)
        s[i][j_star] = (k - e * secs[i]) % secp256k1.n
        if s[i][j_star] == 0:
            # a zero s is the one `BorromeanSig` holds and zkp does not
            # write: `secp256k1_borromean_sign` returns zero on it, and
            # `secp256k1_borromean_verify_impl` refuses one it is handed
            raise BTClibRuntimeError("rangeproof signature value is zero")
    return BorromeanSig(e0, s)


def sign(
    blind: Integer,
    value: int,
    nonce: Octets,
    gen: Point,
    *,
    min_value: int = 0,
    exp: int = 0,
    min_bits: int = 0,
    message: Octets = b"",
    extra_commit: Octets = b"",
) -> RangeProof:
    """Return the proof that a blinded value lies in a stated range.

    `secp256k1_rangeproof_sign_impl`. The commitment the proof is
    written against is `ecc.pedersen.commit` over `blind` and `value`,
    the same point `secp256k1_pedersen_commit` answers, and the range
    the header states is `_prove_params`' rather than the caller's:
    `min_value`, `exp` and `min_bits` are what is asked for, and the
    proof carries what the format has room for.

    `value` and `min_value` are what a uint64 holds and `min_value` no
    more than `value`, `nonce` the 32 octets `rangeproof_genrand` seeds
    its chain with, `exp` in -1..18 and `min_bits` in 0..64 -- the
    bounds `secp256k1_rangeproof_sign_impl` reads before it asks for a
    header.

    `blind` is a scalar, read through `curves.scalar_from_prv_key`,
    which refuses at or past n as zkp does and refuses zero where zkp
    signs one: a zero blinding factor leaves the last ring's own
    commitment blinded by the chain's factor alone, and zkp turns that
    down only where the sum vanishes, which is the single-ring proof.

    Deterministic in every one of them, a rangeproof drawing nothing,
    so what comes back over the arguments both accept is the octets
    `zkp.rangeproof.sign` answers for those same arguments.

    `message` is embedded for `rewind` to read back out: it rides at the
    head of the buffer `_prep` builds, one scalar per key of every ring
    before the last. `_message_room` is what bounds it, and the octets
    are otherwise those of a proof carrying none.

    `extra_commit` is octets of the caller's own -- the output a
    commitment belongs to, say -- bound into the proof rather than
    carried by it, and a verifier is handed them again or the proof
    does not hold for it. It closes the message the rings are signed
    over and nothing else: `secp256k1_rangeproof_sign_impl` writes it
    into `sha256_m` after the ring commitments and immediately before
    finalizing, where `secp256k1_rangeproof_genrand` takes no such
    argument, so the draws are the same and what a rewind reads back
    out is unchanged.

    `gen` is the generator the commitment this proof is written against
    is made under, which `secp256k1_rangeproof.h` documents on each of
    its calls as the "additional generator 'h'". It reaches the
    commitment, the octets `_hashed_prefix` writes and the weight each
    ring's keys step down by, so a proof is bound to it: `verify` and
    `rewind` are handed it again or the proof does not hold.
    """
    blind_int = scalar_from_prv_key(blind, secp256k1)
    if not 0 <= value <= _UINT64_MAX:
        raise BTClibValueError(f"rangeproof value not in 0..2**64-1: {value}")
    if not 0 <= min_value <= value:
        err_msg = f"rangeproof min value not in 0..{value}: {min_value}"
        raise BTClibValueError(err_msg)
    if not -1 <= exp <= _MAX_EXP:
        raise BTClibValueError(f"rangeproof exponent not in -1..18: {exp}")
    if not 0 <= min_bits <= _MAX_MANTISSA:
        raise BTClibValueError(f"rangeproof min bits not in 0..64: {min_bits}")
    nonce_bytes = bytes_from_octets(nonce, _NONCE_SIZE)
    message_bytes = bytes_from_octets(message)
    extra_commit_bytes = bytes_from_octets(extra_commit)

    params = _prove_params(value, min_value, exp, min_bits)
    # zkp's `min_value ? 32 : 0`, over the rewritten floor: a range
    # starting at zero carries no field
    prefix = _hashed_prefix(
        commit(blind_int, value, gen),
        gen,
        params.exp,
        params.mantissa,
        params.min_value or None,
    )

    chain = _genrand(
        nonce_bytes + prefix,
        params.rsizes,
        _prep(params.rsizes, params.v, params.sign_key_idx[-1], message_bytes),
    )
    # the draw at the true digit is spent as that ring's nonce, so it is
    # the one `s` per ring the signature overwrites rather than states
    ks = [ring[j] for ring, j in zip(chain.draws, params.sign_key_idx, strict=True)]
    secs = list(chain.blinding_factors)
    # the chain answers the last ring's factor as minus the sum of the
    # others, so adding the caller's own leaves the whole set summing to
    # it -- which is what lets a verifier recover the ring commitment
    # the proof does not state
    secs[-1] = (secs[-1] + blind_int) % secp256k1.n
    if secs[-1] == 0:
        raise BTClibRuntimeError("rangeproof last ring blinding factor is zero")

    heads = []
    for i, (sec, j) in enumerate(zip(secs, params.sign_key_idx, strict=True)):
        # `secp256k1_pedersen_ecmult`: the ring's own blinding factor,
        # and the digit it proves at the weight of its place
        head = secp256k1.add_aff_var(
            mult(sec, secp256k1.G, secp256k1),
            mult(j * params.scale << 2 * i, gen, secp256k1),
        )
        if head == INF:
            err_msg = "rangeproof ring commitment is the point at infinity"
            raise BTClibRuntimeError(err_msg)
        heads.append(head)

    # every ring commitment but the last, which the verifier recovers
    stated = [_bytes_from_point(head, _RANGEPROOF_TAG) for head in heads[:-1]]
    m = sha256(prefix + b"".join(stated) + extra_commit_bytes).digest()
    sig = _borromean_sign(
        m,
        _pub_expand(heads, gen, params.exp, params.rsizes),
        ks,
        secs,
        params.sign_key_idx,
        chain.draws,
    )
    return RangeProof(
        params.exp,
        params.mantissa,
        params.min_value or None,
        [bool(octets[0]) for octets in stated],
        [int.from_bytes(octets[1:], "big") for octets in stated],
        sig,
    )


def sign_public_value(
    blind: Integer, value: int, nonce: Octets, gen: Point
) -> RangeProof:
    """Return the proof that states its value in the clear.

    `sign` at an `exp` of -1, which `secp256k1_range_proveparams`
    answers with one ring holding the single key the commitment itself
    gives. So this proof asserts no range: it says what the commitment
    commits to, and that whoever wrote it knows the blinding factor.
    The mantissa, the digit decomposition, `rangeproof_pub_expand` and
    the sign bits are all absent from it, a proof carrying one ring
    commitment per ring but the last and this one having a single ring.

    A value of zero writes the flags octet and nothing after it; any
    other writes `min_value` in the eight octets behind bit 5, the
    value being its own floor here.

    A spelling of its own because `min_value`, `exp` and `min_bits`
    name nothing this proof has: its header is fixed.
    """
    return sign(blind, value, nonce, gen, exp=-1)


def _borromean_verify(
    m: bytes, pubk_rings: Sequence[PubkeyRing], sig: BorromeanSig
) -> tuple[tuple[int, ...], ...]:
    """Walk every ring back to `e0`, answering the challenge at each key.

    `secp256k1_borromean_verify_impl`, and what comes back is its
    `evalues` -- the challenges it saves only where a caller asked to
    rewind. `ecc.borromean.assert_as_valid` is the same walk answering
    a bool over rings a caller supplies, and differs where a rangeproof
    cannot follow it: it hashes those rings into a message of its own,
    it walks at `-e` where zkp walks at `+e`, and it reduces a
    challenge zkp refuses. `_borromean_sign` states the second of those
    from the signing side and `_challenge` the third.

    Two refusals of zkp's own, checked before the walk goes on from a
    key. An `s` of zero, which `BorromeanSig.assert_valid` reads
    against 0..n-1 and so accepts, and which
    `secp256k1_borromean_sign` answers zero rather than write. And a
    ring key at infinity, which is no public key: the walk point
    `e*Q + s*G` is `s*G` for one, a point the prover chooses, so
    nothing later in the walk turns it down.
    """
    challenges: list[tuple[int, ...]] = []
    e0_preimage = b""
    for i, ring in enumerate(pubk_rings):
        e = _challenge(m, sig.e0, i, 0)
        ring_challenges: list[int] = []
        for j, Q in enumerate(ring):
            s = sig.s[i][j]
            if s == 0:
                raise BTClibRuntimeError("rangeproof signature value is zero")
            if Q == INF:
                err_msg = "rangeproof ring key is the point at infinity"
                raise BTClibRuntimeError(err_msg)
            ring_challenges.append(e)
            # zkp turns down a walk point at infinity too, and here
            # `bytes_from_point` is what does: infinity has no octet
            # encoding, and the next challenge is over one
            t = double_mult_var(e, Q, s, secp256k1.G, secp256k1)
            r = bytes_from_point(t, secp256k1)
            if j != len(ring) - 1:
                e = _challenge(m, r, i, j + 1)
            else:
                e0_preimage += r
        challenges.append(tuple(ring_challenges))
    # the message closes the preimage the ring points opened, which is
    # `_borromean_sign`'s order too
    if sha256(e0_preimage + m).digest() != sig.e0:
        raise BTClibRuntimeError("rangeproof signature verification failed")
    return tuple(challenges)


def _ring_message(
    commitment: Point, proof: RangeProof, gen: Point, extra_commit: bytes
) -> bytes:
    """Return the message this proof's rings are signed over.

    `secp256k1_rangeproof_verify_impl` closes the same `sha256_m`
    `sign` opens: `_hashed_prefix`, then the sign bit and the x of
    every ring commitment the proof states, then `extra_commit`. Those
    first are the octets already on the wire, which is why they are
    written out here rather than resolved to points and handed back to
    `_bytes_from_point`.
    """
    stated = b"".join(
        bytes([sign_bit]) + x.to_bytes(secp256k1.p_size, "big")
        for x, sign_bit in zip(proof.ring_commitments, proof.signs, strict=True)
    )
    prefix = _hashed_prefix(commitment, gen, proof.exp, proof.mantissa, proof.min_value)
    return sha256(prefix + stated + extra_commit).digest()


def _verify_rings(
    commitment: Point, proof: RangeProof, gen: Point, extra_commit: bytes
) -> tuple[tuple[int, ...], ...]:
    """Return the challenge behind every key of a proof that holds.

    `secp256k1_rangeproof_verify_impl`, assembled from what this module
    already has: `RangeProof.pubk_rings` rebuilds the rings that
    function hands to `secp256k1_borromean_verify_impl`,
    `_ring_message` the message they are signed over, and
    `_borromean_verify` walks them.

    The challenges come back rather than a bool because
    `secp256k1_rangeproof_rewind_inner` consumes them and is called
    from inside `verify_impl` itself: a rewind is verification that
    kept them, so `rewind` calls this and `assert_as_valid` drops what
    it answers.
    """
    return _borromean_verify(
        _ring_message(commitment, proof, gen, extra_commit),
        proof.pubk_rings(commitment, gen),
        proof.sig,
    )


def _proof_from(proof: RangeProof | Octets) -> RangeProof:
    """Return the proof, parsing octets as `RangeProof.parse` reads them."""
    return proof if isinstance(proof, RangeProof) else RangeProof.parse(proof)


def assert_as_valid(
    commitment: Point,
    proof: RangeProof | Octets,
    gen: Point,
    *,
    extra_commit: Octets = b"",
) -> None:
    """Refuse a proof that does not hold for that commitment.

    `commitment` is the Pedersen commitment the proof was written
    against and `gen` the generator it was made under, both
    `RangeProof.pubk_rings`'s arguments of those names: a proof written
    under one generator does not hold under another, the whole
    structure hanging from it. The range
    proven is the proof's own `min_value` and `max_value`, which the
    header states and a parse reads; what this adds is that the header
    is that commitment's, the last ring commitment being recovered from
    it and the whole signature walked against the rings that follow. So
    a commitment a proof holds for opens at some value in
    `min_value..max_value`.

    `zkp.rangeproof.verify` answers that range instead of a verdict,
    having only the octets to answer from. `verify` here is the boolean
    answer, as `ecc.borromean.verify` is to `ecc.borromean.assert_as_valid`.

    `extra_commit` is what the proof was written under, and a proof
    holds for the octets `sign` was given and for no others: they
    close the message the rings are signed over, so any other value
    walks the rings to some `e0` the signature does not state.
    Keyword-only, as the sign-to-contract `commit` of `ecc.dsa` and
    `ecc.ssa` is on the same pair of calls.
    """
    _ = _verify_rings(
        commitment, _proof_from(proof), gen, bytes_from_octets(extra_commit)
    )


def verify(
    commitment: Point,
    proof: RangeProof | Octets,
    gen: Point,
    *,
    extra_commit: Octets = b"",
) -> bool:
    """Return whether the proof holds for that commitment.

    `assert_as_valid`'s docstring has what `extra_commit` is, and a
    proof holds for the octets `sign` was given and for no others.
    """
    # ValueError and BTClibRuntimeError, as `ecc.borromean.verify` catches
    # them and for the reasons `ecc.dsa.verify_` states
    try:
        assert_as_valid(commitment, proof, gen, extra_commit=extra_commit)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def _recover_x(k: int, e: int, s: int) -> int:
    """Return the scalar a real signature was written under.

    `secp256k1_rangeproof_recover_x`. `_borromean_sign` answers `k - e*x`
    at the one key of a ring the prover opens, so `(k - s) / e` is that
    `x` wherever the `k` behind it is in hand -- which is what holding
    the nonce buys, the chain drawing it. `e` is a challenge and
    `_challenge` refuses zero, so the inverse exists.
    """
    return (k - s) * pow(e, -1, secp256k1.n) % secp256k1.n


def _recover_k(x: int, e: int, s: int) -> int:
    """Return the nonce a real signature was closed with.

    `secp256k1_rangeproof_recover_k`, the same equation read the other
    way: `s + x*e`. A rewind takes this rather than `_recover_x` at
    every ring but the last, where what it wants is the nonce itself --
    the message is xored into it, and no inversion is needed to get it
    back.
    """
    return (s + x * e) % secp256k1.n


def _ch32xor(a: int, b: int) -> bytes:
    """Return the xor of two scalars, one scalar width wide.

    `secp256k1_rangeproof_ch32xor`, which is how a message and the
    value encoding both enter and leave the draws.
    """
    size = secp256k1.n_size
    return bytes(
        x ^ y
        for x, y in zip(a.to_bytes(size, "big"), b.to_bytes(size, "big"), strict=True)
    )


def _value_encoding(
    rsizes: Sequence[int], written: Sequence[int], drawn: Sequence[int]
) -> tuple[int, int] | None:
    """Return where the last ring carries the value, and the value.

    `secp256k1_rangeproof_rewind_inner`'s own search, and it looks at
    two keys because `_prep` writes at one of two: the ring's last, or
    the one before it where the value's own digit is that one. A key
    whose xor opens with bit 7 set and repeats the same eight octets
    three times is taken as the encoding, and the value is the last of
    the three. Where neither key matches this answers None, and `rewind`
    is what turns that into a refusal.
    """
    for j in range(2):
        position = rsizes[-1] - 1 - j
        tmp = _ch32xor(written[position], drawn[position])
        if tmp[0] & 128 and tmp[8:16] == tmp[16:24] == tmp[24:32]:
            return position, int.from_bytes(tmp[24:32], "big")
    return None


class Rewound(NamedTuple):
    """What whoever holds a proof's nonce reads back out of it.

    `blind` is the blinding factor the commitment was written under and
    `value` what it commits to, so the two open the commitment.
    `message` is what the draws carry: what `sign` embedded, followed by
    the zeros `_prep` left after it. Nothing in a proof states how long
    a message was, so the padding is the caller's to know the length of
    or to strip.
    """

    blind: int
    value: int
    message: bytes


def rewind(
    commitment: Point,
    proof: RangeProof | Octets,
    nonce: Octets,
    gen: Point,
    *,
    extra_commit: Octets = b"",
) -> Rewound:
    """Return what the author of that proof put in it for its recipient.

    `secp256k1_rangeproof_rewind_inner`, which
    `secp256k1_rangeproof_verify_impl` calls from inside itself: the
    proof is verified first, by `_verify_rings`, and the per-key
    challenges that walk answers are half of what this needs. The other
    half is the chain re-derived from `nonce` over a `prep` of zeros,
    which answers the draws themselves -- the proof's own `s` at a
    forged key is one of those draws with a message octet or the value
    encoding xored into it, and at the one key a ring opens it is the
    nonce that key was closed with.

    A single ring of a single key is the public-value proof, and only
    the blinding factor is recoverable from it: the value is the
    header's `min_value`, stated in the clear, and there is no second
    key to carry a message.

    Everywhere else `_value_encoding` reads the value out of the last
    ring, and two refusals follow it. The position it was found at and
    the last ring's own digit have to differ -- `_prep` writes the
    encoding at whichever of the two keys the digit does not take, so a
    proof stating a value that lands on it states a value it was not
    written for. And a digit above the last ring's own size names no
    key of it, which is where an odd mantissa leaves a ring of two.

    The blinding factor is then `_recover_x` at the last ring's digit,
    less the chain's own factor for that ring: what the ring was signed
    under is the sum of the two, which is what lets a verifier recover
    the ring commitment the proof leaves out.

    The message is every remaining key of every ring, the two the last
    ring spends excepted: the nonce at the key a ring opens, recovered
    by `_recover_k`, and the stated `s` everywhere else, each xored
    against the draw behind it. `Rewound.message` has what that buffer
    holds past the message itself.

    Refused where the value and the blinding factor recovered do not
    open `commitment`, which is what says the nonce was the proof's
    own: `secp256k1_rangeproof_verify_impl` rebuilds the commitment
    from them and compares.

    `gen` is `assert_as_valid`'s argument of that name, and it is what
    the recovered value and blinding factor are put back against in
    the refusal above.

    `extra_commit` is `assert_as_valid`'s argument of that name, and
    it is spent on the verification this opens with: the chain
    re-derived below is seeded by `_hashed_prefix`, which carries none
    of it.
    """
    proof = _proof_from(proof)
    ev = _verify_rings(commitment, proof, gen, bytes_from_octets(extra_commit))
    rsizes = proof.rsizes
    seed = bytes_from_octets(nonce, _NONCE_SIZE) + _hashed_prefix(
        commitment, gen, proof.exp, proof.mantissa, proof.min_value
    )
    # the zeroed `prep` `rewind_inner` calls the chain with: what comes
    # back is then the draws themselves, no message and no value
    # encoding folded into any of them
    chain = _genrand(seed, rsizes, bytes(_RING_STRIDE * secp256k1.n_size * len(rsizes)))
    s = proof.sig.s

    last = len(rsizes) - 1
    if rsizes == (1,):
        blind = _recover_x(chain.draws[0][0], ev[0][0], s[0][0])
        value, message = proof.min_value or 0, b""
    else:
        found = _value_encoding(rsizes, s[last], chain.draws[last])
        if found is None:
            raise BTClibRuntimeError("rangeproof rewind reads no value encoding")
        skip1, v = found
        skip2 = (v >> 2 * last) & 3
        if skip1 == skip2:
            raise BTClibRuntimeError("rangeproof rewind reads the value at the digit")
        if skip2 >= rsizes[last]:
            raise BTClibRuntimeError(
                "rangeproof rewind reads a digit the last ring has no key for"
            )
        value = v * 10**proof.exp + (proof.min_value or 0)
        blind = (
            _recover_x(chain.draws[last][skip2], ev[last][skip2], s[last][skip2])
            - chain.blinding_factors[last]
        ) % secp256k1.n
        message = b"".join(
            _ch32xor(
                _recover_k(chain.blinding_factors[i], ev[i][j], s[i][j])
                if (v >> 2 * i) & 3 == j
                else s[i][j],
                chain.draws[i][j],
            )
            for i, size in enumerate(rsizes)
            for j in range(size)
            if i != last or j not in (skip1, skip2)
        )

    if double_mult_var(value, gen, blind, secp256k1.G, secp256k1) != commitment:
        raise BTClibRuntimeError("rangeproof rewind does not open the commitment")
    return Rewound(blind, value, message)
