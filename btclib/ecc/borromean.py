# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Borromean ring signature functions.

References:
    - https://github.com/ElementsProject/borromean-signatures-writeup
    - https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

Both are also cited inside `sign`, which is not where a reader looks
first; they are here because the module is what one arrives at.

`_hash`'s challenge preimage matches secp256k1-zkp's `rangeproof`
module -- `secp256k1_borromean_hash`,
`src/modules/rangeproof/borromean_impl.h` -- which is the only other
implementation of this construction anything reads, Elements and
Confidential Transactions among its callers: `e || m || ring || pos`,
the point or `e0` bytes first, then the message hash, then the ring
index and the position each as 4 bytes big-endian. It did not always:
issue #1070 found the message and the point swapped, and every
signature this module produced before that fix does not verify after
it and never will -- there is no version byte in the wire format to
switch on, `sign` and `assert_as_valid` compute this hash the same way
every time, and RELEASE_NOTES.md's breaking-changes list has the
"before" and "after" this cost.

`_get_msg_format` was checked against zkp too, in the same issue, and
has nothing to align with: zkp's rangeproof never hashes a caller's
message together with caller-supplied pubkey rings the way this
function does, because it reconstructs its rings from a value
commitment and hashes that commitment, the generator point and the
proof's own header bytes instead. There is no zkp construction here to
diverge from or to match, so this one is untouched.

`BorromeanSig.serialize` follows zkp's `rangeproof` module's own
layout for this signature: `e0` followed by every `s`, `ec.n_size`
bytes each, ring-major, no other framing -- generalizing zkp's
hardcoded 32 to `ec.n_size` (issue 183) rather than contradicting it,
the two agreeing wherever `ec` is secp256k1, zkp's only curve.
`BorromeanSig.parse` reads that layout back at secp256k1 and sha256
always, as `ssa.Sig.parse` reads BIP340's one curve: the serialization
does not name either, so a `BorromeanSig` on another curve or hash
function is built directly rather than parsed. With the challenge hash
aligned too (issue #1070), the *primitive* now interoperates over
secp256k1 with sha256: a signature this module produces there verifies
under zkp's `secp256k1_borromean_verify`, and one zkp produces verifies
here. That is not the same as producing a
Confidential Transactions rangeproof: `rangeproof_impl.h` wraps this
signature in a digit decomposition, a value commitment and an
exponent/mantissa/min-value/sign-bits header this module has no
counterpart for, rebuilding its pubkey rings from that commitment
where this module takes them as an explicit argument. Issue #1072 is
that remaining distance, filed and decided wanted -- after
btclib-org/btclib-secp256k1#283 gives it something to check the
answer against.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256

from btclib.alias import BinaryData, HashF, Octets, Point
from btclib.curves import Curve, bytes_from_point, double_mult_var, mult, secp256k1
from btclib.curves.curve import _assert_valid_ec
from btclib.exceptions import BorromeanRingError, BTClibRuntimeError, BTClibValueError
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    int_from_bits,
    read_exactly,
)

__all__ = [
    "BorromeanSig",
    "PubkeyRing",
    "SValues",
    "assert_as_valid",
    "sign",
    "verify",
]

# the curve and the hash function are parameters, as they are in dsa, ssa
# and pedersen -- not module globals: selecting either through a global
# would mean rebinding an attribute of this module, which changes the
# algorithm for every other caller in the process
#
# ec has to be passed to mult and double_mult_var too, and that is easy to
# miss: both take the curve as their *last* argument and default it to
# secp256k1, so `mult(k)` and `double_mult_var(-e, Q, s, ec.G)` type check,
# read as if they honoured ec, and compute on secp256k1 -- every point
# then encoded against ec, so the first bytes_from_point rejects it and
# no curve but secp256k1 can sign at all (issue 183)


def _hash(m: bytes, R: bytes, i: int, j: int, hf: HashF) -> bytes:
    # R (the nonce point, or e0 closing the rings) before m: zkp's
    # secp256k1_borromean_hash writes e || m || ring || pos, and this
    # used to write m || R -- the two swapped, a byte-for-byte different
    # preimage over identical inputs (issue #1070). Aligning it is a
    # hard break with no migration: every signature this module ever
    # produced was made with the old order and stops verifying under
    # this one
    temp = b"".join(
        [R, m, i.to_bytes(4, "big", signed=False), j.to_bytes(4, "big", signed=False)]
    )
    hasher = hf()
    hasher.update(temp)
    return hasher.digest()


def _bytes_from_ring_point(Q: Point, ec: Curve, ring: int, position: int) -> bytes:
    # bytes_from_point's one remaining refusal on a point this module's
    # own arithmetic produced is the point at infinity: s*G - e*Q can
    # land there, and there is no octet encoding for it to hash. ring
    # and position are always in hand at every call site this wraps --
    # the nonce point of the real signer's own position, or the r a
    # forged or real (e, s) pair produces at any other -- the same as
    # every "implausible signature failure" guard beside them, so this
    # failure is named the same way rather than left a bare
    # BTClibValueError with neither
    try:
        return bytes_from_point(Q, ec)
    except BTClibValueError as exc:
        raise BorromeanRingError(str(exc), ring, position) from exc


PubkeyRing = Sequence[Point]


def _get_msg_format(
    msg: bytes, pubk_rings: Sequence[PubkeyRing], ec: Curve, hf: HashF
) -> bytes:
    # unlike _hash, nothing to align here: zkp never hashes a message
    # together with caller-supplied pubkey rings, so there is no zkp
    # preimage this one could diverge from (issue #1070)
    t = b"".join(
        b"".join(bytes_from_point(Q, ec) for Q in pubk_ring) for pubk_ring in pubk_rings
    )
    hasher = hf()
    hasher.update(msg + t)
    return hasher.digest()


SValues = Sequence[list[int]]


@dataclass(frozen=True, init=False)
class BorromeanSig:
    """A borromean ring signature: e0 and one s per ring member.

    `s` is one tuple of scalars per ring, in the ring's own order:
    `s[i][j]` is the value for `pubk_rings[i][j]` wherever this
    signature is later handed to `verify` or `assert_as_valid` along
    with the pubkey rings argument. `e0` is the hash that pins where
    every ring starts, an `hf` digest and not a curve value -- its
    width is `hf().digest_size`, not `ec.n_size`, so a BorromeanSig
    does not say by itself which hash function produced it, the same
    way it does not carry `hf` as a field: `sign`, `verify` and
    `assert_as_valid` all take `hf` as their own argument, as
    `ssa.sign`/`verify` take theirs.

    `serialize`/`parse` follow secp256k1-zkp's `rangeproof` module's own
    layout for this signature -- the module docstring has why that is
    not only a format but, since issue #1070, an interoperable one.
    """

    e0: bytes
    s: tuple[tuple[int, ...], ...]
    ec: Curve = secp256k1

    # written out rather than an InitVar[bool] field and a __post_init__:
    # see the comment on dsa.Sig.__init__
    def __init__(
        self,
        e0: bytes,
        s: SValues,
        ec: Curve = secp256k1,
        *,
        check_validity: bool = True,
    ) -> None:
        object.__setattr__(self, "e0", e0)
        object.__setattr__(self, "s", tuple(tuple(ring) for ring in s))
        object.__setattr__(self, "ec", ec)

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Refuse a bad curve, no rings, or a scalar s outside 0..n-1."""
        # the curve first, as in dsa.Sig.assert_valid and ssa.Sig.assert_valid
        # and for their reason: every s below is read against it
        _assert_valid_ec(self.ec)

        # a ring signature with no ring signs nothing: refusing it here
        # is what keeps BorromeanSig.parse's rsizes default -- (), kept
        # only so a wrong-typed data argument is still refused ahead of
        # it, as every other parse's own extra argument is -- from
        # quietly building an object that looks like a signature and is
        # not one, for a caller who simply left rsizes out
        if not self.s:
            raise BTClibValueError("no rings")

        for i, ring in enumerate(self.s):
            for j, value in enumerate(ring):
                if not 0 <= value < self.ec.n:
                    err_msg = "scalar s not in 0..n-1: "
                    err_msg += (
                        f"'{hex_string(value)}'" if value > 0xFFFFFFFF else f"{value}"
                    )
                    err_msg += f" (ring {i}, position {j})"
                    raise BTClibValueError(err_msg)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return e0 followed by every s, ec.n_size bytes each, ring-major.

        secp256k1-zkp's own layout for this signature: `e0`, then one
        `secp256k1_scalar_get_b32` per public key in ring order.
        `ec.n_size` generalizes zkp's hardcoded 32 (issue 183) rather
        than contradicting it -- the two agree wherever `ec` is
        secp256k1, zkp's only curve.
        """
        if check_validity:
            self.assert_valid()

        out = self.e0
        for ring in self.s:
            for value in ring:
                out += value.to_bytes(self.ec.n_size, byteorder="big", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[BorromeanSig],
        data: BinaryData,
        rsizes: Sequence[int] = (),
        *,
        check_validity: bool = True,
    ) -> BorromeanSig:
        """Build a BorromeanSig from e0 || s, secp256k1 and sha256 -- zkp's own.

        The serialization does not name its curve or its hash function,
        the same reason `ssa.Sig.parse` reads BIP340's alone: `e0` is a
        32-byte sha256 digest and each `s` is secp256k1's 32-byte
        scalar, which is what makes this the interoperable spelling. A
        BorromeanSig on another curve or another hash function is built
        directly, as `ssa.Sig.parse`'s docstring says for BIP340's one
        curve.

        `rsizes` is how many scalars each ring holds -- the ring sizes
        a verifier's own `pubk_rings` argument already carries -- because
        the wire format has no framing of its own to recover them from:
        zkp's `secp256k1_borromean_verify` takes `rsizes` as a
        caller-supplied argument for the same reason, rather than
        reading it out of the proof. It defaults to `()` only so a
        wrong-typed `data` is refused ahead of it, the same as every
        other `parse`'s own extra argument in
        `tests/serialization_boundary_test.py`'s table -- not because a
        signature with no rings is a value worth building: `assert_valid`
        refuses one, so a caller who leaves `rsizes` out and hands over
        real octets is refused too, either there or by the trailing
        bytes those octets still carry.
        """
        stream = bytesio_from_binarydata(data)
        e0 = read_exactly(stream, sha256().digest_size, "borromean e0")

        s = []
        for i, rsize in enumerate(rsizes):
            ring = []
            for j in range(rsize):
                what = f"borromean s (ring {i}, position {j})"
                chunk = read_exactly(stream, secp256k1.n_size, what)
                ring.append(int.from_bytes(chunk, byteorder="big", signed=False))
            s.append(ring)
        assert_no_trailing(data, stream, "borromean ring signature")

        return cls(e0, s, secp256k1, check_validity=check_validity)


def _initialize(
    msg: Octets, pubk_rings: Sequence[PubkeyRing], ec: Curve, hf: HashF
) -> tuple[bytes, bytes, SValues]:
    msg_ = bytes_from_octets(msg)
    m = _get_msg_format(msg_, pubk_rings, ec, hf)
    e = [[0] * len(pubk_ring) for pubk_ring in pubk_rings]
    return msg_, m, e


def sign(
    msg: Octets,
    ks: Sequence[int],
    sign_key_idx: Sequence[int],
    sign_keys: Sequence[int],
    pubk_rings: Sequence[PubkeyRing],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> BorromeanSig:
    """Sign msg with a borromean ring signature, one key per ring.

    https://github.com/ElementsProject/borromean-signatures-writeup
    https://github.com/Blockstream/borromean_paper/blob/master/borromean_draft_0.01_9ade1e49.pdf

    `ks` is one nonce per ring, `sign_key_idx` the position of the real
    key in each ring, `sign_keys` the real private key of each ring --
    `sign_keys[i]` signs at `pubk_rings[i][sign_key_idx[i]]` -- and
    `pubk_rings` the full public rings, real key included.

    A `BorromeanSig`, because that is what it is: the result verifies
    with `assert_as_valid`/`verify`, serializes with
    `BorromeanSig.serialize`, and handing back a bare `(bytes,
    SValues)` tuple would only make the caller build one to do either.
    """
    msg, m, e = _initialize(msg, pubk_rings, ec, hf)
    e0bytes = m
    # drawn uniformly in [0, ec.n), the same distribution the real
    # s-value has once step 2 reduces it: randbits(256) is uniform over
    # [0, 2**256), not over the scalars, and the two ranges diverge by
    # more than a 2**-127 fraction on a low-cardinality curve -- one
    # forged this way and the real one reduced would then disagree in
    # the same distinguishing way the unreduced real value used to
    s = [
        [secrets.randbelow(ec.n) for _ in range(len(pubk_ring))]
        for pubk_ring in pubk_rings
    ]

    # one entry per ring in each of the three, checked here rather than
    # left to the `strict=True` of the two loops below: a short ks would
    # truncate them silently and sign a subset of the rings -- a signature
    # over fewer rings than the caller asked for, which is the one thing a
    # ring signature must not do quietly. zip's own message is a
    # BTClibValueError's class with none of its content, naming "argument
    # 3" and no parameter of this function; strict=True stays, as the
    # assertion that this check and those loops cannot drift apart
    if not len(pubk_rings) == len(sign_key_idx) == len(ks):
        err_msg = f"{len(pubk_rings)} rings, {len(sign_key_idx)} signing indexes"
        err_msg += f" and {len(ks)} nonces"
        raise BTClibValueError(err_msg)

    # step 1
    for i, (pubk_ring, j_star, k) in enumerate(
        zip(pubk_rings, sign_key_idx, ks, strict=True)
    ):
        keys_size = len(pubk_ring)
        start_idx = (j_star + 1) % keys_size
        # the real signer's own position: r here is R_{j_star} = k*G
        r = _bytes_from_ring_point(mult(k, ec.G, ec), ec, i, j_star)
        if start_idx != 0:
            for j in range(start_idx, keys_size):
                e[i][j] = int_from_bits(_hash(m, r, i, j, hf), ec.nlen) % ec.n
                # e is already reduced mod n, so only zero can trip this,
                # and for secp256k1 with sha256 zero is a 2**-255
                # accident: exactly two of the 256-bit outputs (0 and n)
                # are 0 mod n. On a low-cardinality curve it is one message
                # in n -- one in eleven on ec13_11 -- which is the corner
                # case issue 183 asked for and what makes ec a parameter
                # worth having: tests/ecc/borromean_test.py reaches this
                # raise, and the three below it, on that curve
                if not 0 < e[i][j] < ec.n:
                    err_msg = "implausible signature failure"
                    raise BorromeanRingError(err_msg, i, j)
                t = double_mult_var(-e[i][j], pubk_ring[j], s[i][j], ec.G, ec)
                r = _bytes_from_ring_point(t, ec, i, j)
        e0bytes += r
    hasher = hf()
    hasher.update(e0bytes)
    e0 = hasher.digest()
    # step 2
    # strict=True: see step 1
    for i, (j_star, k) in enumerate(zip(sign_key_idx, ks, strict=True)):
        e[i][0] = int_from_bits(_hash(m, e0, i, 0, hf), ec.nlen) % ec.n
        # zero e again: the same accident documented above
        if not 0 < e[i][0] < ec.n:
            err_msg = "implausible signature failure"
            raise BorromeanRingError(err_msg, i, 0)
        for j in range(1, j_star + 1):
            s[i][j - 1] = secrets.randbelow(ec.n)
            t = double_mult_var(
                -e[i][j - 1], pubk_rings[i][j - 1], s[i][j - 1], ec.G, ec
            )
            r = _bytes_from_ring_point(t, ec, i, j - 1)
            e[i][j] = int_from_bits(_hash(m, r, i, j, hf), ec.nlen) % ec.n
            # zero e again, and the one guard of the four that stays
            # unreachable from a test: this e hashes an r built from
            # s[i][j-1], drawn from secrets two lines up, so a
            # low-cardinality curve makes it a one-in-n *accident* rather
            # than something a chosen message can arrange
            if not 0 < e[i][j] < ec.n:
                err_msg = "implausible signature failure"  # pragma: no cover
                raise BorromeanRingError(err_msg, i, j)  # pragma: no cover
        # reduced mod n, like every forged value above: unreduced, this
        # is about twice the bit length of the others -- k and
        # sign_keys[i] * e[i][j_star] are each near n, so their sum is
        # about 512 bits where a forged s stays at 256 -- and the real
        # signer's ring position is then the longest s in the ring, with
        # no computation needed to read it off a published signature.
        # Every consumer already reduces mod n (`mult`, `double_mult_var`),
        # so this changes no signature, only what it discloses.
        s[i][j_star] = (k + sign_keys[i] * e[i][j_star]) % ec.n
    return BorromeanSig(e0, s, ec)


def verify(
    msg: Octets,
    sig: BorromeanSig | Octets,
    pubk_rings: Sequence[PubkeyRing],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> bool:
    """Return whether sig is a valid borromean ring signature of msg.

    `sig` is a `BorromeanSig`, or its `serialize`d octets -- parsed with
    `BorromeanSig.parse`, secp256k1 and sha256 always, as `ssa.verify`
    parses a `Sig | Octets` over BIP340's one curve. A `BorromeanSig`
    argument keeps its own `ec`, which need not be the one this
    function defaults to; `assert_as_valid`'s docstring has what `ec`
    and `hf` are for either way.
    """
    # ValueError and BTClibRuntimeError, as `ecc.dsa.verify_` catches them
    # and for its reasons, which it states
    try:
        assert_as_valid(msg, sig, pubk_rings, ec, hf)
    except (ValueError, BTClibRuntimeError):
        return False

    return True


def assert_as_valid(
    msg: Octets,
    sig: BorromeanSig | Octets,
    pubk_rings: Sequence[PubkeyRing],
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> None:
    """Refuse an invalid borromean ring signature.

    The rings are walked forward from `sig.e0` and must close on the
    `e0` they started from; errors carry the reason and which ring and
    position it happened at (`BorromeanRingError`), `verify` being the
    boolean answer.

    `sig` as octets is parsed with `BorromeanSig.parse`, which reads
    secp256k1 and sha256 always -- `ec` and `hf` are then not what
    decides the curve or the hash, the same limit `ssa.verify` has for
    a `Sig | Octets` argument and for the same reason: the wire format
    does not name either. They still decide what a `BorromeanSig`
    argument is checked against if it says otherwise: `ec` only for its
    type (`sig.ec` is what is actually used, below), `hf` for real, to
    recompute the challenge of a signature `sign` made with another one.
    """
    # ahead of everything, and checked whatever sig turns out to be: a
    # BorromeanSig argument makes ec's own value the signature's below,
    # or the octets path hardcodes secp256k1 regardless of what was
    # passed, but a caller's wrong-typed ec is still this function's
    # own mistake to report either way -- tests/curve_parameter_test.py
    # drives every public function taking a Curve with one, and neither
    # path may make the parameter stop being checked
    _assert_valid_ec(ec)

    if isinstance(sig, BorromeanSig):
        sig.assert_valid()
    else:
        rsizes = [len(pubk_ring) for pubk_ring in pubk_rings]
        sig = BorromeanSig.parse(sig, rsizes)
    # the signature's own curve wins over the caller's default, as
    # sig.ec already does in ssa.assert_as_valid_ -- secp256k1 always,
    # on the octets path just taken
    ec = sig.ec

    msg, m, e = _initialize(msg, pubk_rings, ec, hf)
    e0bytes = m

    for i, pubk_ring in enumerate(pubk_rings):
        keys_size = len(pubk_ring)
        e[i][0] = int_from_bits(_hash(m, sig.e0, i, 0, hf), ec.nlen) % ec.n
        # a zero e: the same accident documented in sign, and here
        # nothing is random -- the whole signature is an argument -- so a
        # chosen e0 reaches it on a low-cardinality curve
        if e[i][0] == 0:
            err_msg = "implausible signature failure"
            raise BorromeanRingError(err_msg, i, 0)
        r = b"\0x00"
        for j in range(keys_size):
            t = double_mult_var(-e[i][j], pubk_ring[j], sig.s[i][j], ec.G, ec)
            r = _bytes_from_ring_point(t, ec, i, j)
            if j != keys_size - 1:
                h = _hash(m, r, i, j + 1, hf)
                e[i][j + 1] = int_from_bits(h, ec.nlen) % ec.n
                # a zero e: the same accident, one ring position later
                if e[i][j + 1] == 0:
                    err_msg = "implausible signature failure"
                    raise BorromeanRingError(err_msg, i, j + 1)
            else:
                e0bytes += r
    hasher = hf()
    hasher.update(e0bytes)
    e0_prime = hasher.digest()
    if e0_prime != sig.e0:
        # no ring of its own: every ring fed e0bytes, so no single one
        # of them is where a mismatch happened
        raise BorromeanRingError("signature verification failed", None, None)
