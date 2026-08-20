# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ElligatorSwift encoding of a public key, and the x-only ECDH on it.

An ElligatorSwift encoding is 64 bytes that are indistinguishable from
random: a pair of field elements (u, t) that the SwiftEC map takes to an
x-coordinate of the curve. Every 64-byte string decodes -- there is no
invalid encoding to recognize -- which is what an observer is left with,
and what BIP324's v2 handshake needs of the keys it carries.

https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki

This module stops at ElligatorSwift key encoding and x-only ECDH, and
each piece of BIP324's v2 transport it leaves out has a reason of its
own (issue 1066). The key schedule's HKDF-SHA256 is not one of them:
it is a construction over a hash, `hmac` and `hashlib` and nothing else,
and it is `ecc.dh.hkdf`.

- **ChaCha20-Poly1305** is the cipher, and `ecc.ecies` is where the rule
  about a cipher is stated: btclib takes one from its caller rather than
  shipping one. A cipher in the standard library is what would change
  that; a hand-rolled one is not, being the only implementation, on by
  default, for every installation, on a network path.
- **Forward-secure rekeying and length obfuscation** are cipher
  invocations, so a caller-supplied cipher leaves them written against
  something no test here can exercise. They follow the cipher and cannot
  precede it.
- **Packet framing** is the transport itself, which belongs beside a P2P
  client that btclib does not provide.

A complete transport therefore belongs in a separate optional package or
extra, backed by an established cryptographic implementation and BIP324's
packet vectors.

`decode` is the map, and it is deterministic. `encode` and `create` are
its inverse, and are not: up to eight (u, t) pairs decode to one
x-coordinate, one of them is picked at random, and the randomness is the
point -- an encoding derived from the key alone would be recognizable by
anyone who could derive it too. So there is no deterministic option here
the way `dsa.sign` takes a nonce: RFC6979 specifies the nonce it derives,
while nothing specifies a derivation for this, and one invented for
btclib would be a promise the specification does not make.

**The map wants a curve with a == 0**, y^2 = x^3 + b, and every function
here refuses one with a != 0. secp256k1 is such a curve and so are the
other three Koblitz curves of the catalogue, which is why these take an
`ec` at all: the Python arithmetic below is what serves them, where
secp256k1 is handed to the libsecp256k1 bindings.
"""

from __future__ import annotations

import secrets

from btclib._libsecp256k1 import ellswift as libsecp256k1_ellswift
from btclib.alias import Octets, Point
from btclib.curves import Curve, bytes_from_point, mult, secp256k1
from btclib.curves.curve import (
    _assert_valid_ec,
    _is_x_coordinate_var,
    _libsecp256k1_serves,
    _point_from_sec,
    _y_even_var,
)
from btclib.exceptions import BTClibRuntimeError, BTClibValueError
from btclib.hashes import tagged_hash
from btclib.number_theory import mod_inv_var, mod_sqrt_var
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import PubKey, point_from_pub_key
from btclib.utils import bytes_from_octets

__all__ = [
    "ELL_SIZE",
    "XDH_TAG",
    "create_var",
    "decode_var",
    "encode_var",
    "xdh",
]

# two field elements of secp256k1, which is what BIP324 fixes the size
# at; every function below takes 2 * ec.p_size, the same number for it
ELL_SIZE = 64

# BIP324's tag for the hash the shared x-coordinate goes through
XDH_TAG = b"bip324_ellswift_xonly_ecdh"

# sqrt(-3) and the inverse of two, per curve: the map's two constants,
# which cost a modular square root and an extended Euclid to derive and
# are the same for every call on a given curve
_CONSTANTS: dict[Curve, tuple[int, int]] = {}


def _constants(ec: Curve) -> tuple[int, int]:
    """Return (sqrt(-3), 1/2) mod ec.p, for a curve the map is defined on."""
    if ec not in _CONSTANTS:
        # a != 0 has no SwiftEC map at all, and asking for one is a
        # caller error rather than an arithmetic failure further down
        if ec._a:
            err_msg = "the ElligatorSwift map wants a curve with a == 0"
            raise BTClibValueError(err_msg)
        # -3 is a square whenever p == 1 mod 3, which every a == 0 curve
        # fit to carry a key is: the others have p+1 points, x -> x^3
        # being a bijection there, and mod_sqrt_var refuses them by itself
        _CONSTANTS[ec] = mod_sqrt_var(-3 % ec.p, ec.p), mod_inv_var(2, ec.p)
    return _CONSTANTS[ec]


def _try_sqrt(a: int, p: int) -> int | None:
    """Return a square root of a mod p, or None when a is not a square.

    mod_sqrt_var raises instead, which is the wrong shape for the map: a
    non-square is one of the branches, taken for about half the inputs,
    and not an error to phrase.

    That refusal is the whole of the test, rather than a legendre_symbol_var
    asked before it: mod_sqrt_var squares its candidate back to compare with
    a, which is the same question answered, and on a 256-bit prime the
    symbol is an exponentiation the size of the root's.
    """
    try:
        return mod_sqrt_var(a, p)
    except BTClibValueError:
        return None


def _xswiftec_var(u: int, t: int, ec: Curve) -> int:
    """Return the x-coordinate the field elements (u, t) map to.

    `xswiftec` of BIP324's reference implementation. u and t are taken
    modulo p, which is what makes every 64-byte string an encoding: the
    two 32-byte halves are read as integers that may reach past p, and
    reducing them is the first thing the map does.
    """
    p = ec.p
    minus_3_sqrt, inv2 = _constants(ec)
    u %= p
    t %= p
    # zero has no inverse, and either substitution keeps the map total
    if u == 0:
        u = 1
    if t == 0:
        t = 1
    # u^3 + t^2 + b == 0 would make X below zero, whose Y is not a point
    if (pow(u, 3, p) + t * t + ec._b) % p == 0:
        t = 2 * t % p
    X = (pow(u, 3, p) + ec._b - t * t) * mod_inv_var(2 * t, p) % p
    Y = (X + t) * mod_inv_var(minus_3_sqrt * u % p, p) % p
    inv_Y = mod_inv_var(Y, p)
    # three candidates, in the order the specification gives them: the
    # first that is an x-coordinate is the answer, and one of them is
    for x in (
        (u + 4 * Y * Y) % p,
        (-X * inv_Y - u) * inv2 % p,
        (X * inv_Y - u) * inv2 % p,
    ):
        if _is_x_coordinate_var(x, ec):
            return x
    # unreachable, and here for the return type rather than for the case:
    # the map is total -- the SwiftEC paper's result is that one of the
    # three candidates is always an x-coordinate, and BIP324's reference
    # implementation writes this line as `assert False`
    err_msg = "no x-coordinate for the given field elements"  # pragma: no cover
    raise BTClibRuntimeError(err_msg)  # pragma: no cover


def _xswiftec_inv_var(x: int, u: int, case: int, ec: Curve) -> int | None:  # noqa: PLR0911
    """Return a t with _xswiftec_var(u, t) == x, or None if this case has none.

    `xswiftec_inv` of BIP324's reference implementation. Up to eight t
    values map back to one x, and `case` in 0..7 selects which is
    attempted: each may fail, and the successful ones are distinct.
    """
    p = ec.p
    b = ec._b
    minus_3_sqrt, inv2 = _constants(ec)
    x %= p
    u %= p

    if case & 2 == 0:
        # -x-u being an x-coordinate means the pair would decode through
        # the third candidate of _xswiftec_var, which has priority: the
        # encoding would not round-trip, so this case has no answer
        if _is_x_coordinate_var((-x - u) % p, ec):
            return None
        v = x
        s = -(pow(u, 3, p) + b) * mod_inv_var((u * u + u * v + v * v) % p, p) % p
    else:
        s = (x - u) % p
        if s == 0:
            return None
        r = _try_sqrt(-s * (4 * (pow(u, 3, p) + b) + 3 * s * u % p * u) % p, p)
        if r is None:
            return None
        # r == 0 makes the two cases that differ by its sign the same t,
        # and only one of them is to return it
        if case & 1 and r == 0:
            return None
        v = (-u + r * mod_inv_var(s, p)) * inv2 % p

    w = _try_sqrt(s, p)
    if w is None:
        return None

    # the low and high bits of case pick the signs of the two square
    # roots, which is the encoding the paper's four branches take
    if case & 5 == 0:
        return -w * (u * ((1 - minus_3_sqrt) % p) % p * inv2 + v) % p
    if case & 5 == 1:
        return w * (u * ((1 + minus_3_sqrt) % p) % p * inv2 + v) % p
    if case & 5 == 4:
        return w * (u * ((1 - minus_3_sqrt) % p) % p * inv2 + v) % p
    return -w * (u * ((1 + minus_3_sqrt) % p) % p * inv2 + v) % p


def _x_t_from_ell(ell: bytes, ec: Curve) -> tuple[int, int]:
    """Return the decoded x-coordinate and the reduced t beside it."""
    size = ec.p_size
    u = int.from_bytes(ell[:size], byteorder="big", signed=False) % ec.p
    t = int.from_bytes(ell[size:], byteorder="big", signed=False) % ec.p
    return _xswiftec_var(u, t, ec), t


def _point_from_ell_var(ell: bytes, ec: Curve) -> Point:
    """Return the point the encoding decodes to, in Python."""
    x, t = _x_t_from_ell(ell, ec)
    # the parity of t is the y the pair names, which is the half of the
    # encoding BIP324's own reference implementation leaves out: it maps
    # to an x-coordinate and stops, where libsecp256k1's decode lifts the
    # point with secp256k1_fe_is_odd(t) as the tiebreaker
    y = _y_even_var(x, ec)
    return x, (ec.p - y if t % 2 else y)


def _ell_from_point(Q: Point, ec: Curve) -> bytes:
    """Return a random encoding of the point, in Python."""
    p = ec.p
    size = ec.p_size
    while True:
        # a nonzero field element and one of the eight cases; most pairs
        # have no t, and a fresh u is what the retry draws
        u = secrets.randbelow(p - 1) + 1
        t = _xswiftec_inv_var(Q[0], u, secrets.randbelow(8), ec)
        if t is None:
            continue
        # _xswiftec_inv_var pins the x-coordinate alone, so t and p-t encode
        # the two points of that x: the parity of t has to be the y's.
        # Neither Python reference has this step and neither is wrong --
        # BIP324's reference.py and Core's crypto/ellswift.py are x-only
        # end to end, so no y ever reaches them -- while libsecp256k1
        # wraps the same x-only map in the same condition, its
        # elligatorswift_var over xelligatorswift_var. It is here because
        # `decode` answers with a point; without it, half the encodings
        # would decode to -Q
        if t % 2 != Q[1] % 2:
            t = p - t
        return u.to_bytes(size, "big") + t.to_bytes(size, "big")


def _ell_from_octets(ell: Octets, ec: Curve) -> bytes:
    """Return the encoding as the octets the map reads, size checked."""
    # the size is the curve's, so this is where `decode_var` and `xdh`
    # first read theirs; `create_var` and `encode_var` take no encoding in
    # and reach the curve through the key converters instead
    _assert_valid_ec(ec)
    ell = bytes_from_octets(ell)
    if len(ell) != 2 * ec.p_size:
        err_msg = f"invalid ElligatorSwift size: {len(ell)}"
        err_msg += f" instead of {2 * ec.p_size} bytes"
        raise BTClibValueError(err_msg)
    return ell


def create_var(prv_key: PrvKey, ec: Curve = secp256k1) -> bytes:
    """Return an ElligatorSwift encoding of the private key's public key.

    The private key is its own entropy for the encoding, which is what
    `secp256k1_ellswift_create` is for and what makes it preferable to
    encoding the public key: a caller cannot supply randomness that is a
    function of the key, because it supplies none.
    """
    q = int_from_prv_key(prv_key, ec)

    # the bindings hold the private key to the same 1..n-1 int_from_prv_key
    # does, so what reaches them is a key they take
    if _libsecp256k1_serves(ec, None):
        return libsecp256k1_ellswift.create(q)

    _constants(ec)  # the curve is refused here rather than after a mult
    return _ell_from_point(mult(q, ec.G, ec), ec)


def encode_var(pub_key: PubKey, ec: Curve = secp256k1) -> bytes:
    """Return an ElligatorSwift encoding of the public key.

    The randomness is drawn here and is not a function of the key, which
    is what BIP324 requires of it: two encodings of one key are
    unlinkable, and an encoding nobody can recompute is what makes them
    so. `create` is the better call when the private key is at hand.
    """
    Q = point_from_pub_key(pub_key, ec)

    if _libsecp256k1_serves(ec, None):
        # uncompressed, as in `dh.diffie_hellman`: the encoding parses
        # what it is handed, and 65 octets are read where 33 are lifted --
        # 13.1 us against 15.1
        return libsecp256k1_ellswift.encode(bytes_from_point(Q, ec, compressed=False))

    _constants(ec)
    return _ell_from_point(Q, ec)


def decode_var(ell: Octets, ec: Curve = secp256k1) -> Point:
    """Return the point an ElligatorSwift encoding decodes to.

    Every encoding of the right size decodes, there being no invalid one
    to refuse: that is the property the scheme is built on.
    """
    ell = _ell_from_octets(ell, ec)

    # asked for the uncompressed form, so that both coordinates are read
    # off what the decoding already computed: the compressed one drops the
    # y and leaves it to be lifted back, which is a second parse and a
    # serialization of a point libsecp256k1 was holding
    if _libsecp256k1_serves(ec, None):
        return _point_from_sec(libsecp256k1_ellswift.decode(ell, compressed=False))

    return _point_from_ell_var(ell, ec)


def xdh(
    ell_a: Octets,
    ell_b: Octets,
    prv_key: PrvKey,
    party: int,
    ec: Curve = secp256k1,
) -> bytes:
    """Return the x-only ECDH shared secret of two ElligatorSwift keys.

    `party` says which of the two encodings is the caller's -- 0 for
    ell_a, 1 for ell_b -- because the secret is a hash of both encodings
    in a fixed order, and the other one is the key to multiply. The
    correspondence between the private key and the caller's encoding is
    not checked: the two parties reach the same 32 bytes when it holds,
    and nothing here can tell that it does.
    """
    ell_a = _ell_from_octets(ell_a, ec)
    ell_b = _ell_from_octets(ell_b, ec)
    if party not in {0, 1}:
        err_msg = f"invalid party: {party}, not 0 (A) or 1 (B)"
        raise BTClibValueError(err_msg)
    q = int_from_prv_key(prv_key, ec)

    if _libsecp256k1_serves(ec, None):
        return libsecp256k1_ellswift.xdh(ell_a, ell_b, q, party)

    # the shared x-coordinate is the same for either y of the decoded
    # point, q*P and q*(-P) differing by their own y alone, so the t
    # parity the decoding would apply does not reach the secret
    x_theirs, _ = _x_t_from_ell(ell_b if party == 0 else ell_a, ec)
    x = mult(q, (x_theirs, _y_even_var(x_theirs, ec)), ec)[0]
    preimage = ell_a + ell_b + x.to_bytes(ec.p_size, byteorder="big", signed=False)
    return tagged_hash(XDH_TAG, preimage)
