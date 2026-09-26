# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""ElligatorSwift encoding of a public key, and BIP324's x-only ECDH on it.

The encoding is btclib_ecc.ecc.ellswift's: `create_var`, `encode_var`
and `decode_var` are that module's own objects, bound again so that
`btclib.ecc.ellswift` keeps answering for them (issue #2282). What BIP324
builds on the map is a protocol's rather than a fact about a curve, and
it is this module's own: `xdh`, the x-only ECDH over two encodings, with
`XDH_TAG` and `ELL_SIZE`.

https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki

This module stops at the x-only ECDH, and each piece of BIP324's v2
transport it leaves out has a reason of its own (issue 1066). The key
schedule's HKDF-SHA256 is not one of them: it is a construction over a
hash, `hmac` and `hashlib` and nothing else, and it is `kdf.hkdf`.

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
"""

from __future__ import annotations

from btclib_ecc.ecc.ellswift import create_var, decode_var, encode_var
from btclib_ecc.hashes import tagged_hash

from btclib.alias import Integer, Octets
from btclib.curves import (
    Curve,
    is_libsecp256k1_serving,
    mult,
    scalar_from_prv_key,
    secp256k1,
)
from btclib.exceptions import BTClibValueError
from btclib.utils import assert_type, bytes_from_octets

# the bindings' module, imported from their own package; None where they
# are not installed, which nothing calls: what calls it here is behind
# `is_libsecp256k1_serving`, False in that configuration. Installed one
# name short, the call finds no such attribute and raises AttributeError
# while btclib_ecc keeps serving, so it fails rather than degrading: the
# floor the `secp256k1` extra puts on the bindings is what rules that out
try:
    from btclib_secp256k1 import ellswift as libsecp256k1_ellswift
except ImportError:  # pragma: no cover -- only an install without them
    libsecp256k1_ellswift = None  # type: ignore[assignment]

__all__ = [
    "ELL_SIZE",
    "XDH_TAG",
    "create_var",
    "decode_var",
    "encode_var",
    "xdh",
]

# two field elements of secp256k1, which is what BIP324 fixes the size
# at; `xdh` takes 2 * ec.p_size, the same number for it
ELL_SIZE = 64

# BIP324's tag for the hash the shared x-coordinate goes through
XDH_TAG = b"bip324_ellswift_xonly_ecdh"


def _ell_from_octets(ell: Octets, ec: Curve) -> bytes:
    """Return the encoding as the octets the hash reads, size checked."""
    assert_type(ec, Curve, "ec")
    ell = bytes_from_octets(ell)
    if len(ell) != 2 * ec.p_size:
        err_msg = f"invalid ElligatorSwift size: {len(ell)}"
        err_msg += f" instead of {2 * ec.p_size} bytes"
        raise BTClibValueError(err_msg)
    return ell


def xdh(
    ell_a: Octets,
    ell_b: Octets,
    prv_key: Integer,
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
    q = scalar_from_prv_key(prv_key, ec)

    if is_libsecp256k1_serving() and ec == secp256k1:
        return libsecp256k1_ellswift.xdh(ell_a, ell_b, q, party)

    # the shared x-coordinate is the same for either y of the decoded
    # point, q*P and q*(-P) differing by their own y alone, so which y
    # `decode_var` answers with does not reach the secret
    x = mult(q, decode_var(ell_b if party == 0 else ell_a, ec), ec)[0]
    preimage = ell_a + ell_b + x.to_bytes(ec.p_size, byteorder="big", signed=False)
    return tagged_hash(XDH_TAG, preimage)
