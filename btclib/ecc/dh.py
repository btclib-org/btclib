# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Diffie-Hellman elliptic curve key agreement, and the KDFs beside it.

Two parties, each holding the other's public key, compute the same
shared secret -- their key pair times the other's public point -- and
derive symmetric keying data from it through a key derivation
function. The curve and the KDF are the two things the parties must
agree on beforehand; ansi_x9_63_kdf is SEC 1's KDF, and
diffie_hellman is the agreement built on it, per SEC 1 v.2.

**Why `ecdh.shared_secret` of the bindings has no caller in btclib, and
this is the place that says so** (issue 909). That function multiplies
and hashes in one call, and the hash is SHA256 of the compressed shared
point with no way to change it: libsecp256k1 takes it as a C callback, so
exposing it would mean calling back into python from the middle of the
computation. Every ECDH-shaped computation here derives differently, so
what is delegated is the multiplication -- `keys.pubkey_tweak_mul`, which
is that same C multiplication, in constant time -- and the derivation
stays in python:

- `diffie_hellman` below runs SEC 1's ANSI-X9.63-KDF over the
  x-coordinate, under the hash function the caller passed;
- `ecc.ecies.derive_keys` hashes the *compressed point* with sha512 and
  cuts the 64 bytes three ways, which is BIE1's shape and not this one;
- `silent_payments.shared_secret` answers the point itself: BIP352 tags
  it with a counter afterwards, and a BIP375 psbt carries it as a point;
- `ecc.ellswift.xdh` is the exception that proves the rule. BIP324
  defines the hash, libsecp256k1 implements that definition, and it is
  delegated whole -- `ellswift.xdh` is one call there.

So the verdict is not that the function is wrong: it is that a shared
secret is a protocol's own derivation, and only a protocol agreeing with
libsecp256k1's default can hand the whole of it over. Three of the four
here do not, and the fourth already does.

**Why hkdf is here rather than in a KDF module of its own** (issue
1080). RFC 5869's extract-and-expand is a construction over a hash, with
no Diffie-Hellman in it, so the question is whether both KDFs move out
instead. They do not. `ansi_x9_63_kdf` is SEC 1's section 3.6.1 and
`diffie_hellman` is section 6.1 built on it -- its only caller here --
so a split would separate a scheme from the derivation its own
specification defines for it. And `btclib.ecc` re-exports both KDFs, so
`from btclib.ecc import hkdf` is the spelling either way and no caller
has to name this module to reach one. A module of its own would buy a
tidier file name and cost a source break; one drawer is also where the
next KDF goes.
"""

from __future__ import annotations

import hmac
from hashlib import sha256
from math import ceil

from btclib._libsecp256k1 import keys as libsecp256k1_keys
from btclib.alias import HashF, Point
from btclib.curves import Curve, bytes_from_point, mult, secp256k1
from btclib.curves.curve import _assert_valid_ec, _libsecp256k1_serves
from btclib.exceptions import BTClibRuntimeError, BTClibTypeError, BTClibValueError
from btclib.utils import is_integer

__all__ = [
    "ansi_x9_63_kdf",
    "diffie_hellman",
    "hkdf",
    "hkdf_expand",
    "hkdf_extract",
]


def _assert_valid_keying_data_size(size: int, max_size: int) -> None:
    """Refuse an output length no key derivation function can answer.

    `max_size` is what the caller's KDF can derive under the caller's
    hash function: SEC 1's 2**32 - 1 blocks, RFC 5869's 255.
    """
    # the range is checked before the loop bound is computed from it, and
    # the type before the range. Unchecked, a negative size made the loop
    # empty and the final negative slice returned b"" -- an empty key
    # where the caller asked for keying material, which is the one answer
    # a key derivation function must never invent (issue 321). A float
    # went further still and reached that slice, leaving through a bare
    # TypeError from underneath the library rather than through its own
    # exception contract
    if not is_integer(size):
        raise BTClibTypeError(f"non-integer keying data size: {size}")
    # zero and not merely negative: SEC 1 3.6.1 states keydatalen as a
    # positive integer, RFC 5869 states L as at most 255 * HashLen, and a
    # caller asking for no octets of key is a caller with a bug rather
    # than one with an empty key
    if size <= 0:
        raise BTClibValueError(f"invalid keying data size: {size}")
    if size > max_size:
        raise BTClibValueError(f"cannot derive a key larger than {max_size} bytes")


def ansi_x9_63_kdf(z: bytes, size: int, hf: HashF, shared_info: bytes | None) -> bytes:
    """Return keying data according to ANSI-X9.63-KDF.

    Return a keying data octet sequence of the requested size according
    to ANSI-X9.63-KDF specifications for the key derivation function.

    `size` is a positive number of octets, SEC 1's keydatalen: a
    BTClibTypeError if it is no integer, a BTClibValueError if it is zero,
    negative, or above what the hash function can derive.

    http://www.secg.org/sec1-v2.pdf,
    section 3.6.1
    """
    hf_size = hf().digest_size
    # the counter is four octets, so 2**32 - 1 blocks is what the
    # construction can number
    _assert_valid_keying_data_size(size, hf_size * (2**32 - 1))
    # the whole buffer is asked for once, and the blocks are written into
    # it. A list of digests joined and then sliced holds the keying data
    # three times over -- the digests, the join's copy, the slice's --
    # where this holds it twice: deriving 64 MiB peaks at 2.00x the
    # output against 5.79x. It costs about 0.03 us a block, so a fifth of
    # a microsecond at the one or two blocks `diffie_hellman` asks for,
    # which is around one percent of the 15.2 us multiplication it
    # arrives through -- and a tenth of the derivation at sizes far
    # beyond that
    #
    # the `memoryview` is what makes each write exact: a bytearray slice
    # assignment of the wrong length resizes the buffer and shifts every
    # block after it, where this raises. At the end `bytes(view[:size])`
    # copies once, where `bytes(keying_data[:size])` would copy twice
    n_blocks = ceil(size / hf_size)
    keying_data = bytearray(n_blocks * hf_size)
    view = memoryview(keying_data)
    for counter in range(1, n_blocks + 1):
        h = hf()
        hash_input = (
            z
            + counter.to_bytes(4, byteorder="big", signed=False)
            + (b"" if shared_info is None else shared_info)
        )
        h.update(hash_input)
        start = (counter - 1) * hf_size
        view[start : start + hf_size] = h.digest()
    return bytes(view[:size])


def diffie_hellman(
    dU: int,
    QV: Point,
    size: int,
    shared_info: bytes | None = None,
    ec: Curve = secp256k1,
    hf: HashF = sha256,
) -> bytes:
    """Diffie-Hellman elliptic curve key agreement scheme.

    http://www.secg.org/sec1-v2.pdf, section 6.1

    The shared point is the multiplication of a point that is not the
    generator, which is the one case `mult` does not delegate: on
    secp256k1 it is `secp256k1_ec_pubkey_tweak_mul` that computes it
    here, 15.2 us against the 549 of the Python endomorphism path and,
    dU being a secret, in constant time -- which that path is not.

    `ecdh.shared_secret` of the bindings is a different function and not
    a substitute: it hashes the compressed shared point with SHA256,
    where this derives through ANSI-X9.63-KDF. The module docstring above
    has that verdict for all four of btclib's ECDH-shaped computations.
    """
    _assert_valid_ec(ec)
    d = dU % ec.n

    # d == 0 is the infinity point, which the bindings reject as a
    # scalar; so is a low-order QV on a curve with a cofactor, which
    # they have no serialization for either. Both are the Python path's
    # to answer, and it answers them below
    if d and _libsecp256k1_serves(ec, None):
        # uncompressed, which is the cheap form to hand over: parsing 65
        # octets reads both coordinates where 33 are a field square root,
        # and the point is here to be written either way -- 12.6 us
        # against 14.7 for the multiplication that follows
        sec = libsecp256k1_keys.pubkey_tweak_mul(
            bytes_from_point(QV, ec, compressed=False), d
        )
        return ansi_x9_63_kdf(sec[1:], size, hf, shared_info)

    shared_secret_point = mult(dU, QV, ec)
    # a degenerate dU, zero mod n, maps every QV here
    if shared_secret_point[1] == 0:
        err_msg = "invalid (INF) key"
        raise BTClibRuntimeError(err_msg)
    shared_secret_field_element = shared_secret_point[0]
    z = shared_secret_field_element.to_bytes(ec.p_size, byteorder="big", signed=False)
    return ansi_x9_63_kdf(z, size, hf, shared_info)


def hkdf_extract(ikm: bytes, salt: bytes | None, hf: HashF) -> bytes:
    """Return the pseudorandom key of HKDF's extract step.

    `ikm` is the input keying material, which need not be uniformly
    distributed -- concentrating whatever entropy it has into one digest
    is what this step is for. `salt` is an optional non-secret value,
    which may be reused. The answer is one digest of `hf`, and is what
    `hkdf_expand` takes as its `prk`.

    https://www.rfc-editor.org/rfc/rfc5869.html, section 2.2

    An `ikm` that is already a uniformly random key of full length does
    not need this step: RFC 5869 section 3.3 says to skip it and expand
    that key directly, which `hkdf_expand` is separately public for.
    """
    # RFC 5869 sets an absent salt to HashLen zero octets, and b"" is the
    # same HMAC key: a key shorter than the block size is zero-padded to
    # it, so both spellings hash the same first block. Appendix A carries
    # a vector for each of them, and they arrive here as one
    return hmac.new(b"" if salt is None else salt, ikm, hf).digest()


def hkdf_expand(prk: bytes, size: int, hf: HashF, info: bytes | None) -> bytes:
    """Return output keying material of the requested size.

    `prk` is a pseudorandom key, `hkdf_extract`'s answer or a uniformly
    random key of at least a digest's length. `info` is optional context
    -- a protocol label, a party's identity -- which binds the output to
    an application, so that one `prk` yields independent keys.

    `size` is a positive number of octets, RFC 5869's L: a
    BTClibTypeError if it is no integer, a BTClibValueError if it is
    zero, negative, or above 255 digests. A `prk` below a digest is a
    BTClibValueError too.

    https://www.rfc-editor.org/rfc/rfc5869.html, section 2.3
    """
    hf_size = hf().digest_size
    # the counter is a single octet, from 1, so 255 blocks is what the
    # construction can number -- 8160 octets under sha256
    _assert_valid_keying_data_size(size, 255 * hf_size)
    # section 2.3 states the prk as at least HashLen octets, and the
    # length is worth refusing rather than deriving from: HMAC pads a
    # short key with zeros instead of stretching it, so every octet
    # expanded out of one is only as strong as the key was. `hkdf` cannot
    # reach this, `hkdf_extract` answering one digest exactly; a
    # caller skipping the extract step per section 3.3 can
    if len(prk) < hf_size:
        raise BTClibValueError(f"pseudorandom key shorter than {hf_size} bytes")
    context = b"" if info is None else info
    # a list joined, where `ansi_x9_63_kdf` writes into one buffer: that
    # one has no ceiling short of gigabytes, so the copies the join makes
    # are worth avoiding there, while 255 blocks put a few kilobytes at
    # the top of this one. Each block is also the next block's input, so
    # the sequence is held either way
    blocks: list[bytes] = []
    block = b""
    for counter in range(1, ceil(size / hf_size) + 1):
        block = hmac.new(prk, block + context + bytes([counter]), hf).digest()
        blocks.append(block)
    return b"".join(blocks)[:size]


def hkdf(
    ikm: bytes, size: int, hf: HashF, salt: bytes | None, info: bytes | None
) -> bytes:
    """Return keying data according to HKDF, extract then expand.

    The composition of the two steps above, which is how RFC 5869 is
    used unless the caller already holds a uniformly random key: extract
    concentrates the entropy of `ikm` under `salt`, expand stretches the
    result to `size` octets under `info`.

    https://www.rfc-editor.org/rfc/rfc5869.html, section 2
    """
    return hkdf_expand(hkdf_extract(ikm, salt, hf), size, hf, info)
