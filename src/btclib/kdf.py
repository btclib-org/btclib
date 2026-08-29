# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Key derivation functions: SEC 1's ANSI-X9.63-KDF and RFC 5869's HKDF.

A KDF stretches one secret into keying data of the length a protocol
asks for, under a hash function the caller chooses. `ansi_x9_63_kdf` is
SEC 1's, one hash per block over a four-octet counter, and
`ecc.dh.diffie_hellman` is the agreement built on it. `hkdf` is RFC
5869's, extract then expand, and it is the one piece of BIP324's key
schedule btclib implements: a construction over a hash rather than over
a cipher, which is the near side of the line `ecc.ellswift` draws and
`ecc.ecies` argues.

Both are `hashlib` and `hmac` and nothing else: no elliptic curve, and
no bitcoin.

**Why they are here rather than beside the agreement that uses one**
(issue 1080). SEC 1 defines ANSI-X9.63-KDF in section 3.6.1 for the
agreement of section 6.1, so `ecc.dh` is where it reads naturally, and
with one KDF in the tree that costs nothing. HKDF has no such tie -- RFC
5869 has no Diffie-Hellman in it, and nothing that wants HKDF here holds
a public key -- so a drawer under `ecc` leaves either a KDF reached
through a package of signature schemes or two KDFs in two places for the
next one to have to choose between. One drawer, at the layer its
contents belong to, is the answer to both; RELEASE_NOTES.md has the
spellings it costs.
"""

from __future__ import annotations

import hmac
from math import ceil

from btclib.alias import HashF
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import is_integer

__all__ = [
    "ansi_x9_63_kdf",
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
    # output against 5.79x. What the writing costs at the one or two
    # blocks `diffie_hellman` asks for is around one percent of the
    # multiplication it arrives through -- and a tenth of the derivation
    # at sizes far beyond that
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
