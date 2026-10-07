# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Core's file obfuscation: XOR with a repeating 8-byte key.

Bitcoin Core v31.1 obfuscates a v2 `mempool.dat`, and the block and undo
files written with `-blocksxor`, with `Obfuscation`
(`src/util/obfuscation.h`). The byte at absolute offset `p` of the file is
XORed with `key[p % 8]`. The same operation obfuscates and de-obfuscates.

A file stores its key as a `var_bytes` of eight bytes. A v2 `mempool.dat`
begins with the version as a little-endian `u64`, then that key, and only
the bytes after the key are obfuscated: the key is not obfuscated by
itself, but the offset is counted from the start of the file, so a reader
that has read `n` bytes passes `offset=n` for the next slice.

An all-zero key obfuscates nothing, which is how Core writes a file it
does not obfuscate. Core's `Obfuscation` converts to `False` then and
skips the work; here the XOR with zeros returns the same bytes.
"""

from btclib import var_bytes
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import bytes_from_octets, bytesio_from_binarydata, is_integer

__all__ = [
    "KEY_SIZE",
    "obfuscate",
    "parse_key",
    "serialize_key",
]

KEY_SIZE = 8  # Obfuscation::KEY_SIZE


def obfuscate(data: Octets, key: Octets, offset: int = 0) -> bytes:
    """Return `data` XORed with the repeating `key`, starting at `offset`.

    `data` sits at byte `offset` of the file, so `data[i]` is XORed with
    `key[(offset + i) % 8]`. `offset` need not be a multiple of the key
    size, and a file read in pieces is de-obfuscated piece by piece, each
    with its own offset. Applying the function twice with the same
    arguments returns `data`.
    """
    data = bytes_from_octets(data)
    key = bytes_from_octets(key, KEY_SIZE)
    if not is_integer(offset):
        raise BTClibTypeError(f"non-integer offset: {offset}")
    if offset < 0:
        raise BTClibValueError(f"negative offset: {offset}")

    shift = offset % KEY_SIZE
    rotated = key[shift:] + key[:shift]
    size = len(data)
    pad = (rotated * (size // KEY_SIZE + 1))[:size]
    return (int.from_bytes(data) ^ int.from_bytes(pad)).to_bytes(size)


def serialize_key(key: Octets) -> bytes:
    """Return the key as a file stores it: `var_bytes` of its eight bytes."""
    return var_bytes.serialize(bytes_from_octets(key, KEY_SIZE))


def parse_key(stream: BinaryData) -> bytes:
    """Return the key read from a stream, which holds exactly eight bytes.

    Core's `Obfuscation::Unserialize` refuses any other length.
    """
    stream = bytesio_from_binarydata(stream)
    key = var_bytes.parse(stream)
    if len(key) != KEY_SIZE:
        raise BTClibValueError(
            f"invalid key size: {len(key)} bytes instead of {KEY_SIZE}"
        )
    return key
