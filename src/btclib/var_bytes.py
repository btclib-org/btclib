# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Varbytes encoding and decoding: a var_int length, then the bytes."""

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibRuntimeError
from btclib.utils import bytes_from_octets, bytesio_from_binarydata

__all__ = [
    "parse",
    "serialize",
]


def parse(stream: BinaryData, forbid_zero_size: bool = False) -> bytes:
    """Return the variable-length octets read from a stream.

    `forbid_zero_size` is read for its truth and not asked for its type,
    which is the convention `check_validity` is read under: it decides
    only *whether a check runs*, so no value of it changes the octets
    this answers with -- where `taproot.parse`'s `exit_on_op_success`
    decides which of two answers is computed and is therefore refused
    unless it is a bool.
    """
    stream = bytesio_from_binarydata(stream)
    i = var_int.parse(stream)
    if forbid_zero_size and i == 0:
        raise BTClibRuntimeError("zero size")

    result = stream.read(i)
    if len(result) != i:
        raise BTClibRuntimeError("not enough binary data")
    return result


def _size(octets: Octets) -> int:
    """Return the width `serialize` writes, without writing it.

    The coercion is `serialize`'s and is not skipped: a hex string is
    half its own length in bytes, and reading `len` off the string would
    answer twice the width for the one input the codec accepts as text.
    What it does not do is build the concatenation.
    """
    size = len(bytes_from_octets(octets))
    return var_int._size(size) + size


def serialize(octets: Octets) -> bytes:
    """Return the var_int(len(octets)) + octets serialization of octets."""
    bytes_ = bytes_from_octets(octets)
    return var_int.serialize(len(bytes_)) + bytes_
