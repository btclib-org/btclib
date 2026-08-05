# Copyright (C) The btclib developers
#
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
    """Return the variable-length octets read from a stream."""
    stream = bytesio_from_binarydata(stream)
    i = var_int.parse(stream)
    if forbid_zero_size and i == 0:
        raise BTClibRuntimeError("zero size")

    result = stream.read(i)
    if len(result) != i:
        raise BTClibRuntimeError("not enough binary data")
    return result


def serialize(octets: Octets) -> bytes:
    """Return the var_int(len(octets)) + octets serialization of octets."""
    bytes_ = bytes_from_octets(octets)
    return var_int.serialize(len(bytes_)) + bytes_
