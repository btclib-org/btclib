#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Varbytes encoding and decoding functions."

from . import varint
from .alias import BinaryData, Octets
from .exceptions import BTClibRuntimeError
from .utils import bytes_from_octets, bytesio_from_binarydata


def deserialize(stream: BinaryData) -> bytes:
    """Return the variable-length octets read from a stream."""

    stream = bytesio_from_binarydata(stream)
    i = varint.deserialize(stream)
    result = stream.read(i)
    if len(result) != i:
        raise BTClibRuntimeError("not enough binary data")
    return result


def serialize(octets: Octets) -> bytes:
    "Return the varint(len(octets)) + octets serialization of octets."

    bytes_ = bytes_from_octets(octets)
    return varint.serialize(len(bytes_)) + bytes_
