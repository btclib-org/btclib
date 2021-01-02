#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Varbytes encoding and decoding functions."

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibRuntimeError
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


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
    "Return the var_int(len(octets)) + octets serialization of octets."

    bytes_ = bytes_from_octets(octets)
    return var_int.serialize(len(bytes_)) + bytes_
