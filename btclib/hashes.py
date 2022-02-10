#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Hash based helper functions.

"""

import hashlib
from typing import Callable, List, Tuple, Union

from btclib.alias import HashF, Octets
from btclib.ecc.curve import Curve, secp256k1
from btclib.utils import bytes_from_octets, int_from_bits

H160_Net = Tuple[bytes, str]


def ripemd160(octets: Octets) -> bytes:
    "Return the RIPEMD160(*) of the input octet sequence."

    octets = bytes_from_octets(octets)
    return hashlib.new("ripemd160", octets).digest()


def sha256(octets: Octets) -> bytes:
    "Return the SHA256(*) of the input octet sequence."

    octets = bytes_from_octets(octets)
    return hashlib.sha256(octets).digest()


def hash160(octets: Octets) -> bytes:
    "Return the HASH160=RIPEMD160(SHA256) of the input octet sequence."

    return ripemd160(sha256(octets))


def hash256(octets: Octets) -> bytes:
    "Return the SHA256(SHA256(*)) of the input octet sequence."

    return sha256(sha256(octets))


def reduce_to_hlen(msg: Octets, hf: HashF = hashlib.sha256) -> bytes:

    msg = bytes_from_octets(msg)
    # Step 4 of SEC 1 v.2 section 4.1.3
    h = hf()
    h.update(msg)
    return h.digest()


def magic_message(msg: Octets) -> bytes:

    msg = bytes_from_octets(msg)
    t = (
        b"\x18Bitcoin Signed Message:\n"
        + len(msg).to_bytes(1, byteorder="big", signed=False)
        + msg
    )
    return sha256(t)


# FIXME move into ecc folder
def challenge_(
    msg_hash: Octets, ec: Curve = secp256k1, hf: HashF = hashlib.sha256
) -> int:

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # leftmost ec.nlen bits %= ec.n
    return int_from_bits(msg_hash, ec.nlen) % ec.n


def merkle_root(data: List[bytes], hf: Callable[[Union[bytes, str]], bytes]) -> bytes:
    """Return the Merkel tree root of a list of binary hashes.

    The Merkel tree is a binary tree constructed
    with the provided list of binary data as bottom level,
    then recursively going up one level
    by hashing every hash value pair in the current level,
    until a single value (root) is obtained.
    """

    data = [hf(item) for item in data]
    while len(data) != 1:
        parent_level = []
        if len(data) % 2:
            data.append(data[-1])
        for i in range(0, len(data), 2):
            parent = hf(data[i] + data[i + 1])
            parent_level.append(parent)
        data = parent_level[:]
    return data[0]


def tagged_hash(tag: bytes, m: bytes, hf: HashF = hashlib.sha256) -> bytes:

    h1 = hf()
    h1.update(tag)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate

    h2.update(m)
    return h2.digest()
