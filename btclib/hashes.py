#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Hash based helper functions.

"""

import hashlib
from typing import Optional, Tuple

from btclib.alias import HashF, Octets
from btclib.ecc.curve import Curve, secp256k1
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets, hash160, int_from_bits

H160_Net = Tuple[bytes, str]


def hash160_from_key(
    key: Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> H160_Net:
    """Return (public key HASH160, nettwork) from a private/public key.

    HASH160 is RIPEMD160(SHA256).
    """
    pub_key, network = pub_keyinfo_from_key(key, network, compressed)
    return hash160(pub_key), network


def fingerprint(key: Key, network: Optional[str] = None) -> bytes:
    """Return the public key fingerprint from a private/public key.

    The fingerprint is the last four bytes
    of the compressed public key HASH160.
    """

    pub_key, _ = pub_keyinfo_from_key(key, network, compressed=True)
    return hash160(pub_key)[:4]


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
    return hashlib.sha256(t).digest()


# FIXME move into ecc folder
def challenge_(
    msg_hash: Octets, ec: Curve = secp256k1, hf: HashF = hashlib.sha256
) -> int:

    # the message msg_hash: a hf_len array
    hf_len = hf().digest_size
    msg_hash = bytes_from_octets(msg_hash, hf_len)

    # leftmost ec.nlen bits %= ec.n
    c = int_from_bits(msg_hash, ec.nlen) % ec.n
    return c


def tagged_hash(tag: bytes, m: bytes, hf: HashF = hashlib.sha256) -> bytes:

    h1 = hf()
    h1.update(tag)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate

    h2.update(m)
    return h2.digest()
