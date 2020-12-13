#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
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

from .alias import HashF, String
from .to_pub_key import Key, pub_keyinfo_from_key
from .utils import hash160

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


def reduce_to_hlen(msg: String, hf: HashF = hashlib.sha256) -> bytes:

    if isinstance(msg, str):
        # do not strip spaces
        msg = msg.encode()

    # Step 4 of SEC 1 v.2 section 4.1.3
    h = hf()
    h.update(msg)
    return h.digest()


def tagged_hash(tag: str, msg: String, hf: HashF = hashlib.sha256) -> bytes:

    if isinstance(msg, str):
        # do not strip spaces
        msg = msg.encode()

    t = tag.encode()
    h1 = hf()
    h1.update(t)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate
    h2.update(msg)
    return h2.digest()
