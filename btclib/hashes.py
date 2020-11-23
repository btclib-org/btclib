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

from .alias import HashF, Script, String
from .script import serialize
from .to_pubkey import Key, pubkeyinfo_from_key
from .utils import hash160, sha256

_H160_NET = Tuple[bytes, str]


def hash160_from_key(
    key: Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> _H160_NET:
    """Return (public key HASH160, nettwork) from a private/public key.

    HASH160 is RIPEMD160(SHA256).
    """
    pubkey, network = pubkeyinfo_from_key(key, network, compressed)
    h160 = hash160(pubkey)
    return h160, network


def hash160_from_script(script_pubkey: Script) -> bytes:
    "Return the RIPEMD160(SHA256) of the script_pubkey."

    if isinstance(script_pubkey, list):
        script_pubkey = serialize(script_pubkey)
    return hash160(script_pubkey)


def hash256_from_script(script_pubkey: Script) -> bytes:
    "Return the SHA256(SHA256) of the script_pubkey."
    if isinstance(script_pubkey, list):
        script_pubkey = serialize(script_pubkey)
    return sha256(script_pubkey)


def fingerprint(key: Key, network: Optional[str] = None) -> bytes:
    """Return the public key fingerprint from a private/public key.

    The fingerprint is the last four bytes
    of the compressed public key HASH160.
    """

    pubkey, _ = pubkeyinfo_from_key(key, network, compressed=True)
    return hash160(pubkey)[:4]


def reduce_to_hlen(msg: String, hf: HashF = hashlib.sha256) -> bytes:

    if isinstance(msg, str):
        msg = msg.encode()

    # Step 4 of SEC 1 v.2 section 4.1.3
    h = hf()
    h.update(msg)
    return h.digest()


def tagged_hash(tag: str, msg: String, hf: HashF = hashlib.sha256) -> bytes:

    t = tag.encode()
    h1 = hf()
    h1.update(t)
    tag_hash = h1.digest()

    h2 = hf()
    h2.update(tag_hash + tag_hash)

    # it could be sped up by storing the above midstate
    if isinstance(msg, str):
        msg = msg.encode()
    h2.update(msg)
    return h2.digest()
