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

from typing import Optional, Tuple

from .alias import PubKey, Script
from .script import encode
from .to_pubkey import bytes_from_pubkey
from .utils import hash160, sha256


# TODO rename as hash160
def hash160_from_pubkey(pubkey: PubKey, compressed: Optional[bool] = None,
                        network: Optional[str] = None) -> Tuple[bytes, str]:
    pubkey, network = bytes_from_pubkey(pubkey, compressed, network)
    h160 = hash160(pubkey)
    return h160, network


def hash160_from_script(script: Script) -> bytes:
    if isinstance(script, list):
        script = encode(script)
    return hash160(script)


def hash256_from_script(script: Script) -> bytes:
    if isinstance(script, list):
        script = encode(script)
    return sha256(script)
