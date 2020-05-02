#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional

from .alias import PrvKey
from .base58 import b58encode
from .curve import Curve
from .network import NETWORKS
from .to_pubkey import prvkey_info_from_prvkey


def wif_from_prvkey(prvkey: PrvKey, network: Optional[str] = None,
                    compressed: Optional[bool] = None) -> bytes:
    "Return the WIF encoding of a private key."

    q, net, compr = prvkey_info_from_prvkey(prvkey, network, compressed)
    ec = NETWORKS[net]['curve']

    payload = NETWORKS[net]['wif']
    payload += q.to_bytes(ec.nsize, 'big')
    payload += b'\x01' if compr else b''
    return b58encode(payload)
