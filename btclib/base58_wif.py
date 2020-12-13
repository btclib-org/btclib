#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional

from .base58 import b58encode
from .network import NETWORKS
from .to_prv_key import PrvKey, prv_keyinfo_from_prv_key


def wif_from_prv_key(
    prv_key: PrvKey, network: Optional[str] = None, compressed: Optional[bool] = None
) -> str:
    "Return the WIF encoding of a private key."

    q, net, compr = prv_keyinfo_from_prv_key(prv_key, network, compressed)
    ec = NETWORKS[net].curve

    payload = NETWORKS[net].wif
    payload += q.to_bytes(ec.nsize, byteorder="big", signed=False)
    payload += b"\x01" if compr else b""
    return b58encode(payload).decode("ascii")
