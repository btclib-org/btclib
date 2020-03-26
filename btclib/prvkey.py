#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Union

from .bip32 import wif_from_xprv
from .curve import Curve
from .curves import secp256k1
from .utils import int_from_octets
from .wif import prvkey_from_wif, wif_from_prvkey


def prvkey_int(q: Union[int, bytes, str],
               ec: Curve = secp256k1) -> int:

    if isinstance(q, int):
        q2 = q
    else:
        try:
            q2, _, _ = prvkey_from_wif(q)
        except Exception:
            pass
        else:
            return q2

        try:
            wif = wif_from_xprv(q)
        except Exception:
            pass
        else:
            q2, _, _ = prvkey_from_wif(wif)
            return q2

        try:
            q2 = int_from_octets(q)
        except Exception:
            raise ValueError("not a private key")

    if not 0 < q2 < ec.n:
        raise ValueError(f"private key {hex(q2)} not in [1, n-1]")

    return q2
