#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Union

from . import bip32
from .alias import Octets
from .base58wif import prvkeytuple_from_wif, prvkeytuple_from_xprv
from .curve import Curve
from .curves import secp256k1
from .utils import bytes_from_octets


def to_prvkey_int(prvkey: Union[int, bytes, str, bip32.XkeyDict], ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer.
    
    It supports:

    - WIF (bytes or string)
    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(prvkey, int):
        q = prvkey
    elif isinstance(prvkey, dict):
        q, _, _ = prvkeytuple_from_xprv(prvkey)
        # it has been already validated as 0 < q < n
        return q
    else:
        try:
            q, _, _ = prvkeytuple_from_xprv(prvkey)
        except Exception:
            pass
        else:
            # it has been already validated as 0 < q < n
            return q

        try:
            q, _, _ = prvkeytuple_from_wif(prvkey)
        except Exception:
            pass
        else:
            # it has been already validated as 0 < q < n
            return q

        prvkey = bytes_from_octets(prvkey, ec.nsize)
        q = int.from_bytes(prvkey, 'big')

    if not 0 < q < ec.n:
        raise ValueError(f"Private key {hex(q).upper()} not in [1, n-1]")

    return q
