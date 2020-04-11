#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional, Tuple, TypedDict, Union

from . import bip32
from .alias import Octets, String, XkeyDict
from .base58 import b58decode, b58encode
from .curve import Curve
from .curvemult import mult
from .curves import secp256k1
from .network import (curve_from_network, network_from_xprv,
                      wif_prefix_from_network)
from .secpoint import bytes_from_point, point_from_octets
from .utils import bytes_from_octets


def wif_from_xprv(xprv: Union[XkeyDict, String]) -> bytes:
    """Return the WIF encoding of a BIP32 extended private key.

    The WIF is always of the compressed kind,
    as this is the default public key representation in BIP32.
    """

    # the next few lines of code could be replaced by info_from_xprv
    # but the last few lines of code need intermediate results
    if not isinstance(xprv, dict):
        xprv = bip32.deserialize(xprv)

    if xprv['key'][0] != 0:
        raise ValueError(f"Not a private key: {bip32.serialize(xprv).decode}")
    
    network = network_from_xprv(xprv['version'])
    payload = wif_prefix_from_network(network)
    payload += xprv['key'][1:] + b'\x01'
    return b58encode(payload)


def wif_from_prvkey(q: Union[int, Octets],
                    compressed: bool = True,
                    network: str = 'mainnet') -> bytes:
    """Return the WIF encoding of a private key integer."""

    ec = curve_from_network(network)
    payload = wif_prefix_from_network(network)
    if not isinstance(q, int):
        q = bytes_from_octets(q, ec.nsize)
        payload += q
        q = int.from_bytes(q, byteorder='big')
    else:
        payload += q.to_bytes(ec.nsize, 'big')
        q = q

    if not 0 < q < ec.n:
        raise ValueError(f"private key {hex(q)} not in (0, ec.n)")

    payload += b'\x01' if compressed else b''
    return b58encode(payload)
