#!/usr/bin/env python3

# Copyright (C) 2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional, Tuple, Union

from . import bip32
from .alias import Octets, String, XkeyDict
from .base58 import b58decode
from .curve import Curve
from .curves import secp256k1
from .network import (curve_from_network, network_from_wif_prefix,
                      network_from_xprv)
from .utils import bytes_from_octets

PrvKey = Union[int, bytes, str, XkeyDict]


def prvkey_info_from_wif(wif: String) -> Tuple[int, bool, str]:
    "Return (prvkey, compressed, network) info from WIF."

    if isinstance(wif, str):
        wif = wif.strip()

    payload = b58decode(wif)

    network = network_from_wif_prefix(payload[0:1])
    ec = curve_from_network(network)

    if len(payload) == ec.nsize + 2:       # compressed WIF
        compressed = True
        if payload[-1] != 0x01:            # must have a trailing 0x01
            raise ValueError("Not a compressed WIF: missing trailing 0x01")
        prvkey = payload[1:-1]
    elif len(payload) == ec.nsize + 1:     # uncompressed WIF
        compressed = False
        prvkey = payload[1:]
    else:
        raise ValueError(f"Wrong WIF size ({len(payload)})")

    q = int.from_bytes(prvkey, byteorder='big')
    if not 0 < q < ec.n:
        raise ValueError(f"Private key {hex(q)} not in [1, n-1]")

    return q, compressed, network


def prvkey_info_from_xprv(xprv: Union[XkeyDict, String]) -> Tuple[int, bool, str]:
    "Return (prvkey, compressed, network) info from BIP32xprv."

    if not isinstance(xprv, dict):
        xprv = bip32.deserialize(xprv)
    if xprv['key'][0] != 0:
        m = f"Not a private key: {bip32.serialize(xprv).decode()}"
        raise ValueError(m)

    network = network_from_xprv(xprv['version'])
    return xprv['q'], True, network


def prvkey_info_from_xprvwif(xprvwif: Union[XkeyDict, String]) -> Tuple[int, bool, str]:
    """Return (prvkey, compressed, network) info from WIF or BIP32xprv.

    Support WIF or BIP32 xprv.
    """

    if not isinstance(xprvwif, dict):
        try:
            return prvkey_info_from_wif(xprvwif)
        except Exception:
            pass

    return prvkey_info_from_xprv(xprvwif)


def prvkey_info_from_prvkey(prvkey: PrvKey,
                            compressed: Optional[bool] = None,
                            network: Optional[str] = None) -> Tuple[int, bool, str]:

    compr = True if compressed is None else compressed
    net = 'mainnet' if network is None else network
    ec = curve_from_network(net)

    if isinstance(prvkey, int):
        q = prvkey
    elif isinstance(prvkey, dict):
        q, compr, net = prvkey_info_from_xprvwif(prvkey)
        if compressed is not None:
            assert compr == compressed
        if network is not None:
            assert net == network 
        return q, compr, net
    else:
        try:
            q, compr, net = prvkey_info_from_xprvwif(prvkey)
        except Exception:
            pass
        else:
            if compressed is not None:
                assert compr == compressed
            if network is not None:
                assert net == network 
            return q, compr, net

        prvkey = bytes_from_octets(prvkey, ec.nsize)
        q = int.from_bytes(prvkey, 'big')

    if not 0 < q < ec.n:
        raise ValueError(f"Private key {hex(q).upper()} not in [1, n-1]")

    return q, compr, net


def int_from_prvkey(prvkey: PrvKey, ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer.
    
    It supports:

    - WIF (bytes or string)
    - BIP32 extended keys (bytes, string, or XkeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - integer (native int or hex-strin)
    """

    if isinstance(prvkey, int):
        q = prvkey
    elif isinstance(prvkey, dict):
        q, _, network = prvkey_info_from_xprvwif(prvkey)
        # q has been validated on the xprv/wif network
        ec2 =  curve_from_network(network)
        assert ec == ec2, f"ec / network ({network}) mismatch"
        return q
    else:
        try:
            q, _, network = prvkey_info_from_xprvwif(prvkey)
        except Exception:
            pass
        else:
            # q has been validated on the xprv/wif network
            ec2 =  curve_from_network(network)
            assert ec == ec2, f"ec / network ({network}) mismatch"
            return q

        prvkey = bytes_from_octets(prvkey, ec.nsize)
        q = int.from_bytes(prvkey, 'big')

    if not 0 < q < ec.n:
        raise ValueError(f"Private key {hex(q).upper()} not in [1, n-1]")

    return q
