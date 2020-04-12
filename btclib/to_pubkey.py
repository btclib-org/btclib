#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union, Optional

from . import bip32
from .alias import Octets, Point, PubKey, String, XkeyDict
from .curve import Curve
from .curvemult import mult
from .curves import secp256k1
from .network import (_xpub_versions_from_network, curve_from_xpubversion,
                      curve_from_network, network_from_xpub)
from .secpoint import bytes_from_point, point_from_octets
from .to_prvkey import prvkey_info_from_prvkey, PrvKey
from .utils import bytes_from_octets


def _point_from_xpub(xpubd: XkeyDict, ec: Curve) -> Point:
    if xpubd['key'][0] in (2, 3):
        ec2 = curve_from_xpubversion(xpubd['version'])
        assert ec == ec2, f"ec/xpub version ({xpubd['version']!r}) mismatch"
        return point_from_octets(xpubd['key'], ec)
    raise ValueError(f"Not a public key: {xpubd['key'].hex()}")


def point_from_pubkey(P: PubKey, ec: Curve = secp256k1) -> Point:
    """Return a point tuple from any possible pubkey representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """

    if isinstance(P, tuple):
        if ec.is_on_curve(P) and P[1] != 0:
            return P
        raise ValueError(f"Not a public key: {P}")
    elif isinstance(P, dict):
        return _point_from_xpub(P, ec)
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            return _point_from_xpub(xkey, ec)

    return point_from_octets(P, ec)


def _bytes_from_xpub(xpubd: XkeyDict,
                     compressed: Optional[bool] = None,
                     network: Optional[str] = None) -> Tuple[bytes, str]:

    if xpubd['key'][0] not in (2, 3):
        raise ValueError(f"Not a public key: {xpubd['key'].hex()}")

    if compressed is not None:
        if not compressed:
            raise ValueError("Uncompressed SEC / compressed BIP32 mismatch")

    if network is not None:
        allowed_xpubs = _xpub_versions_from_network(network)
        if xpubd['version'] not in allowed_xpubs:
            m = f"network ({network}) / "
            m += f"BIP32 key ({bip32.serialize(xpubd).decode()}) mismatch"
            raise ValueError(m)
        return xpubd['key'], network
    else:
        return xpubd['key'], network_from_xpub(xpubd['version'])


def bytes_from_pubkey(P: PubKey,
                      compressed: Optional[bool] = None,
                      network: Optional[str] = None) -> Tuple[bytes, str]:
    """Return SEC bytes from any possible pubkey representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """

    if isinstance(P, tuple):
        compr = True if compressed is None else compressed
        net = 'mainnet' if network is None else network
        ec = curve_from_network(net)
        return bytes_from_point(P, compr, ec), net
    elif isinstance(P, dict):
        return _bytes_from_xpub(P, compressed, network)
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            return _bytes_from_xpub(xkey, compressed, network)

    net = 'mainnet' if network is None else network
    ec = curve_from_network(net)

    if compressed is None:
        pubkey = bytes_from_octets(P)
        size = len(pubkey)
        if size == ec.psize + 1:
            compr = True
        elif size == 2* ec.psize + 1:
            compr = False
    else:
        size = ec.psize + 1 if compressed else 2* ec.psize + 1
        compr = compressed
        pubkey = bytes_from_octets(P, size)

    # verify that it is a valid point
    Q = point_from_octets(pubkey, ec)

    return bytes_from_point(Q, compr, ec), net


def pubkey_info_from_prvkey(prvkey: PrvKey, compressed: Optional[bool] = None,
                            network: Optional[str] = None) -> Tuple[bytes, str]:

    q, compr, net = prvkey_info_from_prvkey(prvkey, compressed, network)
    ec = curve_from_network(net)
    Pub = mult(q, ec.G, ec)
    pubkey = bytes_from_point(Pub, compr, ec)
    return pubkey, net


def pubkey_info_from_pubkey(pubkey: PubKey, compressed: Optional[bool] = None,
                            network: Optional[str] = None) -> Tuple[bytes, str]:

    pubkey, network = bytes_from_pubkey(pubkey, compressed, network)

    return pubkey, network
