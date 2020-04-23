#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional, Tuple, Union

from . import bip32
from .alias import Octets, Point, PubKey, String, XkeyDict, Key
from .curve import Curve
from .curvemult import mult
from .curves import secp256k1
from .network import (_xpub_versions_from_network, curve_from_network,
                      curve_from_xpubversion, network_from_xpub)
from .secpoint import bytes_from_point, point_from_octets
from .to_prvkey import PrvKey, prvkey_info_from_prvkey
from .utils import bytes_from_octets, hash160


def _point_from_xpub(xpubd: XkeyDict, ec: Curve) -> Point:
    if xpubd['key'][0] in (2, 3):
        ec2 = curve_from_xpubversion(xpubd['version'])
        if ec != ec2:
            raise ValueError(
                f"ec/xpub version ({xpubd['version'].hex()}) mismatch")
        return point_from_octets(xpubd['key'], ec)
    raise ValueError(f"Not a public key: {xpubd['key'].hex()}")


def point_from_key(key: Key, ec: Curve = secp256k1) -> Point:
    """Return a point tuple from any possible key representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """
    try:
        q, net, _ = prvkey_info_from_prvkey(key)
    except:
        pass
    else:
        if ec != curve_from_network(net):
            raise ValueError("Curve mismatch")
        return mult(q, ec.G, ec)

    return point_from_pubkey(key, ec)


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


def _bytes_from_xpub(xpubd: XkeyDict, network: Optional[str] = None,
                     compressed: Optional[bool] = None) -> Tuple[bytes, str]:
    # XkeyDict is always compressed and has information about the network
    # the network, compressed input parameters are passed only for the
    # consistency checks

    if xpubd['key'][0] not in (2, 3):
        raise ValueError(f"Not a public key: {xpubd['key'].hex()}")

    if compressed is not None:
        if not compressed:
            raise ValueError("Uncompressed SEC / compressed BIP32 mismatch")

    if network is not None:
        allowed_xpubs = _xpub_versions_from_network(network)
        if xpubd['version'] not in allowed_xpubs:
            m = f"Not a key for ({network}) network: "
            m += f"{bip32.serialize(xpubd).decode()}"
            raise ValueError(m)
        return xpubd['key'], network
    else:
        return xpubd['key'], network_from_xpub(xpubd['version'])


def bytes_from_key(key: Key, network: Optional[str] = None,
                   compressed: Optional[bool] = None) -> Tuple[bytes, str]:

    try:
        P, network = pubkey_info_from_prvkey(key, network, compressed)
    except:
        P = key

    return bytes_from_pubkey(P, network, compressed)


def bytes_from_pubkey(P: PubKey, network: Optional[str] = None,
                      compressed: Optional[bool] = None) -> Tuple[bytes, str]:
    """Return (SEC-bytes, network) from any possible pubkey representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """

    if isinstance(P, tuple):
        compr = True if compressed is None else compressed
        net = 'mainnet' if network is None else network
        ec = curve_from_network(net)
        return bytes_from_point(P, ec, compr), net
    elif isinstance(P, dict):
        return _bytes_from_xpub(P, network, compressed)
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            return _bytes_from_xpub(xkey, network, compressed)

    net = 'mainnet' if network is None else network
    ec = curve_from_network(net)

    if compressed is None:
        pubkey = bytes_from_octets(P)
        size = len(pubkey)
        if size == ec.psize + 1:
            compr = True
        elif size == 2 * ec.psize + 1:
            compr = False
    else:
        size = ec.psize + 1 if compressed else 2 * ec.psize + 1
        compr = compressed
        pubkey = bytes_from_octets(P, size)

    # verify that it is a valid point
    Q = point_from_octets(pubkey, ec)

    return bytes_from_point(Q, ec, compr), net


def pubkey_info_from_prvkey(prvkey: PrvKey, network: Optional[str] = None,
                            compressed: Optional[bool] = None) -> Tuple[bytes, str]:

    q, net, compr = prvkey_info_from_prvkey(prvkey, network, compressed)
    ec = curve_from_network(net)
    Pub = mult(q, ec.G, ec)
    pubkey = bytes_from_point(Pub, ec, compr)
    return pubkey, net


def fingerprint(key: Key, network: Optional[str] = None) -> bytes:

    pubkey, _ = bytes_from_key(key, network, compressed=True)
    return hash160(pubkey)[:4]
