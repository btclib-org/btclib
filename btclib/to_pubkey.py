#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Optional, Tuple

from . import bip32
from .alias import BIP32Key, Key, Point, PrvKey, PubKey
from .curve import Curve, mult, secp256k1
from .network import (
    NETWORKS,
    curve_from_xkeyversion,
    network_from_xkeyversion,
    xpubversions_from_network,
)
from .secpoint import bytes_from_point, point_from_octets
from .to_prvkey import prvkeyinfo_from_prvkey
from .utils import bytes_from_octets


def _point_from_xpub(xpub: BIP32Key, ec: Curve) -> Point:
    "Return an elliptic curve point tuple from a xpub key."

    if isinstance(xpub, dict):
        # ensure it is a valid BIP32KeyDict
        bip32.serialize(xpub)
    else:
        xpub = bip32.deserialize(xpub)

    if xpub["key"][0] in (2, 3):
        ec2 = curve_from_xkeyversion(xpub["version"])
        if ec != ec2:
            raise ValueError(f"ec/xpub version ({xpub['version'].hex()}) mismatch")
        return point_from_octets(xpub["key"], ec)
    raise ValueError(f"Not a public key: {xpub['key'].hex()}")


def point_from_key(key: Key, ec: Curve = secp256k1) -> Point:
    """Return a point tuple from any possible key representation.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """

    if isinstance(key, tuple):
        return point_from_pubkey(key, ec)
    elif isinstance(key, int):
        q, _, _ = prvkeyinfo_from_prvkey(key)
        return mult(q, ec.G, ec)
    else:
        try:
            q, net, _ = prvkeyinfo_from_prvkey(key)
        except Exception:
            pass
        else:
            if ec != NETWORKS[net]["curve"]:
                raise ValueError("Curve mismatch")
            return mult(q, ec.G, ec)

    return point_from_pubkey(key, ec)


def point_from_pubkey(pubkey: PubKey, ec: Curve = secp256k1) -> Point:
    "Return an elliptic curve point tuple from a public key."

    if isinstance(pubkey, tuple):
        if ec.is_on_curve(pubkey) and pubkey[1] != 0:
            return pubkey
        raise ValueError(f"not a valid public key: {pubkey}")
    elif isinstance(pubkey, dict):
        return _point_from_xpub(pubkey, ec)
    else:
        try:
            return _point_from_xpub(pubkey, ec)
        except Exception:
            pass

    # it must be octets
    try:
        return point_from_octets(pubkey, ec)
    except Exception:
        raise ValueError(f"Not a public key: {pubkey!r}")


# not used so far, probably useless
# def point_from_prvkey(prvkey: PrvKey, network: Optional[str] = None)->Point:
#    "Return an elliptic curve point tuple from a private key."
#
#    q, net, compr = prvkeyinfo_from_prvkey(prvkey, network)
#    ec = NETWORKS[net]['curve']
#    return mult(q, ec.G, ec)


PubKeyInfo = Tuple[bytes, str]


def _pubkeyinfo_from_xpub(
    xpub: BIP32Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubKeyInfo:
    """Return the pubkey tuple (SEC-bytes, network) from a BIP32 xpub.

    BIP32Key is always compressed and includes network information:
    here the 'network, compressed' input parameters are passed
    only to allow consistency checks.
    """

    compressed = True if compressed is None else compressed
    if not compressed:
        raise ValueError("Uncompressed SEC / compressed BIP32 mismatch")

    if isinstance(xpub, dict):
        # ensure it is a valid BIP32KeyDict
        bip32.serialize(xpub)
    else:
        xpub = bip32.deserialize(xpub)

    if xpub["key"][0] not in (2, 3):
        m = f"Not a public key: {bip32.serialize(xpub).decode()}"
        raise ValueError(m)

    if network is not None:
        allowed_versions = xpubversions_from_network(network)
        if xpub["version"] not in allowed_versions:
            m = f"Not a {network} key: "
            m += f"{bip32.serialize(xpub).decode()}"
            raise ValueError(m)
        return xpub["key"], network
    else:
        return xpub["key"], network_from_xkeyversion(xpub["version"])


def pubkeyinfo_from_key(
    key: Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubKeyInfo:
    "Return the pub key tuple (SEC-bytes, network) from a pub/prv key."

    if isinstance(key, tuple):
        return pubkeyinfo_from_pubkey(key, network, compressed)
    elif isinstance(key, int):
        return pubkeyinfo_from_prvkey(key, network, compressed)
    else:
        try:
            return pubkeyinfo_from_pubkey(key, network, compressed)
        except Exception:
            pass

    # it must be a prvkey
    try:
        return pubkeyinfo_from_prvkey(key, network, compressed)
    except Exception:
        err_msg = "not a private or"
        if compressed is not None:
            err_msg += " compressed" if compressed else " uncompressed"
        err_msg += " public key"
        if network is not None:
            err_msg += f" for {network}"
        err_msg += f": {key!r}"
        raise ValueError(err_msg)


def pubkeyinfo_from_pubkey(
    pubkey: PubKey, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubKeyInfo:
    "Return the pub key tuple (SEC-bytes, network) from a public key."

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = NETWORKS[net]["curve"]

    if isinstance(pubkey, tuple):
        return bytes_from_point(pubkey, ec, compr), net
    elif isinstance(pubkey, dict):
        return _pubkeyinfo_from_xpub(pubkey, network, compressed)
    else:
        try:
            return _pubkeyinfo_from_xpub(pubkey, network, compressed)
        except Exception:
            pass

    # it must be octets
    try:
        if compressed is None:
            pubkey = bytes_from_octets(pubkey, (ec.psize + 1, 2 * ec.psize + 1))
            compr = False
            if len(pubkey) == ec.psize + 1:
                compr = True
        else:
            size = ec.psize + 1 if compressed else 2 * ec.psize + 1
            pubkey = bytes_from_octets(pubkey, size)
            compr = compressed
    except Exception:
        raise ValueError("Not a public key")

    # verify that it is a valid point
    Q = point_from_octets(pubkey, ec)

    return bytes_from_point(Q, ec, compr), net


def pubkeyinfo_from_prvkey(
    prvkey: PrvKey, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubKeyInfo:
    "Return the pub key tuple (SEC-bytes, network) from a private key."

    q, net, compr = prvkeyinfo_from_prvkey(prvkey, network, compressed)
    ec = NETWORKS[net]["curve"]
    Pub = mult(q, ec.G, ec)
    pubkey = bytes_from_point(Pub, ec, compr)
    return pubkey, net
