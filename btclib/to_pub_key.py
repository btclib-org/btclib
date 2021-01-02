#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Functions for conversions between different public key formats."

from typing import Optional, Tuple, Union

from btclib.alias import Point
from btclib.bip32.bip32 import BIP32Key, BIP32KeyData
from btclib.ecc.curve import Curve, mult, secp256k1
from btclib.ecc.sec_point import bytes_from_point, point_from_octets
from btclib.exceptions import BTClibValueError
from btclib.network import (
    NETWORKS,
    curve_from_xkeyversion,
    network_from_xkeyversion,
    xpubversions_from_network,
)
from btclib.to_prv_key import PrvKey, prv_keyinfo_from_prv_key
from btclib.utils import bytes_from_octets

# public key inputs:
# elliptic curve point as Union[Octets, BIP32Key, Point]
PubKey = Union[bytes, str, BIP32KeyData, Point]

# public or private key input,
# usable wherever a PubKey is logically expected
Key = Union[int, bytes, str, BIP32KeyData, Point]


def _point_from_xpub(xpub: BIP32Key, ec: Curve) -> Point:
    "Return an elliptic curve point tuple from a xpub key."

    if isinstance(xpub, BIP32KeyData):
        xpub.assert_valid()
    else:
        xpub = BIP32KeyData.b58decode(xpub)

    if xpub.key[0] in (2, 3):
        ec2 = curve_from_xkeyversion(xpub.version)
        if ec != ec2:
            raise BTClibValueError(f"ec/xpub version ({xpub.version.hex()}) mismatch")
        return point_from_octets(xpub.key, ec)
    raise BTClibValueError(f"not a public key: {xpub.key.hex()}")


def point_from_key(key: Key, ec: Curve = secp256k1) -> Point:
    """Return a point tuple from any possible key representation.

    It supports:

    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """

    if isinstance(key, tuple):
        return point_from_pub_key(key, ec)
    if isinstance(key, int):
        q, _, _ = prv_keyinfo_from_prv_key(key)
        return mult(q, ec.G, ec)
    try:
        q, net, _ = prv_keyinfo_from_prv_key(key)
    except BTClibValueError:
        pass
    else:
        if ec != NETWORKS[net].curve:
            raise BTClibValueError("Curve mismatch")
        return mult(q, ec.G, ec)

    return point_from_pub_key(key, ec)


def point_from_pub_key(pub_key: PubKey, ec: Curve = secp256k1) -> Point:
    "Return an elliptic curve point tuple from a public key."

    if isinstance(pub_key, tuple):
        if ec.is_on_curve(pub_key) and pub_key[1] != 0:
            return pub_key
        raise BTClibValueError(f"not a valid public key: {pub_key}")
    if isinstance(pub_key, BIP32KeyData):
        return _point_from_xpub(pub_key, ec)
    try:
        return _point_from_xpub(pub_key, ec)
    except (TypeError, BTClibValueError):
        pass

    # it must be octets
    try:
        return point_from_octets(pub_key, ec)
    except (TypeError, ValueError) as e:
        raise BTClibValueError(f"not a public key: {pub_key!r}") from e


# not used so far, probably useless
# def point_from_prv_key(prv_key: PrvKey, network: Optional[str] = None)->Point:
#    "Return an elliptic curve point tuple from a private key."
#
#    q, net, compr = prv_keyinfo_from_prv_key(prv_key, network)
#    ec = NETWORKS[net]['curve']
#    return mult(q, ec.G, ec)


PubkeyInfo = Tuple[bytes, str]


def _pub_keyinfo_from_xpub(
    xpub: BIP32Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubkeyInfo:
    """Return the pub_key tuple (SEC-bytes, network) from a BIP32 xpub.

    BIP32Key is always compressed and includes network information:
    here the 'network, compressed' input parameters are passed
    only to allow consistency checks.
    """

    compressed = True if compressed is None else compressed
    if not compressed:
        raise BTClibValueError("Uncompressed SEC / compressed BIP32 mismatch")

    if isinstance(xpub, BIP32KeyData):
        xpub.assert_valid()
    else:
        xpub = BIP32KeyData.b58decode(xpub)

    if xpub.key[0] not in (2, 3):
        err_msg = f"not a public key: {xpub.b58encode()}"
        raise BTClibValueError(err_msg)

    if network is None:
        return xpub.key, network_from_xkeyversion(xpub.version)

    allowed_versions = xpubversions_from_network(network)
    if xpub.version not in allowed_versions:
        err_msg = f"Not a {network} key: "
        err_msg += f"{xpub.b58encode()}"
        raise BTClibValueError(err_msg)

    return xpub.key, network


def pub_keyinfo_from_key(
    key: Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubkeyInfo:
    "Return the pub key tuple (SEC-bytes, network) from a pub/prv key."

    if isinstance(key, tuple):
        return pub_keyinfo_from_pub_key(key, network, compressed)
    if isinstance(key, int):
        return pub_keyinfo_from_prv_key(key, network, compressed)
    try:
        return pub_keyinfo_from_pub_key(key, network, compressed)
    except BTClibValueError:
        pass

    # it must be a prv_key
    try:
        return pub_keyinfo_from_prv_key(key, network, compressed)
    except BTClibValueError as e:
        err_msg = "not a private or"
        if compressed is not None:
            err_msg += " compressed" if compressed else " uncompressed"
        err_msg += " public key"
        if network is not None:
            err_msg += f" for {network}"
        err_msg += f": {key!r}"
        raise BTClibValueError(err_msg) from e


def pub_keyinfo_from_pub_key(
    pub_key: PubKey, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubkeyInfo:
    "Return the pub key tuple (SEC-bytes, network) from a public key."

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = NETWORKS[net].curve

    if isinstance(pub_key, tuple):
        return bytes_from_point(pub_key, ec, compr), net
    if isinstance(pub_key, BIP32KeyData):
        return _pub_keyinfo_from_xpub(pub_key, network, compressed)
    try:
        return _pub_keyinfo_from_xpub(pub_key, network, compressed)
    except (TypeError, BTClibValueError):
        pass

    # it must be octets
    try:
        if compressed is None:
            pub_key = bytes_from_octets(pub_key, (ec.p_size + 1, 2 * ec.p_size + 1))
            compr = False
            if len(pub_key) == ec.p_size + 1:
                compr = True
        else:
            size = ec.p_size + 1 if compressed else 2 * ec.p_size + 1
            pub_key = bytes_from_octets(pub_key, size)
            compr = compressed
    except (TypeError, ValueError) as e:
        err_msg = f"not a public key: {pub_key!r}"
        raise BTClibValueError(err_msg) from e

    # verify that it is a valid point
    Q = point_from_octets(pub_key, ec)

    return bytes_from_point(Q, ec, compr), net


def pub_keyinfo_from_prv_key(
    prv_key: PrvKey, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PubkeyInfo:
    "Return the pub key tuple (SEC-bytes, network) from a private key."

    q, net, compr = prv_keyinfo_from_prv_key(prv_key, network, compressed)
    ec = NETWORKS[net].curve
    pub_key = mult(q, ec.G, ec)
    return bytes_from_point(pub_key, ec, compr), net
