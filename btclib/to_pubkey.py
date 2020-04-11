#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import Tuple, Union

from . import bip32
from .alias import Octets, Point, PubKey, String, XkeyDict
from .curve import Curve
from .curvemult import mult
from .curves import secp256k1
from .network import (_xpub_versions_from_network, curve_from_xpubversion,
                      curve_from_network)
from .secpoint import bytes_from_point, point_from_octets
from .to_prvkey import prvkey_info_from_xprvwif
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


def _bytes_from_xpub(xpubd: XkeyDict, compr: bool, network: str) -> bytes:
        if not compr:
            m = "Uncompressed SEC / compr BIP32 key mismatch"
            raise ValueError(m)
        if xpubd['version'] not in _xpub_versions_from_network(network):
            m = f"network ({network}) / "
            m += f"BIP32 key ({bip32.serialize(xpubd).decode()}) mismatch"
            raise ValueError(m)
        if xpubd['key'][0] in (2, 3):
            return xpubd['key']
        raise ValueError(f"Not a public key: {xpubd['key'].hex()}")


def bytes_from_pubkey(P: PubKey,
                      compr: bool = True, network: str = 'mainnet') -> bytes:
    """Return SEC bytes from any possible pubkey representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - native tuple
    """

    if isinstance(P, tuple):
        ec = curve_from_network(network)
        return bytes_from_point(P, compr, ec)
    elif isinstance(P, dict):
        return _bytes_from_xpub(P, compr, network)
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            return _bytes_from_xpub(xkey, compr, network)

    ec = curve_from_network(network)
    pubkey = bytes_from_octets(P)
    if not compr and len(pubkey) != 2*ec.psize + 1:
        m = f"Wrong size ({len(pubkey)}-bytes) for uncompressed SEC key"
        raise ValueError(m)
    if compr and len(pubkey) != ec.psize + 1:
        m = f"Wrong size ({len(pubkey)}-bytes) for compr SEC key"
        raise ValueError(m)
    Q = point_from_octets(pubkey, ec)  # verify it is a valid point
    return bytes_from_point(Q, compr, ec)


def pubkeyinfo_from_xprvwif(xprvwif: Union[XkeyDict, String]) -> Tuple[bytes, bool, str]:

    prvkey, compr, network = prvkey_info_from_xprvwif(xprvwif)
    ec = curve_from_network(network)
    Pub = mult(prvkey, ec.G, ec)
    pubkey = bytes_from_point(Pub, compr, ec)
    return pubkey, compr, network
