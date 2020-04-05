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
from .alias import Octets, Point, PubKey
from .curve import Curve
from .curves import secp256k1
from .secpoint import bytes_from_point, point_from_octets
from .utils import bytes_from_octets


def to_pub_tuple(P: Union[Point, bip32.XkeyDict, bytes, str], ec: Curve) -> Point:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        if ec.is_on_curve(P) and P[1] != 0:
            return P
        raise ValueError(f"Not a public key: {P}")
    elif isinstance(P, dict):
        if P['key'][0] in (2, 3):
            return point_from_octets(P['key'], ec)
        raise ValueError(f"Not a public key: {P['key'].hex()}")
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['key'][0] in (2, 3):
                return point_from_octets(xkey['key'], ec)
            raise ValueError(f"Not a public key: {xkey['key'].hex()}")

    return point_from_octets(P, ec)


def to_pub_bytes(P: Union[Point, bip32.XkeyDict, bytes, str], compressed: bool, ec: Curve) -> bytes:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        return bytes_from_point(P, compressed, ec)
    elif isinstance(P, dict):
        if not compressed:
            m = "Uncompressed SEC / compressed BIP32 key mismatch"
            raise ValueError(m)
        if P['key'][0] in (2, 3):
            return P['key']
        raise ValueError(f"Not a public key: {P['key'].hex()}")
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if not compressed:
                m = "Uncompressed SEC / compressed BIP32 key mismatch"
                raise ValueError(m)
            if xkey['key'][0] in (2, 3):
                return xkey['key']
            raise ValueError(f"Not a public key: {xkey['key'].hex()}")


        pubkey = bytes_from_octets(P)
        if not compressed and len(pubkey) != 2*ec.psize + 1:
            m = f"Wrong size ({len(pubkey)}-bytes) for uncompressed SEC key"
            raise ValueError(m)
        if compressed and len(pubkey) != ec.psize + 1:
            m = f"Wrong size ({len(pubkey)}-bytes) for compressed SEC key"
            raise ValueError(m)
        Q = point_from_octets(pubkey, ec)  # verify it is a valid point
        return bytes_from_point(Q, compressed, ec)
