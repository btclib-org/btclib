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
from .curve import Curve, Point
from .curves import secp256k1
from .utils import octets_from_point, point_from_octets


def to_pub_tuple(P: Union[Point, bip32.XkeyDict, bytes, str],
                 ec: Curve = secp256k1) -> Point:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        ec.require_on_curve(P)
        return P
    elif isinstance(P, dict):
        if P['q'] != 0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        else:
            return P['Q']
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['q'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            else:
                return xkey['Q']

    return point_from_octets(P, ec)


def to_pub_bytes(P: Union[Point, bytes, str, bip32.XkeyDict],
                 compressed: bool = True, ec: Curve = secp256k1) -> bytes:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        return octets_from_point(P, compressed, ec)
    elif isinstance(P, dict):
        if P['q'] != 0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        else:
            if compressed:
                return P['key']
            else:
                return octets_from_point(P['Q'], False, ec)
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['q'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            else:
                if compressed:
                    return xkey['key']
                else:
                    return octets_from_point(xkey['Q'], False, ec)

        Q = point_from_octets(P, ec)
        return octets_from_point(Q, compressed, ec)
