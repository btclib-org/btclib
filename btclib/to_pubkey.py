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
from .alias import Point, PubKey
from .curve import Curve
from .curves import secp256k1
from .utils import bytes_from_hexstring, octets_from_point, point_from_octets

# TODO: raise exception for infinite point?

def to_pub_tuple(P: Union[Point, bip32.XkeyDict, bytes, str], ec: Curve) -> Point:
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
        return P['Q']
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['q'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            return xkey['Q']

    return point_from_octets(P, ec)


def to_pub_bytes(P: Union[Point, bytes, str, bip32.XkeyDict], compressed: bool, ec: Curve) -> bytes:
    """Return a public key tuple from any possible representation.

    It supports:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - Octets (bytes or hex-string)
    - native tuple
    """

    if isinstance(P, tuple):
        return octets_from_point(P, compressed, ec)
    elif isinstance(P, dict):
        if not compressed:
            m = "Uncompressed BIP32 / compressed SEC key mismatch"
            raise ValueError(m)
        if P['q'] != 0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        return P['key']
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if not compressed:
                m = "Uncompressed BIP32 / compressed SEC key mismatch"
                raise ValueError(m)
            if xkey['q'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            return xkey['key']


        pubkey = bytes_from_hexstring(P)
        if not compressed and len(pubkey) != 2*ec.psize + 1:
            m = f"Wrong size ({len(pubkey)}-bytes) for uncompressed SEC key"
            raise ValueError(m)
        if compressed and len(pubkey) != ec.psize + 1:
            m = f"Wrong size ({len(pubkey)}-bytes) for compressed SEC key"
            raise ValueError(m)
        Q = point_from_octets(pubkey, ec)  # verify it is a valid point
        return octets_from_point(Q, compressed, ec)
