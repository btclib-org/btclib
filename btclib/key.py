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
from .utils import bytes_from_hexstring, octets_from_point, point_from_octets
from .wif import prvkey_from_wif, wif_from_prvkey


def to_prv_int(q: Union[int, bip32.XkeyDict, bytes, str], ec: Curve = secp256k1) -> int:
    """Return a private key int from any possible key representation.

    Support:

    - BIP32 extended keys (bytes, string, or XkeyDict)
    - WIF keys (bytes or string)
    - Octets (bytes or hex-string)
    - native int
    """

    if isinstance(q, int):
        q2 = q
    elif isinstance(q, dict):
        if q['prvkey'] != 0:
            return q['prvkey']
        else:
            raise ValueError(f"Not a private key: {q['key'].hex()}")
    else:
        try:
            q2, _, _ = prvkey_from_wif(q)
        except Exception:
            pass
        else:
            return q2

        try:
            xkey = bip32.deserialize(q)
        except Exception:
            pass
        else:
            if xkey['prvkey'] != 0:
                return xkey['prvkey']
            else:
                raise ValueError(f"Not a private key: {xkey['key'].hex()}")

        try:
            q = bytes_from_hexstring(q)
            if len(q) != ec.nsize:
                m = "Invalid private key size: "
                m += f"{len(q)} bytes instead of {ec.nsize}"
                raise ValueError(m)
            q2 = int.from_bytes(q, 'big')
        except Exception:
            raise ValueError("not a private key")

    if not 0 < q2 < ec.n:
        raise ValueError(f"private key {hex(q2)} not in [1, n-1]")

    return q2


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
        if P['prvkey'] != 0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        else:
            return P['Point']
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['prvkey'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            else:
                return xkey['Point']

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
        if P['prvkey'] != 0:
            raise ValueError(f"Not a public key: {P['key'].hex()}")
        else:
            if compressed:
                return P['key']
            else:
                return octets_from_point(P['Point'], False, ec)
    else:
        try:
            xkey = bip32.deserialize(P)
        except Exception:
            pass
        else:
            if xkey['prvkey'] != 0:
                raise ValueError(f"Not a public key: {xkey['key'].hex()}")
            else:
                if compressed:
                    return xkey['key']
                else:
                    return octets_from_point(xkey['Point'], False, ec)

        Q = point_from_octets(P, ec)
        return octets_from_point(Q, compressed, ec)
