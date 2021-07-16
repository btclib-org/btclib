#!/usr/bin/env python3

# Copyright (C) 2020-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"Functions for conversions between different private key formats."

from typing import Optional, Tuple

from btclib.alias import String, Union
from btclib.base58 import b58decode
from btclib.bip32.bip32 import BIP32Key, BIP32KeyData
from btclib.ecc.curve import Curve, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.network import (
    NETWORKS,
    network_from_key_value,
    network_from_xkeyversion,
    xprvversions_from_network,
)
from btclib.utils import bytes_from_octets

# private key inputs:
# integer as Union[int, Octets]
# BIP32key as BIP32Key
# WIF as String
#
# BIP32key and WIF also provide extra info about
# network and (un)compressed-pub_key-derivation
PrvKey = Union[int, bytes, str, BIP32KeyData]


def int_from_prv_key(prv_key: PrvKey, ec: Curve = secp256k1) -> int:
    """Return a verified-as-valid private key integer.

    It supports:

    - WIF (bytes or string)
    - BIP32 extended keys (bytes, string, or BIP32KeyData)
    - SEC Octets (bytes or hex-string, with 02, 03, or 04 prefix)
    - integer (native int or hex-strin)

    Network and compressed informations from the input key
    are not used.
    """

    if isinstance(prv_key, int):
        q = prv_key
    elif isinstance(prv_key, BIP32KeyData):
        q, network, _ = _prv_keyinfo_from_xprv(prv_key)
        # q has been validated on the xprv/wif network
        ec2 = NETWORKS[network].curve
        if ec != ec2:
            raise BTClibValueError(f"ec / network ({network}) mismatch")
        return q
    else:
        try:
            q, network, _ = _prv_keyinfo_from_xprvwif(prv_key)
        except ValueError:
            pass
        else:
            # q has been validated on the xprv/wif network
            ec2 = NETWORKS[network].curve
            if ec != ec2:
                raise BTClibValueError(f"ec / network ({network}) mismatch")
            return q

        # it must be octets
        try:
            prv_key = bytes_from_octets(prv_key, ec.n_size)
            q = int.from_bytes(prv_key, "big")
        except ValueError as e:
            raise BTClibValueError(f"not a private key: {prv_key!r}") from e

    if not 0 < q < ec.n:
        raise BTClibValueError(f"private key not in 1..n-1: {hex(q).upper()}")

    return q


PrvkeyInfo = Tuple[int, str, bool]


def _prv_keyinfo_from_wif(
    wif: String, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PrvkeyInfo:
    """Return private key tuple(int, compressed, network) from a WIF.

    WIF is always compressed and includes network information:
    here the 'network, compressed' input parameters are passed
    only to allow consistency checks.
    """

    if isinstance(wif, str):
        wif = wif.strip()

    payload = b58decode(wif)

    net = network_from_key_value("wif", payload[:1])
    if net is None:
        raise BTClibValueError(f"invalid wif prefix: {payload[:1]!r}")
    if network is not None and net != network:
        raise BTClibValueError(f"not a {network} wif: {wif!r}")

    ec = NETWORKS[net].curve

    if len(payload) == ec.n_size + 2:  # compressed WIF
        compr = True
        if payload[-1] != 0x01:  # must have a trailing 0x01
            raise BTClibValueError("not a compressed WIF: missing trailing 0x01")
        prv_key = payload[1:-1]
    elif len(payload) == ec.n_size + 1:  # uncompressed WIF
        compr = False
        prv_key = payload[1:]
    else:
        raise BTClibValueError(f"wrong WIF size: {len(payload)}")

    if compressed is not None and compr != compressed:
        raise BTClibValueError("compression requirement mismatch")

    q = int.from_bytes(prv_key, byteorder="big")
    if not 0 < q < ec.n:
        raise BTClibValueError(f"private key {hex(q)} not in [1, n-1]")

    return q, net, compr


def _prv_keyinfo_from_xprv(
    xprv: BIP32Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PrvkeyInfo:
    """Return prv_key tuple (int, compressed, network) from BIP32 xprv.

    BIP32Key is always compressed and includes network information:
    here the 'network, compressed' input parameters are passed
    only to allow consistency checks.
    """

    compressed = True if compressed is None else compressed
    if not compressed:
        raise BTClibValueError("uncompressed SEC / compressed BIP32 mismatch")

    if isinstance(xprv, BIP32KeyData):
        xprv.assert_valid()
    else:
        xprv = BIP32KeyData.b58decode(xprv)

    if xprv.key[0] != 0:
        err_msg = f"not a private key: {xprv.b58encode()}"
        raise BTClibValueError(err_msg)

    if network is None:
        network = network_from_xkeyversion(xprv.version)

    allowed_versions = xprvversions_from_network(network)
    if xprv.version not in allowed_versions:
        err_msg = f"not a {network} key: "
        err_msg += f"{xprv.b58encode()}"
        raise BTClibValueError(err_msg)

    q = int.from_bytes(xprv.key[1:], byteorder="big")
    return q, network, True


def _prv_keyinfo_from_xprvwif(
    xprvwif: BIP32Key, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PrvkeyInfo:
    """Return prv_key tuple (int, compressed, network) from WIF/BIP32.

    Support WIF or BIP32 xprv.
    """

    if not isinstance(xprvwif, BIP32KeyData):
        try:
            return _prv_keyinfo_from_wif(xprvwif, network, compressed)
        # FIXME: except the NotPrvKeyError only, let InvalidPrvKey go through
        except BTClibValueError:
            pass

    return _prv_keyinfo_from_xprv(xprvwif, network, compressed)


def prv_keyinfo_from_prv_key(
    prv_key: PrvKey, network: Optional[str] = None, compressed: Optional[bool] = None
) -> PrvkeyInfo:

    compr = True if compressed is None else compressed
    net = "mainnet" if network is None else network
    ec = NETWORKS[net].curve

    if isinstance(prv_key, int):
        q = prv_key
    elif isinstance(prv_key, BIP32KeyData):
        return _prv_keyinfo_from_xprv(prv_key, network, compressed)
    else:
        try:
            return _prv_keyinfo_from_xprvwif(prv_key, network, compressed)
        # FIXME: except the NotPrvKeyError only, let InvalidPrvKey go through
        except ValueError:
            pass

        # it must be octets
        try:
            prv_key = bytes_from_octets(prv_key, ec.n_size)
            q = int.from_bytes(prv_key, byteorder="big", signed=False)
        except ValueError as e:
            raise BTClibValueError(f"not a private key: {prv_key!r}") from e

    if not 0 < q < ec.n:
        raise BTClibValueError(f"private key not in 1..n-1: {hex(q).upper()}")

    return q, net, compr
