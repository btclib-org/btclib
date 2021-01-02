#!/usr/bin/env python3

# Copyright (C) 2017-2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""SLIP132 address.

https://github.com/satoshilabs/slips/blob/master/slip-0132.md
"""
from typing import Any, Callable, List

from btclib import b32, b58
from btclib.bip32.bip32 import BIP32Key, BIP32KeyData, xpub_from_xprv
from btclib.exceptions import BTClibValueError
from btclib.network import network_from_key_value


def address_from_xkey(xkey: BIP32Key) -> str:
    """Return the SLIP132 base58/bech32 address.

    The address is always derived from the compressed public key,
    as this is the default public key representation in BIP32.
    """

    try:
        xkey = xpub_from_xprv(xkey)
    except BTClibValueError:
        pass

    return address_from_xpub(xkey)


def address_from_xpub(xpub: BIP32Key) -> str:
    """Return the SLIP132 base58/bech32 address.

    The address is always derived from the compressed public key,
    as this is the default public key representation in BIP32.
    """

    if not isinstance(xpub, BIP32KeyData):
        xpub = BIP32KeyData.b58decode(xpub)

    if xpub.key[0] not in (2, 3):
        err_msg = f"not a public key: {xpub.b58encode()}"
        raise BTClibValueError(err_msg)

    function_list: List[Callable[[Any, str], str]] = [
        b58.p2pkh,
        b32.p2wpkh,
        b58.p2wpkh_p2sh,
    ]
    version_list: List[str] = [
        "bip32_pub",
        "slip132_p2wpkh_pub",
        "slip132_p2wpkh_p2sh_pub",
    ]
    for version, function in zip(version_list, function_list):
        # with pytohn>=3.8 use walrus operator
        # if network := network_from_key_value(version, xpub.version):
        network = network_from_key_value(version, xpub.version)
        if network:
            return function(xpub, network)
    err_msg = f"unknown xpub version: {xpub.version.hex()}"  # pragma: no cover
    raise BTClibValueError(err_msg)  # pragma: no cover
