#!/usr/bin/env python3

# Copyright (C) 2017-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""SLIP132 address.

https://github.com/satoshilabs/slips/blob/master/slip-0132.md
"""
from typing import Any, Callable, List, Tuple

from btclib import b32, b58
from btclib.bip32.bip32 import (
    BIP32DerPath,
    BIP32Key,
    BIP32KeyData,
    derive,
    xpub_from_xprv,
)
from btclib.exceptions import BTClibValueError
from btclib.network import (
    NETWORKS,
    Network,
    network_from_key_value,
    network_from_xkeyversion,
)


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
        raise BTClibValueError(f"not a public key: {xpub.b58encode()}")

    version_list: List[str] = [
        "bip32_pub",
        "slip132_p2wpkh_pub",
        "slip132_p2wpkh_p2sh_pub",
    ]
    function_list: List[Callable[[Any, str], str]] = [
        b58.p2pkh,
        b32.p2wpkh,
        b58.p2wpkh_p2sh,
    ]
    for version, function in zip(version_list, function_list):
        # with python>=3.8 use walrus operator
        # if network := network_from_key_value(version, xpub.version):
        network = network_from_key_value(version, xpub.version)
        if network:
            return function(xpub, network)
    err_msg = f"unknown xpub version: {xpub.version.hex()}"  # pragma: no cover
    raise BTClibValueError(err_msg)  # pragma: no cover


def _helper_checks(
    xkey: BIP32Key, check_root_xkey: bool
) -> Tuple[BIP32KeyData, Network]:
    if not isinstance(xkey, BIP32KeyData):
        xkey = BIP32KeyData.b58decode(xkey)
    if check_root_xkey and not xkey.is_root:
        raise BTClibValueError(f"not a root key: {xkey.b58encode()}")
    network = NETWORKS[network_from_xkeyversion(xkey.version)]
    return xkey, network


def p2pkh_xkey(
    xkey: BIP32Key, der_path: BIP32DerPath = "m/44h/0h/0h", check_root_xkey: bool = True
) -> str:
    "Return a p2pkh BIP32 xprv/xpub master key at the derivation path."

    xkey, network = _helper_checks(xkey, check_root_xkey)
    version = network.bip32_prv if xkey.is_private else network.bip32_pub
    return derive(xkey, der_path, version)


def p2wpkh_p2sh_xkey(
    xkey: BIP32Key, der_path: BIP32DerPath = "m/49h/0h/0h", check_root_xkey: bool = True
) -> str:
    "Return a p2wpkh-p2sh BIP32 yprv/ypub master key at the derivation path."

    xkey, network = _helper_checks(xkey, check_root_xkey)
    version = (
        network.slip132_p2wpkh_p2sh_prv
        if xkey.is_private
        else network.slip132_p2wpkh_p2sh_pub
    )
    return derive(xkey, der_path, version)


def p2wpkh_xkey(
    xkey: BIP32Key, der_path: BIP32DerPath = "m/84h/0h/0h", check_root_xkey: bool = True
) -> str:
    "Return a p2wpkh BIP32 zprv/zpub master key at the derivation path."

    xkey, network = _helper_checks(xkey, check_root_xkey)
    version = (
        network.slip132_p2wpkh_prv if xkey.is_private else network.slip132_p2wpkh_pub
    )
    return derive(xkey, der_path, version)
