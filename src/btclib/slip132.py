# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""SLIP132 address.

https://github.com/satoshilabs/slips/blob/master/slip-0132.md
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from typing import Any

from btclib import b32, b58
from btclib.alias import NetworkField
from btclib.bip32.bip32 import (
    BIP32Key,
    BIP32KeyData,
    _key_data_from_bip32_key,
    derive,
    xpub_from_xprv,
)
from btclib.bip32.der_path import DerPath
from btclib.exceptions import BTClibValueError
from btclib.network import (
    NETWORKS,
    Network,
    network_from_key_value,
    network_from_xkeyversion,
)

__all__ = [
    "address_from_xkey",
    "address_from_xpub",
    "p2pkh_xkey",
    "p2wpkh_p2sh_xkey",
    "p2wpkh_xkey",
]


def address_from_xkey(xkey: BIP32Key) -> str:
    """Return the SLIP132 base58/bech32 address.

    The address is always derived from the compressed public key, as
    this is the default public key representation in BIP32.
    """
    with contextlib.suppress(BTClibValueError):
        xkey = xpub_from_xprv(xkey)
    return address_from_xpub(xkey)


def address_from_xpub(xpub: BIP32Key) -> str:
    """Return the SLIP132 base58/bech32 address.

    The address is always derived from the compressed public key, as
    this is the default public key representation in BIP32.
    """
    xpub = _key_data_from_bip32_key(xpub)

    if xpub.key[0] not in {2, 3}:
        # this branch is reached with an xprv: never echo it,
        # the prefix already says what is wrong
        raise BTClibValueError(f"not a public key: prefix 0x{xpub.key[:1].hex()}")

    # NetworkField, where inference would widen the three to str: they
    # are field names of Network, resolved with getattr by the lookup
    version_list: list[NetworkField] = [
        "bip32_pub",
        "slip132_p2wpkh_pub",
        "slip132_p2wpkh_p2sh_pub",
    ]
    function_list: list[Callable[[Any, str], str]] = [
        b58.p2pkh,
        b32.p2wpkh,
        b58.p2wpkh_p2sh,
    ]
    for version, function in zip(version_list, function_list, strict=True):
        if network := network_from_key_value(version, xpub.version):
            return function(xpub, network)
    # reachable: b58decode accepts the p2wsh versions too, and a p2wsh
    # address is not a function of the public key alone
    err_msg = f"unknown xpub version: {xpub.version.hex()}"
    raise BTClibValueError(err_msg)


def _helper_checks(
    xkey: BIP32Key, check_root_xkey: bool
) -> tuple[BIP32KeyData, Network]:
    xkey = _key_data_from_bip32_key(xkey)
    if check_root_xkey and not xkey.is_root:
        # xkey may be an xprv: never echo it; depth and
        # parent fingerprint are the non-root, non-secret, parts
        err_msg = f"not a root key: depth {xkey.depth}"
        err_msg += f", parent fingerprint 0x{xkey.parent_fingerprint.hex()}"
        raise BTClibValueError(err_msg)
    network = NETWORKS[network_from_xkeyversion(xkey.version)]
    return xkey, network


def p2pkh_xkey(
    xkey: BIP32Key, der_path: DerPath = "m/44h/0h/0h", check_root_xkey: bool = True
) -> str:
    """Return a p2pkh BIP32 xprv/xpub key at the derivation path."""
    xkey, network = _helper_checks(xkey, check_root_xkey)
    version = network.bip32_prv if xkey.is_private else network.bip32_pub
    return derive(xkey, der_path, version)


def p2wpkh_p2sh_xkey(
    xkey: BIP32Key, der_path: DerPath = "m/49h/0h/0h", check_root_xkey: bool = True
) -> str:
    """Return a p2wpkh-p2sh BIP32 yprv/ypub key at the derivation path."""
    xkey, network = _helper_checks(xkey, check_root_xkey)
    version = (
        network.slip132_p2wpkh_p2sh_prv
        if xkey.is_private
        else network.slip132_p2wpkh_p2sh_pub
    )
    return derive(xkey, der_path, version)


def p2wpkh_xkey(
    xkey: BIP32Key, der_path: DerPath = "m/84h/0h/0h", check_root_xkey: bool = True
) -> str:
    """Return a p2wpkh BIP32 zprv/zpub master key at the derivation path."""
    xkey, network = _helper_checks(xkey, check_root_xkey)
    version = (
        network.slip132_p2wpkh_prv if xkey.is_private else network.slip132_p2wpkh_pub
    )
    return derive(xkey, der_path, version)
