#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""SLIP132 address.

https://github.com/satoshilabs/slips/blob/master/slip-0132.md
"""

from . import base58_address, bech32_address, bip32
from .bip32 import BIP32Key, BIP32KeyData
from .exceptions import BTClibValueError
from .network import (
    _P2WPKH_P2SH_PUB_PREFIXES,
    _P2WPKH_PUB_PREFIXES,
    _XPUB_PREFIXES,
)


def address_from_xkey(xkey: BIP32Key) -> str:
    """Return the SLIP132 base58/bech32 address.

    The address is always derived from the compressed public key,
    as this is the default public key representation in BIP32.
    """

    try:
        xkey = bip32.xpub_from_xprv(xkey)
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
        m = f"not a public key: {xpub.b58encode()}"
        raise BTClibValueError(m)

    if xpub.version in _XPUB_PREFIXES:
        return base58_address.p2pkh(xpub)
    if xpub.version in _P2WPKH_PUB_PREFIXES:
        return bech32_address.p2wpkh(xpub)
    if xpub.version in _P2WPKH_P2SH_PUB_PREFIXES:
        return base58_address.p2wpkh_p2sh(xpub)

    err_msg = f"unknown xpub version: {xpub.version.hex()}"  # pragma: no cover
    raise BTClibValueError(err_msg)  # pragma: no cover
