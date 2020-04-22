#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""SLIP32 address.

"""

from typing import Union

from . import base58address, bech32address, bip32
from .alias import String, XkeyDict
from .network import _P2WPKH_PUB_PREFIXES, _XPUB_PREFIXES


def address_from_xpub(d: Union[XkeyDict, String]) -> bytes:
    """Return the SLIP32 base58/bech32 address.

    The address is always derived from the compressed public key,
    as this is the default public key representation in BIP32.
    """

    if not isinstance(d, dict):
        d = bip32.deserialize(d)

    if d['key'][0] not in (2, 3):
        m = f"Not a public key: {bip32.serialize(d).decode()}"
        raise ValueError(m)

    if d['version'] in _XPUB_PREFIXES:
        return base58address.p2pkh(d)
    elif d['version'] in _P2WPKH_PUB_PREFIXES:
        return bech32address.p2wpkh(d)
    else:
        # v has been already checked at parsing stage
        # v must be in _P2WPKH_P2SH_PUB_PREFIXES
        return base58address.p2wpkh_p2sh(d)
