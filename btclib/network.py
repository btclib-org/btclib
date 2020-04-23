#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Network constants and associated functions."""

from typing import List

from .alias import String
from .curve import Curve
from .curves import secp256k1

_NETWORKS = ['mainnet', 'testnet', 'regtest']

_CURVES = [secp256k1, secp256k1, secp256k1]

_WIF_PREFIXES = [
    b'\x80',  # WIF starts with {K,L} (if compressed) or 5 (if uncompressed)
    b'\xef',  # WIF starts with c (if compressed) or 9 (if uncompressed)
    b'\xef',  # WIF starts with c (if compressed) or 9 (if uncompressed)
]

_P2PKH_PREFIXES = [
    b'\x00',  # address starts with 1
    b'\x6f',  # address starts with {m, n}
    b'\x6f'   # address starts with {m, n}
]
_P2SH_PREFIXES = [
    b'\x05',  # address starts with 3
    b'\xc4',  # address starts with 2
    b'\xc4',  # address starts with 2
]
_P2W_PREFIXES = ['bc', 'tb', 'bcrt']


# VERSION BYTES (4 bytes)
#
# Bitcoin core uses the m/0h (core) BIP32 derivation path
# with xprv/xpub and tprv/tpub Base58 encoding

# m/44h/0h  p2pkh or p2sh
MAIN_xprv = b'\x04\x88\xAD\xE4'
MAIN_xpub = b'\x04\x88\xB2\x1E'
# m/44h/1h  p2pkh or p2sh
TEST_tprv = b'\x04\x35\x83\x94'
TEST_tpub = b'\x04\x35\x87\xCF'

# m/49h/0h  p2wpkh-p2sh (p2sh-wrapped-segwit)
MAIN_yprv = b'\x04\x9D\x78\x78'
MAIN_ypub = b'\x04\x9D\x7C\xB2'
# m/49h/1h  p2wpkh-p2sh (p2sh-wrapped-segwit)
TEST_uprv = b'\x04\x4A\x4E\x28'
TEST_upub = b'\x04\x4A\x52\x62'

#   ---     p2wsh-p2sh (p2sh-wrapped-segwit)
MAIN_Yprv = b'\x02\x95\xB0\x05'
MAIN_Ypub = b'\x02\x95\xB4\x3F'
TEST_Uprv = b'\x02\x42\x85\xB5'
TEST_Upub = b'\x02\x42\x89\xEF'

# m/84h/0h  p2wpkh (native-segwit)
MAIN_zprv = b'\x04\xB2\x43\x0C'
MAIN_zpub = b'\x04\xB2\x47\x46'
# m/84h/1h  p2wpkh (native-segwit)
TEST_vprv = b'\x04\x5F\x18\xBC'
TEST_vpub = b'\x04\x5F\x1C\xF6'

#   ---     p2wsh (native-segwit)
MAIN_Zprv = b'\x02\xAA\x7A\x99'
MAIN_Zpub = b'\x02\xAA\x7E\xD3'
TEST_Vprv = b'\x02\x57\x50\x48'
TEST_Vpub = b'\x02\x57\x54\x83'

# p2pkh or p2sh
_XPRV_PREFIXES = [MAIN_xprv, TEST_tprv, TEST_tprv]
_XPUB_PREFIXES = [MAIN_xpub, TEST_tpub, TEST_tpub]

# FIXME: these are not used/tested
# p2wpkh p2sh-wrapped-segwit
_P2WPKH_P2SH_PRV_PREFIXES = [MAIN_yprv, TEST_uprv, TEST_uprv]
_P2WPKH_P2SH_PUB_PREFIXES = [MAIN_ypub, TEST_upub, TEST_upub]

# FIXME: these are not used/tested
# p2wsh p2sh-wrapped-segwit
_P2WSH_P2SH_PRV_PREFIXES = [MAIN_Yprv, TEST_Uprv, TEST_Uprv]
_P2WSH_P2SH_PUB_PREFIXES = [MAIN_Ypub, TEST_Upub, TEST_Upub]

# p2wpkh native-segwit
_P2WPKH_PRV_PREFIXES = [MAIN_zprv, TEST_vprv, TEST_vprv]
_P2WPKH_PUB_PREFIXES = [MAIN_zpub, TEST_vpub, TEST_vpub]

# FIXME: these are not used/tested
# p2wsh native-segwit
_P2WSH_PRV_PREFIXES = [MAIN_Zprv, TEST_Vprv, TEST_Vprv]
_P2WSH_PUB_PREFIXES = [MAIN_Zpub, TEST_Vpub, TEST_Vpub]


_XPRV_VERSIONS_MAIN = [MAIN_xprv, MAIN_yprv, MAIN_zprv, MAIN_Yprv, MAIN_Zprv]
_XPRV_VERSIONS_TEST = [TEST_tprv, TEST_uprv, TEST_vprv, TEST_Uprv, TEST_Vprv]
_XPUB_VERSIONS_MAIN = [MAIN_xpub, MAIN_ypub, MAIN_zpub, MAIN_Ypub, MAIN_Zpub]
_XPUB_VERSIONS_TEST = [TEST_tpub, TEST_upub, TEST_vpub, TEST_Upub, TEST_Vpub]

_XPRV_VERSIONS = [_XPRV_VERSIONS_MAIN,
                  _XPRV_VERSIONS_TEST, _XPRV_VERSIONS_TEST]
_XPUB_VERSIONS = [_XPUB_VERSIONS_MAIN,
                  _XPUB_VERSIONS_TEST, _XPUB_VERSIONS_TEST]

# it provides false match for regtest
# not a problem as long as it is used for WIF/Base58Address/BIP32xkey
# where the two network share same prefixes.
_REPEATED_NETWORKS = [
    'mainnet', 'mainnet', 'mainnet', 'mainnet', 'mainnet',
    'testnet', 'testnet', 'testnet', 'testnet', 'testnet',
    'regtest', 'regtest', 'regtest', 'regtest', 'regtest']
_XPRV_VERSIONS_ALL = _XPRV_VERSIONS_MAIN + \
    _XPRV_VERSIONS_TEST + _XPRV_VERSIONS_TEST
_XPUB_VERSIONS_ALL = _XPUB_VERSIONS_MAIN + \
    _XPUB_VERSIONS_TEST + _XPUB_VERSIONS_TEST


def curve_from_network(network: str) -> Curve:
    index = _NETWORKS.index(network)
    return _CURVES[index]


def curve_from_xpubversion(xpubversion: bytes) -> Curve:
    index = _XPUB_VERSIONS_ALL.index(xpubversion)
    return _CURVES[index]


def _xpub_versions_from_network(network: str) -> List[bytes]:
    index = _NETWORKS.index(network)
    return _XPUB_VERSIONS[index]


def wif_prefix_from_network(network: str) -> bytes:
    index = _NETWORKS.index(network)
    return _WIF_PREFIXES[index]


def p2pkh_prefix_from_network(network: str) -> bytes:
    network_index = _NETWORKS.index(network)
    return _P2PKH_PREFIXES[network_index]


def p2sh_prefix_from_network(network: str) -> bytes:
    index = _NETWORKS.index(network)
    return _P2SH_PREFIXES[index]


def p2w_prefix_from_network(network: str) -> str:
    index = _NETWORKS.index(network)
    return _P2W_PREFIXES[index]


def has_segwit_prefix(addr: String) -> bool:

    if isinstance(addr, str):
        str_addr = addr.strip()
        str_addr = str_addr.lower()
    else:
        str_addr = addr.decode('ascii')

    for prefix in _P2W_PREFIXES:
        if str_addr.startswith(prefix + '1'):
            return True

    return False


def network_from_wif_prefix(prefix: bytes) -> str:
    """Return network string from WIF prefix.

    Warning: when used on 'regtest' it returns 'testnet', which is not
    a problem as long as it is used for WIF/Base58Address/BIP32xkey
    where the two network share same prefixes.
    """
    index = _WIF_PREFIXES.index(prefix)
    return _NETWORKS[index]


def network_from_p2pkh_prefix(prefix: bytes) -> str:
    """Return network string from p2pkh prefix.

    Warning: when used on 'regtest' it returns 'testnet', which is not
    a problem as long as it is used for WIF/Base58Address/BIP32xkey
    where the two network share same prefixes.
    """
    index = _P2PKH_PREFIXES.index(prefix)
    return _NETWORKS[index]


def network_from_p2sh_prefix(prefix: bytes) -> str:
    """Return network string from p2sh prefix.

    Warning: when used on 'regtest' it returns 'testnet', which is not
    a problem as long as it is used for WIF/Base58Address/BIP32xkey
    where the two network share same prefixes.
    """
    index = _P2SH_PREFIXES.index(prefix)
    return _NETWORKS[index]


def network_from_xprv(xprvversion: bytes) -> str:
    """Return network string from xprv prefix.

    Warning: when used on 'regtest' it returns 'testnet', which is not
    a problem as long as it is used for WIF/Base58Address/BIP32xkey
    where the two network share same prefixes.
    """
    index = _XPRV_VERSIONS_ALL.index(xprvversion)
    return _REPEATED_NETWORKS[index]


def network_from_xpub(xpubversion: bytes) -> str:
    """Return network string from xpub prefix.

    Warning: when used on 'regtest' it returns 'testnet', which is not
    a problem as long as it is used for WIF/Base58Address/BIP32xkey
    where the two network share same prefixes.
    """
    index = _XPUB_VERSIONS_ALL.index(xpubversion)
    return _REPEATED_NETWORKS[index]


def network_from_p2w_prefix(prefix: str) -> str:
    "Return network string from p2w prefix."
    index = _P2W_PREFIXES.index(prefix)
    return _NETWORKS[index]
