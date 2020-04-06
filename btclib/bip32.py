#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""BIP32 Hierarchical Deterministic Wallet functions.

A deterministic wallet is a hash-chain of private/public key pairs that
derives from a single root, which is the only element requiring backup.
Moreover, there are schemes where public keys can be calculated without
accessing private keys.

A hierarchical deterministic wallet is a tree of multiple hash-chains,
derived from a single root, allowing for selective sharing of keypair
chains.

Here, the HD wallet is implemented according to BIP32 bitcoin standard
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki.

A BIP32 extended key is 78 bytes:

- [  : 4] version
- [ 4: 5] depth in the derivation path
- [ 5: 9] parent fingerprint
- [ 9:13] index
- [13:45] chain code
- [45:78] compressed pubkey or [0x00][prvkey]
"""

import copy
import hmac
from typing import Iterable, List, Tuple, TypedDict, Union

from . import bip39, electrum
from .alias import INF, Octets, Path, Point, String, XkeyDict
from .base58 import b58decode, b58encode
from .curvemult import mult
from .curves import secp256k1 as ec
from .mnemonic import Mnemonic
from .network import (_NETWORKS, _P2WPKH_P2SH_PRV_PREFIXES,
                      _P2WPKH_P2SH_PUB_PREFIXES, _P2WPKH_PRV_PREFIXES,
                      _P2WPKH_PUB_PREFIXES, _P2WSH_P2SH_PRV_PREFIXES,
                      _P2WSH_P2SH_PUB_PREFIXES, _P2WSH_PRV_PREFIXES,
                      _P2WSH_PUB_PREFIXES, _PRV_VERSIONS, _PUB_VERSIONS,
                      _REPEATED_NETWORKS, _XPRV_PREFIXES, _XPUB_PREFIXES,
                      MAIN_xprv, MAIN_xpub, MAIN_yprv, MAIN_Yprv, MAIN_ypub,
                      MAIN_Ypub, MAIN_zprv, MAIN_Zprv, MAIN_zpub, MAIN_Zpub,
                      TEST_tprv, TEST_tpub, TEST_uprv, TEST_Uprv, TEST_upub,
                      TEST_Upub, TEST_vprv, TEST_Vprv, TEST_vpub, TEST_Vpub)
from .secpoint import bytes_from_point, point_from_octets
from .utils import bytes_from_octets, hash160

# TODO avoid BIP32 extensions as much as possible (i.e. everywhere but _ckd)


def _check_version_key(v: bytes, k: bytes) -> None:

    if v in _PRV_VERSIONS:
        if k[0] != 0:
            raise ValueError("prv_version/pubkey mismatch")
    elif v in _PUB_VERSIONS:
        if k[0] not in (2, 3):
            raise ValueError("pub_version/prvkey mismatch")
    else:
        raise ValueError(f"unknown extended key version {v!r}")


def _check_depth_pfp_index(d: int, pfp: bytes, i: bytes) -> None:

    if d < 0 or d > 255:
        raise ValueError(f"Invalid BIP32 depth ({d})")
    elif d == 0:
        if pfp != b'\x00\x00\x00\x00':
            m = f"Zero depth with non-zero parent_fingerprint {pfp!r}"
            raise ValueError(m)
        if i != b'\x00\x00\x00\x00':
            m = f"Zero depth with non-zero index {i!r}"
            raise ValueError(m)
    else:
        if pfp == b'\x00\x00\x00\x00':
            m = f"Zon-zero depth ({d}) with zero parent_fingerprint {pfp!r}"
            raise ValueError(m)


def deserialize(xkey: Octets) -> XkeyDict:

    if isinstance(xkey, str):
        xkey = xkey.strip()

    xkey = b58decode(xkey, 78)
    d: XkeyDict = {
        'version'            : xkey[:4],
        'depth'              : xkey[4],
        'parent_fingerprint' : xkey[5:9],
        'index'              : xkey[9:13],
        'chain_code'         : xkey[13:45],
        'key'                : xkey[45:],
        # extensions
        'q'                  : 0,   # non zero only if xprv
        'Q'                  : INF, # non INF only if xpub
        'network'            : ''
    }

    _check_version_key(d['version'], d['key'])
    _check_depth_pfp_index(d['depth'], d['parent_fingerprint'], d['index'])

    # calculate d['q'] and d['Q']
    if d['key'][0] == 0:
        q = int.from_bytes(d['key'][1:], byteorder='big')
        if not 0 < q < ec.n:
            raise ValueError(f"Private key {hex(q).upper()} not in [1, n-1]")
        d['q'] = q
        d['Q'] = INF
        d['network'] = _REPEATED_NETWORKS[_PRV_VERSIONS.index(d['version'])]
    else:  # must be public (already checked by _check_version_key)
        d['q'] = 0
        d['Q'] = point_from_octets(d['key'], ec)
        d['network'] = _REPEATED_NETWORKS[_PUB_VERSIONS.index(d['version'])]

    return d


def serialize(d: XkeyDict) -> bytes:

    if len(d['key']) != 33:
        m = f"Invalid {len(d['key'])}-bytes BIP32 'key' length"
        raise ValueError(m)
    # version length is checked in _check_version_key
    _check_version_key(d['version'], d['key'])
    t = d['version']

    if len(d['parent_fingerprint']) != 4:
        m = f"Invalid {len(d['parent_fingerprint'])}-bytes "
        m += "BIP32 parent_fingerprint length"
        raise ValueError(m)
    if len(d['index']) != 4:
        m = f"Invalid {len(d['index'])}-bytes BIP32 index length"
        raise ValueError(m)
    _check_depth_pfp_index(d['depth'],
                                   d['parent_fingerprint'], d['index'])
    t += d['depth'].to_bytes(1, 'big')
    t += d['parent_fingerprint']
    t += d['index']

    if len(d['chain_code']) != 32:
        m = f"Invalid {len(d['chain_code'])}-bytes BIP32 chain_code length"
        raise ValueError(m)
    t += d['chain_code']

    # already checked in _check_version_key
    t += d['key']

    # d['q'], d['Q'], and d['network']  are just neglected

    return b58encode(t)


def fingerprint(d: Union[XkeyDict, String]) -> bytes:

    if not isinstance(d, dict):
        d = deserialize(d)

    if d['key'][0] == 0:
        P = mult(d['q'])
        pubkey = bytes_from_point(P, True, ec)
        return hash160(pubkey)[:4]

    # must be a public key
    return hash160(d['key'])[:4]


def rootxprv_from_seed(seed: Octets, version: Octets = MAIN_xprv) -> bytes:
    """Return BIP32 root master extended private key from seed."""

    seed = bytes_from_octets(seed)
    hd = hmac.digest(b"Bitcoin seed", seed, 'sha512')
    k = b'\x00' + hd[:32]
    v = bytes_from_octets(version)
    #if v not in _PRV_VERSIONS:
    #    raise ValueError(f"unknown extended private key version {v!r}")
    network = _REPEATED_NETWORKS[_PRV_VERSIONS.index(v)]

    d: XkeyDict = {
        'version'            : v,
        'depth'              : 0,
        'parent_fingerprint' : b'\x00\x00\x00\x00',
        'index'              : b'\x00\x00\x00\x00',
        'chain_code'         : hd[32:],
        'key'                : k,
        'q'                  : int.from_bytes(hd[:32], byteorder='big'),
        'Q'                  : INF,
        'network'            : network
    }
    return serialize(d)


def rootxprv_from_bip39mnemonic(mnemonic: Mnemonic,
                                passphrase: str = "",
                                version: Octets = MAIN_xprv) -> bytes:
    """Return BIP32 root master extended private key from BIP39 mnemonic."""

    seed = bip39.seed_from_mnemonic(mnemonic, passphrase)
    return rootxprv_from_seed(seed, version)


def masterxprv_from_electrummnemonic(mnemonic: Mnemonic,
                                     passphrase: str = "",
                                     network: str = 'mainnet') -> bytes:
    """Return BIP32 master extended private key from Electrum mnemonic.

    Note that for a 'standard' mnemonic the derivation path is "m",
    for a 'segwit' mnemonic it is "m/0h" instead.
    """

    version, seed = electrum._seed_from_mnemonic(mnemonic, passphrase)
    prefix = _NETWORKS.index(network)

    if version == 'standard':
        xversion = _XPRV_PREFIXES[prefix]
        return rootxprv_from_seed(seed, xversion)
    elif version == 'segwit':
        xversion = _P2WPKH_PRV_PREFIXES[prefix]
        rootxprv = rootxprv_from_seed(seed, xversion)
        return derive(rootxprv, 0x80000000)  # "m/0h"
    else:
        raise ValueError(f"Unmanaged electrum mnemonic version ({version})")


def xpub_from_xprv(d: Union[XkeyDict, String]) -> bytes:
    """Neutered Derivation (ND).

    Derivation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    if isinstance(d, dict):
        d = copy.copy(d)
    else:
        d = deserialize(d)

    if d['key'][0] != 0:
        raise ValueError("extended key is not a private one")

    d['Q'] = mult(d['q'])
    d['key'] = bytes_from_point(d['Q'], True, ec)
    d['q'] = 0
    d['version'] = _PUB_VERSIONS[_PRV_VERSIONS.index(d['version'])]

    return serialize(d)


def _ckd(d: XkeyDict, index: bytes) -> None:

    # d is a prvkey
    if d['key'][0] == 0:
        d['depth'] += 1
        Pbytes = bytes_from_point(mult(d['q']), True, ec)
        d['parent_fingerprint'] = hash160(Pbytes)[:4]
        d['index'] = index
        if index[0] >= 0x80:  # hardened derivation
            h = hmac.digest(d['chain_code'], d['key'] + index, 'sha512')
        else:                 # normal derivation
            h = hmac.digest(d['chain_code'], Pbytes + index, 'sha512')
        d['chain_code'] = h[32:]
        offset = int.from_bytes(h[:32], byteorder='big')
        d['q'] = (d['q'] + offset) % ec.n
        d['key'] = b'\x00' + d['q'].to_bytes(32, 'big')
        d['Q'] = INF
    # d is a pubkey
    else:
        if index[0] >= 0x80:
            raise ValueError("hardened derivation from pubkey is impossible")
        d['depth'] += 1
        d['parent_fingerprint'] = hash160(d['key'])[:4]
        d['index'] = index
        h = hmac.digest(d['chain_code'], d['key'] + index, 'sha512')
        d['chain_code'] = h[32:]
        offset = int.from_bytes(h[:32], byteorder='big')
        Offset = mult(offset)
        d['Q'] = ec.add(d['Q'], Offset)
        d['key'] = bytes_from_point(d['Q'], True, ec)
        d['q'] = 0


def _indexes_from_path(path: str) -> Tuple[List[bytes], bool]:

    steps = path.split('/')
    if steps[0] in ('m', 'M'):
        absolute = True
    elif steps[0] == '.':
        absolute = False
    elif steps[0] == '':
        raise ValueError('Empty derivation path')
    else:
        raise ValueError(f'Invalid derivation path root: "{steps[0]}"')
    if len(steps) > 256:
        raise ValueError(f'Derivation path depth {len(steps)-1}>255')

    indexes: List[bytes] = list()
    for step in steps[1:]:
        hardened = False
        if step[-1] in ("'", "H", "h"):
            hardened = True
            step = step[:-1]
        index = int(step)
        index += 0x80000000 if hardened else 0
        indexes.append(index.to_bytes(4, 'big'))

    return indexes, absolute


def derive(d: Union[XkeyDict, String], path: Path) -> bytes:
    """Derive an extended key across a path spanning multiple depth levels.

    Derivation is according to:
    
    - absolute path as "m/44h/0'/1H/0/10" string
    - relative path as "./0/10" string
    - relative path as iterable integer indexes
    - relative one level child derivation with single integer index
    - relative one level child derivation with single 4-bytes index
    """

    if isinstance(d, dict):
        d = copy.copy(d)
    else:
        d = deserialize(d)

    if isinstance(path, str):
        path = path.strip()
        indexes, absolute = _indexes_from_path(path)
        if absolute and d["depth"] != 0:
            msg = "Absolute derivation path for non-root master key"
            raise ValueError(msg)
    elif isinstance(path, int):
        indexes = [path.to_bytes(4, byteorder='big')]
    elif isinstance(path, bytes):
        if len(path) != 4:
            raise ValueError(f"Index must be 4-bytes, not {len(path)}")
        indexes = [path]
    else:
        indexes = [i.to_bytes(4, byteorder='big') for i in path]

    final_depth = d["depth"] + len(indexes)
    if final_depth > 255:
        raise ValueError(f'Derivation path final depth {final_depth}>255')

    for index in indexes:
        _ckd(d, index)

    return serialize(d)


def crack_prvkey(parent_xpub: Union[XkeyDict, String],
                 child_xprv: Union[XkeyDict, String]) -> bytes:

    if isinstance(parent_xpub, dict):
        p = copy.copy(parent_xpub)
    else:
        p = deserialize(parent_xpub)

    if p['key'][0] not in (2, 3):
        raise ValueError("extended parent key is not a public one")

    if isinstance(child_xprv, dict):
        c = child_xprv
    else:
        c = deserialize(child_xprv)
    if c['key'][0] != 0:
        raise ValueError("extended child key is not a private one")

    # check depth
    if c['depth'] != p['depth'] + 1:
        raise ValueError("not a parent's child: wrong depth relation")

    # check fingerprint
    if c['parent_fingerprint'] != hash160(p['key'])[:4]:
        raise ValueError("not a parent's child: wrong parent fingerprint")

    # check normal derivation
    if c['index'][0] >= 0x80:
        raise ValueError("hardened child derivation")

    p['version'] = c['version']

    h = hmac.digest(p['chain_code'], p['key'] + c['index'], 'sha512')
    offset = int.from_bytes(h[:32], byteorder='big')
    p['q'] = (c['q'] - offset) % ec.n
    p['key'] = b'\x00' + p['q'].to_bytes(32, byteorder='big')
    p['Q'] = INF

    return serialize(p)
