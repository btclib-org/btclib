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
"""

from hashlib import sha512
from hmac import HMAC
from typing import List, Optional, Sequence, Tuple, Union

from . import base58
from .address import p2pkh_address
from .curvemult import mult
from .curves import secp256k1 as ec
from .segwitaddress import p2wpkh_address, p2wpkh_p2sh_address
from .utils import (Octets, bytes_from_hexstring, h160, int_from_octets,
                    octets_from_point, point_from_octets)
from .wif import wif_from_prvkey

# Bitcoin core uses the m/0h (core) BIP32 derivation path
# with xprv/xpub and tprv/tpub Base58 encoding

# VERSION BYTES (4 bytes)

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

_REPEATED_NETWORKS = [
    'mainnet', 'mainnet', 'mainnet', 'mainnet', 'mainnet',
    'testnet', 'testnet', 'testnet', 'testnet', 'testnet',
    'regtest', 'regtest', 'regtest', 'regtest', 'regtest']
_PRV_VERSIONS = [
    MAIN_xprv, MAIN_yprv, MAIN_zprv, MAIN_Yprv, MAIN_Zprv,
    TEST_tprv, TEST_uprv, TEST_vprv, TEST_Uprv, TEST_Vprv,
    TEST_tprv, TEST_uprv, TEST_vprv, TEST_Uprv, TEST_Vprv]
_PUB_VERSIONS = [
    MAIN_xpub, MAIN_ypub, MAIN_zpub, MAIN_Ypub, MAIN_Zpub,
    TEST_tpub, TEST_upub, TEST_vpub, TEST_Upub, TEST_Vpub,
    TEST_tpub, TEST_upub, TEST_vpub, TEST_Upub, TEST_Vpub]

_NETWORKS = ['mainnet', 'testnet', 'regtest']
# p2pkh or p2sh
_XPRV_PREFIXES = [MAIN_xprv, TEST_tprv, TEST_tprv]
_XPUB_PREFIXES = [MAIN_xpub, TEST_tpub, TEST_tpub]
# p2wpkh p2sh-wrapped-segwit
_P2WPKH_P2SH_PRV_PREFIXES = [MAIN_yprv, TEST_uprv, TEST_uprv]
_P2WPKH_P2SH_PUB_PREFIXES = [MAIN_ypub, TEST_upub, TEST_upub]
# p2wsh p2sh-wrapped-segwit
_P2WSH_P2SH_PRV_PREFIXES = [MAIN_Yprv, TEST_Uprv, TEST_Uprv]
_P2WSH_P2SH_PUB_PREFIXES = [MAIN_Ypub, TEST_Upub, TEST_Upub]
# p2wpkh native-segwit
_P2WPKH_PRV_PREFIXES = [MAIN_zprv, TEST_vprv, TEST_vprv]
_P2WPKH_PUB_PREFIXES = [MAIN_zpub, TEST_vpub, TEST_vpub]
# p2wsh native-segwit
_P2WSH_PRV_PREFIXES = [MAIN_Zprv, TEST_Vprv, TEST_Vprv]
_P2WSH_PUB_PREFIXES = [MAIN_Zpub, TEST_Vpub, TEST_Vpub]


# [  : 4] version
# [ 4: 5] depth
# [ 5: 9] parent _pubkey_ fingerprint
# [ 9:13] child index
# [13:45] chain code
# [45:78] key (private/public)


def xkey_parse(xkey: Octets) -> Tuple:
    xkey = base58.decode(xkey, 78)

    version = xkey[:4]
    depth = xkey[4]
    parent_fingerprint = xkey[5:9]
    child_index = xkey[9:13]
    chain_code = xkey[13:45]
    key = xkey[45:]

    if version in _PRV_VERSIONS:
        if key[0] != 0:
            raise ValueError("extended key: (prvversion/pubkey) mismatch")
        P = mult(int_from_octets(key))
    elif version in _PUB_VERSIONS:
        if key[0] not in (2, 3):
            raise ValueError("extended key: (pubversion/prvkey) mismatch")
        P = point_from_octets(key, ec)
    else:
        raise ValueError("extended key: unknown version")

    if depth == 0:
        if parent_fingerprint != b'\x00\x00\x00\x00':
            msg = f"extended key: zero depth with non-zero parent_fingerprint {parent_fingerprint}"
            raise ValueError(msg)
        if child_index != b'\x00\x00\x00\x00':
            msg = f"extended key: zero depth with non-zero child_index {child_index}"
            raise ValueError(msg)
    else:
        if parent_fingerprint == b'\x00\x00\x00\x00':
            msg = f"extended key: non-zero depth ({depth}) with zero parent_fingerprint"
            raise ValueError()

    return (version, depth, parent_fingerprint,
            child_index, chain_code, key, P)


def parent_fingerprint(xkey: Octets) -> bytes:
    _, depth, parent_fingerprint, _, _, _, _ = xkey_parse(xkey)
    if depth == 0:
        raise ValueError("master key provided")
    return parent_fingerprint


def child_index(xkey: Octets) -> bytes:
    _, depth, _, child_index, _, _, _ = xkey_parse(xkey)
    if depth == 0:
        raise ValueError("master key provided")
    return child_index


def fingerprint(xkey: Octets) -> bytes:
    _, _, _, _, _, key, P = xkey_parse(xkey)
    if key[0] == 0:
        key = octets_from_point(P, True, ec)
    return h160(key)[:4]


def rootxprv_from_seed(seed: Octets, version: Octets = MAIN_xprv) -> bytes:
    """derive the BIP32 root master extended private key from the seed"""

    version = bytes_from_hexstring(version)
    if version not in _PRV_VERSIONS:
        msg = f"invalid private version ({version})"
        raise ValueError(msg)

    # serialization data
    rootxprv = version                            # version
    rootxprv += b'\x00'                           # depth
    rootxprv += b'\x00\x00\x00\x00'               # parent pubkey fingerprint
    rootxprv += b'\x00\x00\x00\x00'               # child index

    # actual extended key (key + chain code) derivation
    seed = bytes_from_hexstring(seed)
    hd = HMAC(b"Bitcoin seed", seed, sha512).digest()
    rootprv = int_from_octets(hd[:32])
    rootxprv += hd[32:]                                # chain code
    rootxprv += b'\x00' + rootprv.to_bytes(32, 'big')  # private key

    return base58.encode(rootxprv)


def xpub_from_xprv(xprv: Octets) -> bytes:
    """Neutered Derivation (ND).

    Computation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    v, d, f, i, c, k, P = xkey_parse(xprv)

    if k[0] != 0:
        raise ValueError("extended key is not a private one")

    # serialization data
    xpub = _PUB_VERSIONS[_PRV_VERSIONS.index(v)]  # version
    xpub += d.to_bytes(1, 'big')                  # depth
    xpub += f                                     # parent pubkey fingerprint
    xpub += i                                     # child index
    xpub += c                                     # chain code
    xpub += octets_from_point(P, True, ec)        # public key
    return base58.encode(xpub)


def ckd(xparentkey: Octets, index: Union[Octets, int]) -> bytes:
    """Child Key Derivation (CDK)

    Key derivation is normal if the extended parent key is public or
    child_index is less than 0x80000000.

    Key derivation is hardened if the extended parent key is private and
    child_index is not less than 0x80000000.
    """

    if isinstance(index, int):
        index = index.to_bytes(4, byteorder='big')

    index = bytes_from_hexstring(index)

    if len(index) != 4:
        raise ValueError(f"a 4 bytes int is required, not {len(index)}")

    v, depth, _, _, chain_code, bytes_key, P = xkey_parse(xparentkey)

    # serialization data
    xkey = v                                # child version
    xkey += (depth + 1).to_bytes(1, 'big')  # child depth, fail if depth=255

    if bytes_key[0] == 0:                   # parent is a prvkey
        Parent_bytes = octets_from_point(P, True, ec)
    else:                                   # parent is a pubkey
        Parent_bytes = bytes_key
        if index[0] >= 0x80:                # hardened derivation
            raise ValueError("hardened derivation from pubkey is impossible")
    xkey += h160(Parent_bytes)[:4]          # parent pubkey fingerprint
    xkey += index                           # child index

    if bytes_key[0] == 0:                            # parent is a prvkey
        if index[0] >= 0x80:                         # hardened derivation
            h = HMAC(chain_code, bytes_key + index, sha512).digest()
        else:                                        # normal derivation
            h = HMAC(chain_code, Parent_bytes + index, sha512).digest()
        xkey += h[32:]                               # child chain code
        offset = int.from_bytes(h[:32], byteorder='big')
        parent = int.from_bytes(bytes_key[1:], byteorder='big')
        child = (parent + offset) % ec.n
        xkey += b'\x00' + child.to_bytes(32, 'big')  # child private key
    else:                                            # parent is a pubkey
        h = HMAC(chain_code, bytes_key + index, sha512).digest()
        xkey += h[32:]                               # child chain code
        offset = int.from_bytes(h[:32], byteorder='big')
        Offset = mult(offset)
        Child = ec.add(P, Offset)
        xkey += octets_from_point(Child, True, ec)   # child public key

    return base58.encode(xkey)


def indexes_from_path(path: str) -> Tuple[Sequence[int], bool]:
    """Extract derivation indexes from a derivation path.

    Derivation path must be like "m/44'/0'/1'/0/10" (absolute)
    or "./0/10" (relative).
    """

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

    indexes: List[int] = list()
    for step in steps[1:]:
        hardened = False
        if step[-1] in ("'", "H", "h"):
            hardened = True
            step = step[:-1]
        index = int(step)
        index += 0x80000000 if hardened else 0
        indexes.append(index)

    return indexes, absolute


def derive(xkey: Octets, path: Union[str, Sequence[int]]) -> bytes:
    """Derive an extended key.

    Derivation is according to path like "m/44h/0'/1H/0/10" (absolute)
    or "./0/10" (relative).
    """

    _, depth, _, _, _, _, _ = xkey_parse(xkey)

    if isinstance(path, str):
        path = path.strip()
        indexes, absolute = indexes_from_path(path)
        if absolute and depth != 0:
            msg = "Absolute derivation path for non-root master key"
            raise ValueError(msg)
    else:
        indexes = path

    final_depth = depth + len(indexes)
    if final_depth > 255:
        raise ValueError(f'Derivation path final depth {final_depth}>255')

    for index in indexes:
        xkey = ckd(xkey, index)

    return xkey


def address_from_xpub(xpub: Octets) -> bytes:
    """Return the address according to the xpub SLIP32 version type."""

    v, _, _, _, _, k, _ = xkey_parse(xpub)

    if k[0] not in (2, 3):
        raise ValueError("xkey is not a public one")

    if v in _XPUB_PREFIXES:
        # p2pkh
        return _p2pkh_address_from_xpub(v, k)
    elif v in _P2WPKH_PUB_PREFIXES:
        # p2wpkh native-segwit
        return _p2wpkh_address_from_xpub(v, k)
    else:
        # v in _P2WPKH_P2SH_PUB_PREFIXES
        # p2wpkh p2sh-wrapped-segwit
        return _p2wpkh_p2sh_address_from_xpub(v, k)


def wif_from_xprv(xprv: Octets) -> bytes:
    """Return the WIF according to xpub version type."""

    v, _, _, _, _, k, _ = xkey_parse(xprv)

    if k[0] != 0:
        raise ValueError("xkey is not a private one")

    compressed = True
    network = _REPEATED_NETWORKS[_PRV_VERSIONS.index(v)]
    return wif_from_prvkey(k, compressed, network)


def _p2pkh_address_from_xpub(v: bytes, pk: bytes) -> bytes:
    network = _REPEATED_NETWORKS[_PUB_VERSIONS.index(v)]
    return p2pkh_address(pk, network)


def p2pkh_address_from_xpub(xpub: Octets) -> bytes:
    """Return the p2pkh address."""
    v, _, _, _, _, k, _ = xkey_parse(xpub)
    if k[0] not in (2, 3):
        # Deriving pubkey from prvkey would not be enough:
        # compressed ot uncompressed?
        raise ValueError("xkey is not a public one")
    return _p2pkh_address_from_xpub(v, k)


def _p2wpkh_address_from_xpub(v: bytes, pk: bytes) -> bytes:
    network = _REPEATED_NETWORKS[_PUB_VERSIONS.index(v)]
    return p2wpkh_address(pk, network)


def p2wpkh_address_from_xpub(xpub: Octets) -> bytes:
    """Return the p2wpkh (native SegWit) address."""
    v, _, _, _, _, k, _ = xkey_parse(xpub)
    if k[0] not in (2, 3):
        # pubkey could be derived from prvkey
        # and this safety check could be removed
        raise ValueError("xkey is not a public one")
    return _p2wpkh_address_from_xpub(v, k)


def _p2wpkh_p2sh_address_from_xpub(v: bytes, pk: bytes) -> bytes:
    network = _REPEATED_NETWORKS[_PUB_VERSIONS.index(v)]
    return p2wpkh_p2sh_address(pk, network)


def p2wpkh_p2sh_address_from_xpub(xpub: Octets) -> bytes:
    """Return the p2wpkh p2sh-wrapped (legacy) address."""
    v, _, _, _, _, k, _ = xkey_parse(xpub)
    if k[0] not in (2, 3):
        # pubkey could be derived from prvkey
        # and this safety check could be removed
        raise ValueError("xkey is not a public one")
    return _p2wpkh_p2sh_address_from_xpub(v, k)


def crack(parent_xpub: Octets, child_xprv: Octets) -> bytes:
    _, pd, pf, pi, pc, pk, _ = xkey_parse(parent_xpub)

    if pk[0] not in (2, 3):
        raise ValueError("extended parent key is not a public one")

    cv, cd, cf, ci, _, ck, _ = xkey_parse(child_xprv)
    if ck[0] != 0:
        raise ValueError("extended child key is not a private one")

    # check depth
    if cd != pd + 1:
        raise ValueError("not a parent's child: wrong depth relation")

    # check fingerprint
    if cf != h160(pk)[:4]:
        raise ValueError("not a parent's child: wrong parent fingerprint")

    # check normal derivation
    if ci[0] >= 0x80:
        raise ValueError("hardened child derivation")

    parent_xprv = cv                      # version
    parent_xprv += pd.to_bytes(1, 'big')  # depth
    parent_xprv += pf                     # parent pubkey fingerprint
    parent_xprv += pi                     # child index
    parent_xprv += pc                     # chain code

    h = HMAC(pc, pk + ci, sha512).digest()
    offset = int.from_bytes(h[:32], byteorder='big')
    child = int.from_bytes(ck[1:], byteorder='big')
    parent = (child - offset) % ec.n
    parent_bytes = b'\x00' + parent.to_bytes(32, byteorder='big')
    parent_xprv += parent_bytes           # private key

    return base58.encode(parent_xprv)
