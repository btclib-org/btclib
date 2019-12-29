#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
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

from hmac import HMAC
from hashlib import sha512
from typing import Union, Optional, Sequence, List, Tuple

from . import base58
from .curve import mult
from .curves import secp256k1 as ec
from .utils import Octets, point_from_octets, octets_from_point, \
    int_from_octets, h160
from .wifaddress import p2pkh_address

# Bitcoin core uses the m/0h (core) BIP32 derivation path
# with xprv/xpub and tprv/tpub Base58 encoding

# VERSION BYTES (4 bytes)

# m/44h/0h  p2pkh or p2sh
MAIN_xprv = b'\x04\x88\xAD\xE4'
MAIN_xpub = b'\x04\x88\xB2\x1E'
# m/44h/1h  p2pkh or p2sh
TEST_tprv = b'\x04\x35\x83\x94'
TEST_tpub = b'\x04\x35\x87\xCF'

# m/49h/0h  p2sh-segwit p2wpkh-p2sh
MAIN_yprv = b'\x04\x9D\x78\x78'
MAIN_ypub = b'\x04\x9D\x7C\xB2'
# m/49h/1h  p2sh-segwit p2wpkh-p2sh
TEST_uprv = b'\x04\x4A\x4E\x28'
TEST_upub = b'\x04\x4A\x52\x62'

# m/84h/0h  native segwit P2WPKH
MAIN_zprv = b'\x04\xB2\x43\x0C'
MAIN_zpub = b'\x04\xB2\x47\x46'
# m/84h/1h  native segwit P2WPKH
TEST_vprv = b'\x04\x5F\x18\xBC'
TEST_vpub = b'\x04\x5F\x1C\xF6'

#   ---     p2sh-segwit multi-sig p2wpkh-p2sh
MAIN_Yprv = b'\x02\x95\xB0\x05'
MAIN_Ypub = b'\x02\x95\xB4\x3F'
TEST_Uprv = b'\x02\x42\x85\xB5'
TEST_Upub = b'\x02\x42\x89\xEF'

#   ---     native segwit multi-sig p2wpkh
MAIN_Zprv = b'\x02\xAA\x7A\x99'
MAIN_Zpub = b'\x02\xAA\x7E\xD3'
TEST_Vprv = b'\x02\x57\x50\x48'
TEST_Vpub = b'\x02\x57\x54\x83'


PRV_VERSION = [
    MAIN_xprv, MAIN_yprv, MAIN_zprv, MAIN_Yprv, MAIN_Zprv,
    TEST_tprv, TEST_uprv, TEST_vprv, TEST_Uprv, TEST_Vprv]
PUB_VERSION = [
    MAIN_xpub, MAIN_ypub, MAIN_zpub, MAIN_Ypub, MAIN_Zpub,
    TEST_tpub, TEST_upub, TEST_vpub, TEST_Upub, TEST_Vpub]

# [  : 4] version
# [ 4: 5] depth
# [ 5: 9] parent _pubkey_ fingerprint
# [ 9:13] child index
# [13:45] chain code
# [45:78] key (private/public)


def xkey_parse(xkey: Octets) -> Tuple:
    xkey = base58.decode_check(xkey, 78)

    version = xkey[:4]
    depth = xkey[4]
    parent_fingerprint = xkey[5:9]
    child_index = xkey[9:13]
    chain_code = xkey[13:45]
    key = xkey[45:]

    if version in PRV_VERSION:
        if key[0] != 0:
            raise ValueError("extended key: (prvversion/pubkey) mismatch")
        Point = mult(ec, int_from_octets(key))
    elif version in PUB_VERSION:
        if key[0] not in (2, 3):
            raise ValueError("extended key: (pubversion/prvkey) mismatch")
        Point = point_from_octets(ec, key)
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

    return version, depth, parent_fingerprint, \
        child_index, chain_code, key, Point


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
    _, _, _, _, _, key, Point = xkey_parse(xkey)
    if key[0] == 0:
        key = octets_from_point(ec, Point, True)
    return h160(key)[:4]


def rootxprv_from_seed(seed: Octets, version: Octets) -> bytes:
    """derive the BIP32 root master extended private key from the seed"""

    if isinstance(version, str):  # hex string
        version = bytes.fromhex(version)
    if version not in PRV_VERSION:
        msg = f"invalid private version ({version})"
        raise ValueError(msg)

    # serialization data
    rootxprv = version                            # version
    rootxprv += b'\x00'                           # depth
    rootxprv += b'\x00\x00\x00\x00'               # parent pubkey fingerprint
    rootxprv += b'\x00\x00\x00\x00'               # child index

    # actual extended key (key + chain code) derivation
    if isinstance(seed, str):  # hex string
        seed = bytes.fromhex(seed)
    hd = HMAC(b"Bitcoin seed", seed, sha512).digest()
    rootprv = int_from_octets(hd[:32])
    rootxprv += hd[32:]                                # chain code
    rootxprv += b'\x00' + rootprv.to_bytes(32, 'big')  # private key

    return base58.encode_check(rootxprv)


def xpub_from_xprv(xprv: Octets) -> bytes:
    """Neutered Derivation (ND).

    Computation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions).
    """

    v, d, f, i, c, k, P = xkey_parse(xprv)

    if k[0] != 0:
        raise ValueError("extended key is not a private one")

    # serialization data
    xpub = PUB_VERSION[PRV_VERSION.index(v)]  # version
    xpub += d.to_bytes(1, 'big')              # depth
    xpub += f                                 # parent pubkey fingerprint
    xpub += i                                 # child index
    xpub += c                                 # chain code
    xpub += octets_from_point(ec, P, True)    # public key
    return base58.encode_check(xpub)


def ckd(xparentkey: Octets, index: Union[Octets, int]) -> bytes:
    """Child Key Derivation (CDK)

    Key derivation is normal if the extended parent key is public or
    child_index is less than 0x80000000.

    Key derivation is hardened if the extended parent key is private and
    child_index is not less than 0x80000000.
    """

    if isinstance(index, int):
        index = index.to_bytes(4, 'big')
    elif isinstance(index, str):  # hex string
        index = bytes.fromhex(index)

    if len(index) != 4:
        raise ValueError(f"a 4 bytes int is required, not {len(index)}")

    v, depth, _, _, chain_code, bytes_key, Point = xkey_parse(xparentkey)

    # serialization data
    xkey = v                                # child version
    xkey += (depth + 1).to_bytes(1, 'big')  # child depth, fail if depth=255

    if bytes_key[0] == 0:                   # parent is a prvkey
        Parent_bytes = octets_from_point(ec, Point, True)
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
        offset = int.from_bytes(h[:32], 'big')
        parent = int.from_bytes(bytes_key[1:], 'big')
        child = (parent + offset) % ec.n
        xkey += b'\x00' + child.to_bytes(32, 'big')  # child private key
    else:                                            # parent is a pubkey
        h = HMAC(chain_code, bytes_key + index, sha512).digest()
        xkey += h[32:]                               # child chain code
        offset = int.from_bytes(h[:32], 'big')
        Offset = mult(ec, offset)
        Child = ec.add(Point, Offset)
        xkey += octets_from_point(ec, Child, True)   # child public key

    return base58.encode_check(xkey)


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


def p2pkh_address_from_xpub(xpub: Octets) -> bytes:
    """Return the p2pkh address from the xpub, according to the xpub version.

    Even if/when generalized to alt-coins, the p2pkh prefix should always
    be deduced from the xpub version, not requiring explicit prefix
    """

    v, _, _, _, _, k, P = xkey_parse(xpub)

    if k[0] not in (2, 3):
        raise ValueError("xkey is not a public one")

    if v == MAIN_xpub:
        testnet = False
    elif v == TEST_tpub:
        testnet = True
    else:
        raise ValueError(f"xkey is of {v} type, not p2pkh (xpub/tpub)")

    compressed = True
    return p2pkh_address(P, compressed, testnet)


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
    offset = int.from_bytes(h[:32], 'big')
    child = int.from_bytes(ck[1:], 'big')
    parent = (child - offset) % ec.n
    parent_bytes = b'\x00' + parent.to_bytes(32, 'big')
    parent_xprv += parent_bytes           # private key

    return base58.encode_check(parent_xprv)
