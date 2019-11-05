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

# VERSION BYTES =      4 bytes
# m/44h/0h  p2pkh or p2sh
MAIN_xprv = b'\x04\x88\xAD\xE4'; MAIN_xpub = b'\x04\x88\xB2\x1E'
# m/44h/1h  p2pkh or p2sh
TEST_tprv = b'\x04\x35\x83\x94'; TEST_tpub = b'\x04\x35\x87\xCF'
# m/49h/0h  p2sh-segwit p2wpkh-p2sh
MAIN_yprv = b'\x04\x9D\x78\x78'; MAIN_ypub = b'\x04\x9D\x7C\xB2'
# m/49h/1h  p2sh-segwit p2wpkh-p2sh
TEST_uprv = b'\x04\x4A\x4E\x28'; TEST_upub = b'\x04\x4A\x52\x62'
# m/84h/0h  native segwit P2WPKH
MAIN_zprv = b'\x04\xB2\x43\x0C'; MAIN_zpub = b'\x04\xB2\x47\x46'
# m/84h/1h  native segwit P2WPKH
TEST_vprv = b'\x04\x5F\x18\xBC'; TEST_vpub = b'\x04\x5F\x1C\xF6'
#   ---     p2sh-segwit multi-sig p2wpkh-p2sh
MAIN_Yprv = b'\x02\x95\xB0\x05'; MAIN_Ypub = b'\x02\x95\xB4\x3F'
TEST_Uprv = b'\x02\x42\x85\xB5'; TEST_Upub = b'\x02\x42\x89\xEF'
#   ---     native segwit multi-sig p2wpkh
MAIN_Zprv = b'\x02\xAA\x7A\x99'; MAIN_Zpub = b'\x02\xAA\x7E\xD3'
TEST_Vprv = b'\x02\x57\x50\x48'; TEST_Vpub = b'\x02\x57\x54\x83'


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
    """Neutered Derivation (ND)

    Computation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions)
    """

    xprv = base58.decode_check(xprv, 78)
    if xprv[45] != 0:
        raise ValueError("extended key is not a private one")

    i = PRV_VERSION.index(xprv[:4])

    # serialization data
    xpub = PUB_VERSION[i]                      # version
    # unchanged serialization data
    xpub += xprv[4: 5]                         # depth
    xpub += xprv[5: 9]                         # parent pubkey fingerprint
    xpub += xprv[9:13]                         # child index
    xpub += xprv[13:45]                        # chain code

    p = int_from_octets(xprv[46:])
    P = mult(ec, p)
    xpub += octets_from_point(ec, P, True)          # public key
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

    xparent = base58.decode_check(xparentkey, 78)

    version = xparent[:4]

    # serialization data
    xkey = version                               # version
    xkey += (xparent[4] + 1).to_bytes(1, 'big')  # (increased) depth

    if version in PUB_VERSION:
        if xparent[45] not in (2, 3):  # not a compressed public key
            raise ValueError("(pubversion/prvkey) mismatch in extended parent key")
        Parent_bytes = xparent[45:]
        Parent = point_from_octets(ec, Parent_bytes)
        xkey += h160(Parent_bytes)[:4]           # parent pubkey fingerprint
        if index[0] >= 0x80:
            raise ValueError("no private/hardened derivation from pubkey")
        xkey += index                            # child index
        parent_chain_code = xparent[13:45]       # normal derivation
        # actual extended key (key + chain code) derivation
        h = HMAC(parent_chain_code, Parent_bytes + index, sha512).digest()
        offset = int.from_bytes(h[:32], 'big')
        Offset = mult(ec, offset)
        Child = ec.add(Parent, Offset)
        Child_bytes = octets_from_point(ec, Child, True)
        xkey += h[32:]                           # chain code
        xkey += Child_bytes                      # public key
    elif version in PRV_VERSION:
        if xparent[45] != 0:    # not a private key
            raise ValueError("(prvversion/pubkey) mismatch in extended parent key")
        parent = int.from_bytes(xparent[46:], 'big')
        Parent = mult(ec, parent)
        Parent_bytes = octets_from_point(ec, Parent, True)
        xkey += h160(Parent_bytes)[:4]           # parent pubkey fingerprint
        xkey += index                            # child index
        # actual extended key (key + chain code) derivation
        parent_chain_code = xparent[13:45]
        if (index[0] < 0x80):                    # normal derivation
            h = HMAC(parent_chain_code, Parent_bytes + index, sha512).digest()
        else:                                    # hardened derivation
            h = HMAC(parent_chain_code, xparent[45:] + index, sha512).digest()
        offset = int.from_bytes(h[:32], 'big')
        child = (parent + offset) % ec.n
        child_bytes = b'\x00' + child.to_bytes(32, 'big')
        xkey += h[32:]                           # chain code
        xkey += child_bytes                      # private key
    else:
        raise ValueError("invalid extended key version")

    return base58.encode_check(xkey)


def indexes_from_path(path: str) -> Tuple[Sequence[int], bool]:
    """Extract derivation indexes from a derivation path like
       "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative)
    """

    steps = path.split('/')
    if steps[0] == 'm':
        absolute = True
    elif steps[0] == '.':
        absolute = False
    else:
        raise ValueError(f'Invalid derivation path: {path}')

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
    """derive an extended key according to path like
       "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative)
    """

    if isinstance(path, str):
        indexes, absolute = indexes_from_path(path)
        if absolute:
            decoded = base58.decode_check(xkey, 78)
            t = b'\x00'*9
            if decoded[4:13] != t:
                msg = "Absolute derivation path for non-root master key"
                raise ValueError(msg)
    else:
        indexes = path

    for index in indexes:
        xkey = ckd(xkey, index)

    return xkey


def p2pkh_address_from_xpub(xpub: Octets, version: Optional[Octets] = None) -> bytes:
    xpub = base58.decode_check(xpub, 78)
    if xpub[45] not in (2, 3):
        raise ValueError("extended key is not a public one")

    if version is None:
        xversion = xpub[:4]
        if xversion == MAIN_xpub:
            version = b'\x00'          # 1
        elif xversion == TEST_tpub:
            version = b'\x6F'          # m or n
        else:
            raise ValueError(f"xkey is not of p2pkh type (xpub/tpub)")

    P = point_from_octets(ec, xpub[45:])
    return p2pkh_address(P, True, version)


def crack(parent_xpub: Octets, child_xprv: Octets) -> bytes:
    parent_xpub = base58.decode_check(parent_xpub, 78)
    if parent_xpub[45] not in (2, 3):
        raise ValueError("extended parent key is not a public one")

    child_xprv = base58.decode_check(child_xprv, 78)
    if child_xprv[45] != 0:
         raise ValueError("extended child key is not a private one")

    # check depth
    if child_xprv[4] != parent_xpub[4] + 1:
         raise ValueError("wrong child/parent depth relation")

    # check fingerprint
    Parent_bytes = parent_xpub[45:]
    if child_xprv[5: 9] != h160(Parent_bytes)[:4]:
        raise ValueError("not a child for the provided parent")

    # check normal derivation
    child_index = child_xprv[9:13]
    if child_index[0] >= 0x80:
        raise ValueError("hardened derivation")

    parent_xprv = child_xprv[: 4]     # version
    parent_xprv += parent_xpub[4: 5]  # depth
    parent_xprv += parent_xpub[5: 9]  # parent pubkey fingerprint
    parent_xprv += parent_xpub[9:13]  # child index

    parent_chain_code = parent_xpub[13:45]
    parent_xprv += parent_chain_code  # chain code

    h = HMAC(parent_chain_code, Parent_bytes + child_index, sha512).digest()
    offset = int.from_bytes(h[:32], 'big')
    child = int.from_bytes(child_xprv[46:], 'big')
    parent = (child - offset) % ec.n
    parent_bytes = b'\x00' + parent.to_bytes(32, 'big')
    parent_xprv += parent_bytes        # private key

    return base58.encode_check(parent_xprv)


def child_index(xkey: Octets) -> bytes:
    xkey = base58.decode_check(xkey, 78)
    if xkey[4] == 0:
        raise ValueError("master key provided")
    return xkey[9:13]

def fingerprint(xkey: Octets) -> bytes:
    key = base58.decode_check(xkey, 78)
    version = key[:4]

    if key[45] == 0:
        if version in PRV_VERSION:
            xkey = xpub_from_xprv(xkey)
            key = base58.decode_check(xkey, 78)
        else:
            raise ValueError("(pubversion/prvkey) mismatch in extended parent key")
    elif key[45] in (2, 3):
        if version not in PUB_VERSION:
            raise ValueError("(prvversion/pubkey) mismatch in extended parent key")
    else:
        ValueError("not a valid extended key")

    return h160(key[45:])[:4]
