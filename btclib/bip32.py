#!/usr/bin/env python3

# Copyright (C) 2017-2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from hmac import HMAC
from hashlib import sha512
from typing import Union, Optional, Sequence, List

from . import base58 
from .curve import mult
from .curves import secp256k1 as ec
from .utils import octets, point_from_octets, octets_from_point, \
                         int_from_octets, h160
from .wifaddress import address_from_pubkey

# VERSION BYTES =      4 bytes     Base58 encode starts with
MAINNET_PRV = b'\x04\x88\xAD\xE4'  # xprv
TESTNET_PRV = b'\x04\x35\x83\x94'  # tprv
SEGWIT_PRV  = b'\x04\xb2\x43\x0c'
PRV = [MAINNET_PRV, TESTNET_PRV, SEGWIT_PRV]

MAINNET_PUB = b'\x04\x88\xB2\x1E'  # xpub
TESTNET_PUB = b'\x04\x35\x87\xCF'  # tpub
SEGWIT_PUB  = b'\x04\xb2\x47\x46'
PUB = [MAINNET_PUB,  TESTNET_PUB,  SEGWIT_PUB]

MAINNET_ADDRESS = b'\x00'          # 1
TESTNET_ADDRESS = b'\x6F'          # m or n
ADDRESS = [MAINNET_ADDRESS,  TESTNET_ADDRESS]

# [  : 4] version
# [ 4: 5] depth
# [ 5: 9] parent pubkey fingerprint
# [ 9:13] child index
# [13:45] chain code
# [45:78] key (private/public)

def xmprv_from_seed(seed: octets, version: octets) -> bytes:
    """derive the master extended private key from the seed"""

    if isinstance(version, str):  # hex string
        version = bytes.fromhex(version)
    if version not in PRV:
        m = f"invalid private version ({version})"
        raise ValueError(m)

    # serialization data
    xmprv = version                               # version
    xmprv += b'\x00'                              # depth
    xmprv += b'\x00\x00\x00\x00'                  # parent pubkey fingerprint
    xmprv += b'\x00\x00\x00\x00'                  # child index

    # actual extended key (key + chain code) derivation
    if isinstance(seed, str):  # hex string
        seed = bytes.fromhex(seed)
    hd = HMAC(b"Bitcoin seed", seed, sha512).digest()
    mprv = int_from_octets(hd[:32])
    xmprv += hd[32:]                              # chain code
    xmprv += b'\x00' + mprv.to_bytes(32, 'big')   # private key

    return base58.encode_check(xmprv)


def xpub_from_xprv(xprv: octets) -> bytes:
    """Neutered Derivation (ND)

    Computation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions)
    """

    xprv = base58.decode_check(xprv, 78)
    if xprv[45] != 0:
        raise ValueError("extended key is not a private one")

    i = PRV.index(xprv[:4])

    # serialization data
    xpub = PUB[i]                           # version
    # unchanged serialization data
    xpub += xprv[4: 5]                         # depth
    xpub += xprv[5: 9]                         # parent pubkey fingerprint
    xpub += xprv[9:13]                         # child index
    xpub += xprv[13:45]                        # chain code

    p = int_from_octets(xprv[46:])
    P = mult(ec, p)
    xpub += octets_from_point(ec, P, True)          # public key
    return base58.encode_check(xpub)


def ckd(xparentkey: octets, index: Union[octets, int]) -> bytes:
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

    if (version in PUB):
        if xparent[45] not in (2, 3):  # not a compressed public key
            raise ValueError("version/key mismatch in extended parent key")
        Parent_bytes = xparent[45:]
        Parent = point_from_octets(ec, Parent_bytes)
        xkey += h160(Parent_bytes)[:4]          # parent pubkey fingerprint
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
        xkey += h[32:]                            # chain code
        xkey += Child_bytes                       # public key
    elif (version in PRV):
        if xparent[45] != 0:    # not a private key
            raise ValueError("version/key mismatch in extended parent key")
        parent = int.from_bytes(xparent[46:], 'big')
        Parent = mult(ec, parent)
        Parent_bytes = octets_from_point(ec, Parent, True)
        xkey += h160(Parent_bytes)[:4]           # parent pubkey fingerprint
        xkey += index                             # child index
        # actual extended key (key + chain code) derivation
        parent_chain_code = xparent[13:45]
        if (index[0] < 0x80):                     # normal derivation
            h = HMAC(parent_chain_code, Parent_bytes + index, sha512).digest()
        else:                                     # hardened derivation
            h = HMAC(parent_chain_code, xparent[45:] + index, sha512).digest()
        offset = int.from_bytes(h[:32], 'big')
        child = (parent + offset) % ec.n
        child_bytes = b'\x00' + child.to_bytes(32, 'big')
        xkey += h[32:]                            # chain code
        xkey += child_bytes                       # private key
    else:
        raise ValueError("invalid extended key version")

    return base58.encode_check(xkey)


def derive(xkey: octets, path: Union[str, Sequence[int]]) -> bytes:
    """derive an extended key according to path like
       "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative)
    """

    if isinstance(path, str):
        steps = path.split('/')
        if steps[0] not in {'m', '.'}:
            raise ValueError(f'Invalid derivation path: {path}')
        if steps[0] == 'm':
            decoded = base58.decode_check(xkey, 78)
            t = b'\x00'*9
            if decoded[4:13] != t:
                raise ValueError("Absolute derivation path for non-master key")

        indexes: List[int] = list()
        for step in steps[1:]:
            hardened = False
            if step[-1] == "'" or step[-1] == "H":
                hardened = True
                step = step[:-1]
            index = int(step)
            index += 0x80000000 if hardened else 0
            indexes.append(index)
    else:
        indexes = path

    for index in indexes:
        xkey = ckd(xkey, index)

    return xkey

# FIXME: revise address_from_xpub / address_from_pubkey relation
# FIXME: address_from_xpub should be pubkey_from_xpub o point_from_xpub


def address_from_xpub(xpub: octets, version: Optional[octets] = None) -> bytes:
    xpub = base58.decode_check(xpub, 78)
    if xpub[45] not in (2, 3):
        raise ValueError("extended key is not a public one")
    # bitcoin: address version can be derived from xkey version
    # altcoin: address version cannot be derived from xkey version
    #          if xkey version bytes have not been specialized
    # FIXME use BIP44 here
    if version is None:
        xversion = xpub[:4]
        i = PUB.index(xversion)
        version = ADDRESS[i]
    P = point_from_octets(ec, xpub[45:])
    return address_from_pubkey(P, True, version)


def crack(parent_xpub: octets, child_xprv: octets) -> bytes:
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


def child_index(xkey: octets) -> bytes:
    xkey = base58.decode_check(xkey, 78)
    if xkey[4] == 0:
        raise ValueError("master key provided")
    return xkey[9:13]
