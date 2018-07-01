#!/usr/bin/env python3

from hmac import HMAC
from hashlib import sha512
from typing import Union, Optional
from btclib.base58 import b58encode_check, b58decode_check
from btclib.ellipticcurves import secp256k1 as ec, pointMultiply, \
                                  bytes_from_Point, int_from_Scalar, \
                                  tuple_from_Point
from btclib.wifaddress import h160, address_from_pubkey

# VERSION BYTES =      4 bytes        Base58 encode starts with
MAINNET_PRIVATE = b'\x04\x88\xAD\xE4' # xprv
TESTNET_PRIVATE = b'\x04\x35\x83\x94' # tprv
SEGWIT_PRIVATE  = b'\x04\xb2\x43\x0c'
PRIVATE = [MAINNET_PRIVATE, TESTNET_PRIVATE, SEGWIT_PRIVATE]

MAINNET_PUBLIC  = b'\x04\x88\xB2\x1E' # xpub
TESTNET_PUBLIC  = b'\x04\x35\x87\xCF' # tpub
SEGWIT_PUBLIC   = b'\x04\xb2\x47\x46'
PUBLIC  = [MAINNET_PUBLIC,  TESTNET_PUBLIC,  SEGWIT_PUBLIC]

MAINNET_ADDRESS  = b'\x00'             # 1
TESTNET_ADDRESS  = b'\x6F'             # m or n
ADDRESS  = [MAINNET_ADDRESS,  TESTNET_ADDRESS]

# [  : 4] version
# [ 4: 5] depth
# [ 5: 9] parent pubkey fingerprint
# [ 9:13] child index
# [13:45] chain code
# [45:78] key (private/public)

def bip32_master_prvkey_from_seed(bip32_seed: Union[str, bytes], version: bytes) -> bytes:
    """derive the master extended private key from the seed"""
    if type(bip32_seed) == str: # hex string
        bip32_seed = bytes.fromhex(bip32_seed)
    assert version in PRIVATE, "wrong version, master key must be private"

    # serialization data
    xmprv = version                             # version
    xmprv += b'\x00'                            # depth
    xmprv += b'\x00\x00\x00\x00'                # parent pubkey fingerprint
    xmprv += b'\x00\x00\x00\x00'                # child index

    # actual extended key (key + chain code) derivation
    hashValue = HMAC(b"Bitcoin seed", bip32_seed, sha512).digest()
    mprv = int.from_bytes(hashValue[:32], 'big') % ec.order
    xmprv += hashValue[32:]                     # chain code
    xmprv += b'\x00' + mprv.to_bytes(32, 'big') # private key

    return b58encode_check(xmprv)


def bip32_xpub_from_xprv(xprv: bytes) -> bytes:
    """Neutered Derivation (ND)
    
    Computation of the extended public key corresponding to an extended
    private key (“neutered” as it removes the ability to sign transactions)
    """
    xprv = b58decode_check(xprv)
    assert len(xprv) == 78, "wrong length for decoded extended private key"
    assert xprv[45] == 0, "extended key is not a private one"

    i = PRIVATE.index(xprv[:4])

    # serialization data
    xpub = PUBLIC[i]                            # version
    # unchanged serialization data
    xpub += xprv[ 4: 5]                         # depth
    xpub += xprv[ 5: 9]                         # parent pubkey fingerprint
    xpub += xprv[ 9:13]                         # child index
    xpub += xprv[13:45]                         # chain code

    p = xprv[46:]
    P = pointMultiply(ec, p, ec.G)
    xpub += bytes_from_Point(ec, P, True)       # public key
    return b58encode_check(xpub)


def bip32_ckd(xparentkey: bytes, index: Union[bytes, int]) -> bytes:
    """Child Key Derivation (CDK)

    Key derivation is normal if the extended parent key is public or
    child_index is less than 0x80000000.
    
    Key derivation is hardened if the extended parent key is private and
    child_index is not less than 0x80000000.
    """

    if isinstance(index, int):
        index = index.to_bytes(4, 'big')
    elif isinstance(index, bytes):
        assert len(index) == 4
    else:
        raise TypeError("a 4 bytes int is required")

    xparent = b58decode_check(xparentkey)
    assert len(xparent) == 78, "wrong length for extended parent key"

    version = xparent[:4]

    # serialization data
    xkey = version                              # version
    xkey += (xparent[4] + 1).to_bytes(1, 'big') # (increased) depth

    if (version in PUBLIC):
        assert xparent[45] in (2, 3), \
               "version/key mismatch in extended parent key"
        Parent_bytes = xparent[45:]
        Parent = tuple_from_Point(ec, Parent_bytes)
        xkey += h160(Parent_bytes)[:4]          # parent pubkey fingerprint
        assert index[0] < 0x80, \
               "no private/hardened derivation from pubkey"
        xkey += index                           # child index
        parent_chain_code = xparent[13:45]      ## normal derivation
        # actual extended key (key + chain code) derivation
        h = HMAC(parent_chain_code, Parent_bytes + index, sha512).digest()
        offset = int.from_bytes(h[:32], 'big')
        Offset = ec.pointMultiply(offset, ec.G)
        Child = ec.pointAdd(Parent, Offset)
        Child_bytes = bytes_from_Point(ec, Child, True)
        xkey += h[32:]                          # chain code
        xkey += Child_bytes                     # public key
    elif (version in PRIVATE):
        assert xparent[45] == 0, "version/key mismatch in extended parent key"
        parent = int.from_bytes(xparent[46:], 'big')
        Parent = ec.pointMultiply(parent, ec.G)
        Parent_bytes = bytes_from_Point(ec, Parent, True)
        xkey += h160(Parent_bytes)[:4]          # parent pubkey fingerprint
        xkey += index                           # child index
        # actual extended key (key + chain code) derivation
        parent_chain_code = xparent[13:45]
        if (index[0] < 0x80):                   ## normal derivation
            h = HMAC(parent_chain_code, Parent_bytes + index, sha512).digest()
        else:                                   ## hardened derivation
            h = HMAC(parent_chain_code, xparent[45:] + index, sha512).digest()
        offset = int.from_bytes(h[:32], 'big')
        child = (parent + offset) % ec.order
        child_bytes = b'\x00' + child.to_bytes(32, 'big')
        xkey += h[32:]                          # chain code
        xkey += child_bytes                     # private key
    else:
        raise ValueError("invalid extended key version")

    return b58encode_check(xkey)


def bip32_derive(xkey: bytes, path: str) -> bytes:
    """derive an extended key according to path like "m/44'/0'/1'/0/10" (absolute) or "./0/10" (relative) """

    indexes = []
    if isinstance(path, list):
        indexes = path
    elif isinstance(path, str):
        steps = path.split('/')
        if steps[0] not in {'m', '.'}:
            raise ValueError('Invalid derivation path: {}'.format(path))  
        if steps[0] == 'm':
            decoded = b58decode_check(xkey)
            t = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            assert decoded[4:13] == t, "Trying to derive absolute path from non-master key"

        for step in steps[1:]:
            hardened = False
            if step[-1] == "'" or step[-1] == "H":
                hardened = True
                step = step[:-1]
            index = int(step)
            index += 0x80000000 if hardened else 0
            indexes.append(index)
    else:
        raise TypeError("list of indexes or string like 'm/44'/0'/1'/0/10' expected")

    for index in indexes:
        xkey = bip32_ckd(xkey, index)

    return xkey

# FIXME: revise address_from_xpub / address_from_pubkey relation
def address_from_xpub(xpub: bytes, version: Optional[bytes] = None):
    xpub = b58decode_check(xpub)
    assert len(xpub) == 78, "wrong length for decoded extended public key"
    assert xpub[45] in (2, 3), "extended key is not a public one"
    # bitcoin: address version can be derived from xkey version
    # altcoin: address version cannot be derived from xkey version
    #          if xkey version bytes have not been specialized
    # FIXME use BIP44 here
    if version is None:
        xversion = xpub[:4]
        i = PUBLIC.index(xversion)
        version = ADDRESS[i]
    return address_from_pubkey(xpub[45:], version)

def bip32_crack(parent_xpub: bytes, child_xprv: bytes) -> bytes:
    parent_xpub = b58decode_check(parent_xpub)
    assert len(parent_xpub) == 78, "wrong length for decoded extended parent public key"
    assert parent_xpub[45] in (2, 3), "extended parent key is not a public one"

    child_xprv = b58decode_check(child_xprv)
    assert len(child_xprv) == 78, "wrong length for decoded extended child private key"
    assert child_xprv[45] == 0, "extended child key is not a private one"

    # check depth
    assert child_xprv[4] == parent_xpub[4]+1, "wrong child/parent depth relation"

    # check fingerprint
    Parent_bytes = parent_xpub[45:  ]
    assert child_xprv[ 5: 9] == h160(Parent_bytes)[:4], "not a child for the provided parent"

    # check normal derivation
    child_index  =  child_xprv[ 9:13]
    assert child_index[0] < 0x80, "hardened derivation"

    parent_xprv =   child_xprv[  : 4] # version
    parent_xprv += parent_xpub[ 4: 5] # depth
    parent_xprv += parent_xpub[ 5: 9] # parent pubkey fingerprint
    parent_xprv += parent_xpub[ 9:13] # child index

    parent_chain_code = parent_xpub[13:45]
    parent_xprv += parent_chain_code  # chain code

    h = HMAC(parent_chain_code, Parent_bytes + child_index, sha512).digest()
    offset = int.from_bytes(h[:32], 'big')
    child = int.from_bytes(child_xprv[46:], 'big')
    parent = (child - offset) % ec.order
    parent_bytes = b'\x00' + parent.to_bytes(32, 'big')
    parent_xprv += parent_bytes        # private key

    return b58encode_check(parent_xprv)

def bip32_child_index(xkey: bytes) -> bytes:
    xkey = b58decode_check(xkey)
    assert len(xkey) == 78, "wrong length for extended key"
    if xkey[4]==0:
        raise ValueError("master key provided")
    return xkey[ 9:13]
