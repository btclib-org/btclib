#!/usr/bin/env python3

from hmac import HMAC
from hashlib import sha512
from base58 import b58encode_check, b58decode_check
from ellipticcurves import secp256k1 as ec
from wifaddress import h160, address_from_pubkey

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

# version                  : [  : 4]  4 bytes
# depth                    : [ 4: 5]  1 byte
# parent pubkey fingerprint: [ 5: 9]  4 bytes
# child index              : [ 9:13]  4 bytes
# chain code               : [13:45] 32 bytes
# key (private/public)     : [45:78] 33 bytes

def bip32_master_prvkey_from_seed(bip32_seed, version = PRIVATE[0]):
    """derive the master extended private key from the seed"""
    if type(bip32_seed) == str:
        bip32_seed = bytes.fromhex(bip32_seed)
    assert version in PRIVATE, "wrong version, master key must be private"
    xmprv = version                             # version
    xmprv += b'\x00'                            # depth
    xmprv += b'\x00\x00\x00\x00'                # parent's pubkey fingerprint
    xmprv += b'\x00\x00\x00\x00'                # child_index
    hashValue = HMAC(b"Bitcoin seed", bip32_seed, sha512).digest()
    xmprv += hashValue[32:]                     # chain_code
    mprv = int.from_bytes(hashValue[:32], 'big') % ec.order
    xmprv += b'\x00' + mprv.to_bytes(32, 'big') # private key
    return b58encode_check(xmprv)


def bip32_xpub_from_xprv(xprv):
    """derive the extended public key from the extended private key"""
    xprv = b58decode_check(xprv)
    assert len(xprv) == 78, "wrong length for decoded extended private key"
    assert xprv[45] == 0, "the extended key is not a private one"

    i = PRIVATE.index(xprv[:4])
    xpub = PUBLIC[i]                            # version

    # depth, fingerprint, child index, and chain code are left unchanged
    xpub += xprv[4:45]

    p = xprv[46:]
    P = ec.pointMultiply(p)
    xpub += ec.bytes_from_point(P, True)        # public key
    return b58encode_check(xpub)


def bip32_ckd(xparentkey, child_index):
    """Child Key Derivation

    Key derivation is normal if the extended parent key is public or
    child_index is less than 0x80000000.
    
    Key derivation is hardened if the extended parent key is private and
    child_index is not less than 0x80000000.
    """

    if isinstance(child_index, int):
        child_index = child_index.to_bytes(4, 'big')

    xparent = b58decode_check(xparentkey)
    assert len(xparent) == 78, "wrong length for extended parent key"

    version = xparent[:4]

    xkey = version                              # version
    xkey += (xparent[4] + 1).to_bytes(1, 'big') # (increased) depth

    if (version in PRIVATE):
        assert xparent[45] == 0, "version/key mismatch in extended parent key"
        parent_prvkey = xparent[46:]
        parent_pubkey = ec.bytes_from_point(ec.pointMultiply(parent_prvkey), True)
        xkey += h160(parent_pubkey)[:4]         # parent's pubkey fingerprint
        xkey += child_index                     # child index
        if (child_index[0] < 0x80): # normal derivation
            h = HMAC(xparent[13:45], parent_pubkey + child_index, sha512).digest()
        else:                       # hardened derivation
            h = HMAC(xparent[13:45], xparent[45:] + child_index, sha512).digest()
        xkey += h[32:]                          # chain code
        p = int.from_bytes(h[:32], 'big')
        p = (p + int.from_bytes(parent_prvkey, 'big')) % ec.order
        xkey += b'\x00' + p.to_bytes(32, 'big') # private key
    elif (version in PUBLIC):
        assert xparent[45] in (2, 3), "version/key mismatch in extended parent key"
        xkey += h160(xparent[45:])[:4]          # fingerprint of parent pubkey
        assert child_index[0] < 0x80, "No private/hardened derivation from pubkey"
        xkey += child_index                     # child index
        # normal derivation
        h = HMAC(xparent[13:45], xparent[45:] + child_index, sha512).digest()
        xkey += h[32:]                          # chain_code
        P = ec.pointMultiply(h[:32])
        parentPoint = ec.tuple_from_point(xparent[45:])
        P = ec.pointAdd(P, parentPoint)
        xkey += ec.bytes_from_point(P, True)    # public key
    else:
        raise ValueError("invalid extended key version")

    return b58encode_check(xkey)


def bip32_derive(xkey, path):
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
def address_from_xpub(xpub, version=None):
    xpub = b58decode_check(xpub)
    assert len(xpub) == 78, "wrong length for decoded extended public key"
    assert xpub[45] in (2, 3), "the extended key is not a public one"
    # bitcoin: address version can be derived from xkey version
    # altcoin: address version cannot be derived from xkey version
    #          if xkey version bytes have not been specialized
    # FIXME use BIP44 here
    if version is None:
        xversion = xpub[:4]
        i = PUBLIC.index(xversion)
        version = ADDRESS[i]
    return address_from_pubkey(xpub[45:], version)
