#!/usr/bin/env python3

'''wifs and addresses

Implementation of Base58 encoding of private keys (wifs)
and public keys (addresses)
'''

from hashlib import sha256, new as hnew
from btclib.ellipticcurves import secp256k1 as ec
from btclib.base58 import b58encode_check, b58decode_check, base58digits


def bytes_from_prvkey(prv):
    """Return private key as 32 bytes"""
    
    if isinstance(prv, int):
        assert 0 < prv           , "Invalid Private Key"
        assert     prv < ec.order, "Invalid Private Key"
        return prv.to_bytes(32, 'big')

    if isinstance(prv, str):
        # wif
        if len(prv) in (51, 52) and all(c in base58digits for c in prv):
          return prvkey_from_wif(prv)
        # hex string
        if prv[:2] == "0x":
          prv = prv[2:]
        assert len(prv) & 2 == 0, "odd-length hex string"
        prv = bytes.fromhex(prv)

    if isinstance(prv, bytes) or isinstance(prv, bytearray):
        assert len(prv) == 32, "wrong lenght"
        assert int.from_bytes(prv, 'big') < ec.order, "prvkey >= order"
        return prv
    else: 
        raise TypeError("a bytes-like object is required (also str or int)")


def int_from_prvkey(prv):
    """Return private key as int"""
    
    if isinstance(prv, str):
        # wif
        if len(prv) in (51, 52) and all(c in base58digits for c in prv):
            prv = prvkey_from_wif(prv)
        # hex string
        if prv[:2] == "0x":
            prv = prv[2:]
        assert len(prv) & 2 == 0, "odd-length hex string"
        prv = bytes.fromhex(prv)

    if isinstance(prv, bytes) or isinstance(prv, bytearray):
        assert len(prv) == 32, "wrong lenght"
        prv = int.from_bytes(prv, 'big')

    if isinstance(prv, int):
        assert 0 < prv           , "Invalid Private Key"
        assert     prv < ec.order, "Invalid Private Key"
        return prv
    else:
        raise TypeError("a bytes-like object is required (also str or int)")


def wif_from_prvkey(p, compressed=True):
    """private key to Wallet Import Format"""

    payload = b'\x80' + bytes_from_prvkey(p)
    if compressed: payload += b'\x01'
    return b58encode_check(payload)


def prvkey_from_wif(wif):
    """Wallet Import Format to (bytes) private key"""

    payload = b58decode_check(wif)
    assert payload[0] == 0x80, "not a wif"

    if len(payload) == 34: # compressed
        assert payload[33] == 0x01, "not a wif"
        return bytes_from_prvkey(payload[1:-1]), True
    else:                  # uncompressed
        assert len(payload) == 33, "not a wif"
        return bytes_from_prvkey(payload[1:]), False


def pubkey_from_prvkey(prvkey, compressed = True):
    P = ec.pointMultiply(prvkey, ec.G)
    return ec.bytes_from_point(P, compressed)
  

def h160(pubkey):
    pubkey = ec.bytes_from_point(pubkey, True)
    t = sha256(pubkey).digest()
    return hnew('ripemd160', t).digest()


def address_from_pubkey(pubkey, version=b'\x00'):
    vh160 = version + h160(pubkey)
    return b58encode_check(vh160)


def hash160_from_address(addr):
    payload = b58decode_check(addr)
    assert len(payload) == 21
    assert payload[0] == 0x00, "not an address"
    return payload[1:]
