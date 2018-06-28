#!/usr/bin/env python3

'''wifs and addresses

Implementation of Base58 encoding of private keys (wifs)
and public keys (addresses)
'''

from hashlib import sha256, new as hnew
from btclib.ellipticcurves import Union, Scalar as PrivateKey, Point as PublicKey, secp256k1 as ec
from btclib.base58 import b58encode_check, b58decode_check, base58digits

WIF = Union[str, bytes]
Address = Union[str, bytes]

def wif_from_prvkey(prvkey: PrivateKey, compressed: bool = True) -> bytes:
    """private key to Wallet Import Format"""

    payload = b'\x80' + ec.bytes_from_Scalar(prvkey)
    if compressed: payload += b'\x01'
    return b58encode_check(payload)


def prvkey_from_wif(wif: WIF) -> bytes:
    """Wallet Import Format to (bytes) private key"""

    payload = b58decode_check(wif)
    assert payload[0] == 0x80, "not a WIF"

    if len(payload) == ec.lencompressed+1: # compressed WIF
        # must have a trailing 0x01
        assert payload[ec.lencompressed] == 0x01, "not a WIF"
        return ec.bytes_from_Scalar(payload[1:-1]), True
    elif len(payload) == ec.lencompressed: # uncompressed WIF
        return ec.bytes_from_Scalar(payload[1:]), False

    raise ValueError("not a WIF")


def pubkey_from_prvkey(prvkey: PrivateKey, compressed: bool = True) -> bytes:
    """Private key to (bytes) public key"""
    P = ec.pointMultiply(prvkey, ec.G)
    return ec.bytes_from_point(P, compressed)


def h160(pubkey: PublicKey) -> bytes:
    pubkey = ec.bytes_from_point(pubkey, True)
    t = sha256(pubkey).digest()
    return hnew('ripemd160', t).digest()


def address_from_pubkey(pubkey: PublicKey, version: bytes = b'\x00') -> bytes:
    """Public key to (bytes) address"""
    # FIXME: this is mainnet only
    vh160 = version + h160(pubkey)
    return b58encode_check(vh160)


def hash160_from_address(addr: Address) -> bytes:
    payload = b58decode_check(addr)
    assert len(payload) == 21
    # FIXME: this is mainnet only
    assert payload[0] == 0x00, "not an address"
    return payload[1:]
