#!/usr/bin/env python3

from hashlib import sha1, sha256
from btclib.ellipticcurves import EllipticCurve, Scalar as PrvKey, \
                                  GenericPoint as GenericPubKey, \
                                  int_from_Scalar, tuple_from_Point, \
                                  bytes_from_Scalar, pointMultiply
from btclib.rfc6979 import int2octets

 
def ecdh(ec: EllipticCurve, prv_sender: PrvKey, pub_recv: GenericPubKey) -> int:
    shared_point = pointMultiply(ec, prv_sender, pub_recv)
    shared_pubkey = tuple_from_Point(ec, shared_point)
    return shared_pubkey[0]

def key_setup(hash_digest_size: int) -> None:
    if hash_digest_size == 20:
        return sha1
    return sha256

def key_derivation_function(ec: EllipticCurve, shared_secret_octet: bytes, key_data_len: int, \
                           hash_digest_size: int, hash_max_len = 2**61 - 1) -> bytes:
    """ ANS X9.63 kdf - SEC 1 specification

    source: http://www.secg.org/sec1-v2.pdf, section 6.1
    """
    hasher = key_setup(hash_digest_size)
    assert len(shared_secret_octet) + 4 < hash_max_len, "invalid"
    assert key_data_len < hash_digest_size * (2**32 - 1), "invalid"
    counter = 1
    counter_bytes = counter.to_bytes(4, 'big')
    K_temp = []
    for i in range(key_data_len // hash_digest_size):
        K_temp.append(hasher(shared_secret_octet + counter_bytes).digest())
        counter += 1
        counter_bytes = counter.to_bytes(4, 'big') 
        i += 1
    K_bytes = b''.join(K_temp[i] for i in range(key_data_len // hash_digest_size))
    K = int_from_Scalar(ec, K_bytes) >> (key_data_len - hash_digest_size)
    return bytes_from_Scalar(ec, K)
    
def key_agreement_operation(ec: EllipticCurve, key_data_len: int, prv_sender: PrvKey, pub_recv: GenericPubKey, \
                           hash_digest_size: int) -> bytes:
    shared_secret = ecdh(ec, prv_sender, pub_recv)
    shared_secret_octet = int2octets(shared_secret)
    K = key_derivation_function(ec, shared_secret_octet, key_data_len, hash_digest_size)
    return K
