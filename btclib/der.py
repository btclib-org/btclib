#!/usr/bin/env python3

DER_follows = b'\x30'
int_follows = b'\x02'
double_0 = b'\x00'
mid = b'\x80'
sighash_all = b'\x01'
sighash_none = b'\x02'
sighash_single = b'\x03'
sighash_all_anyonecanpay = b'\x81'
sighash_none_anyonecanpay = b'\x82'
sighash_single_anyonecanpay = b'\x83'


def to_bytes_min_length(n, byteorder="big"):
    assert type(n) == int and n >= 0, "n must be a positive int"
    return n.to_bytes(n.bit_length() // 8 + 1, byteorder)  # at least 1 byte, even if n = 0

def to_bytes_add00(n):
    n_bytes = to_bytes_min_length(n, "big")
    return (double_0 if n_bytes[:1] >= mid else b'') + n_bytes

def encode_DER_sig(r, s, sighash=sighash_all):
    r_DER = to_bytes_add00(r)
    s_DER = to_bytes_add00(s)
    r_len = len(r_DER).to_bytes(1, "big")
    s_len = len(s_DER).to_bytes(1, "big")
    DER_sig = int_follows + r_len + r_DER + int_follows + s_len + s_DER
    total_len = len(DER_sig).to_bytes(1, "big")
    return DER_follows + total_len + DER_sig + sighash

def check_DER_sig(DER_sig):
    # following the instructions on BIP 066 in that order
    assert type(DER_sig) == bytes, "DER sig must be in bytes"
    assert 9 <= len(DER_sig) and len(DER_sig) <= 73, \
        "DER sig must at least 9 bytes and at most 73 bytes"
    assert DER_sig[0] == 0x30, "DER sig must start with 30"
    assert DER_sig[1] == len(DER_sig) - 3, "Length must cover the entire sig"
    lenR = DER_sig[3]
    assert 5 + lenR <= len(DER_sig), "Length of the s element must be inside the signature"
    lenS = DER_sig[5 + lenR]
    assert lenR + lenS + 7 == len(DER_sig), \
        "Length of the sig must match the sum of the length of the elements"
    assert DER_sig[2] == 0x02, "r element must be an int"
    assert lenR != 0, "Zero-length integers are not allowed for r"
    assert DER_sig[4] < 0x80, "Negative numbers are not allowed for r"
    if lenR > 1 and DER_sig[4] == 0x00: assert DER_sig[5] >= 0x80, \
        "Null bytes at the start of r are not allowed, unless r would" + \
        "otherwise be interpreted as a negative number"
    assert DER_sig[lenR + 4] == 0x02, "s element must be an int"
    assert lenS != 0, "Zero-length integers are not allowed for s"
    assert DER_sig[lenR + 6] < 0x80, "Negative numbers are not allowed for s"
    if lenS > 1 and DER_sig[lenR + 6] == 0x00: assert DER_sig[lenR + 7] >= 0x80, \
        "Null bytes at the start of s are not allowed, unless s would" + \
        "otherwise be interpreted as a negative number"
    return True
