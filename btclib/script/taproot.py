# !/usr/bin/env python3

# Copyright (C) 2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""Taproot related functions"""


from btclib import var_bytes
from btclib.alias import Octets
from btclib.ecc.curve import Curve, mult, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script.script import serialize
from btclib.utils import bytes_from_octets

# from btclib.sig_hash import taproot


def tweak_pubkey(pubkey, h, ec: Curve = secp256k1):
    t = int.from_bytes(tagged_hash(b"TapTweak", pubkey + h), "big")
    if t >= ec.n:
        raise ValueError
    x = int.from_bytes(pubkey, "big")
    Q = ec.add((x, ec.y_even(x)), mult(t))
    has_even_y = ec.y_even(Q[0]) != Q[1]
    return 0 if has_even_y else 1, Q[0].to_bytes(32, "big")


def taproot_tweak_seckey(seckey0, h, ec: Curve = secp256k1):
    P = mult(int.from_bytes(seckey0, "big"))
    has_even_y = ec.y_even(P[0]) != P[1]
    seckey = seckey0 if has_even_y else ec.n - seckey0
    t = int.from_bytes(tagged_hash(b"TapTweak", P[0].to_bytes(32, "big") + h), "big")
    if t >= ec.n:
        raise ValueError
    return (seckey + t) % ec.n


def taproot_tree_helper(script_tree):
    if isinstance(script_tree, tuple):
        leaf_version, script = script_tree
        h = tagged_hash(b"TapLeaf", bytes([leaf_version]) + serialize(script))
        return ([((leaf_version, script), bytes())], h)
    left, left_h = taproot_tree_helper(script_tree[0])
    right, right_h = taproot_tree_helper(script_tree[1])
    ret = [(leaf, c + right_h) for leaf, c in left]
    ret += [(leaf, c + left_h) for leaf, c in right]
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (ret, tagged_hash(b"TapBranch", left_h + right_h))


def taproot_output_script(internal_pubkey, script_tree):
    """Given a internal public key and a tree of scripts, compute the output script.
    script_tree is either:
     - a (leaf_version, script) tuple (leaf_version is 0xc0 for [[bip-0342.mediawiki|BIP342]] scripts)
     - a list of two elements, each with the same structure as script_tree itself
     - None
    """
    if script_tree is None:
        h = bytes()
    else:
        _, h = taproot_tree_helper(script_tree)
    output_pubkey, _ = tweak_pubkey(internal_pubkey, h)
    return serialize("OP_1" + output_pubkey)


# def taproot_sign_key(script_tree, internal_seckey, hash_type):
#     _, h = taproot_tree_helper(script_tree)
#     output_seckey = taproot_tweak_seckey(internal_seckey, h)
#     sig = sign_(taproot(hash_type), output_seckey)
#     if hash_type != 0:
#         sig += bytes([hash_type])
#     return [sig]


def taproot_sign_script(internal_pubkey, script_tree, script_num, inputs):
    info, h = taproot_tree_helper(script_tree)
    (leaf_version, script), path = info[script_num]
    output_pubkey_y_parity, _ = tweak_pubkey(internal_pubkey, h)
    pubkey_data = bytes([output_pubkey_y_parity + leaf_version]) + internal_pubkey
    return inputs + [script, pubkey_data + path]


def check_tree_hash(q: Octets, script: Octets, control: Octets) -> bool:
    q = bytes_from_octets(q)
    script = bytes_from_octets(script)
    control = bytes_from_octets(control)
    m = (len(control) - 33) // 32
    if len(control) != 33 + 32 * m:
        raise BTClibValueError()
    leaf_version = control[0] & 0xFE
    preimage = leaf_version.to_bytes(1, "big") + var_bytes.serialize(script)
    k = tagged_hash(b"TapLeaf", preimage)
    for j in range(m):
        e = control[33 + 32 * j : 65 + 32 * j]
        if k < e:
            k = tagged_hash(b"TapBranch", k + e)
        else:
            k = tagged_hash(b"TapBranch", e + k)
    p_bytes = control[1:33]
    t_bytes = tagged_hash(b"TapTweak", p_bytes + k)
    p = int.from_bytes(p_bytes, "big")
    t = int.from_bytes(t_bytes, "big")
    if t >= secp256k1.n:
        raise BTClibValueError()
    P = (p, secp256k1.y_even(p))
    Q = secp256k1.add(P, mult(t))
    return Q[0] == int.from_bytes(q, "big")
