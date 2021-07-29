# !/usr/bin/env python3

# Copyright (C) 2021 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""Taproot related functions"""

from typing import Tuple, Any, Optional, Union, List
from btclib import var_bytes
from btclib.alias import Octets
from btclib.ecc.curve import Curve, mult, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script.script import serialize, Script
from btclib.utils import bytes_from_octets
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.to_prv_key import PrvKey, int_from_prv_key

# TODO: add type hinting to script_tree
# unfortunately recursive type hinting is not supported
# https://github.com/python/mypy/issues/731
# TaprootLeaf = Tuple[int, Script]
# TaprootScriptTree = List[Union[Any, TaprootLeaf]]
TaprootScriptTree = Any


def tree_helper(script_tree) -> Tuple[Any, bytes]:
    if len(script_tree) == 1:
        leaf_version, script = script_tree[0]
        leaf_version = leaf_version & 0xFE
        preimage = leaf_version.to_bytes(1, "big")
        preimage += var_bytes.serialize(serialize(script))
        h = tagged_hash(b"TapLeaf", preimage)
        return ([((leaf_version, script), bytes())], h)
    left, left_h = tree_helper(script_tree[0])
    right, right_h = tree_helper(script_tree[1])
    info = [(leaf, c + right_h) for leaf, c in left]
    info += [(leaf, c + left_h) for leaf, c in right]
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (info, tagged_hash(b"TapBranch", left_h + right_h))


def output_pubkey(
    internal_pubkey: Optional[Key] = None,
    script_tree: Optional[TaprootScriptTree] = None,
    ec: Curve = secp256k1,
) -> Tuple[bytes, int]:
    if not internal_pubkey and not script_tree:
        raise BTClibValueError("Missing data")
    if internal_pubkey:
        pubkey = pub_keyinfo_from_key(internal_pubkey, compressed=True)[0][1:]
    else:
        h_str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        pubkey = bytes.fromhex(h_str)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = tagged_hash(b"TapTweak", pubkey)
    t = int.from_bytes(tagged_hash(b"TapTweak", pubkey + h), "big")
    if t >= ec.n:
        raise ValueError
    x = int.from_bytes(pubkey, "big")
    Q = ec.add((x, ec.y_even(x)), mult(t))
    return Q[0].to_bytes(32, "big"), 1 - Q[1] % 2


def output_prvkey(
    internal_prvkey: PrvKey,
    script_tree: Optional[TaprootScriptTree] = None,
    ec: Curve = secp256k1,
) -> int:
    internal_prvkey = int_from_prv_key(internal_prvkey)
    P = mult(internal_prvkey)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = tagged_hash(b"TapTweak", P[0].to_bytes(32, "big"))
    has_even_y = ec.y_even(P[0]) != P[1]
    internal_prvkey = internal_prvkey if has_even_y else ec.n - internal_prvkey
    t = int.from_bytes(tagged_hash(b"TapTweak", P[0].to_bytes(32, "big") + h), "big")
    if t >= ec.n:
        raise ValueError
    return (internal_prvkey + t) % ec.n


def input_script_sig(
    internal_pubkey: Key, script_tree: TaprootScriptTree, script_num: int
) -> Tuple[bytes, bytes]:
    parity_bit = output_pubkey(internal_pubkey, script_tree)[1]
    pub_key_bytes = pub_keyinfo_from_key(internal_pubkey, compressed=True)[0][1:]
    (leaf_version, script), path = tree_helper(script_tree)[0][script_num]
    pubkey_data = (parity_bit + leaf_version).to_bytes(1, "big") + pub_key_bytes
    return script, pubkey_data + path


def check_tree_hash(q: Octets, script: Octets, control: Octets) -> bool:
    q = bytes_from_octets(q)
    script = bytes_from_octets(script)
    control = bytes_from_octets(control)
    m = (len(control) - 33) // 32
    if len(control) != 33 + 32 * m:
        raise BTClibValueError()
    if m > 127:
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
    return Q[0] == int.from_bytes(q, "big") and control[0] & 1 == Q[1] % 2
