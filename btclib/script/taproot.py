# !/usr/bin/env python3

# Copyright (C) 2021-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""Taproot related functions"""

from typing import Any, Optional, Tuple

from btclib import var_bytes
from btclib.alias import Octets
from btclib.ecc.curve import Curve, mult, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script.script import serialize
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets

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
        h_str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        pubkey = bytes.fromhex(h_str)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = b""
    t = int.from_bytes(tagged_hash(b"TapTweak", pubkey + h), "big")
    # edge case that cannot be reproduced in the test suite
    if t >= ec.n:
        raise BTClibValueError("Invalid script tree hash")  # pragma: no cover
    P_x = int.from_bytes(pubkey, "big")
    Q = ec.add((P_x, ec.y_even(P_x)), mult(t))
    return Q[0].to_bytes(32, "big"), Q[1] % 2


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
        h = b""
    has_even_y = ec.y_even(P[0]) == P[1]
    internal_prvkey = internal_prvkey if has_even_y else ec.n - internal_prvkey
    t = int.from_bytes(tagged_hash(b"TapTweak", P[0].to_bytes(32, "big") + h), "big")
    # edge case that cannot be reproduced in the test suite
    if t >= ec.n:
        raise BTClibValueError("Invalid script tree hash")  # pragma: no cover
    return (internal_prvkey + t) % ec.n


def input_script_sig(
    internal_pubkey: Optional[Key], script_tree: TaprootScriptTree, script_num: int
) -> Tuple[bytes, bytes]:
    parity_bit = output_pubkey(internal_pubkey, script_tree)[1]
    if internal_pubkey:
        pub_key_bytes = pub_keyinfo_from_key(internal_pubkey, compressed=True)[0][1:]
    else:
        h_str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        pub_key_bytes = bytes.fromhex(h_str)
    (leaf_version, script), path = tree_helper(script_tree)[0][script_num]
    control = (parity_bit + leaf_version).to_bytes(1, "big")
    control += pub_key_bytes
    control += path
    return script, control


def check_output_pubkey(
    q: Octets, script: Octets, control: Octets, ec: Curve = secp256k1
) -> bool:
    q = bytes_from_octets(q)
    script = bytes_from_octets(script)
    control = bytes_from_octets(control)
    if len(control) > 4129:  # 33 + 32 * 128
        raise BTClibValueError("Control block too long")
    m = (len(control) - 33) // 32
    if len(control) != 33 + 32 * m:
        raise BTClibValueError("Invalid control block length")
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
    # edge case that cannot be reproduced in the test suite
    if t >= ec.n:
        raise BTClibValueError("Invalid script tree hash")  # pragma: no cover
    P = (p, secp256k1.y_even(p))
    Q = secp256k1.add(P, mult(t))
    return Q[0] == int.from_bytes(q, "big") and control[0] & 1 == Q[1] % 2
