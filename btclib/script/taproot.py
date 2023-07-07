#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Taproot related functions."""

from __future__ import annotations

from typing import Any

from btclib import var_bytes
from btclib.alias import BinaryData, Octets, ScriptList, TaprootScriptTree
from btclib.ec import Curve, mult, secp256k1
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script.op_codes_tapscript import (
    OP_CODE_NAMES,
    OP_SUCCESS,
    _serialize_bytes_command,
    _serialize_int_command,
    _serialize_str_command,
)
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import Key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets, bytesio_from_binarydata


def serialize(script: ScriptList) -> bytes:
    r: list[bytes] = []
    script = script[::-1]
    while script:
        command = script.pop()
        if isinstance(command, int):
            r.append(_serialize_int_command(command))
        elif isinstance(command, str):
            r.append(_serialize_str_command(command))
            if "OP_SUCCESS" in command:
                if len(script) != 1 or not isinstance(script[0], bytes):
                    raise BTClibValueError()
                return b"".join(r) + script[0]
        else:  # must be bytes
            r.append(_serialize_bytes_command(command))
    return b"".join(r)


def parse(stream: BinaryData, exit_on_op_success: bool = False) -> ScriptList:
    s = bytesio_from_binarydata(stream)
    r: ScriptList = []  # initialize the result list
    invalid_element_size = False

    while True:
        t = s.read(1)  # get one byte
        if not t:
            break
        i = t[0]  # convert the byte to an integer
        if 0 < i <= 78:  # push
            if 0 < i < 76:  # 1-byte-data-length | data
                data_length = i
            if 76 <= i <= 78:
                if i == 76:  # OP_PUSHDATA1 | 1-byte-data-length | data
                    x = 1
                elif i == 77:  # OP_PUSHDATA2 | 2-byte-data-length | data
                    x = 2
                elif i == 78:  # OP_PUSHDATA4 | 4-byte-data-length | data
                    x = 4
                y = s.read(x)
                if len(y) != x:
                    raise BTClibValueError("Invalid pushdata length")
                data_length = int.from_bytes(y, byteorder="little")
            if data_length > 520:
                invalid_element_size = True
            data = s.read(data_length)
            if len(data) != data_length:
                raise BTClibValueError("Invalid pushdata length")
            new_op_code = data.hex().upper()
        elif i in OP_SUCCESS:  # OP_SUCCESSx
            if exit_on_op_success:
                return ["OP_SUCCESS"]
            r.append(f"OP_SUCCESS{i}")
            r.append(s.read())
            return r
        else:  # OP_CODE
            new_op_code = OP_CODE_NAMES[i]
        r.append(new_op_code)
    if invalid_element_size:
        raise BTClibValueError("Invalid pushdata length")
    return r


def tree_helper(script_tree: TaprootScriptTree) -> tuple[Any, bytes]:
    if len(script_tree) == 1:
        return _tree_helper(script_tree)
    left, left_h = tree_helper(script_tree[0])
    right, right_h = tree_helper(script_tree[1])
    info = [(leaf, c + right_h) for leaf, c in left]
    info += [(leaf, c + left_h) for leaf, c in right]
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (info, tagged_hash(b"TapBranch", left_h + right_h))


def _tree_helper(script_tree: TaprootScriptTree) -> TaprootScriptTree:
    leaf_version, script = script_tree[0]
    leaf_version = leaf_version & 0xFE
    preimage = leaf_version.to_bytes(1, "big")
    preimage += var_bytes.serialize(serialize(script))
    h = tagged_hash(b"TapLeaf", preimage)
    return ([((leaf_version, script), b"")], h)


def output_pubkey(
    internal_pubkey: Key | None = None,
    script_tree: TaprootScriptTree | None = None,
    ec: Curve = secp256k1,
) -> tuple[bytes, int]:
    if not internal_pubkey and not script_tree:
        raise BTClibValueError("missing data")
    if internal_pubkey:
        pub_key = pub_keyinfo_from_key(internal_pubkey, compressed=True)[0][1:]
    else:
        h_str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        pub_key = bytes.fromhex(h_str)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = b""
    t = int.from_bytes(tagged_hash(b"TapTweak", pub_key + h), "big")
    # edge case that cannot be reproduced in the test suite
    if t >= ec.n:
        raise BTClibValueError("Invalid script tree hash")  # pragma: no cover
    P_x = int.from_bytes(pub_key, "big")
    Q = ec.add((P_x, ec.y_even(P_x)), mult(t))
    return Q[0].to_bytes(32, "big"), Q[1] % 2


def output_prvkey(
    prv_key: PrvKey,
    script_tree: TaprootScriptTree | None = None,
    ec: Curve = secp256k1,
) -> int:
    internal_prvkey: int = int_from_prv_key(prv_key)
    P = mult(internal_prvkey)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = b""
    has_even_y = ec.y_even(P[0]) == P[1]
    internal_prvkey = internal_prvkey if has_even_y else ec.n - internal_prvkey
    t: int = int.from_bytes(
        tagged_hash(b"TapTweak", P[0].to_bytes(32, "big") + h), "big"
    )
    # edge case that cannot be reproduced in the test suite
    if t >= ec.n:
        raise BTClibValueError("Invalid script tree hash")  # pragma: no cover
    return (internal_prvkey + t) % ec.n


def input_script_sig(
    internal_pubkey: Key | None, script_tree: TaprootScriptTree, script_num: int
) -> tuple[ScriptList, bytes]:
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
        raise BTClibValueError("control block too long")
    m = (len(control) - 33) // 32
    if len(control) != 33 + 32 * m:
        raise BTClibValueError("invalid control block length")
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


def assert_valid_control_block(control_block: bytes) -> None:
    if (len(control_block) - 1) % 32 != 0:
        raise BTClibValueError("invalid control block size")
