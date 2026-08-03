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

from io import BytesIO
from typing import cast

from btclib_libsecp256k1 import xonly as libsecp256k1_xonly

from btclib import var_bytes
from btclib.alias import (
    BinaryData,
    Octets,
    ScriptList,
    TaprootLeaf,
    TaprootLeafPaths,
    TaprootScriptTree,
)
from btclib.curves import Curve, bytes_from_prv_key_int, mult, secp256k1
from btclib.curves.curve import _libsecp256k1_applicable, _y_even
from btclib.exceptions import BTClibValueError
from btclib.hashes import tagged_hash
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.script.op_codes_tapscript import (
    OP_CODE_NAMES,
    OP_SUCCESS,
    _serialize_str_command,
)
from btclib.script.script import _serialize_bytes_command, _serialize_int_command
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
                    raise BTClibValueError(
                        "OP_SUCCESS must be followed by a single bytes command"
                    )
                return b"".join(r) + script[0]
        else:  # must be bytes
            r.append(_serialize_bytes_command(command))
    return b"".join(r)


def _read_push_data(s: BytesIO, i: int) -> bytes:
    """Read the data of the push whose first byte is i, 0 < i <= 78.

    The 520-byte element limit is not checked here, unlike in
    script.parse: an OP_SUCCESS makes a tapscript valid whatever else it
    holds, so only the caller -- which knows whether one has been met --
    can turn an oversized element into a refusal.
    """
    data_length = i  # 0 < i < 76 -> 1-byte-data-length | data
    if i > 75:
        # i == 76 -> OP_PUSHDATA1 | 1-byte-data-length | data
        # i == 77 -> OP_PUSHDATA2 | 2-byte-data-length | data
        # i == 78 -> OP_PUSHDATA4 | 4-byte-data-length | data
        size = 2 ** (i - 76)
        y = s.read(size)
        if len(y) != size:
            raise BTClibValueError("Invalid pushdata length")
        data_length = int.from_bytes(y, byteorder="little")
    data = s.read(data_length)
    if len(data) != data_length:
        raise BTClibValueError("Invalid pushdata length")
    return data


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
            data = _read_push_data(s, i)
            # BIP342: an element over 520 bytes is invalid, but an
            # OP_SUCCESS anywhere makes the script valid without the rest
            # of it being executed, so the refusal waits for a parse that
            # ends without meeting one
            invalid_element_size |= len(data) > MAX_SCRIPT_ELEMENT_SIZE
            r.append(data.hex().upper())
        elif i in OP_SUCCESS:  # OP_SUCCESSx
            if exit_on_op_success:
                return ["OP_SUCCESS"]
            # what follows an OP_SUCCESS is returned unparsed: BIP342 does
            # not require it to be a script at all
            r.append(f"OP_SUCCESS{i}")
            r.append(s.read())
            return r
        elif i in OP_CODE_NAMES:  # OP_CODE
            r.append(OP_CODE_NAMES[i])
        else:
            raise BTClibValueError(f"unknown op code: {hex(i)}")
    if invalid_element_size:
        raise BTClibValueError("Invalid pushdata length")
    return r


def tree_helper(script_tree: TaprootScriptTree) -> tuple[TaprootLeafPaths, bytes]:
    if len(script_tree) == 1:
        return _tree_helper(script_tree)
    # a branch: both elements are subtrees, and the alias says only that
    # an element may also be a leaf, so the narrowing is ours to assert
    left, left_h = tree_helper(cast("TaprootScriptTree", script_tree[0]))
    right, right_h = tree_helper(cast("TaprootScriptTree", script_tree[1]))
    info = [(leaf, c + right_h) for leaf, c in left]
    info += [(leaf, c + left_h) for leaf, c in right]
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (info, tagged_hash(b"TapBranch", left_h + right_h))


def _tree_helper(script_tree: TaprootScriptTree) -> tuple[TaprootLeafPaths, bytes]:
    leaf_version, script = cast("TaprootLeaf", script_tree[0])
    leaf_version = leaf_version & 0xFE
    preimage = leaf_version.to_bytes(1, "big")
    preimage += var_bytes.serialize(serialize(script))
    h = tagged_hash(b"TapLeaf", preimage)
    return ([((leaf_version, script), b"")], h)


def _tap_tweak(pub_key: bytes, h: bytes, ec: Curve) -> int:
    """Return the BIP341 tweak an x-only key and a tree hash commit to.

    One function for the three tweaks, the two that build an output and
    the one that checks a control block against it, so that the rule
    below cannot hold in one of them and not in another.
    """
    t = int.from_bytes(tagged_hash(b"TapTweak", pub_key + h), "big")
    # BIP341: fail if t is not smaller than the group order
    if t >= ec.n:
        raise BTClibValueError("Invalid script tree hash")
    return t


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
    t = _tap_tweak(pub_key, h, ec)

    # secp256k1_xonly_pubkey_tweak_add is this very operation, parity
    # included, and it answers the pair this function returns. 12.0 us
    # against 109.3 for the three lines below, over 2000 tweaks: the
    # Python path lifts the x-only key to a point with
    # ec.y_even, i.e. a modular square root, which is 74 us of that on
    # its own -- while libsecp256k1 needs no such lift, having the
    # y coordinate as it goes
    if _libsecp256k1_applicable(ec):
        return libsecp256k1_xonly.tweak_add(pub_key, t)

    P_x = int.from_bytes(pub_key, "big")
    Q = ec.add((P_x, ec.y_even(P_x)), mult(t))
    return Q[0].to_bytes(32, "big"), Q[1] % 2


def output_prvkey(
    prv_key: PrvKey,
    script_tree: TaprootScriptTree | None = None,
    ec: Curve = secp256k1,
) -> int:
    internal_prvkey: int = int_from_prv_key(prv_key)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = b""

    # secp256k1_keypair_xonly_tweak_add is the whole of this function
    # below the tweak: it negates the key whose public point has an odd
    # y, as BIP341 requires, and adds the tweak to it -- in constant
    # time, which the Python `%` on a secret scalar is not. The x-only
    # public key the tweak commits to comes from the bindings too, and
    # the parity byte dropped from it is the one they will decide again
    # for themselves: 32.0 us against 82.3 over 2000 tweaks, the
    # difference being the point this path never materializes and
    # the square root it never takes to check that point's parity
    if _libsecp256k1_applicable(ec):
        pub_key = bytes_from_prv_key_int(internal_prvkey, ec)[1:]
        t = _tap_tweak(pub_key, h, ec)
        tweaked = libsecp256k1_xonly.prvkey_tweak_add(internal_prvkey, t)
        return int.from_bytes(tweaked, "big")

    P = mult(internal_prvkey)
    has_even_y = ec.y_even(P[0]) == P[1]
    internal_prvkey = internal_prvkey if has_even_y else ec.n - internal_prvkey
    t = _tap_tweak(P[0].to_bytes(32, "big"), h, ec)
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
    p = int.from_bytes(p_bytes, "big")
    t = _tap_tweak(p_bytes, k, ec)

    # secp256k1_xonly_pubkey_tweak_add_check is the call libsecp256k1
    # provides for this very question, and it compares the serialized
    # keys instead of tweaking into a point and back.
    # Only for a 32-byte q, which is what it takes: a q of any other
    # length is not a taproot output key, but it is not necessarily
    # unequal either -- b"\x00" + 32 bytes reads as the same integer the
    # comparison below makes -- so the answer for it stays the Python
    # one rather than becoming an exception
    if _libsecp256k1_applicable(ec) and len(q) == 32:
        try:
            return libsecp256k1_xonly.tweak_add_check(q, control[0] & 1, p_bytes, t)
        except ValueError as e:
            # an internal key that is not a point leaves the bindings
            # through a plain ValueError and the Python path below
            # through the BTClibValueError of _y_even. The engine
            # catches the library's own error, so the two must agree on
            # what they raise as well as on what they answer
            raise BTClibValueError(f"invalid internal public key: {e}") from e

    # _y_even, i.e. ec.y_even with the lift delegated: this is the path a
    # q of any other length takes, secp256k1 included, so the modular
    # square root is worth not taking here either
    P = (p, _y_even(p, secp256k1))
    Q = secp256k1.add(P, mult(t))
    return Q[0] == int.from_bytes(q, "big") and control[0] & 1 == Q[1] % 2


def assert_valid_control_block(control_block: bytes) -> None:
    if (len(control_block) - 1) % 32 != 0:
        raise BTClibValueError("invalid control block size")
