# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Taproot keys, script trees and control blocks, per BIP341.

The output side and the spend side of taproot, tapscript execution
excepted: output_pubkey and output_prvkey build the tweaked keys,
tree_helper and input_script_sig walk a script tree into leaves,
merkle paths and control blocks, check_output_pubkey verifies one,
and serialize/parse are the tapscript codec the engine reads.
"""

from __future__ import annotations

from io import BytesIO
from typing import cast

from btclib import var_bytes
from btclib._libsecp256k1 import xonly as libsecp256k1_xonly
from btclib.alias import (
    BinaryData,
    Octets,
    ScriptList,
    TaprootLeaf,
    TaprootLeafPaths,
    TaprootScriptTree,
)
from btclib.curves import bytes_from_prv_key_int, mult, secp256k1
from btclib.curves.curve import _libsecp256k1_serves, _y_even_var
from btclib.curves.curve_group import HEX_THRESHOLD
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import tagged_hash
from btclib.key import _HYBRID_PREFIXES, PubKeyData
from btclib.script.limits import MAX_SCRIPT_ELEMENT_SIZE
from btclib.script.op_codes_tapscript import (
    OP_CODE_NAMES,
    OP_SUCCESS,
    _serialize_str_command,
)
from btclib.script.script import _serialize_bytes_command, _serialize_int_command
from btclib.to_prv_key import PrvKey, int_from_prv_key
from btclib.to_pub_key import Key, _sec_from_key
from btclib.utils import (
    assert_type,
    bytes_from_octets,
    bytesio_from_binarydata,
    hex_string,
    is_integer,
)

__all__ = [
    "MAX_TREE_DEPTH",
    "assert_valid_control_block",
    "check_output_pubkey",
    "input_script_sig",
    "leaf_hash",
    "output_prvkey",
    "output_prvkey_from_merkle_root",
    "output_pubkey",
    "output_pubkey_from_merkle_root",
    "parse",
    "serialize",
    "tree_helper",
]

# How deep a script tree may be, which is Core's
# TAPROOT_CONTROL_MAX_NODE_COUNT in script/interpreter.h. One number for
# two things that cannot differ: a leaf at depth d is proved by a merkle
# path of d nodes, and the control block carrying that path is capped at
# TAPROOT_CONTROL_MAX_SIZE = 33 + 32 * 128 -- so a leaf deeper than this
# has no control block to be spent with, whatever built the tree.
#
# Here rather than in script/limits.py, whose five caps are the ones at
# the top of Core's script/script.h: this one is BIP341's, declared
# beside the control block it bounds and read by the descriptor parser
# through this name
MAX_TREE_DEPTH = 128


def serialize(script: ScriptList) -> bytes:
    """Serialize a tapscript from its commands.

    The tapscript twin of script.serialize, differing where BIP342
    differs: the OP_SUCCESSx names exist here, and one must be followed
    by exactly one bytes command, appended raw -- what follows an
    OP_SUCCESS need not be a script, so it round-trips unparsed.
    """
    # what is not a list reached the reversal and the `pop` below
    # untouched, so a None was "not subscriptable" and a str was a str with
    # no `pop` -- neither of them a word about the script
    assert_type(script, list, "tapscript")

    r: list[bytes] = []
    script = script[::-1]
    while script:
        command = script.pop()
        if isinstance(command, int):
            r.append(_serialize_int_command(command))
        elif isinstance(command, str):
            r.append(_serialize_str_command(command))
            if "OP_SUCCESS" in command:
                if len(script) != 1 or not isinstance(
                    script[0], (bytes, bytearray, memoryview)
                ):
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
    """Parse a tapscript into its commands, per BIP342.

    An unknown op code is refused, data pushes come back as hex
    strings, and an OP_SUCCESSx ends the parse: what follows one is
    returned as raw bytes, BIP342 not requiring it to be a script --
    or, with `exit_on_op_success`, the whole answer is the single
    marker ["OP_SUCCESS"], which is Core's pre-scan. An element over
    520 bytes is refused only by a parse that meets no OP_SUCCESSx,
    one anywhere making the script valid.

    A `bool` and nothing else, which is the line
    `tests/built_object_contract_test.py` draws: this flag decides *what
    is computed* rather than whether a check runs, so a value read for
    its truth answered the pre-scan's marker where the commands were
    asked for -- two different readings of the same bytes.
    """
    assert_type(exit_on_op_success, bool, "exit_on_op_success")

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


def leaf_hash(leaf_version: int, script: bytes) -> bytes:
    """Return the BIP341 tapleaf hash of a serialized leaf script.

    What names a leaf everywhere but in the control block: the merkle
    path is built from these, a BIP342 signature commits to one, and
    BIP371's psbt fields key their taproot data by one. `script` is the
    leaf script already serialized, which is the form all three of those
    hold it in.
    """
    preimage = leaf_version.to_bytes(1, "big") + var_bytes.serialize(script)
    return tagged_hash(b"TapLeaf", preimage)


def tree_helper(script_tree: TaprootScriptTree) -> tuple[TaprootLeafPaths, bytes]:
    """Walk a script tree: (every leaf with its merkle path, root hash).

    BIP341's taproot_tree_helper: the leaves come back in tree order,
    each with the control-block path that proves it, and the root is
    what the output key commits to.
    """
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
    leaf_version &= 0xFE
    h = leaf_hash(leaf_version, serialize(script))
    return ([((leaf_version, script), b"")], h)


def _tap_tweak(pub_key: bytes, h: bytes) -> int:
    """Return the BIP341 tweak an x-only key and a tree hash commit to.

    One function for the three tweaks, the two that build an output and
    the one that checks a control block against it, so that the rule
    below cannot hold in one of them and not in another.
    """
    t = int.from_bytes(tagged_hash(b"TapTweak", pub_key + h), "big")
    # BIP341: fail if t is not smaller than the group order
    if t >= secp256k1.n:
        raise BTClibValueError("Invalid script tree hash")
    return t


def _output_pubkey_and_internal_key(
    internal_pubkey: Key | None, script_tree: TaprootScriptTree | None
) -> tuple[bytes, int, bytes]:
    """Return the output key, its parity, and the x-only internal key.

    What `output_pubkey` and `input_script_sig` want between them: the
    first answers the pair and drops the third, the second needs the
    internal key beside the parity. Read twice, that key was lifted twice
    on the Python path -- the same square root of the same x, which is the
    redundancy issue 896 is about, one function further out -- and 3.74 us
    of ec_pubkey_parse twice with the bindings.

    Sharing it is also what keeps the two answering for the same spellings
    of an internal key: a form accepted for the output key and refused for
    the control block that proves it would be refused one call after being
    accepted, and one reader cannot drift from another.

    The key travels as a `PubKeyData`, so that neither arm has to say how
    much of it is worth building (issue #1188): the octets are the field
    and `point` is a `cached_property`. The bindings arm wants the octets
    unproven, the tweak's own parse being the proof and a second lift
    issue 887; the Python arm wants the point it would otherwise lift
    twice, which is issue 896. The arm that reads the point pays for it
    and the arm that does not never asks.
    """
    if not internal_pubkey and not script_tree:
        raise BTClibValueError("missing data")
    if internal_pubkey:
        # `_sec_from_key` and not `pub_keyinfo_from_key`: unproven octets
        # are what both arms want, and `PubKeyData` proves them in `point`
        # or not at all. It accepts the 33-byte and the 65-byte form, and
        # `[1:33]` is the x-coordinate of either.
        sec = _sec_from_key(internal_pubkey)
        # A hybrid prefix is refused here, above the arm split, rather
        # than left to whichever arm's own parse runs: it is a third
        # spelling of a compressed or uncompressed key and not a
        # malformed one, so libsecp256k1 admits it where the Python
        # arm's `hybrid=False` default does not, and which internal keys
        # this function takes would otherwise be `pip install`'s
        # decision rather than btclib's (issue #1227). key.py's
        # paragraph on `_HYBRID_PREFIXES` is why the answer is refusal.
        if sec[0] in _HYBRID_PREFIXES:
            raise BTClibValueError(
                f"invalid internal public key: hybrid SEC prefix {sec[0]:#04x}"
            )
        #
        # check_validity=False, and not because what arrives is known
        # good: `assert_valid` reads a length and a prefix, and
        # `_sec_from_key` answers any prefix at those two lengths the
        # check above does not -- so some of what reaches here it would
        # still refuse. It is skipped because it is half a proof bought
        # early: whatever these octets are handed to parses them, which is
        # `_sec_from_key`'s own reason for not proving them, and it names
        # what is wrong with the key where a prefix check names the prefix
        key_data = PubKeyData(sec, check_validity=False)
    else:
        h_str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
        # BIP341's unspendable point is published as an x-only key and
        # nothing else, so the prefix is this module's to supply -- 02,
        # BIP341's lift being the even one
        key_data = PubKeyData(b"\x02" + bytes.fromhex(h_str), check_validity=False)
    if script_tree:
        _, h = tree_helper(script_tree)
    else:
        h = b""
    q, parity_bit = _tweaked_pubkey(key_data, h)
    return q, parity_bit, key_data.sec[1:33]


def output_pubkey(
    internal_pubkey: Key | None = None,
    script_tree: TaprootScriptTree | None = None,
) -> tuple[bytes, int]:
    """Return a taproot output key and its parity, per BIP341.

    The x-only internal key is tweaked by the script tree's root hash,
    an empty tree contributing empty bytes -- key path only -- and a
    missing internal key replaced by BIP341's unspendable point, script
    path only. The parity bit is the tweaked point's, needed by the
    control block and never serialized in the output.
    """
    q, parity_bit, _ = _output_pubkey_and_internal_key(internal_pubkey, script_tree)
    return q, parity_bit


def _tweaked_pubkey(pub_key: PubKeyData, h: bytes) -> tuple[bytes, int]:
    """Return the x-only key an internal key tweaked by h, and its parity.

    The half of BIP341's output key that does not care where h came
    from: a tree the caller built, or the merkle root a psbt carries.

    One `PubKeyData` for both arms, each reading off it the field it
    uses (issue #1188). `sec` is what `xonly.tweak_add` prefers whole,
    `04 || x || y` carrying the y it would otherwise lift -- 4.11 us
    against 5.92 -- and `02 || x`, `03 || x` and `04 || x || y` all name
    the same x-only key to it. `point` is the square root, taken once
    however many readers ask, which is issue 896.
    """
    t = _tap_tweak(pub_key.sec[1:33], h)

    # secp256k1_xonly_pubkey_tweak_add is this very operation, parity
    # included, and it answers the pair this function returns. 12.0 us
    # against 109.3 for the three lines below, over 2000 tweaks: the
    # Python path lifts the x-only key to a point with secp256k1.y_even_var,
    # i.e. a modular square root, which is 74 us of that on its own --
    # while libsecp256k1 needs no such lift, having the y coordinate as
    # it goes.
    #
    # The predicate is a constant now that the curve is, and the guards
    # in this module keep it rather than saying so: it is the seam the
    # suite closes -- curve._libsecp256k1_available set to False -- to
    # reach the Python arithmetic below, which is the reference
    # implementation the bindings are checked against and not a path any
    # caller takes. Stated here for every one of them: whatever else a
    # guard goes on to read, its `_libsecp256k1_serves` half asks the
    # one question, which arithmetic runs
    if _libsecp256k1_serves(secp256k1, None):
        try:
            return libsecp256k1_xonly.tweak_add(pub_key.sec, t)
        except ValueError as e:
            # this arm hands the tweak octets nothing has proved are a
            # point, deliberately (issue 887): tweak_add's own parse is
            # the proof, and lifting first would be a second square root
            # of one x. What comes with that trade is that the refusal
            # arrives from the bindings rather than from btclib's own
            # validation, and it arrives as a bare ValueError. dsa states
            # the rule the whole tree follows: the discrimination is
            # theirs, but the hierarchy has to be btclib's, a caller
            # catching BTClibValueError not having to know which arm
            # answered.
            #
            # Two messages, and what decides between them is what the
            # octets are rather than which caller handed them over. A
            # compressed key names its y by its prefix, so its x is all
            # that is left for tweak_add to object to, and the wording is
            # the lift's below, so that the two arms say one sentence for
            # one input: `point_from_octets` is that lift, and it answers
            # both of `curve_group.y_var`'s complaints -- an x out of
            # range and an x that is no coordinate -- in the one sentence
            # this reproduces.
            #
            # Anything else carries more than an x. An uncompressed key's
            # y is unproven for the same reason as its x, and a valid x
            # with a y that is not its own is refused here too, where
            # naming the x would name the half that is right; and
            # `_sec_from_key` answers any prefix at either length, a
            # prefix being the fault of neither coordinate.
            # `check_output_pubkey`'s arm already says that in these
            # words, its refusal being one it cannot decompose either
            if not (pub_key.is_compressed and pub_key.sec[0] in (0x02, 0x03)):
                raise BTClibValueError(f"invalid internal public key: {e}") from e
            x_Q = int.from_bytes(pub_key.sec[1:33], "big")
            raise BTClibValueError(f"invalid x-coordinate: '{hex_string(x_Q)}'") from e

    # which of the two roots the key names is its prefix's business and
    # not BIP341's, whose lift wants the even one: an 03 key is the odd-y
    # point, and the even y is then a subtraction from the root already
    # taken rather than a second root
    P_x, y_P = pub_key.point
    P_y = y_P if y_P % 2 == 0 else secp256k1.p - y_P
    Q = secp256k1.add_var((P_x, P_y), mult(t))
    return Q[0].to_bytes(32, "big"), Q[1] % 2


def output_pubkey_from_merkle_root(
    internal_pubkey: Octets, merkle_root: Octets = b""
) -> tuple[bytes, int]:
    """Return a taproot output key from a merkle root, per BIP341.

    `output_pubkey` with the root already in hand, which is the shape a
    psbt has it in: BIP371's `PSBT_IN_TAP_MERKLE_ROOT` is the root and
    not the tree that produced it, an input naming the branch it spends
    by its leaf script and control block instead -- so a signer that
    takes the key path is told the root and nothing else about the tree.
    An empty root is key path only, as an empty tree is.

    The internal key is x-only and 32 bytes, which is what BIP341 tweaks
    and what the psbt field holds; `output_pubkey` takes the wider `Key`
    because a caller building an output has the key in whatever form it
    reached them in.
    """
    internal_pubkey = bytes_from_octets(internal_pubkey, 32)
    # 02 and not 03: x-only octets are all this caller has, and BIP341's
    # lift is the even one, so the prefix says what the key means rather
    # than adding anything to it
    return _tweaked_pubkey(
        # `assert_valid` reads a length and a prefix, and this call
        # settles both itself: the size is checked on the way in and the
        # prefix is the one supplied on the line below
        PubKeyData(b"\x02" + internal_pubkey, check_validity=False),
        bytes_from_octets(merkle_root),
    )


def output_prvkey(
    prv_key: PrvKey,
    script_tree: TaprootScriptTree | None = None,
) -> int:
    """Return the private key of the taproot output key, per BIP341.

    The private counterpart of output_pubkey: the internal key is
    negated where its public point has an odd y, then tweaked by the
    script tree's root hash, so its public point is the output key
    exactly.
    """
    h = tree_helper(script_tree)[1] if script_tree else b""
    return _tweaked_prvkey(int_from_prv_key(prv_key), h)


def _tweaked_prvkey(internal_prvkey: int, h: bytes) -> int:
    """Return the private key an internal one tweaked by h.

    The private half of `_tweaked_pubkey`, h coming from the same two
    places: a tree the caller built, or the merkle root a psbt carries.
    """
    # secp256k1_keypair_xonly_tweak_add is the whole of this function
    # below the tweak: it negates the key whose public point has an odd
    # y, as BIP341 requires, and adds the tweak to it -- in constant
    # time, which the Python `%` on a secret scalar is not. The x-only
    # public key the tweak commits to comes from the bindings too, and
    # the parity byte dropped from it is the one they will decide again
    # for themselves: 32.0 us against 82.3 over 2000 tweaks, the
    # difference being the point this path never materializes and
    # the square root it never takes to check that point's parity
    if _libsecp256k1_serves(secp256k1, None):
        pub_key = bytes_from_prv_key_int(internal_prvkey, secp256k1)[1:]
        t = _tap_tweak(pub_key, h)
        tweaked = libsecp256k1_xonly.prvkey_tweak_add(internal_prvkey, t)
        return int.from_bytes(tweaked, "big")

    P = mult(internal_prvkey)
    # the parity of a y already in hand: secp256k1.y_even_var(P[0]) lifted
    # the x back to the point P is -- 74.6 us of modular square root
    # against 0.03 -- to compare its y with the one beside it (issue
    # 619). Not a delegation but a deletion, which is what this path
    # needed: it runs where the bindings do not, so there was nothing
    # here to dispatch to. The two spellings differ on the infinity
    # btclib writes as y == 0, and mult of a key int_from_prv_key has
    # refused zero for cannot be it
    has_even_y = P[1] % 2 == 0
    internal_prvkey = internal_prvkey if has_even_y else secp256k1.n - internal_prvkey
    t = _tap_tweak(P[0].to_bytes(32, "big"), h)
    return (internal_prvkey + t) % secp256k1.n


def output_prvkey_from_merkle_root(prv_key: PrvKey, merkle_root: Octets = b"") -> int:
    """Return the private key of a taproot output from a merkle root.

    `output_prvkey` with the root already in hand, the shape
    `PSBT_IN_TAP_MERKLE_ROOT` carries it in: a `KeyManager` signing a
    taproot key path spend holds the internal private key and this
    field, never the script tree that produced the root, a psbt naming
    a script path by its leaf and control block instead.
    """
    return _tweaked_prvkey(int_from_prv_key(prv_key), bytes_from_octets(merkle_root))


def input_script_sig(
    internal_pubkey: Key | None, script_tree: TaprootScriptTree, script_num: int
) -> tuple[ScriptList, bytes]:
    """Return (leaf script, control block) for a script-path spend.

    `script_num` picks the leaf in tree order, as tree_helper returns
    them; the control block is BIP341's -- parity bit plus leaf
    version, then the x-only internal key, then the merkle path -- and
    a missing internal key is the unspendable point output_pubkey uses.

    In tree order and counting from zero: Python would read -1 as the
    last leaf and hand back a control block that proves it, so a leaf
    named from the wrong end is refused rather than answered.
    """
    # one read of the internal key for the two things this needs of it: the
    # parity of the output key it is tweaked into, and the key itself, which
    # the control block carries. Read twice -- `output_pubkey` and then here
    # -- it was lifted twice on the Python path, and the unspendable point
    # was written out twice besides
    _, parity_bit, pub_key_bytes = _output_pubkey_and_internal_key(
        internal_pubkey, script_tree
    )
    leaves = tree_helper(script_tree)[0]
    if not is_integer(script_num):
        raise BTClibTypeError(f"invalid leaf index type: {type(script_num).__name__}")
    if not 0 <= script_num < len(leaves):
        raise BTClibValueError(f"invalid leaf index: {script_num}")
    (leaf_version, script), path = leaves[script_num]
    control = (parity_bit + leaf_version).to_bytes(1, "big")
    control += pub_key_bytes
    control += path
    return script, control


def check_output_pubkey(q: Octets, script: Octets, control: Octets) -> bool:
    """Answer whether the control block proves the script against the key.

    BIP341's control-block verification: the leaf hash is folded up
    the merkle path in the control block, and the internal key tweaked
    by the result must equal the output key q, parity included. A
    malformed control block or an internal key that is not a point is
    refused rather than answered False, either being no proof at all.
    """
    q = bytes_from_octets(q)
    script = bytes_from_octets(script)
    control = bytes_from_octets(control)
    if len(control) > 33 + 32 * MAX_TREE_DEPTH:
        raise BTClibValueError("control block too long")
    m = (len(control) - 33) // 32
    if len(control) != 33 + 32 * m:
        raise BTClibValueError("invalid control block length")
    k = leaf_hash(control[0] & 0xFE, script)
    for j in range(m):
        e = control[33 + 32 * j : 65 + 32 * j]
        if k < e:
            k = tagged_hash(b"TapBranch", k + e)
        else:
            k = tagged_hash(b"TapBranch", e + k)
    p_bytes = control[1:33]
    p = int.from_bytes(p_bytes, "big")
    t = _tap_tweak(p_bytes, k)

    # secp256k1_xonly_pubkey_tweak_add_check is the call libsecp256k1
    # provides for this very question, and it compares the serialized
    # keys instead of tweaking into a point and back.
    # Only for a 32-byte q, which is what it takes: a q of any other
    # length is not a taproot output key, but it is not necessarily
    # unequal either -- b"\x00" + 32 bytes reads as the same integer the
    # comparison below makes -- so the answer for it stays the Python
    # one rather than becoming an exception
    if _libsecp256k1_serves(secp256k1, None) and len(q) == 32:
        try:
            return libsecp256k1_xonly.tweak_add_check(q, control[0] & 1, p_bytes, t)
        except ValueError as e:
            # an internal key that is not a point leaves the bindings
            # through a plain ValueError and the Python path below
            # through the BTClibValueError of _y_even_var. The engine
            # catches the library's own error, so the two must agree on
            # what they raise as well as on what they answer -- and this
            # call knows which half was refused, unlike _tweaked_pubkey's
            # arm given a sec: tweak_add_check is handed the internal
            # key's x alone, and a q that is no x-coordinate is answered
            # False by both arms rather than raised on. So the wording is
            # the lift's below, range check included, and the two arms
            # answer the same sentence for the same control block
            err_msg = (
                "invalid x-coordinate: "
                if p < secp256k1.p
                else "x-coordinate not in 0..p-1: "
            )
            err_msg += f"{hex_string(p)}" if p > HEX_THRESHOLD else f"{p}"
            raise BTClibValueError(err_msg) from e

    # _y_even_var, i.e. secp256k1.y_even_var with the lift delegated: this is
    # the path a q of any other length takes, secp256k1 included, so the
    # modular square root is worth not taking here either
    P = (p, _y_even_var(p, secp256k1))
    Q = secp256k1.add_var(P, mult(t))
    return Q[0] == int.from_bytes(q, "big") and control[0] & 1 == Q[1] % 2


def assert_valid_control_block(control_block: Octets) -> None:
    """Refuse a control block whose size no leaf depth can produce.

    Size only, and only its residue: one leading byte plus a multiple
    of 32, which BIP341's 33 + 32m sizes all satisfy. Proving the
    block against an output key is check_output_pubkey's.

    The octets first, as check_output_pubkey takes them: `len` of the
    text spelling counts characters, so "e" * 33 -- 33 characters and
    the 66 octets of a hex string -- was a size this accepted, and
    "é" * 33, 33 characters and 66 octets of UTF-8, was a size it
    accepted for no reason at all.
    """
    if (len(bytes_from_octets(control_block)) - 1) % 32 != 0:
        raise BTClibValueError("invalid control block size")
