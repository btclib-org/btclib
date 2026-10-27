# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib.script.engine` against libbitcoinkernel, through py-bitcoinkernel.

Hypothesis draws a spend: a script type, signatures valid or corrupted,
the consensus flags, and the other inputs of the transaction. `verify_input`
and Core's own `VerifyScript`, reached through the kernel, then answer
whether it is valid, and the two answers must be the same.

Where the kernel has the script tracer of bitcoin/bitcoin#35641, the
`trace` tests also compare every script the two run: before each command,
its position, its op code, whether it executes, and both stacks; where
the script stops, its position and both stacks. Without the tracer they
skip, and only the verdict is compared. The script error code is not
compared.

The kernel takes the consensus flags and no policy flag, so the policy
flags are not drawn. tests/README.md says how to run the module.

A disagreement prints the transaction, the spent outputs and the flags, and
the exception btclib raised.
"""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from dataclasses import dataclass
from itertools import zip_longest
from typing import Any, NamedTuple

import pytest
from ecc.curves import bytes_from_point, mult
from ecc.ecc import dsa, ssa
from ecc.hashes import tagged_hash
from hypothesis import given
from hypothesis import strategies as st
from typing_extensions import override

from btclib.alias import TaprootScriptTree
from btclib.exceptions import ScriptError
from btclib.hashes import hash160, sha256
from btclib.key import PubKeyData
from btclib.script import serialize, sig_hash, taproot
from btclib.script.engine import ALL_FLAGS, NO_FLAGS, ScriptFlag, verify_input
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

pbk = pytest.importorskip("pbk")

# what verify_input's `step` reports, and what a kernel frame is read into:
# position, op code (None where the script stops), executing, stack, altstack
Frame = tuple[int, int | None, bool, tuple[bytes, ...], tuple[bytes, ...]]

_FRAME_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p)
_WRITE_BYTES = ctypes.CFUNCTYPE(
    ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p
)

# the tracer's C API, bitcoinkernel.h at bitcoin/bitcoin@0161ebdbf6
_TRACER_API = {
    "btck_script_trace_register_callback": (
        ctypes.c_int,
        [_FRAME_CALLBACK, ctypes.c_void_p, ctypes.c_void_p],
    ),
    "btck_script_trace_unregister_callback": (None, []),
    "btck_script_trace_frame_get_kind": (ctypes.c_uint8, [ctypes.c_void_p]),
    "btck_script_trace_frame_get_stack": (ctypes.c_void_p, [ctypes.c_void_p]),
    "btck_script_trace_frame_get_altstack": (ctypes.c_void_p, [ctypes.c_void_p]),
    "btck_script_trace_frame_get_opcode_pos": (ctypes.c_uint32, [ctypes.c_void_p]),
    "btck_script_trace_frame_get_exec": (ctypes.c_int, [ctypes.c_void_p]),
    "btck_script_trace_frame_get_opcode": (ctypes.c_uint8, [ctypes.c_void_p]),
    "btck_script_eval_stack_count_items": (ctypes.c_size_t, [ctypes.c_void_p]),
    "btck_script_eval_stack_get_item_at": (
        ctypes.c_void_p,
        [ctypes.c_void_p, ctypes.c_size_t],
    ),
    "btck_script_eval_stack_item_to_bytes": (
        ctypes.c_int,
        [ctypes.c_void_p, _WRITE_BYTES, ctypes.c_void_p],
    ),
}
_BEGIN, _STEP = 0, 1


def _kernel_tracer() -> Any:
    """Return the kernel library where it has the script tracer, else None.

    The functions are missing from a kernel built without the tracer, and
    registering a callback fails where it was compiled out.
    """
    lib = pbk.capi.library.BITCOINKERNEL_LIB
    if not all(hasattr(lib, name) for name in _TRACER_API):
        return None
    for name, (restype, argtypes) in _TRACER_API.items():
        function = getattr(lib, name)
        function.restype, function.argtypes = restype, argtypes
    no_op = _FRAME_CALLBACK(lambda _, __: None)
    available = lib.btck_script_trace_register_callback(no_op, None, None) == 0
    lib.btck_script_trace_unregister_callback()
    return lib if available else None


_TRACER = _kernel_tracer()
needs_tracer = pytest.mark.skipif(
    _TRACER is None,
    reason="the kernel has no script tracer (bitcoin/bitcoin#35641)",
)

_CONSENSUS_FLAGS = [
    ScriptFlag.P2SH,
    ScriptFlag.DERSIG,
    ScriptFlag.NULLDUMMY,
    ScriptFlag.CHECKLOCKTIMEVERIFY,
    ScriptFlag.CHECKSEQUENCEVERIFY,
    ScriptFlag.WITNESS,
    ScriptFlag.TAPROOT,
]

_OP_TRUE = b"\x51"

# SIGHASH_ALL, NONE, SINGLE, each with ANYONECANPAY; 0 is taproot's default
_HASH_TYPES = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83]

# 500000000 is where a lock time stops being a height and becomes a time
_U32 = st.one_of(
    st.sampled_from([0, 1, 499999999, 500000000, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF]),
    st.integers(min_value=0, max_value=0xFFFFFFFF),
)
_PRV_KEYS = st.integers(min_value=1, max_value=2**24)


_DUMMIES = st.sampled_from([b"", b"", b"", b"\x00", b"\x01", b"\x51\x51"])


class _Template(NamedTuple):
    """One script type, before it is signed.

    `fill` builds the script_sig and the witness from the signatures, so
    the same function writes the placeholders that sig_hash needs to
    find the script in the transaction and the signatures that replace
    them.
    """

    script_pub_key: bytes
    fill: Callable[[list[bytes]], tuple[bytes, tuple[bytes, ...]]]
    signers: list[int]
    schnorr: bool


@dataclass(frozen=True)
class Spend:
    """What both engines are asked about."""

    prevouts: list[TxOut]
    tx: Tx
    index: int
    flags: ScriptFlag

    @override
    def __str__(self) -> str:
        """Return what a person needs to replay the spend in Core."""
        return (
            f"tx {self.tx.serialize(include_witness=True).hex()}\n"
            f"input {self.index}, flags {self.flags}\n"
            + "\n".join(
                f"prevout {p.value} {p.script_pub_key.script.hex()}"
                for p in self.prevouts
            )
        )


def _pub_key(prv_key: int, compressed: bool = True) -> bytes:
    return bytes_from_point(mult(prv_key), compressed=compressed)


def _multisig_script(m: int, keys: list[bytes]) -> bytes:
    return serialize([f"OP_{m}", *keys, f"OP_{len(keys)}", "OP_CHECKMULTISIG"])


def _p2sh(redeem_script: bytes) -> bytes:
    return serialize(["OP_HASH160", hash160(redeem_script), "OP_EQUAL"])


def _p2wsh(witness_script: bytes) -> bytes:
    return serialize(["OP_0", sha256(witness_script)])


def _p2wpkh(pub_key: bytes) -> bytes:
    return serialize(["OP_0", hash160(pub_key)])


# the opcodes whose scripts get furthest: stack, flow control, arithmetic,
# the locktime checks and the upgradable nops
_CORE_OPS = [
    0x00,
    *range(0x4F, 0x61),
    *range(0x63, 0x6B),
    0x6D,
    0x75,
    0x76,
    0x82,
    0x87,
    0x88,
    0x8B,
    0x8C,
    *range(0x93, 0xA6),
    *range(0xB0, 0xBA),
]


# an operand of OP_CHECKLOCKTIMEVERIFY or OP_CHECKSEQUENCEVERIFY on either
# side of the height/time boundary and of the sequence type and disable bits,
# so that it meets a lock time or sequence of each kind
_LOCK_TIME_CHECKS = st.builds(
    lambda operand, op: (
        serialize([operand if operand > 16 else f"OP_{operand}"]) + bytes([op])
    ),
    st.one_of(
        st.sampled_from(
            [0, 1, 499999999, 500000000, 500000001, 1 << 22, (1 << 22) | 1, 1 << 31]
        ),
        st.integers(min_value=0, max_value=0xFFFFFFFF),
    ),
    st.sampled_from([0xB1, 0xB2]),
)


@st.composite
def _scripts(draw: st.DrawFn, max_size: int = 12) -> bytes:
    """Draw a script made of whole opcodes and pushes, valid or not."""
    atoms = st.one_of(
        _LOCK_TIME_CHECKS,
        st.sampled_from(_CORE_OPS).map(lambda op: bytes([op])),
        st.integers(min_value=0x4F, max_value=0xFF).map(lambda op: bytes([op])),
        st.binary(min_size=1, max_size=8).map(lambda data: serialize([data])),
    )
    # a lone check, DROP and OP_1, which is what a lock time script is: a
    # random list meets a satisfiable one too rarely to compare the type rule
    lock_time_script = _LOCK_TIME_CHECKS.map(lambda check: check + b"\x75\x51")
    return draw(
        st.one_of(lock_time_script, st.lists(atoms, max_size=max_size).map(b"".join))
    )


@st.composite
def _pushes(draw: st.DrawFn) -> list[bytes]:
    """Draw the items a free script is given on its stack."""
    return draw(st.lists(st.binary(max_size=4), max_size=3))


@st.composite
def _templates(draw: st.DrawFn, kind: str, valid: bool) -> _Template:  # noqa: C901, PLR0911
    """Draw the script of one type, with the keys that sign it."""

    def push(*items: bytes) -> bytes:
        return serialize(list(items))

    if kind in {"script", "p2sh_script", "p2wsh_script"}:
        script, items = draw(_scripts()), draw(_pushes())
        if kind == "script":
            return _Template(script, lambda _: (push(*items), ()), [], False)
        if kind == "p2sh_script":
            return _Template(
                _p2sh(script), lambda _: (push(*items, script), ()), [], False
            )
        return _Template(_p2wsh(script), lambda _: (b"", (*items, script)), [], False)

    prv_key = draw(_PRV_KEYS)
    compressed = draw(st.booleans())
    pub_key = _pub_key(prv_key, compressed)
    n = draw(st.integers(min_value=1, max_value=3))
    m = draw(st.integers(min_value=1, max_value=n))
    prv_keys = sorted(draw(st.sets(_PRV_KEYS, min_size=n, max_size=n)))
    pub_keys = [_pub_key(k, draw(st.booleans())) for k in prv_keys]
    signers = prv_keys[:m]
    multisig = _multisig_script(m, pub_keys)
    # the element CHECKMULTISIG pops too many; NULLDUMMY wants it empty
    dummy = b"" if valid else draw(_DUMMIES)

    if kind == "p2pk":
        script_pub_key = serialize([pub_key, "OP_CHECKSIG"])
        return _Template(script_pub_key, lambda s: (push(*s), ()), [prv_key], False)
    if kind == "p2pkh":
        script_pub_key = serialize(
            ["OP_DUP", "OP_HASH160", hash160(pub_key), "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
        return _Template(
            script_pub_key, lambda s: (push(*s, pub_key), ()), [prv_key], False
        )
    if kind == "p2ms":
        return _Template(
            multisig, lambda s: (serialize([dummy, *s]), ()), signers, False
        )
    if kind == "p2sh_p2ms":
        return _Template(
            _p2sh(multisig),
            lambda s: (serialize([dummy, *s, multisig]), ()),
            signers,
            False,
        )
    if kind == "p2wpkh":
        return _Template(
            _p2wpkh(pub_key), lambda s: (b"", (*s, pub_key)), [prv_key], False
        )
    if kind == "p2sh_p2wpkh":
        redeem = _p2wpkh(pub_key)
        return _Template(
            _p2sh(redeem), lambda s: (push(redeem), (*s, pub_key)), [prv_key], False
        )
    if kind == "p2wsh_p2ms":
        return _Template(
            _p2wsh(multisig), lambda s: (b"", (dummy, *s, multisig)), signers, False
        )
    if kind == "p2sh_p2wsh_p2ms":
        redeem = _p2wsh(multisig)
        return _Template(
            _p2sh(redeem),
            lambda s: (push(redeem), (dummy, *s, multisig)),
            signers,
            False,
        )
    return _taproot_template(draw, kind, prv_key, prv_keys, m, valid)


def _taproot_template(
    draw: st.DrawFn, kind: str, prv_key: int, prv_keys: list[int], m: int, valid: bool
) -> _Template:
    """Draw a taproot output: key path, a signed leaf, or a free leaf."""
    internal = PubKeyData(_pub_key(prv_key))
    annex = draw(st.sampled_from([b"", b"\x50", b"\x50\x01\x02"]))
    tail = (annex,) if annex else ()
    # a leaf version other than 0xC0 is anyone-can-spend, valid unsigned
    leaf_version = (
        0xC0 if valid else draw(st.sampled_from([0xC0, 0xC0, 0xC0, 0xC2, 0xFE]))
    )
    x_only = [_pub_key(k)[1:] for k in prv_keys]

    if kind == "p2tr_key":
        key_tree: TaprootScriptTree | None = (
            None if draw(st.booleans()) else [(0xC0, ["OP_1"])]
        )
        output = taproot.output_pubkey(internal, key_tree)[0]
        signer = taproot.output_prvkey(prv_key, key_tree)
        return _Template(
            serialize(["OP_1", output]), lambda s: (b"", (*s, *tail)), [signer], True
        )

    if kind == "p2tr_checksig":
        script: list[Any] = [x_only[0], "OP_CHECKSIG"]
        signers = prv_keys[:1]
    elif kind == "p2tr_multi_a":
        script = [x_only[0], "OP_CHECKSIG"]
        for key in x_only[1:]:
            script += [key, "OP_CHECKSIGADD"]
        script += [f"OP_{m}", "OP_NUMEQUAL"]
        # a key that does not sign is answered with the empty signature
        signers = prv_keys[:m]
    else:
        leaf = draw(_scripts(max_size=8))
        output, control = _free_leaf(internal.sec[1:], leaf_version, leaf)
        # a wrong control block would make both engines refuse, and agree
        assert taproot.check_output_pubkey(output, leaf, control)
        items = draw(_pushes())
        return _Template(
            serialize(["OP_1", output]),
            lambda _: (b"", (*items, leaf, control, *tail)),
            [],
            True,
        )
    tree: TaprootScriptTree = [[(leaf_version, script)], [(0xC0, ["OP_2"])]]
    output = taproot.output_pubkey(internal, tree)[0]
    leaf_script, control = taproot.input_script_sig(internal, tree, 0)
    absent = len(prv_keys) - len(signers) if kind == "p2tr_multi_a" else 0

    def fill(sigs: list[bytes]) -> tuple[bytes, tuple[bytes, ...]]:
        stack = [*([b""] * absent), *reversed(sigs)]
        return b"", (*stack, serialize(leaf_script), control, *tail)

    return _Template(serialize(["OP_1", output]), fill, signers, True)


def _free_leaf(internal: bytes, leaf_version: int, leaf: bytes) -> tuple[bytes, bytes]:
    """Return the output key and the control block of a leaf beside OP_2.

    The leaf is the drawn bytes, hashed as they are: taproot.serialize
    has no spelling for 0xFF, which _scripts draws.
    """
    sibling = taproot.leaf_hash(0xC0, serialize(["OP_2"]))
    own = taproot.leaf_hash(leaf_version, leaf)
    root = tagged_hash(b"TapBranch", min(own, sibling) + max(own, sibling))
    output, parity = taproot.output_pubkey_from_merkle_root_var(internal, root)
    return output, bytes([leaf_version | parity]) + internal + sibling


_KINDS = [
    "p2pk",
    "p2pkh",
    "p2ms",
    "p2sh_p2ms",
    "p2wpkh",
    "p2sh_p2wpkh",
    "p2wsh_p2ms",
    "p2sh_p2wsh_p2ms",
    "p2tr_key",
    "p2tr_checksig",
    "p2tr_multi_a",
]
_FREE_KINDS = ["script", "p2sh_script", "p2wsh_script", "p2tr_free"]


@st.composite
def _mutations(draw: st.DrawFn, slots: int) -> list[tuple[int, int, int]]:
    """Draw up to two (slot, byte, xor mask) edits, none most of the time.

    An empty slot takes the mask as its one byte.
    """
    edit = st.tuples(
        st.integers(min_value=0, max_value=slots - 1),
        st.integers(min_value=0, max_value=1000),
        st.integers(min_value=1, max_value=255),
    )
    count = draw(st.sampled_from([0, 0, 0, 1, 1, 2]))
    return [draw(edit) for _ in range(count)]


def _flags_from(chosen: set[ScriptFlag]) -> ScriptFlag:
    flags = NO_FLAGS
    for flag in chosen:
        flags |= flag
    # the kernel refuses WITNESS without P2SH rather than answer
    return flags | ScriptFlag.P2SH if ScriptFlag.WITNESS in flags else flags


_FLAGS = st.one_of(
    st.just(ALL_FLAGS),
    st.sets(st.sampled_from(_CONSENSUS_FLAGS)).map(_flags_from),
)


@st.composite
def spends(
    draw: st.DrawFn,
    kinds: list[str],
    *,
    valid: bool = False,
    flags: st.SearchStrategy[ScriptFlag] = _FLAGS,
) -> Spend:
    """Draw a spend of one of the script types, signed and then edited.

    `valid` draws no edit, the lower-S signatures and the flags it is
    given, which makes a control of the generator and of the comparison.
    """
    template = draw(st.sampled_from(kinds).flatmap(lambda k: _templates(k, valid)))
    n_in = draw(st.integers(min_value=1, max_value=3))
    index = draw(st.integers(min_value=0, max_value=n_in - 1))
    value = draw(st.integers(min_value=0, max_value=10**12))
    prevouts = [
        TxOut(draw(st.integers(min_value=0, max_value=10**12)), _OP_TRUE)
        for _ in range(n_in)
    ]
    prevouts[index] = TxOut(value, template.script_pub_key)

    script_sig, witness = template.fill([b"\x00" * 65 for _ in template.signers])
    vin = [
        TxIn(OutPoint(bytes([j]) * 32, j), b"", draw(_U32), Witness())
        for j in range(n_in)
    ]
    vin[index] = TxIn(
        vin[index].prev_out, script_sig, vin[index].sequence, Witness(witness)
    )
    vout = [
        TxOut(draw(st.integers(min_value=0, max_value=10**6)), _OP_TRUE)
        for _ in range(draw(st.integers(min_value=1, max_value=3)))
    ]
    tx = Tx(draw(st.sampled_from([1, 2, 3])), draw(_U32), vin, vout)

    hash_type = draw(
        st.sampled_from(_HASH_TYPES if not template.schnorr else [0, *_HASH_TYPES])
    )
    # BIP341 has no hash for SIGHASH_SINGLE without a matching output
    if template.schnorr and hash_type & 3 == 3 and index >= len(vout):
        hash_type = 1
    lower_s = True if valid else draw(st.booleans())
    sigs = []
    for prv_key in template.signers:
        digest = sig_hash.from_tx(prevouts, tx, index, hash_type)
        if template.schnorr:
            raw = ssa.sign_(digest, prv_key).serialize()
            sigs.append(raw + (bytes([hash_type]) if hash_type else b""))
        else:
            raw = dsa.sign_(digest, prv_key, lower_s=lower_s).serialize()
            sigs.append(raw + bytes([hash_type]))
    script_sig, witness = template.fill(sigs)

    script_pub_key = template.script_pub_key
    if not valid:
        slots = [script_sig, script_pub_key, *witness]
        for slot, position, mask in draw(_mutations(len(slots))):
            data = bytearray(slots[slot])
            if data:
                data[position % len(data)] ^= mask
            else:
                data = bytearray([mask])
            slots[slot] = bytes(data)
        script_sig, script_pub_key, *rest = slots
        witness = tuple(rest)
    prevouts[index] = TxOut(value, script_pub_key)
    vin[index] = TxIn(
        vin[index].prev_out, script_sig, vin[index].sequence, Witness(witness)
    )
    return Spend(
        prevouts, Tx(tx.version, tx.lock_time, vin, tx.vout), index, draw(flags)
    )


def btclib_verdict(spend: Spend) -> tuple[bool, str]:
    """Return btclib's verdict and the refusal's text, empty if accepted.

    A refusal other than ScriptError propagates.
    """
    try:
        verify_input(spend.prevouts, spend.tx, spend.index, spend.flags)
    except ScriptError as error:
        return False, f"{error.code.name}: {error}"
    return True, ""


def btclib_accepts(spend: Spend) -> bool:
    """Return whether btclib accepts the spend."""
    return btclib_verdict(spend)[0]


def kernel_accepts(spend: Spend) -> bool:
    """Return the kernel's verdict."""
    tx = pbk.Transaction(spend.tx.serialize(include_witness=True))
    spent = [
        pbk.TransactionOutput(pbk.ScriptPubkey(p.script_pub_key.script), p.value)
        for p in spend.prevouts
    ]
    precomputed = pbk.script.PrecomputedTransactionData(tx, spent)
    prevout = spend.prevouts[spend.index]
    return bool(
        pbk.ScriptPubkey(prevout.script_pub_key.script).verify(
            prevout.value,
            tx,
            precomputed,
            spend.index,
            pbk.ScriptVerificationFlags(spend.flags.value),
        )
    )


def btclib_trace(spend: Spend) -> tuple[bool, list[Frame]]:
    """Return btclib's verdict and the frames its `step` reported."""
    frames: list[Frame] = []

    def step(
        index: int,
        op_code: int | None,
        executing: bool,
        stack: tuple[bytes, ...],
        altstack: tuple[bytes, ...],
    ) -> None:
        frames.append((index, op_code, executing, stack, altstack))

    try:
        verify_input(spend.prevouts, spend.tx, spend.index, spend.flags, step=step)
    except ScriptError:
        return False, frames
    return True, frames


def _kernel_stack(stack: int) -> tuple[bytes, ...]:
    """Copy a stack out of a kernel frame."""
    items = []
    for j in range(_TRACER.btck_script_eval_stack_count_items(stack)):
        chunks: list[bytes] = []

        def write(data: int, size: int, _: int, chunks: list[bytes] = chunks) -> int:
            chunks.append(ctypes.string_at(data, size) if size else b"")
            return 0

        item = _TRACER.btck_script_eval_stack_get_item_at(stack, j)
        writer = _WRITE_BYTES(write)
        if _TRACER.btck_script_eval_stack_item_to_bytes(item, writer, None):
            raise RuntimeError("the kernel did not write a stack item")
        items.append(b"".join(chunks))
    return tuple(items)


def kernel_trace(spend: Spend) -> tuple[bool, list[Frame]]:
    """Return the kernel's verdict and its tracer's frames, as Frames.

    The begin frames are dropped, a script's frames ending on its end
    frame, as btclib's do. An end frame reports executing as true.
    """
    frames: list[Frame] = []
    errors: list[Exception] = []

    def on_frame(_: int, frame: int) -> None:
        # an exception does not cross back into C: it is kept for later
        try:
            kind = _TRACER.btck_script_trace_frame_get_kind(frame)
            if kind == _BEGIN:
                return
            index = _TRACER.btck_script_trace_frame_get_opcode_pos(frame)
            stack = _kernel_stack(_TRACER.btck_script_trace_frame_get_stack(frame))
            altstack = _kernel_stack(
                _TRACER.btck_script_trace_frame_get_altstack(frame)
            )
            if kind == _STEP:
                op_code = _TRACER.btck_script_trace_frame_get_opcode(frame)
                executing = bool(_TRACER.btck_script_trace_frame_get_exec(frame))
                frames.append((index, op_code, executing, stack, altstack))
            else:
                frames.append((index, None, True, stack, altstack))
        except Exception as error:  # noqa: BLE001
            errors.append(error)

    callback = _FRAME_CALLBACK(on_frame)
    if _TRACER.btck_script_trace_register_callback(callback, None, None):
        raise RuntimeError("the kernel refused the trace callback")
    try:
        verdict = kernel_accepts(spend)
    finally:
        _TRACER.btck_script_trace_unregister_callback()
    if errors:
        raise errors[0]
    return verdict, frames


def _by_script(frames: list[Frame]) -> list[list[Frame]]:
    """Split the frames into one list per script, each ending on its end."""
    scripts: list[list[Frame]] = []
    current: list[Frame] = []
    for frame in frames:
        current.append(frame)
        if frame[1] is None:
            scripts.append(current)
            current = []
    assert not current, f"frames after the last end frame: {current}"
    return scripts


def _aligned(ours: list[Frame], theirs: list[Frame]) -> list[Frame]:
    """Return btclib's frames of a script in the shape the kernel reports.

    The kernel's end frame reports executing as true. Core reads a whole
    command before its step frame, so a push running past the end of the
    script stops it with no step frame for that command; btclib reports
    one, having read the op code.
    """
    *steps, end = ours
    end = (end[0], None, True, end[3], end[4])
    their_end_has_a_step = len(theirs) > 1 and theirs[-2][0] == theirs[-1][0]
    if steps and steps[-1][0] == end[0] and not their_end_has_a_step:
        steps.pop()
    return [*steps, end]


def assert_same_trace(spend: Spend) -> None:
    """Fail unless btclib and the kernel agree on the verdict and the frames."""
    ours, our_frames = btclib_trace(spend)
    theirs, their_frames = kernel_trace(spend)
    assert ours == theirs, f"btclib {ours}, kernel {theirs}\n{spend}"
    our_scripts, their_scripts = _by_script(our_frames), _by_script(their_frames)
    assert len(our_scripts) == len(their_scripts), (
        f"btclib ran {len(our_scripts)} scripts, the kernel "
        f"{len(their_scripts)}\n{spend}"
    )
    for n, (mine, core) in enumerate(zip(our_scripts, their_scripts, strict=True)):
        for a, b in zip_longest(_aligned(mine, core), core):
            assert a == b, f"script {n}: btclib {a}, kernel {b}\n{spend}"


def assert_same_verdict(spend: Spend) -> bool:
    """Fail unless btclib and the kernel agree; return their verdict."""
    ours, reason = btclib_verdict(spend)
    theirs = kernel_accepts(spend)
    assert ours == theirs, f"btclib {ours} {reason!r}, kernel {theirs}\n{spend}"
    return ours


@pytest.mark.parametrize("kind", _KINDS)
@given(data=st.data())
def test_a_signed_spend_is_valid_to_both(kind: str, data: st.DataObject) -> None:
    """The generator signs what the engines accept, and each can say yes."""
    spend = data.draw(spends([kind], valid=True, flags=st.just(ALL_FLAGS)))
    assert btclib_accepts(spend)
    assert kernel_accepts(spend)


@pytest.mark.parametrize("kind", _KINDS)
@given(data=st.data())
def test_a_wrong_amount_fails_only_where_it_is_signed(
    kind: str, data: st.DataObject
) -> None:
    """A signature commits to the amount from segwit on, and only there."""
    spend = data.draw(spends([kind], valid=True, flags=st.just(ALL_FLAGS)))
    prevout = spend.prevouts[spend.index]
    wrong = [*spend.prevouts]
    wrong[spend.index] = TxOut(prevout.value + 1, prevout.script_pub_key.script)
    spend = Spend(wrong, spend.tx, spend.index, spend.flags)
    # a pre-segwit signature does not commit to the amount
    if kind in {"p2pk", "p2pkh", "p2ms", "p2sh_p2ms"}:
        assert btclib_accepts(spend)
        assert kernel_accepts(spend)
    else:
        assert not btclib_accepts(spend)
        assert not kernel_accepts(spend)


@given(spend=spends(_KINDS))
def test_signed_spends_agree(spend: Spend) -> None:
    """A signed spend, edited or not, under any consensus flags."""
    assert_same_verdict(spend)


@given(spend=spends(_FREE_KINDS))
def test_free_scripts_agree(spend: Spend) -> None:
    """A script drawn from opcodes, with no signature in it."""
    assert_same_verdict(spend)


@needs_tracer
@given(spend=spends(_KINDS))
def test_signed_spends_trace_alike(spend: Spend) -> None:
    """A signed spend, edited or not: the same frames in every script."""
    assert_same_trace(spend)


@needs_tracer
@given(spend=spends(_FREE_KINDS))
def test_free_scripts_trace_alike(spend: Spend) -> None:
    """A script drawn from opcodes: the same frames in every script."""
    assert_same_trace(spend)
