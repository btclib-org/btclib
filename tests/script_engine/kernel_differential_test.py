# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""`btclib.script.engine` against libbitcoinkernel, through py-bitcoinkernel.

Hypothesis draws a spend: a script type, signatures valid or corrupted,
the consensus flags, and the other inputs of the transaction. `verify_input`
and Core's own `VerifyScript`, reached through the kernel, then answer
whether it is valid, and the two answers must be the same. Only the
verdict is compared: the kernel reports no script error code.

The kernel takes the consensus flags and no policy flag, so the policy
flags are not drawn. tests/README.md says how to run the module.

A disagreement prints the transaction, the spent outputs and the flags, and
the exception btclib raised.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NamedTuple

import pytest
from btclib_ecc.curves import bytes_from_point, mult
from btclib_ecc.ecc import dsa, ssa
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
        script = [draw(_scripts(max_size=8))]
        signers = []
    tree: TaprootScriptTree = [[(leaf_version, script)], [(0xC0, ["OP_2"])]]
    output = taproot.output_pubkey(internal, tree)[0]
    leaf_script, control = taproot.input_script_sig(internal, tree, 0)
    items = draw(_pushes()) if kind == "p2tr_free" else []
    absent = len(prv_keys) - len(signers) if kind == "p2tr_multi_a" else 0

    def fill(sigs: list[bytes]) -> tuple[bytes, tuple[bytes, ...]]:
        stack = [*items, *([b""] * absent), *reversed(sigs)]
        script_bytes = serialize(leaf_script)
        return b"", (*stack, script_bytes, control, *tail)

    return _Template(serialize(["OP_1", output]), fill, signers, True)


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
