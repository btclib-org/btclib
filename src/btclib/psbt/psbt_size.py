# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""How large the inputs of a Psbt will be once they are signed.

`Tx.size`, `Tx.vsize` and `Tx.weight` are read off a serialization, so
all three need the signatures a `Psbt` does not have yet. What a psbt
does have is, per input, the output being spent and the scripts that
unlock it, and those say how many bytes the missing signatures will
take -- which is what a fee has to be computed from, before there is
anything to sign.

Two rules are what make the answer honest rather than merely available.

**A signature is 72 bytes**, the sig_hash byte that follows it in the
script included. A DER signature is `30 <len> 02 <r len> r 02 <s len> s`,
so 71 bytes when the 32-byte `r` needs the leading zero its high bit
calls for and 70 when it does not: with the sig_hash byte, 72 or 71. Low
s is exactly the rule that keeps `s` from ever needing that zero, which
is why 72 is the largest and not merely the likeliest. Assuming the
shorter form would underpay the intended fee rate one transaction in
two, so the worst case is what is assumed here and every estimate is an
upper bound.

**An input whose type cannot be read raises.** The utxo, the redeem
script, the witness script and the derivation data are what the type is
read from, and an input that carries too little of them has no estimate:
guessing costs bytes in one direction only, and a fee computed from a
guess is a transaction that does not relay.

A caller who does not have to guess says so, with a `SolutionSizer`.
`descriptors.miniscript_sizer` is one for every input whose witness script
is a BIP379 miniscript, and it is a sizer rather than a branch of this
module for a reason of layering: `descriptors` imports this one and nothing
here imports back.
Two inputs are refused above not for want of data but for want of
knowledge nobody but the caller has -- a script of no standard type, and
a taproot script path, where which leaf will be spent is not in the psbt
-- and a sizer is asked exactly there, never in place of an answer this
file can work out. What it returns is the whole of what the input will
push, the witness script of a p2wsh and the control block of a taproot
leaf included: a caller who knows the solution holds those too, and one
rule with no exceptions is what keeps the two sides from each appending
the other's element.
"""

from __future__ import annotations

from collections.abc import Callable

from btclib.alias import Command
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.hashes import hash160
from btclib.psbt.psbt_in import PsbtIn
from btclib.script import serialize, type_and_payload
from btclib.tx import TxIn
from btclib.utils import assert_type

__all__ = [
    "COMPRESSED_PUB_KEY_SIZE",
    "SCHNORR_SIG_SIZE",
    "SIG_SIZE",
    "SolutionSizer",
    "estimated_input_sizes",
]

# what an input will push, by the caller who knows: the size of every
# element of the witness stack, or of every push of a legacy script_sig,
# and None for an input this caller cannot answer for either
SolutionSizer = Callable[[PsbtIn, TxIn], "list[int] | None"]

# a DER signature and its sig_hash byte, at the largest a low-s signature
# can be; see the module docstring, which is where the assumption is
# stated because it is the one number a caller has to know about
SIG_SIZE = 72

# a BIP340 signature, to which a sig_hash byte is appended only when the
# sig_hash type is not the default one
SCHNORR_SIG_SIZE = 64

# a SEC compressed point
COMPRESSED_PUB_KEY_SIZE = 33

# OP_1 is 0x51 and OP_16 is 0x60, so the m and the n of an m-of-n
# multisig script are each written as its value plus this
_OP_INT_OFFSET = 0x50


def _script_pub_key(psbt_in: PsbtIn, tx_in: TxIn) -> bytes:
    """Return the script_pub_key of the output the input spends.

    Not `psbt._signable_payload`, which answers a neighbouring question
    and a different one: it returns the payload a Signer has to check a
    script against, and refuses a witness utxo that is not a segwit
    output. Here every type is an answer, and the whole script is what
    the type is read from.
    """
    if psbt_in.witness_utxo:
        return psbt_in.witness_utxo.script_pub_key.script

    if psbt_in.non_witness_utxo:
        script_pub_key = psbt_in.non_witness_utxo.vout[
            tx_in.prev_out.vout
        ].script_pub_key
        return script_pub_key.script

    raise BTClibValueError("no utxo")


def _pub_key_size(psbt_in: PsbtIn, payload: bytes) -> int:
    """Return the size of the pub key a p2pkh input will push.

    Compressed unless the derivation data says otherwise. A p2pkh script
    commits to the hash160 of a key and not to its length, so the psbt is
    the only thing that can tell the two apart, and an uncompressed key
    is 32 bytes more: assuming compressed for an input that carries the
    key would be assuming low, which is what this file is against.
    """
    for pub_key in psbt_in.hd_key_paths:
        if hash160(pub_key) == payload:
            return len(pub_key)
    return COMPRESSED_PUB_KEY_SIZE


def _solution_sizes(
    script_type: str, payload: bytes, psbt_in: PsbtIn
) -> list[int] | None:
    """Return the size of each element that will satisfy the script.

    In the order the elements go on the stack, so this is the witness
    stack of a segwit input and the pushes of a legacy script_sig, one
    list because it is one list of signatures either way.

    None for a type this file has no answer for, which is the word a
    `SolutionSizer` uses for the same thing: the caller of both tells
    "no answer" from an answer by looking at what came back, and a
    second spelling of it -- a raise, a set of the types answered for,
    a caller catching what it does not want -- would be one more thing
    to keep in agreement with the branches below.
    """
    if script_type == "p2pkh":
        return [SIG_SIZE, _pub_key_size(psbt_in, payload)]

    if script_type == "p2pk":
        # the pub key is in the script being spent, so only a signature
        # is pushed
        return [SIG_SIZE]

    if script_type == "p2wpkh":
        # no _pub_key_size: BIP143 refuses an uncompressed key in a
        # witness v0 program, so there is nothing to look up
        return [SIG_SIZE, COMPRESSED_PUB_KEY_SIZE]

    if script_type == "p2ms":
        # type_and_payload has vetted the shape -- 0 < m <= n < 17 -- so
        # the first byte is OP_m and the arithmetic below cannot be wrong.
        # The leading zero-size element is the one CHECKMULTISIG pops and
        # does not use (BIP147)
        m = payload[0] - _OP_INT_OFFSET
        return [0, *[SIG_SIZE] * m]

    return None


def _asked(
    sizer: SolutionSizer | None,
    psbt_in: PsbtIn,
    tx_in: TxIn,
    err_msg: str,
) -> list[int]:
    """Return what the sizer says the input pushes, or raise what it cannot.

    The one place a sizer is consulted, so the rule that it answers only
    where this file cannot is this function existing rather than a
    condition repeated at each site. A sizer answering None is a caller
    saying "not this input either", which is the refusal that was there
    before it was asked.
    """
    sizes = sizer(psbt_in, tx_in) if sizer else None
    if sizes is None:
        raise BTClibValueError(err_msg)
    return sizes


def _taproot_sig_size(psbt_in: PsbtIn) -> int:
    """Return the size of the BIP341 key path signature.

    64 bytes, or 65 when the input asks for a sig_hash type other than
    the default one: that type is the byte appended to the signature, and
    SIGHASH_DEFAULT is the absence of it.
    """
    return SCHNORR_SIG_SIZE + (1 if psbt_in.sig_hash_type else 0)


def _p2wsh_witness_sizes(
    psbt_in: PsbtIn,
    tx_in: TxIn,
    sizer: SolutionSizer | None,
) -> list[int]:
    """Return the witness stack of a p2wsh input, asking where it cannot."""
    witness_script = psbt_in.witness_script
    if not witness_script:
        raise BTClibValueError("no witness script")
    inner_type, inner_payload = type_and_payload(witness_script)
    sizes = _solution_sizes(inner_type, inner_payload, psbt_in)
    if sizes is None:
        err_msg = f"no estimate for a script of type '{inner_type}'"
        return _asked(sizer, psbt_in, tx_in, err_msg)
    return [*sizes, len(witness_script)]


def _taproot_witness_sizes(
    psbt_in: PsbtIn,
    tx_in: TxIn,
    sizer: SolutionSizer | None,
) -> list[int]:
    """Return the witness stack of a taproot input, asking for a script path.

    A script path witness is the script's own inputs, the leaf script and
    the control block, and which leaf will be spent is not something the
    psbt says: an input carrying three of them has three different
    answers and no way to choose. A caller that has chosen answers all
    three.
    """
    if psbt_in.taproot_leaf_scripts:
        err_msg = "no estimate for a taproot script path"
        return _asked(sizer, psbt_in, tx_in, err_msg)
    return [_taproot_sig_size(psbt_in)]


def _assert_input_types(psbt_in: PsbtIn, tx_in: TxIn) -> None:
    """Refuse either object before a field is read off it.

    Both are read for their fields, so a value of another type is an
    AttributeError about a field name rather than a refusal. Every
    `SolutionSizer` takes the same pair and owes its callers the same
    check, so `descriptors`' two sizers ask this one -- the layering
    allows it, `descriptors` importing this module and nothing here
    importing back.
    """
    assert_type(psbt_in, PsbtIn, "psbt_in")
    assert_type(tx_in, TxIn, "tx_in")


def _assert_arguments(
    psbt_in: PsbtIn, tx_in: TxIn, sizer: SolutionSizer | None
) -> None:
    """Refuse an argument of the wrong type before any field is read.

    The sizer is asked for here and not where it is consulted, which is a
    single branch: one of no callable type went unnoticed for every input
    `estimated_input_sizes` answers for on its own.
    """
    _assert_input_types(psbt_in, tx_in)
    if sizer is not None and not callable(sizer):
        err_msg = f"invalid sizer type: {type(sizer).__name__}"  # type: ignore[unreachable]
        raise BTClibTypeError(err_msg)


def estimated_input_sizes(
    psbt_in: PsbtIn,
    tx_in: TxIn,
    *,
    sizer: SolutionSizer | None = None,
) -> tuple[int, list[int]]:
    """Return the script_sig size and the witness stack of a signed input.

    The second element is the size of each element the witness stack will
    hold, and not the size of its serialization: the count and the length
    prefixes are the transaction's layout, which `Tx.serialize` is the
    one place that knows.

    A signature is assumed to be 72 bytes; an input whose type cannot be
    read raises, unless `sizer` answers for it. All three rules, and why,
    are in the module docstring.
    """
    _assert_arguments(psbt_in, tx_in, sizer)

    if psbt_in.final_script_sig or psbt_in.final_script_witness:
        # nothing to estimate: a Finalizer has been here, and what it
        # produced is what the transaction will carry
        return len(psbt_in.final_script_sig), [
            len(element) for element in psbt_in.final_script_witness.stack
        ]

    script_type, payload = type_and_payload(_script_pub_key(psbt_in, tx_in))

    redeem_script = b""
    if script_type == "p2sh":
        redeem_script = psbt_in.redeem_script
        if not redeem_script:
            raise BTClibValueError("no redeem script")
        # what is spent is the redeem script; the script_pub_key is the
        # hash160 that names it, and _assert_input_signable is where the
        # two are checked against each other
        script_type, payload = type_and_payload(redeem_script)

    # the push of the redeem script ends the script_sig of a wrapped
    # input, and is the whole of it when what is wrapped is segwit
    wrapper: list[Command] = [redeem_script] if redeem_script else []

    if script_type == "p2wsh":
        return len(serialize(wrapper)), _p2wsh_witness_sizes(psbt_in, tx_in, sizer)

    if script_type == "p2tr":
        # a witness v1 program wrapped in p2sh is not refused here: it is
        # unspendable by consensus, so what a psbt carrying one is missing
        # is not an estimate
        return len(serialize(wrapper)), _taproot_witness_sizes(psbt_in, tx_in, sizer)

    sizes = _solution_sizes(script_type, payload, psbt_in)
    if sizes is None:
        err_msg = f"no estimate for a script of type '{script_type}'"
        sizes = _asked(sizer, psbt_in, tx_in, err_msg)

    if script_type == "p2wpkh":
        return len(serialize(wrapper)), sizes

    # a legacy script takes the whole of what unlocks it in the script_sig
    # the pushes are measured rather than counted: how a push is written
    # -- a one-byte length below 76, OP_PUSHDATA1 above it -- is
    # script.serialize's rule, and a second implementation of it here is
    # one that can disagree with the transaction actually built
    commands: list[Command] = [b"\x00" * size for size in sizes]
    return len(serialize(commands + wrapper)), []
