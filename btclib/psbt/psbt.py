# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Partially Signed Bitcoin Transaction (Psbt) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki

Both versions are held the same way, and it is BIP370's way: the fields
of the transaction being built -- its version, each input's outpoint and
sequence, each output's amount and script -- live in the psbt, and the
unsigned transaction is computed from them (`Psbt.tx`). Version 0, where
that transaction is the field and those are computed, is then a
conversion at the two edges, `parse` taking it apart and `serialize`
putting it back together, and nothing between the two has to ask which
version it is holding.

The other way round -- keeping BIP174's transaction and shadowing the
BIP370 fields beside it -- costs the same conversion and leaves the two
able to disagree, and BIP370 needs a second transaction anyway: the one
that identifies a psbt has every sequence zeroed (`Psbt.unique_id`), so
one stored transaction could not be both.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, fields
from math import ceil
from typing import Any, Protocol, TypeVar, cast

from btclib.alias import BinaryData, Octets, ScriptList, String
from btclib.bip32 import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_size import SolutionSizer, estimated_input_sizes
from btclib.psbt.psbt_utils import (
    LEAF_HASH_SIZE,
    PSBT_SEPARATOR,
    assert_not_a_v2_field,
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    deserialize_count,
    deserialize_map,
    deserialize_sized_int,
    deserialize_tx,
    encode_dict_bytes_bytes,
    serialize_bytes,
    serialize_count,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
    serialize_sized_int,
)
from btclib.script import (
    Witness,
    is_p2ms,
    is_p2pkh,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    p2ms_m_and_keys,
    serialize,
    sig_hash,
    taproot,
    type_and_payload,
)
from btclib.script.sig_hash import ALL, DEFAULT, assert_valid_hash_type
from btclib.tx import Tx, TxIn, TxOut
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
)

__all__ = [
    "HAS_SIG_HASH_SINGLE",
    "INPUTS_MODIFIABLE",
    "OUTPUTS_MODIFIABLE",
    "PSBT_GLOBAL_FALLBACK_LOCKTIME",
    "PSBT_GLOBAL_INPUT_COUNT",
    "PSBT_GLOBAL_OUTPUT_COUNT",
    "PSBT_GLOBAL_TX_MODIFIABLE",
    "PSBT_GLOBAL_TX_VERSION",
    "PSBT_GLOBAL_UNSIGNED_TX",
    "PSBT_GLOBAL_VERSION",
    "PSBT_GLOBAL_XPUB",
    "PSBT_MAGIC_BYTES",
    "PSBT_V0",
    "PSBT_V2",
    "KeyManager",
    "Psbt",
    "assert_signatures_only",
    "combine",
    "ecdsa_sig_hash",
    "extract_tx",
    "finalize",
    "join",
    "leaf_script",
    "prevouts",
    "sign",
    "single_leaf_key",
    "taproot_sig_hash",
]

# the whole of BIP174's <magic>, five bytes: the four of "psbt" and the
# 0xff that makes a psbt fail to deserialize as a transaction. It is one
# constant and one check because it is one header -- the 0xff is no more
# optional than the "p" -- and because the alternative is a second thing
# called a separator, which the 0x00 that ends a map already is
PSBT_MAGIC_BYTES = b"psbt\xff"

PSBT_GLOBAL_UNSIGNED_TX = b"\x00"
PSBT_GLOBAL_XPUB = b"\x01"
PSBT_GLOBAL_TX_VERSION = b"\x02"
PSBT_GLOBAL_FALLBACK_LOCKTIME = b"\x03"
PSBT_GLOBAL_INPUT_COUNT = b"\x04"
PSBT_GLOBAL_OUTPUT_COUNT = b"\x05"
PSBT_GLOBAL_TX_MODIFIABLE = b"\x06"
PSBT_GLOBAL_VERSION = b"\xfb"
# 0xfc is reserved for proprietary use, and needs no constant of its own:
# explicit support for proprietary (and por) is unnecessary,
# see https://github.com/bitcoin/bips/pull/1038

# the two versions there are. Version 1 is not one of them and never will
# be: BIP370 skipped the number because version 0 had been colloquially
# called version 1 while it was being designed
PSBT_V0 = 0
PSBT_V2 = 2

# the global fields BIP370 defines, which a version 0 psbt must not
# carry: in version 2 the unsigned transaction stops being a field and
# these are what replaces it. Named rather than merely listed, the name
# being what a rejection has to say -- a type byte says nothing to whoever
# reads the error. See psbt_utils.assert_not_a_v2_field
_V2_GLOBAL_FIELDS = {
    PSBT_GLOBAL_TX_VERSION: "PSBT_GLOBAL_TX_VERSION",
    PSBT_GLOBAL_FALLBACK_LOCKTIME: "PSBT_GLOBAL_FALLBACK_LOCKTIME",
    PSBT_GLOBAL_INPUT_COUNT: "PSBT_GLOBAL_INPUT_COUNT",
    PSBT_GLOBAL_OUTPUT_COUNT: "PSBT_GLOBAL_OUTPUT_COUNT",
    PSBT_GLOBAL_TX_MODIFIABLE: "PSBT_GLOBAL_TX_MODIFIABLE",
}

# the three bits BIP370 defines in PSBT_GLOBAL_TX_MODIFIABLE. The other
# five are undefined and kept as they arrive: an undefined flag is one of
# the BIP's own valid vectors
INPUTS_MODIFIABLE = 0b0000_0001
OUTPUTS_MODIFIABLE = 0b0000_0010
HAS_SIG_HASH_SINGLE = 0b0000_0100

# what an input's sequence is when the field is absent, which BIP370
# spells out: "if omitted, the sequence number is assumed to be the final
# sequence number"
_FINAL_SEQUENCE = 0xFFFFFFFF


def _global_version(global_map: Mapping[bytes, bytes]) -> int:
    """Return PSBT_GLOBAL_VERSION, or 0 for a map that does not carry it.

    BIP174 makes the field optional and its absence version 0, which is
    what a psbt written before BIP370 looks like. Present, it is four
    octets and no other number of them: the BIP calls it a little-endian
    uint32, and a value read without its width makes one psbt out of five
    encodings -- an empty value, one octet, two, three and four all
    deserialize to a version this writes back as four.
    """
    for k, v in global_map.items():
        if k[:1] == PSBT_GLOBAL_VERSION:
            return deserialize_sized_int(k, v, "global version", 4)
    return 0


def _assert_valid_version(version: int) -> None:
    # must be a 4-bytes int
    if not 0 <= version <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid version: {version}")
    # and one of the two that exist, which is a narrower rule than "a
    # version btclib does not know": a psbt claiming version 3 is not a
    # psbt of a later BIP, no such BIP being written -- version 1 was
    # skipped and nothing has taken any number since
    if version not in {PSBT_V0, PSBT_V2}:
        raise BTClibValueError(f"invalid psbt version: {version}")


def _lock_time(inputs: Sequence[PsbtIn], fallback_lock_time: int | None) -> int:
    """Return the lock time of the transaction these inputs make.

    BIP370's "Determining Lock Time", which is the whole of it: with no
    input requiring one, the fallback, and 0 when there is no fallback
    either; otherwise the kind of lock time *every* requiring input can
    satisfy, and the maximum of the values of that kind.

    An input requiring neither kind takes either, and so does one
    requiring both -- which is what leaves a tie to settle when every
    requiring input carries both, and the BIP settles it on the height:
    signatures commit to the lock time, so the two ends have to reach
    the same answer, and the block height is bitcoin's own unit of time.

    A psbt where one input requires a height and another a time has no
    answer at all, one nLockTime being one number of one kind, and that
    is a psbt this refuses rather than resolves.
    """
    requiring = [
        psbt_in
        for psbt_in in inputs
        if psbt_in.required_height_lock_time is not None
        or psbt_in.required_time_lock_time is not None
    ]
    if not requiring:
        return fallback_lock_time or 0

    if all(psbt_in.required_height_lock_time is not None for psbt_in in requiring):
        # the heights are not None by the test above, which mypy cannot see
        return max(
            cast(int, psbt_in.required_height_lock_time) for psbt_in in requiring
        )
    if all(psbt_in.required_time_lock_time is not None for psbt_in in requiring):
        return max(cast(int, psbt_in.required_time_lock_time) for psbt_in in requiring)

    err_msg = "no lock time satisfies every input: "
    err_msg += "a height is required by one and a time by another"
    raise BTClibValueError(err_msg)


def _unsigned_tx(psbt: Psbt, *, zeroed_sequences: bool = False) -> Tx:
    """Return the transaction a psbt's fields describe.

    check_validity=False throughout, and Psbt.assert_valid is what
    checks the result: a psbt's transaction is a template -- BIP174
    lists two psbts with no inputs as valid (issue 170) -- and every
    element of it is validated where it is held.

    zeroed_sequences=True is BIP370's "Unique Identification": the
    sequence is an Updater's to change, so the transaction that
    identifies a psbt is the one with every sequence set to 0, which is
    neither the final sequence nor the input's own.
    """
    vin = [
        TxIn(
            psbt_in.prev_out,
            b"",
            0 if zeroed_sequences else _sequence(psbt_in),
            check_validity=False,
        )
        for psbt_in in psbt.inputs
    ]
    vout = [
        TxOut(psbt_out.amount or 0, psbt_out.script_pub_key, check_validity=False)
        for psbt_out in psbt.outputs
    ]
    return Tx(psbt.tx_version, psbt.lock_time, vin, vout, check_validity=False)


def _sequence(psbt_in: PsbtIn) -> int:
    """Return the input's sequence, the final one when it has none."""
    return _FINAL_SEQUENCE if psbt_in.sequence is None else psbt_in.sequence


# one entry per BIP370 global: the name it is read into, the name an
# error message calls it by, and the deserializer of its value. A table
# for the same reason PsbtIn has two -- the fields differ in these three
# things and in nothing else -- and it is what keeps the parse of the
# global map one dispatch rather than one branch per field
_V2_GLOBAL_PARSERS: dict[bytes, tuple[str, str, Callable[[bytes, bytes, str], int]]] = {
    # unsigned, where BIP370 calls this field a "32-bit little endian
    # signed integer": what it holds is Tx.version one layer down, and
    # there it is unsigned, for the two mainnet transactions Tx.parse
    # names. Core arbitrates neither way -- it implements no PSBTv2, so
    # it has no counterpart to this field at all -- and the type it does
    # declare, CTransaction::version, is uint32_t. Read as signed, the
    # versions above 0x7fffffff come back negative and Tx refuses them,
    # so the BIP's word would buy a psbt this library cannot hold
    PSBT_GLOBAL_TX_VERSION: (
        "tx_version",
        "tx version",
        lambda k, v, what: deserialize_sized_int(k, v, what, 4),
    ),
    PSBT_GLOBAL_FALLBACK_LOCKTIME: (
        "fallback_lock_time",
        "fallback locktime",
        lambda k, v, what: deserialize_sized_int(k, v, what, 4),
    ),
    PSBT_GLOBAL_INPUT_COUNT: ("input_count", "input count", deserialize_count),
    PSBT_GLOBAL_OUTPUT_COUNT: ("output_count", "output count", deserialize_count),
    PSBT_GLOBAL_TX_MODIFIABLE: (
        "tx_modifiable",
        "tx modifiable",
        lambda k, v, what: deserialize_sized_int(k, v, what, 1),
    ),
}


def _parse_global_map(
    global_map: Mapping[bytes, bytes], version: int
) -> tuple[
    Tx | None, dict[str, int | None], dict[Octets, BIP32KeyOrigin], dict[Octets, Octets]
]:
    """Return what the global map holds: the transaction, if any, and the rest.

    None for every field the map does not carry, which each version
    requires a different set of: BIP174's "The unsigned transaction must
    be provided" for version 0, and BIP370's three globals for version
    2. Not zero-valued placeholders -- an empty transaction is
    indistinguishable from a *parsed* one with no inputs, and a count of
    0 from a psbt with no maps, so a check on the value would refuse the
    two zero-input psbts BIP174 lists as valid (issue 170).
    """
    tx: Tx | None = None
    globals_: dict[str, int | None] = {
        field: None for field, _, _ in _V2_GLOBAL_PARSERS.values()
    }
    hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
    unknown: dict[Octets, Octets] = {}

    for k, v in global_map.items():
        type_ = k[:1]
        assert_not_a_v2_field(type_, version, _V2_GLOBAL_FIELDS)
        if type_ in _V2_GLOBAL_PARSERS:
            field, what, deserialize = _V2_GLOBAL_PARSERS[type_]
            globals_[field] = deserialize(k, v, what)
        elif type_ == PSBT_GLOBAL_UNSIGNED_TX:
            if version != PSBT_V0:
                err_msg = "PSBT_GLOBAL_UNSIGNED_TX is not allowed in a v2 psbt"
                raise BTClibValueError(err_msg)
            tx = deserialize_tx(
                k, v, "global unsigned tx", False, unsigned_template=True
            )
        elif type_ == PSBT_GLOBAL_VERSION:
            pass  # read before this loop, the map having no order
        elif type_ == PSBT_GLOBAL_XPUB:
            hd_key_paths[k[1:]] = BIP32KeyOrigin.parse(v)
        else:  # unknown
            unknown[k] = v

    return tx, globals_, hd_key_paths, unknown


def _settle_globals(
    tx: Tx | None, globals_: dict[str, int | None], version: int
) -> None:
    """Fill in what a version 0 psbt says with a transaction, or check.

    The two versions state the same four things and state them in
    different places: version 0 in the unsigned transaction, whose
    version, lock time and two counts these are, and version 2 in the
    fields, three of which it requires. Which leaves the fields filled
    either way, and the rest of the parse with one thing to read.
    """
    if version == PSBT_V0:
        if tx is None:
            raise BTClibValueError("malformed psbt: missing global unsigned tx")
        globals_["tx_version"] = tx.version
        globals_["fallback_lock_time"] = tx.lock_time
        globals_["input_count"] = len(tx.vin)
        globals_["output_count"] = len(tx.vout)
        return

    for field, name in (
        ("tx_version", "PSBT_GLOBAL_TX_VERSION"),
        ("input_count", "PSBT_GLOBAL_INPUT_COUNT"),
        ("output_count", "PSBT_GLOBAL_OUTPUT_COUNT"),
    ):
        if globals_[field] is None:
            raise BTClibValueError(f"malformed psbt: missing {name}")


def _read_unsigned_tx(
    tx: Tx, inputs: Sequence[PsbtIn], outputs: Sequence[PsbtOut]
) -> None:
    """Write BIP174's unsigned transaction into the BIP370 fields.

    The version 0 conversion on the way in, and its only place: what
    that transaction says about an input -- the outpoint it spends and
    its sequence -- is written into the input map, and what it says
    about an output into the output map, after which nothing has to read
    it again. `Psbt.tx` puts it back together on the way out.

    The sequence is written even when it is the final one: a version 0
    transaction states a sequence for every input, so keeping the value
    rather than the absence is what makes the round trip exact.

    That the transaction is unsigned is checked here, this being the
    only door such a transaction comes through: a psbt built from the
    fields has no script_sig to carry, `Psbt.tx` writing an empty one.
    """
    if any(tx_in.script_sig or tx_in.script_witness for tx_in in tx.vin):
        raise BTClibValueError("non empty script_sig or witness")

    # one map per input and one per output, which `parse` gets from the
    # transaction itself and a caller of `from_tx` may not: strict=True
    # below would answer that caller with a bare ValueError, where
    # malformed input owes them a BTClibValueError
    if len(inputs) != len(tx.vin):
        err_msg = "mismatched number of tx.vin and psbt inputs: "
        err_msg += f"{len(tx.vin)} vs {len(inputs)}"
        raise BTClibValueError(err_msg)
    if len(outputs) != len(tx.vout):
        err_msg = "mismatched number of tx.vout and psbt outputs: "
        err_msg += f"{len(tx.vout)} vs {len(outputs)}"
        raise BTClibValueError(err_msg)

    for psbt_in, tx_in in zip(inputs, tx.vin, strict=True):
        psbt_in.previous_tx_id = tx_in.prev_out.tx_id
        psbt_in.output_index = tx_in.prev_out.vout
        psbt_in.sequence = tx_in.sequence

    for psbt_out, tx_out in zip(outputs, tx.vout, strict=True):
        psbt_out.amount = tx_out.value
        psbt_out.script_pub_key = tx_out.script_pub_key.script


def _assert_modifiable(psbt: Psbt, *, inputs: bool) -> None:
    """Raise unless this side of the transaction may still be changed.

    BIP370 gives the Constructor two bits of PSBT_GLOBAL_TX_MODIFIABLE
    to consult before adding an input or an output, and reordering is
    under the same rule rather than beside it: what the flag protects is
    the transaction the signatures already made commit to, and the order
    of the inputs and outputs is part of that transaction.

    The Has SIGHASH_SINGLE bit refuses both sides whatever the other two
    say. Such a signature commits to the output at the signed input's
    own index, so the pairing is positional, and a permutation that
    preserves every position is the one that changes nothing.

    A version 0 psbt has no such field and no Constructor either, so it
    passes: BIP174 has nothing to say about who may reorder what, and
    saying it here would break the callers that have always done so.
    """
    what = "inputs" if inputs else "outputs"
    if psbt.has_sig_hash_single:
        err_msg = "a SIGHASH_SINGLE signature pins each input to its output: "
        err_msg += f"the {what} cannot be reordered"
        raise BTClibValueError(err_msg)
    if not (psbt.inputs_modifiable if inputs else psbt.outputs_modifiable):
        raise BTClibValueError(f"the {what} are not modifiable")


def _assert_valid_input_fields(psbt_in: PsbtIn, version: int, i: int) -> None:
    """Raise unless the input carries what its psbt's version asks of it.

    The outpoint is asked of both versions, and named as BIP370 names it
    even when the psbt is version 0: it is the field btclib holds it in
    whatever the version, and a version 0 psbt gets it from the unsigned
    transaction on the way in. Without it there is no transaction to
    build -- an empty txid is no outpoint -- so the check is here rather
    than left to `OutPoint` to report as a length.

    The two required lock times are the other way round: BIP370 excludes
    them from version 0, where the transaction has one nLockTime and no
    field to compute it from, so a version 0 psbt carrying one would
    lose it on serialization. The message is the one `Psbt.parse` gives
    a version 0 psbt carrying the field itself.
    """
    if not psbt_in.previous_tx_id:
        raise BTClibValueError(f"input {i}: missing PSBT_IN_PREVIOUS_TXID")
    if psbt_in.output_index is None:
        raise BTClibValueError(f"input {i}: missing PSBT_IN_OUTPUT_INDEX")

    if version != PSBT_V0:
        return
    for value, name in (
        (psbt_in.required_time_lock_time, "PSBT_IN_REQUIRED_TIME_LOCKTIME"),
        (psbt_in.required_height_lock_time, "PSBT_IN_REQUIRED_HEIGHT_LOCKTIME"),
    ):
        if value is not None:
            err_msg = f"input {i}: {name} is not allowed in a v0 psbt"
            raise BTClibValueError(err_msg)


def _assert_valid_output_fields(psbt_out: PsbtOut, version: int, i: int) -> None:
    """Raise unless the output carries what its psbt's version asks of it.

    Version 2 alone, where the two are the output: BIP370 requires both
    fields, and an output map carrying neither is one of its invalid
    vectors. A version 0 output is under no such rule -- its amount and
    script are read from the unsigned transaction, which can carry a
    zero amount and an empty script, and neither is distinguishable from
    a field that is not there.
    """
    if version != PSBT_V2:
        return
    if psbt_out.amount is None:
        raise BTClibValueError(f"output {i}: missing PSBT_OUT_AMOUNT")
    if not psbt_out.script_pub_key:
        raise BTClibValueError(f"output {i}: missing PSBT_OUT_SCRIPT")


def _signable_payload(psbt_in: PsbtIn) -> bytes:
    """Return the hash the input's script_pub_key commits to.

    Which utxo the input carries is which kind of input it is. A
    witness_utxo is the spent output itself, and it has to be a witness
    one: p2sh is accepted only as the wrapper, so what is typed then is
    the redeem script, while the payload stays the p2sh one -- the
    hash160 the caller checks that redeem script against. A
    non_witness_utxo is the whole previous transaction, and the output
    being spent is the one the input's own outpoint names.

    p2tr is one of the three because it is a witness kind, which is the
    whole of the rule: BIP174 wrote the rule when witness v0 was the
    only witness there was. Only unwrapped, there being no p2sh-wrapped
    taproot spend -- and a redeem script beside one is refused by the
    hash160 the caller checks next, 20 bytes never equalling the 32 of
    an output key.
    """
    if witness_utxo := psbt_in.witness_utxo:
        script_type, payload = type_and_payload(witness_utxo.script_pub_key.script)
        if script_type == "p2sh":
            script_type, _ = type_and_payload(psbt_in.redeem_script)
        if script_type not in {"p2wpkh", "p2wsh", "p2tr"}:
            raise BTClibValueError("script type not in ('p2wpkh', 'p2wsh', 'p2tr')")
        return payload

    if psbt_in.non_witness_utxo:
        script_pub_key = psbt_in.non_witness_utxo.vout[
            psbt_in.output_index or 0
        ].script_pub_key
        _, payload = type_and_payload(script_pub_key.script)
        return payload

    err_msg = "missing script_pub_key"
    raise BTClibValueError(err_msg)


def _assert_taproot_signable(psbt_in: PsbtIn) -> None:
    """Raise unless a taproot input's fields commit to the key being spent.

    The same question the script checks below ask, in BIP341's terms:
    what the input says about how it is spent has to reach the output
    that is being spent. A taproot output commits to one key and can be
    spent two ways, so there are two answers and an input may carry
    either or both (issue #435):

    - the key path: the output key is the internal key tweaked by the
      merkle root, and `PSBT_IN_TAP_INTERNAL_KEY` with
      `PSBT_IN_TAP_MERKLE_ROOT` has to produce the 32 bytes the
      script_pub_key holds. No merkle root is key path only;
    - the script path: each `PSBT_IN_TAP_LEAF_SCRIPT` is keyed by its
      control block, which is BIP341's proof of that leaf against the
      output key -- `check_output_pubkey`'s whole question.

    Absence is not refused, as it is not for a p2sh input carrying no
    redeem script: an input that says nothing about how it is spent has
    told the signer nothing that can be wrong. What is there must be
    true.

    The leaf version is checked against the control block's because the
    two are read by different callers: `check_output_pubkey` folds the
    leaf hash from the version the *control block* declares, while
    `leaf_script` finds a leaf by the hash of the version the *field*
    stores. Where they disagree, the proof is of a leaf no other reader
    will look up.
    """
    prev_out = _prev_out(psbt_in)
    if prev_out is None or not is_p2tr(prev_out.script_pub_key.script):
        return
    output_key = type_and_payload(prev_out.script_pub_key.script)[1]

    if psbt_in.taproot_internal_key:
        tweaked = taproot.output_pubkey_from_merkle_root(
            psbt_in.taproot_internal_key, psbt_in.taproot_merkle_root
        )[0]
        if tweaked != output_key:
            err_msg = f"the tweaked internal key {tweaked.hex()} is not "
            err_msg += f"the output key being spent, {output_key.hex()}"
            raise BTClibValueError(err_msg)

    for control_block, (script, leaf_version) in psbt_in.taproot_leaf_scripts.items():
        if control_block[0] & 0xFE != leaf_version & 0xFE:
            err_msg = f"leaf version {hex(leaf_version)} is not the control "
            err_msg += f"block's {hex(control_block[0] & 0xFE)}"
            raise BTClibValueError(err_msg)
        if not taproot.check_output_pubkey(output_key, script, control_block):
            err_msg = "the control block does not prove leaf script "
            err_msg += f"{script.hex()} against output key {output_key.hex()}"
            raise BTClibValueError(err_msg)


def _assert_input_signable(psbt_in: PsbtIn) -> None:
    """Raise an exception unless the input carries what a Signer needs.

    Each script the input provides has to be the one the level above it
    commits to: the redeem script the hash160 in the script_pub_key
    names, and the witness script the sha256 in whichever of the two is
    the level above *it* -- the redeem script when the input is wrapped,
    the script_pub_key when it is native.

    A taproot input has neither script and answers the same question
    with its own fields, which `_assert_taproot_signable` asks. The two
    are not exclusive: the checks below still run, and refuse the redeem
    or witness script a taproot input has no use for.
    """
    payload = _signable_payload(psbt_in)
    _assert_taproot_signable(psbt_in)
    redeem_script = psbt_in.redeem_script

    if redeem_script and payload != hash160(redeem_script):
        raise BTClibValueError("invalid redeem script hash160")

    if psbt_in.witness_script:
        if redeem_script:
            _, payload = type_and_payload(redeem_script)
        if payload != sha256(psbt_in.witness_script):
            raise BTClibValueError("invalid witness script sha256")


@dataclass
class Psbt:
    """A partially signed bitcoin transaction, BIP174 and BIP370.

    Both versions are held BIP370's way -- the transaction's fields
    live in the psbt and `tx` computes the unsigned transaction; the
    module docstring says why. The global fields are here, each input's
    and output's in its PsbtIn or PsbtOut; the wire form is serialize
    and parse, the customary text form b64encode and b64decode.
    """

    tx_version: int
    inputs: list[PsbtIn]
    outputs: list[PsbtOut]
    version: int
    hd_key_paths: HdKeyPaths
    unknown: dict[bytes, bytes]
    fallback_lock_time: int | None
    tx_modifiable: int | None

    @property
    def lock_time(self) -> int:
        """Return the lock time of the transaction being built.

        Computed, never stored: BIP370 makes it the answer to the
        inputs' required lock times, with the fallback for a psbt whose
        inputs require none -- which is every version 0 psbt, its
        unsigned transaction's nLockTime being read into the fallback.
        _lock_time is the algorithm.
        """
        return _lock_time(self.inputs, self.fallback_lock_time)

    @property
    def tx(self) -> Tx:
        """Return the unsigned transaction this psbt is of.

        Computed from the fields each time, so it is a copy and not the
        psbt: what is written into it is written into nothing, and an
        outpoint or a sequence is changed on the input that holds it.
        The transaction is the psbt's serialization in version 0 and
        nowhere at all in version 2, which is why it cannot be the field
        the rest hangs off.
        """
        return _unsigned_tx(self)

    @property
    def unique_id(self) -> bytes:
        """Return the identifier BIP370 gives this psbt.

        The txid of the unsigned transaction with every sequence set to
        0: an Updater may set PSBT_IN_SEQUENCE, so two psbts of one
        transaction can disagree about it, and the identifier must not.
        It is what a Combiner compares -- `combine` does -- rather
        than `tx.id`, which for a version 2 psbt would call the same
        transaction two.
        """
        return _unsigned_tx(self, zeroed_sequences=True).id

    @property
    def inputs_modifiable(self) -> bool:
        """Return whether a Constructor may add or remove an input.

        Bit 0 of PSBT_GLOBAL_TX_MODIFIABLE. A version 2 psbt with no
        such field says no: "A Constructor may choose to declare that no
        further inputs and outputs can be added to the transaction by
        setting the appropriate bits ... to 0 or by removing the field
        entirely". Version 0 has no field to consult and no Constructor
        role either, so it answers yes and nothing changes for it.
        """
        if self.version == PSBT_V0:
            return True
        return bool(self.tx_modifiable and self.tx_modifiable & INPUTS_MODIFIABLE)

    @property
    def outputs_modifiable(self) -> bool:
        """Return whether a Constructor may add or remove an output.

        Bit 1 of PSBT_GLOBAL_TX_MODIFIABLE; `inputs_modifiable` says
        what an absent field and a version 0 psbt answer.
        """
        if self.version == PSBT_V0:
            return True
        return bool(self.tx_modifiable and self.tx_modifiable & OUTPUTS_MODIFIABLE)

    @property
    def has_sig_hash_single(self) -> bool:
        """Return whether a SIGHASH_SINGLE signature pins input to output.

        Bit 2 of PSBT_GLOBAL_TX_MODIFIABLE. Such a signature commits to
        the output at the signed input's own index, so the pairing is
        positional: adding, removing or reordering either side breaks
        it, whatever the two modifiable bits say.
        """
        return bool(self.tx_modifiable and self.tx_modifiable & HAS_SIG_HASH_SINGLE)

    @property
    def estimated_weight(self) -> int:
        """Return the weight the transaction will have once signed.

        A signature is assumed to be 72 bytes, the largest a low-s one
        can be with its sig_hash byte, so the answer is an upper bound;
        an input whose type the psbt does not determine has no estimate
        and raises, naming itself. Both rules are `psbt_size`'s, and why
        each is what it is, is there.

        `Tx.weight` is what the placeholders below are handed to: a
        signature is bytes wherever it goes, and how many of them a
        transaction is once they are in place is one arithmetic, written
        once, in the class whose serialization it is.
        """
        return self.weight_estimate()

    def weight_estimate(self, sizer: SolutionSizer | None = None) -> int:
        """Return the weight once signed, asking a sizer where needed.

        What `estimated_weight` is, with the one thing a property cannot
        take: a `psbt_size.SolutionSizer`, for the inputs this library
        refuses to estimate because what they will push is knowledge only
        the caller has -- a script of no standard type, a taproot script
        path. Without one this is that property exactly.
        """
        vin: list[TxIn] = []
        # read once: the transaction is computed at every access, being
        # the psbt's fields put together rather than a field of its own
        tx = self.tx
        # strict=True costs nothing: the vin is built from the inputs, so
        # the two are of one length by construction
        for i, (psbt_in, tx_in) in enumerate(zip(self.inputs, tx.vin, strict=True)):
            try:
                script_sig_size, witness_sizes = estimated_input_sizes(
                    psbt_in, tx_in, sizer=sizer
                )
            except BTClibValueError as e:
                raise BTClibValueError(f"input {i}: {e}") from e
            vin.append(
                TxIn(
                    tx_in.prev_out,
                    b"\x00" * script_sig_size,
                    tx_in.sequence,
                    Witness([b"\x00" * size for size in witness_sizes]),
                    check_validity=False,
                )
            )
        # built rather than copied: the placeholders would otherwise have
        # to be written into this psbt's own transaction, and the outputs
        # are only read here -- serialized, and by this very call
        placeholder = Tx(tx.version, tx.lock_time, vin, tx.vout, check_validity=False)
        return placeholder.weight

    @property
    def estimated_vsize(self) -> int:
        """Return the virtual size the transaction will have once signed.

        The name Bitcoin Core's `analyzepsbt` reports it under, and the
        `Tx.vsize` arithmetic: a quarter of the weight, rounded up.
        """
        return self.vsize_estimate()

    def vsize_estimate(self, sizer: SolutionSizer | None = None) -> int:
        """Return the virtual size once signed, asking a sizer where needed.

        `estimated_vsize` over `weight_estimate`, so that a fee computed
        from a caller's own solution sizes is the same arithmetic as one
        computed from this library's.
        """
        return ceil(self.weight_estimate(sizer) / 4)

    def __init__(
        self,
        tx_version: int,
        inputs: Sequence[PsbtIn],
        outputs: Sequence[PsbtOut],
        version: int,
        hd_key_paths: Mapping[Octets, BIP32KeyOrigin],
        unknown: Mapping[Octets, Octets] | None = None,
        fallback_lock_time: int | None = None,
        tx_modifiable: int | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.tx_version = tx_version
        self.inputs = list(inputs)
        self.outputs = list(outputs)
        self.version = version
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))
        self.fallback_lock_time = fallback_lock_time
        self.tx_modifiable = tx_modifiable

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency.

        Two questions, and the version answers the first: which fields
        this psbt must have and which it must not, BIP370 giving each of
        its twelve a "Versions Requiring Inclusion" and a "Versions
        Requiring Exclusion". The second is what the fields hold, which
        is the same question in both versions -- an outpoint is an
        outpoint whether it was read from an input map or from an
        unsigned transaction.
        """
        # first, the version being what every rule below is read under
        _assert_valid_version(self.version)

        for i, psbt_in in enumerate(self.inputs):
            _assert_valid_input_fields(psbt_in, self.version, i)
            psbt_in.assert_valid()

        for i, psbt_out in enumerate(self.outputs):
            _assert_valid_output_fields(psbt_out, self.version, i)
            psbt_out.assert_valid()

        if self.version == PSBT_V0 and self.tx_modifiable is not None:
            raise BTClibValueError(
                "PSBT_GLOBAL_TX_MODIFIABLE is not allowed in a v0 psbt"
            )
        if self.tx_modifiable is not None and not 0 <= self.tx_modifiable <= 0xFF:
            raise BTClibValueError(f"invalid tx modifiable: {self.tx_modifiable}")

        if self.fallback_lock_time is not None and not (
            0 <= self.fallback_lock_time <= 0xFFFFFFFF
        ):
            err_msg = f"invalid fallback locktime: {self.fallback_lock_time}"
            raise BTClibValueError(err_msg)

        # the unsigned transaction is incomplete by construction, so it is
        # checked as a template: no "at least one input", no "at least one
        # output", either of which would refuse the two psbts BIP174 lists
        # as valid with no inputs (issue 170). deserialize_tx checks it
        # the same way on the way in. The lock time is computed by the
        # very act of building it, so a psbt whose inputs require both
        # kinds is refused here, by _lock_time
        self.tx.assert_valid(unsigned_template=True)

        if any(
            psbt_in.non_witness_utxo
            and psbt_in.non_witness_utxo.id != psbt_in.previous_tx_id
            for psbt_in in self.inputs
        ):
            err_msg = "mismatched non-witness utxo / outpoint tx_id"
            raise BTClibValueError(err_msg)

        # the outpoint names one of that transaction's outputs, and the
        # tx_id check above does not say so: an index past its vout is an
        # IndexError to everything that reads the spent output --
        # _signable_payload, the Finalizer's sig_hash -- where malformed
        # input owes the caller a BTClibValueError
        if any(
            psbt_in.non_witness_utxo
            and (psbt_in.output_index or 0) >= len(psbt_in.non_witness_utxo.vout)
            for psbt_in in self.inputs
        ):
            err_msg = "outpoint vout out of range for the non-witness utxo"
            raise BTClibValueError(err_msg)

        assert_valid_hd_key_paths(self.hd_key_paths)
        assert_valid_unknown(self.unknown)

    def assert_signable(self) -> None:
        """Assert that every input carries what a Signer needs.

        Valid and signable are different questions, and BIP174 answers only
        the first: it lists two psbts with no inputs as valid, and
        assert_valid accepts them. This one is the Signer's pre-flight, so
        it answers the second, and a psbt with nothing to sign is not
        signable.

        The check has to be explicit because every check below is per
        input: without it an empty vin passes the loop vacuously, and a
        caller doing assert_signable() and then looping over the inputs
        signs none of them and is told nothing.
        """
        self.assert_valid()

        if not self.inputs:
            raise BTClibValueError("nothing to sign: no inputs")

        for psbt_in in self.inputs:
            _assert_input_signable(psbt_in)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        """Return the psbt as a dict of json-friendly values.

        The "tx" entry is derived for the reader and ignored by
        from_dict, the comment on it saying why; everything else
        round-trips.
        """
        if check_validity:
            self.assert_valid()

        return {
            "tx_version": self.tx_version,
            "inputs": [
                psbt_in.to_dict(check_validity=False) for psbt_in in self.inputs
            ],
            "outputs": [
                psbt_out.to_dict(check_validity=False) for psbt_out in self.outputs
            ],
            "version": self.version,
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
            "fallback_lock_time": self.fallback_lock_time,
            "tx_modifiable": self.tx_modifiable,
            # what the fields above make, for whoever is reading rather
            # than round-tripping: from_dict ignores it, as it must --
            # two ways in would let a dict say two different things.
            # check_validity=False for the same reason as in serialize:
            # a template, already validated by assert_valid above
            "tx": self.tx.to_dict(check_validity=False),
        }

    @classmethod
    def from_dict(
        cls: type[Psbt], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Psbt:
        """Build a Psbt from the dict shape to_dict writes."""
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            # check_validity=False, as for every other element here (issue
            # 264): Psbt.assert_valid below validates it as part of the whole
            decode_from_bip32_derivs(dict_["bip32_derivs"], check_validity=False),
        )
        return cls(
            dict_["tx_version"],
            # check_validity=False, as for every other element here: what
            # the inputs and outputs make is a template, and
            # Psbt.assert_valid below checks it as one. Validating it here
            # as a complete transaction would refuse the two zero-input
            # psbts BIP174 lists as valid (issue 170)
            [
                PsbtIn.from_dict(psbt_in, check_validity=False)
                for psbt_in in dict_["inputs"]
            ],
            [
                PsbtOut.from_dict(psbt_out, check_validity=False)
                for psbt_out in dict_["outputs"]
            ],
            dict_["version"],
            hd_key_paths,
            dict_["unknown"],
            dict_["fallback_lock_time"],
            dict_["tx_modifiable"],
            check_validity=check_validity,
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the psbt as the bytes of the version it declares.

        Version 0 writes the unsigned transaction its fields make and
        nothing else of BIP370; version 2 writes those fields and no
        transaction. `to_v0` and `to_v2` are the conversions between the
        two, and neither is done here: what a psbt is written as is what
        it says it is.
        """
        if check_validity:
            self.assert_valid()

        psbt_bin: list[bytes] = [PSBT_MAGIC_BYTES]

        if self.version == PSBT_V0:
            # check_validity=False: Psbt.assert_valid above has already
            # validated it, as the template it is, and Tx.serialize would
            # otherwise re-check it as a complete transaction and refuse
            # the two zero-input psbts BIP174 lists as valid (issue 170)
            temp = self.tx.serialize(include_witness=False, check_validity=False)
            psbt_bin.append(serialize_bytes(PSBT_GLOBAL_UNSIGNED_TX, temp))
        elif self.version == PSBT_V2:
            # ascending by type byte, which is the order BIP370's own
            # psbts are written in and so the order a byte-for-byte
            # comparison with them requires

            # the version is written unsigned, where BIP370 says signed;
            # _V2_GLOBAL_PARSERS says why, and every version Tx accepts
            # has to be writable here
            psbt_bin.append(
                serialize_sized_int(PSBT_GLOBAL_TX_VERSION, self.tx_version, 4)
            )
            if self.fallback_lock_time is not None:
                psbt_bin.append(
                    serialize_sized_int(
                        PSBT_GLOBAL_FALLBACK_LOCKTIME, self.fallback_lock_time, 4
                    )
                )
            # the counts are what tells the parser how many maps follow,
            # so they are written from the maps themselves rather than
            # held as fields that could disagree with them
            psbt_bin.extend(
                (
                    serialize_count(PSBT_GLOBAL_INPUT_COUNT, len(self.inputs)),
                    serialize_count(PSBT_GLOBAL_OUTPUT_COUNT, len(self.outputs)),
                )
            )
            if self.tx_modifiable is not None:
                psbt_bin.append(
                    serialize_sized_int(
                        PSBT_GLOBAL_TX_MODIFIABLE, self.tx_modifiable, 1
                    )
                )
        else:
            # asked even when the caller asked for no validation: which
            # fields are written *is* the version, so a version with no
            # answer to that has no serialization for the check to be
            # skipped over
            _assert_valid_version(self.version)

        if self.version:
            temp = self.version.to_bytes(4, byteorder="little", signed=False)
            psbt_bin.append(serialize_bytes(PSBT_GLOBAL_VERSION, temp))
        if self.hd_key_paths:
            psbt_bin.append(serialize_hd_key_paths(PSBT_GLOBAL_XPUB, self.hd_key_paths))
        if self.unknown:
            psbt_bin.append(serialize_dict_bytes_bytes(b"", self.unknown))

        # the global map is the one with no dataclass of its own, so it is
        # the only separator written here: an input and an output each end
        # themselves, as they do in Bitcoin Core
        psbt_bin.append(PSBT_SEPARATOR)
        psbt_bin.extend(
            psbt_in.serialize(psbt_version=self.version) for psbt_in in self.inputs
        )
        psbt_bin.extend(
            psbt_out.serialize(psbt_version=self.version) for psbt_out in self.outputs
        )
        return b"".join(psbt_bin)

    @classmethod
    def parse(
        cls: type[Psbt], data: BinaryData, *, check_validity: bool = True
    ) -> Psbt:
        """Return a Psbt by parsing binary data.

        A psbt ends at the separator of its last map. A stream is left
        right there, what follows in it being the caller's, so a psbt can
        be read out of a stream that carries more than the psbt; octets
        are the whole of one, so anything after it is refused. Bitcoin
        Core splits the two the same way, between PSBTInput::Unserialize
        and DecodeRawPSBT's "extra data after PSBT".
        """
        stream = bytesio_from_binarydata(data)

        if stream.read(5) != PSBT_MAGIC_BYTES:
            raise BTClibValueError("malformed psbt: missing magic bytes")

        global_map = deserialize_map(stream)
        # before the rest of the map, and before the input and output maps
        # it is handed to: what a type byte means is version-dependent,
        # BIP370 defining twelve of them that version 0 must not carry, and
        # a map has no order to put the version first in
        version = _global_version(global_map)
        _assert_valid_version(version)
        tx, globals_, hd_key_paths, unknown = _parse_global_map(global_map, version)
        _settle_globals(tx, globals_, version)
        input_count = cast(int, globals_["input_count"])
        output_count = cast(int, globals_["output_count"])

        inputs = [
            PsbtIn.parse(stream, psbt_version=version) for _ in range(input_count)
        ]
        outputs = [
            PsbtOut.parse(stream, psbt_version=version) for _ in range(output_count)
        ]

        # the version 0 conversion, and the whole of it: what BIP174 puts
        # in one transaction, BIP370 puts in the maps, and the rest of
        # this module reads the maps
        if tx is not None:
            _read_unsigned_tx(tx, inputs, outputs)

        # octets are one whole psbt and a stream is the caller's:
        # btclib/utils.py states the rule both halves of this contract read
        assert_no_trailing(data, stream, "psbt")

        return cls(
            cast(int, globals_["tx_version"]),
            inputs,
            outputs,
            version,
            hd_key_paths,
            unknown,
            globals_["fallback_lock_time"],
            globals_["tx_modifiable"],
            check_validity=check_validity,
        )

    def b64encode(self, *, check_validity: bool = True) -> str:
        """Return the serialization as base64 text, BIP174's file form."""
        psbt_bin = self.serialize(check_validity=check_validity)
        return base64.b64encode(psbt_bin).decode("ascii")

    @classmethod
    def b64decode(
        cls: type[Psbt], psbt_str: String, *, check_validity: bool = True
    ) -> Psbt:
        """Build a Psbt from its base64 text, stripping whitespace."""
        if isinstance(psbt_str, str):
            psbt_str = psbt_str.strip()

        psbt_decoded = base64.b64decode(psbt_str)

        return cls.parse(psbt_decoded, check_validity=check_validity)

    @classmethod
    def from_tx(
        cls: type[Psbt],
        tx: Tx,
        inputs: Sequence[PsbtIn] | None = None,
        outputs: Sequence[PsbtOut] | None = None,
        *,
        check_validity: bool = True,
    ) -> Psbt:
        """Return the version 0 psbt of a transaction, Creator-style.

        The transaction is taken apart into the fields the psbt holds,
        which is the same conversion `parse` makes: one input map per
        input and one output map per output, each carrying what the
        transaction said about it.

        inputs and outputs are the maps to fill, for a caller who
        already has them -- a Combiner or an Updater -- and empty ones
        otherwise, which is what a Creator starts from.
        """
        inputs = [PsbtIn() for _ in tx.vin] if inputs is None else list(inputs)
        outputs = [PsbtOut() for _ in tx.vout] if outputs is None else list(outputs)
        for tx_in in tx.vin:
            tx_in.script_sig = b""
            tx_in.script_witness = Witness()
        _read_unsigned_tx(tx, inputs, outputs)

        psbt_version = PSBT_V0
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        unknown: dict[Octets, Octets] = {}

        return cls(
            tx.version,
            inputs,
            outputs,
            psbt_version,
            hd_key_paths,
            unknown,
            tx.lock_time,
            check_validity=check_validity,
        )

    def to_v0(self) -> Psbt:
        """Return this psbt as the version 0 psbt of the same transaction.

        What version 0 cannot say is dropped, and the transaction is
        unchanged by the dropping: the computed lock time becomes the
        fallback, which is where a version 0 psbt keeps its nLockTime,
        so the inputs' required lock times go with nothing lost from the
        transaction -- only the record of which input required what.
        The modifiable flags go too, version 0 having no Constructor to
        obey them.

        A psbt whose inputs require both kinds of lock time has no
        transaction to be the version 0 psbt of, and raises here as it
        does anywhere else its lock time is asked for.
        """
        psbt = deepcopy(self)
        psbt.fallback_lock_time = self.lock_time
        psbt.tx_modifiable = None
        for psbt_in in psbt.inputs:
            psbt_in.required_time_lock_time = None
            psbt_in.required_height_lock_time = None
        psbt.version = PSBT_V0
        psbt.assert_valid()
        return psbt

    def to_v2(self) -> Psbt:
        """Return this psbt as the version 2 psbt of the same transaction.

        Nothing but the version number: every field version 2 writes is
        already held, this being how btclib holds a psbt of either
        version, so the conversion the other way is the one with work to
        do. What was the unsigned transaction's nLockTime is written as
        the fallback, which is what it is -- no input of a version 0
        psbt requires a lock time, none being able to say so.
        """
        psbt = deepcopy(self)
        psbt.version = PSBT_V2
        psbt.assert_valid()
        return psbt

    def sort_inputs(self, ordering_func: Callable[[PsbtIn], int] | None = None) -> None:
        """Sort psbt inputs.

        sorting logic is ordering_func if present, shuffle otherwise.

        A version 2 psbt is asked first: reordering the inputs is a
        change to the transaction every signature commits to, so it is
        one the Inputs Modifiable flag has to allow. `_assert_modifiable`
        is where the two flags are read.
        """
        _assert_modifiable(self, inputs=True)
        self.inputs = _sort_or_shuffle(self.inputs, ordering_func)

    def sort_outputs(
        self, ordering_func: Callable[[PsbtOut], int] | None = None
    ) -> None:
        """Sort psbt outputs.

        sorting logic is ordering_func if present, shuffle otherwise.

        The Outputs Modifiable flag is what allows it in a version 2
        psbt, as the Inputs Modifiable one allows `sort_inputs`.
        """
        _assert_modifiable(self, inputs=False)
        self.outputs = _sort_or_shuffle(self.outputs, ordering_func)


def _combine_field(
    psbt_map: PsbtIn | PsbtOut | Psbt, out: PsbtIn | PsbtOut | Psbt, key: str
) -> None:
    """Add one field of psbt_map to out, as BIP174's Combiner does.

    "The resulting PSBT must contain all of the key-value pairs from each
    of the PSBTs", so a field that is *several* key-value pairs -- a map
    keyed by pub key, by hash, by control block -- is the union of the
    two, merged pair by pair. A field that is one pair is taken when out
    has none and kept when out has one, which is the arbitrary choice the
    BIP allows a Combiner "when conflicts occur" and the choice Bitcoin
    Core's PSBTInput::Merge makes.

    A final_script_witness is one of the latter, and it survives the
    combine either way round because a Witness is sized: an empty one is
    falsy, so the input finalized in the other psbt is the one taken. It
    is not merged element-wise, which is the one wrong answer here -- a
    witness stack is positional, so two stacks for one input are two
    spends of it and not the halves of one.
    """
    item = getattr(psbt_map, key)
    if not item:
        return
    attr = getattr(out, key)
    if not attr:
        setattr(out, key, item)
    elif isinstance(item, dict):
        attr.update(item)


def _combine_optional_field(
    psbt_map: PsbtIn | PsbtOut | Psbt, out: PsbtIn | PsbtOut | Psbt, key: str
) -> None:
    """Add one optional integer field of psbt_map to out.

    _combine_field's rule -- take it when out has none, keep out's when
    it has one -- read with `is not None` rather than with truthiness,
    which for these fields answers the wrong question: 0 is a sequence
    BIP125 gives a meaning to, and an amount of 0 is an amount.
    """
    item = getattr(psbt_map, key)
    if item is None:
        return
    if getattr(out, key) is None:
        setattr(out, key, item)


def _combined_tx_modifiable(psbts: Sequence[Psbt]) -> int | None:
    """Return the modifiable flags of the psbt these combine into.

    Not an arbitrary pick, which is what BIP174 allows a Combiner for a
    field of one key-value pair, because this one is a claim about what
    may still be done: a Signer clears a modifiable bit when it adds a
    signature that would be broken by a change, so a psbt where the bit
    is clear must not come out of a combine with it set. The two
    modifiable bits are therefore the AND of the sides and the Has
    SIGHASH_SINGLE bit their OR -- each in the direction that keeps the
    combined psbt no more permissive than either half.

    The five undefined bits are OR-ed with the third: nobody here knows
    what they mean, and dropping a flag somebody set is the change with
    consequences. None when no psbt carries the field, so that a combine
    of psbts without it does not invent one.
    """
    flags = [psbt.tx_modifiable for psbt in psbts if psbt.tx_modifiable is not None]
    if not flags:
        return None
    modifiable = INPUTS_MODIFIABLE | OUTPUTS_MODIFIABLE
    # a psbt with no field at all is "nothing may be modified", which is
    # what the AND has to see for the bits it takes
    and_bits = 0xFF
    for psbt in psbts:
        and_bits &= psbt.tx_modifiable or 0
    or_bits = 0
    for value in flags:
        or_bits |= value
    return (and_bits & modifiable) | (or_bits & ~modifiable & 0xFF)


def _combine_musig2_participants(
    psbt_map: PsbtIn | PsbtOut, out: PsbtIn | PsbtOut
) -> None:
    """Merge the participant lists, refusing two of them under one key.

    Not `_combine_field`'s union, which for a map takes each side's pairs
    and lets the second write over the first: an aggregate key is
    computed from its participants, so two different lists filed under
    one key are not a conflict to resolve by picking. One of the two says
    that key aggregates something it does not, and nothing in either psbt
    says which.
    """
    for key, participants in psbt_map.musig2_participant_pub_keys.items():
        other = out.musig2_participant_pub_keys.get(key)
        if other is not None and other != participants:
            err_msg = f"mismatched musig2 participants for aggregate key {key.hex()}"
            raise BTClibValueError(err_msg)
        out.musig2_participant_pub_keys[key] = participants


def combine(psbts: Sequence[Psbt]) -> Psbt:
    """Merge the data of several psbts of one transaction: the Combiner.

    BIP174's Combiner role, whose ordinary use is merging the partial
    signatures different signers added to copies of one psbt.

    Every field a psbt map holds is merged, and the four left out are
    left out for one reason: `amount`, `script_pub_key`, `previous_tx_id`
    and `output_index` are part of what identifies the psbt, so the psbt
    being merged into carries them already and two psbts disagreeing
    about one of them are two transactions, refused above.

    Which psbts are of one transaction is a question the two versions
    answer differently, and each is asked its own: a version 0 psbt is
    identified by the txid of the unsigned transaction every copy of it
    carries, so two copies whose sequences differ are two transactions;
    a version 2 psbt is identified as BIP370 says, by the txid of that
    transaction with every sequence zeroed, the sequence being a field
    an Updater may set. Comparing `tx.id` there would refuse two psbts
    of one transaction, which is what the identifier exists to prevent.

    The versions must match, and are not converted here: `to_v0` and
    `to_v2` are that, and doing it silently would decide for the caller
    which of the two the combined psbt is -- and, from v0 to v2, hand
    back a psbt whose lock time comes from the fallback rather than
    from the unsigned transaction the caller wrote it into.

    The psbt handed back shares nothing with the ones handed in, which is
    `finalize`'s rule and `extract_tx`'s stated one. It matters more here
    than anywhere: without the copy this *is* `psbts[0]`, merged into in
    place, so the copy a coordinator keeps to check the next signer's
    answer against is the copy the last answer went into -- and a check
    against it would then pass whatever came back. The whole sequence is
    copied and not only the first, `_combine_field` assigning the objects
    it takes rather than copying them: a witness_utxo or a leaf script
    map that came from `psbts[1]` would otherwise be the very object
    `psbts[1]` still holds.
    """
    psbts = deepcopy(list(psbts))
    final_psbt = psbts[0]
    version = final_psbt.version
    for psbt in psbts[1:]:
        if psbt.version != version:
            err_msg = f"mismatched psbt version: {psbt.version} vs {version}"
            raise BTClibValueError(err_msg)

    tx_id = final_psbt.unique_id if version == PSBT_V2 else final_psbt.tx.id
    for psbt in psbts[1:]:
        other_id = psbt.unique_id if version == PSBT_V2 else psbt.tx.id
        if other_id != tx_id:
            raise BTClibValueError(f"mismatched psbt.tx.id: {other_id.hex()}")

    final_psbt.tx_modifiable = _combined_tx_modifiable(psbts)
    for psbt in psbts[1:]:
        for i, inp in enumerate(final_psbt.inputs):
            _combine_field(psbt.inputs[i], inp, "non_witness_utxo")
            _combine_field(psbt.inputs[i], inp, "witness_utxo")
            _combine_field(psbt.inputs[i], inp, "partial_sigs")
            _combine_field(psbt.inputs[i], inp, "sig_hash_type")
            _combine_field(psbt.inputs[i], inp, "redeem_script")
            _combine_field(psbt.inputs[i], inp, "witness_script")
            _combine_field(psbt.inputs[i], inp, "hd_key_paths")
            _combine_field(psbt.inputs[i], inp, "final_script_sig")
            _combine_field(psbt.inputs[i], inp, "final_script_witness")
            _combine_field(psbt.inputs[i], inp, "unknown")
            _combine_field(psbt.inputs[i], inp, "ripemd160_preimages")
            _combine_field(psbt.inputs[i], inp, "sha256_preimages")
            _combine_field(psbt.inputs[i], inp, "hash160_preimages")
            _combine_field(psbt.inputs[i], inp, "hash256_preimages")
            # the key path signature is one key-value pair, so the rule
            # for it is the arbitrary pick, and here that pick is between
            # two spends rather than between two descriptions of one.
            # Taking the first is defensible only because either one
            # finalizes the input on its own -- unlike the merged maps
            # below, where the halves are of one spend
            _combine_field(psbt.inputs[i], inp, "taproot_key_spend_signature")
            _combine_field(psbt.inputs[i], inp, "taproot_script_spend_signatures")
            _combine_field(psbt.inputs[i], inp, "taproot_leaf_scripts")
            _combine_field(psbt.inputs[i], inp, "taproot_hd_key_paths")
            _combine_field(psbt.inputs[i], inp, "taproot_internal_key")
            _combine_field(psbt.inputs[i], inp, "taproot_merkle_root")
            # merging the musig2 maps is what makes a session survive a
            # Combiner: BIP373 puts round 1 in one psbt per signer, and
            # a nonce that does not reach the aggregate is a session the
            # partial signatures of the others are not against
            _combine_musig2_participants(psbt.inputs[i], inp)
            _combine_field(psbt.inputs[i], inp, "musig2_pub_nonces")
            _combine_field(psbt.inputs[i], inp, "musig2_partial_sigs")
            # the two lock times an input may require are not part of
            # what identifies the psbt -- the identifier holds the lock
            # time they compute, not which input asked for it -- so a
            # Combiner takes the one it is given. `is not None` and not
            # truthiness: 0 is not a value either field can hold, but
            # the sequence beside them takes it, and one rule for the
            # four is one rule to read
            _combine_optional_field(psbt.inputs[i], inp, "sequence")
            _combine_optional_field(psbt.inputs[i], inp, "required_time_lock_time")
            _combine_optional_field(psbt.inputs[i], inp, "required_height_lock_time")

        for i, out in enumerate(final_psbt.outputs):
            _combine_field(psbt.outputs[i], out, "redeem_script")
            _combine_field(psbt.outputs[i], out, "witness_script")
            _combine_field(psbt.outputs[i], out, "hd_key_paths")
            _combine_field(psbt.outputs[i], out, "unknown")
            _combine_field(psbt.outputs[i], out, "taproot_internal_key")
            # a taproot tree is positional -- depth, leaf version and
            # script, in the order that rebuilds the merkle root -- so it
            # is taken whole or not at all, the way a witness stack is
            _combine_field(psbt.outputs[i], out, "taproot_tree")
            _combine_field(psbt.outputs[i], out, "taproot_hd_key_paths")
            _combine_musig2_participants(psbt.outputs[i], out)

        _combine_field(psbt, final_psbt, "hd_key_paths")
        _combine_field(psbt, final_psbt, "unknown")
        # the fallback is reached only when no input requires a lock time,
        # so two psbts that differ in it can still be one transaction and
        # reach here -- and a Combiner that dropped it answered one thing
        # for combine([a, b]) and another for combine([b, a]), the copy
        # merged into being the one that happened to come first
        _combine_optional_field(psbt, final_psbt, "fallback_lock_time")

    return final_psbt


def _prev_out(psbt_in: PsbtIn) -> TxOut | None:
    """Return the output the input spends, or None if the psbt omits it.

    Either utxo field answers the question, and a psbt carries whichever
    its kind of input needs: the witness_utxo is the spent output itself,
    the non_witness_utxo the whole transaction it belongs to, indexed by
    the outpoint.

    The index is bound-checked rather than trusted. Psbt.assert_valid
    does check it against that transaction's vout, and every caller here
    runs after it, so this is belt and braces -- but None is a answer both
    callers already handle, and an IndexError out of a private helper is
    not.
    """
    if psbt_in.witness_utxo:
        return psbt_in.witness_utxo
    vout = psbt_in.output_index or 0
    if psbt_in.non_witness_utxo and vout < len(psbt_in.non_witness_utxo.vout):
        return psbt_in.non_witness_utxo.vout[vout]
    return None


def _spent_script(psbt_in: PsbtIn) -> bytes:
    """Return the script the input's signatures satisfy, or b"".

    Which script that is depends on the kind of input: a p2sh one is
    spent by its redeem script, and it is the redeem script -- not the
    p2sh wrapper, which every wrapped kind shares -- that says whether
    the spend is legacy, p2wpkh or p2wsh. Every other input is spent by
    the script_pub_key of the output it names.

    b"" is "the psbt does not say", which is a missing utxo or a p2sh
    input carrying no redeem script. Not an error: the finalizer then
    builds what it built before there was anything to dispatch on, and
    an input that does not say what it spends is not one this function
    can contradict.
    """
    prev_out = _prev_out(psbt_in)
    if prev_out is None:
        return b""
    script = prev_out.script_pub_key.script
    return psbt_in.redeem_script if is_p2sh(script) else script


def _single_key(psbt_in: PsbtIn) -> bytes:
    """Return the one public key a single-key input is spent with.

    partial_sigs is keyed by public key, and p2pkh and p2wpkh are the
    kinds that need that key on the stack beside the signature: what the
    output commits to is its hash160, so the script is given the key and
    hashes it itself. Reading only .values(), as a multisig finalizer
    can, leaves the key nowhere.

    A single-key input carrying more than one signature is refused
    rather than picked from: the output commits to one key, so a second
    signature is a signature for some other output.
    """
    if len(psbt_in.partial_sigs) > 1:
        err_msg = f"{len(psbt_in.partial_sigs)} signatures for a single-key input"
        raise BTClibValueError(err_msg)
    return next(iter(psbt_in.partial_sigs))


def _satisfied_script(psbt_in: PsbtIn) -> bytes:
    """Return the script the input's signatures are pushed for, or b"".

    The witness script where the multisig is wrapped in a p2wsh,
    `_spent_script` naming the p2wsh there rather than what it commits
    to; and `_spent_script` itself for a bare multisig and for a legacy
    p2sh, whose redeem script that already is.

    Two questions read it -- how many elements the spend pushes, and in
    which order -- and both are the script's to answer, so it is found
    in one place.
    """
    return psbt_in.witness_script or _spent_script(psbt_in)


def _bip147_dummy(psbt_in: PsbtIn) -> list[bytes]:
    """Return the empty push OP_CHECKMULTISIG pops, or nothing.

    OP_CHECKMULTISIG pops one element more than it reads, whatever the
    threshold, and BIP147 is the rule that the extra element be empty
    rather than the rule that it be there:

        https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation

    So what decides the push is the kind of the script, not how many
    signatures satisfy it. Counting them agrees everywhere but a 1-of-n,
    where one signature is a full satisfaction and the element is popped
    all the same, and on a p2pk carrying two signatures, which is caller
    error and gets a dummy on top of it (issue #305).

    `_satisfied_script` is the script to read, and says why it is that
    one.

    The count survives as the fallback for an input that says nothing.
    A bare multisig needs no script of its own to be finalized, so it
    reaches here with a utxo missing the way `_assert_partial_sigs_verify`
    lets an unverifiable signature through -- and the count is then the
    only evidence there is. A bare 1-of-n without a utxo therefore stays
    an element short, unknowably: one signature, no script, and nothing
    to tell it from a p2pk.
    """
    script = _satisfied_script(psbt_in)
    if script:
        return [b""] if is_p2ms(script) else []
    return [b""] if len(psbt_in.partial_sigs) > 1 else []


def _pushed_sigs(psbt_in: PsbtIn) -> list[bytes]:
    """Return the signatures the spend pushes, in the order it needs them.

    A multisig input pushes the signatures of the keys its script lists,
    in the order the script lists them, and as many as the script asks
    for. Both halves matter to OP_CHECKMULTISIG: it walks the keys
    forward and never goes back, so a signature out of that order is one
    it cannot match; and it pops one element beyond the threshold, which
    BIP147 requires to be empty, so an extra signature is one that lands
    where the dummy belongs (issue #431).

    Nothing about `partial_sigs` gives that order. A dict holds what it
    was given in the order it was given, and `combine` merges with an
    update, so for a coordinator it is the order the copies came back
    in.

    A signature whose key the script does not list is dropped rather
    than refused: the Finalizer builds the spend this script asks for,
    and a key that is not in it is not evidence of anything wrong.
    Fewer than the threshold is refused, being an input that cannot be
    finalized at all.

    Every other kind pushes what the input carries, which for the
    single-key ones is the one signature `_single_key` pairs with its
    key, and for a p2pk the one the script already names.
    """
    script = _satisfied_script(psbt_in)
    if not is_p2ms(script):
        return list(psbt_in.partial_sigs.values())

    m, pub_keys = p2ms_m_and_keys(script)
    sigs = [
        psbt_in.partial_sigs[pub_key]
        for pub_key in pub_keys
        if pub_key in psbt_in.partial_sigs
    ]
    if len(sigs) < m:
        err_msg = f"{len(sigs)} signatures for a {m}-of-{len(pub_keys)} multisig"
        raise BTClibValueError(err_msg)
    return sigs[:m]


def _finalized_input(psbt_in: PsbtIn) -> tuple[bytes, Witness]:
    """Return the final script_sig and witness the input is spent with.

    Four shapes, and the kind of the spent script picks between them:

    - p2wsh, native or wrapped: the witness carries the signatures and
      the witness script, the script_sig only the redeem script of a
      wrapped one;
    - p2wpkh, native or wrapped: the witness is [signature, public key],
      the script_sig again only the redeem script;
    - p2pkh: [signature, public key] in the script_sig;
    - everything else -- p2pk, bare multisig, legacy p2sh: the
      signatures in the script_sig, and the redeem script last.

    A native segwit input gets the empty script_sig BIP141 requires, and
    that is what the *absence* of a redeem script buys here: pushing an
    empty one would write a one-byte script_sig of OP_0, which btclib's
    own engine refuses as "non-empty script_sig for a native segwit
    input" (issue #249).
    """
    sigs: list[bytes] = _pushed_sigs(psbt_in)
    cmds: list[bytes] = _bip147_dummy(psbt_in) + sigs
    redeem_script: list[bytes] = (
        [psbt_in.redeem_script] if psbt_in.redeem_script else []
    )

    script = _spent_script(psbt_in)

    # a list of pushes is a ScriptList, which mypy will not infer from a
    # list[bytes]: ScriptList is list[Command] and a list is invariant
    if psbt_in.witness_script:
        witness = Witness([*cmds, psbt_in.witness_script])
        return serialize(cast(ScriptList, redeem_script)), witness

    if is_p2wpkh(script):
        witness = Witness([*sigs, _single_key(psbt_in)])
        return serialize(cast(ScriptList, redeem_script)), witness

    if is_p2pkh(script):
        script_sig = cast(ScriptList, [*sigs, _single_key(psbt_in)])
        return serialize(script_sig), Witness()

    return serialize(cast(ScriptList, [*cmds, *redeem_script])), Witness()


# the codesep position BIP341 writes when no OP_CODESEPARATOR was
# executed, which is every script Core's own signer supports signing:
# "Only support non-OP_CODESEPARATOR BIP342 signing for now"
_NO_CODESEP = 0xFFFFFFFF

# a tapscript spending a single key: a 32-byte push of it followed by
# OP_CHECKSIG, which is the leaf shape whose witness is one signature and
# therefore the only script path a Finalizer here can build
_SINGLE_KEY_LEAF_SIZE = 34
_PUSH_32 = 0x20
_OP_CHECKSIG = 0xAC


def prevouts(psbt: Psbt) -> list[TxOut]:
    """Return the output each input of the psbt spends.

    A taproot signature commits to the amount and script of *every*
    input (BIP341's sha_amounts and sha_scriptpubkeys), not only of the
    one being signed, so a single missing utxo leaves the whole
    transaction unsignable rather than one input of it -- which is why
    this raises where `_prev_out` answers None.
    """
    outs: list[TxOut] = []
    for i, psbt_in in enumerate(psbt.inputs):
        prev_out = _prev_out(psbt_in)
        if prev_out is None:
            err_msg = f"no utxo for input {i}: a taproot signature commits "
            err_msg += "to the amount and script of every input"
            raise BTClibValueError(err_msg)
        outs.append(prev_out)
    return outs


def taproot_sig_hash(
    psbt: Psbt, vin_i: int, *, leaf_hash: Octets = b"", hash_type: int | None = None
) -> bytes:
    """Return the hash a taproot spend of one input signs.

    BIP341 for a key path spend, BIP342 for a script path one, and the
    tapleaf hash is what tells the two apart: given one, the message
    carries it along with the key version and the codesep position, as
    the script engine's own OP_CHECKSIG builds them.

    hash_type defaults to the type the input asks for, and to
    SIGHASH_DEFAULT when it asks for none. Passing it is what a Finalizer
    does: a taproot signature carries its own type appended, so the hash
    to check it against is the one *it* committed to.

    The annex is empty: BIP341 leaves it undefined, no psbt field carries
    one, and a signer cannot invent what the spender will put on the
    stack.
    """
    leaf_hash = bytes_from_octets(leaf_hash)
    if hash_type is None:
        hash_type = psbt.inputs[vin_i].sig_hash_type or DEFAULT
    ext = leaf_hash + b"\x00" + _NO_CODESEP.to_bytes(4, "little") if leaf_hash else b""
    return sig_hash.taproot(
        psbt.tx, vin_i, prevouts(psbt), hash_type, int(bool(ext)), b"", ext
    )


def leaf_script(psbt_in: PsbtIn, leaf_hash: Octets) -> tuple[bytes, bytes]:
    """Return the leaf script of a tapleaf hash, and its control block.

    `PSBT_IN_TAP_LEAF_SCRIPT` is keyed by control block and holds the
    script and its leaf version, while every other taproot field names a
    leaf by its BIP341 hash: this is that lookup, and it computes the
    hashes rather than trusting a second index of them.
    """
    leaf_hash = bytes_from_octets(leaf_hash, LEAF_HASH_SIZE)
    for control_block, (script, leaf_version) in psbt_in.taproot_leaf_scripts.items():
        if taproot.leaf_hash(leaf_version, script) == leaf_hash:
            return script, control_block
    raise BTClibValueError(f"no leaf script for tapleaf hash {leaf_hash.hex()}")


def single_leaf_key(script: bytes) -> bytes:
    """Return the key of a `<32-byte key> OP_CHECKSIG` leaf script.

    What a Finalizer has to know to build the witness of a script path
    spend is what the leaf script pops, and that is a property of the
    script rather than of the psbt: one signature for this shape, and for
    a leaf that asks for more -- a threshold of CHECKSIGADD, a hash
    preimage -- the psbt says nothing about what else goes on the stack.
    """
    if (
        len(script) != _SINGLE_KEY_LEAF_SIZE
        or script[0] != _PUSH_32
        or script[-1] != _OP_CHECKSIG
    ):
        err_msg = "cannot finalize a taproot script path whose leaf script "
        err_msg += f"is not a single key and OP_CHECKSIG: {script.hex()}"
        raise BTClibValueError(err_msg)
    return script[1:-1]


def _assert_taproot_sig_hash_type(signature: bytes, psbt_in: PsbtIn, what: str) -> int:
    """Return the sig_hash type a taproot signature commits to.

    BIP341 appends the type to the 64 bytes when it is not the default
    one, so the signature says which hash it signed; what this adds is
    that it must be the type the *input* asks for, as
    `_assert_sig_hash_type` asks of a partial signature. A Finalizer that
    skipped the comparison would happily build a witness whose signature
    commits to other outputs than the ones the psbt was built for.
    """
    hash_type = signature[-1] if len(signature) == 65 else DEFAULT
    if (psbt_in.sig_hash_type or DEFAULT) != hash_type:
        err_msg = f"invalid {what} sig_hash type: {hash_type}, "
        err_msg += f"the input asks for {psbt_in.sig_hash_type}"
        raise BTClibValueError(err_msg)
    return hash_type


def _finalized_taproot_input(psbt: Psbt, vin_i: int) -> tuple[bytes, Witness]:
    """Return the script_sig and witness a taproot input is spent with.

    An empty script_sig, always: BIP341 spends a witness v1 program with
    the witness alone, and a p2sh-wrapped one is unspendable by
    consensus.

    The key path is preferred when the input carries both, as Bitcoin
    Core's finalizer prefers it: it is the cheaper spend and the one the
    output key commits to directly. The script path witness is the
    signature, the leaf script and its control block, which is BIP341's
    order and needs the leaf to be a single-key one.

    Each signature is verified against the hash it says it committed to,
    for the reason the legacy path verifies its own: a Finalizer is the
    last role that can still refuse, and a witness built from a bad
    signature is a transaction the network drops.
    """
    psbt_in = psbt.inputs[vin_i]

    if psbt_in.taproot_key_spend_signature:
        signature = psbt_in.taproot_key_spend_signature
        hash_type = _assert_taproot_sig_hash_type(
            signature, psbt_in, "taproot key path signature"
        )
        msg = taproot_sig_hash(psbt, vin_i, hash_type=hash_type)
        output_key = type_and_payload(prevouts(psbt)[vin_i].script_pub_key.script)[1]
        if not ssa.verify_(msg, output_key, signature[:64]):
            err_msg = "invalid taproot key path signature for output key "
            err_msg += output_key.hex()
            raise BTClibValueError(err_msg)
        return b"", Witness([signature])

    if not psbt_in.taproot_script_spend_signatures:
        raise BTClibValueError("missing taproot signature")

    if len(psbt_in.taproot_script_spend_signatures) > 1:
        # which leaf to spend is a choice, and one the psbt does not
        # record: two signatures under two leaves are two spends, both
        # valid, and picking either would be this function deciding what
        # the transaction costs
        err_msg = f"{len(psbt_in.taproot_script_spend_signatures)} taproot script "
        err_msg += "path signatures: the psbt does not say which leaf to spend"
        raise BTClibValueError(err_msg)

    key_data, signature = next(iter(psbt_in.taproot_script_spend_signatures.items()))
    pub_key, leaf_hash = key_data[:LEAF_HASH_SIZE], key_data[LEAF_HASH_SIZE:]
    hash_type = _assert_taproot_sig_hash_type(
        signature, psbt_in, "taproot script path signature"
    )
    script, control_block = leaf_script(psbt_in, leaf_hash)
    if single_leaf_key(script) != pub_key:
        err_msg = f"taproot script path signature of {pub_key.hex()}, which is "
        err_msg += f"not the key of leaf script {script.hex()}"
        raise BTClibValueError(err_msg)
    msg = taproot_sig_hash(psbt, vin_i, leaf_hash=leaf_hash, hash_type=hash_type)
    if not ssa.verify_(msg, pub_key, signature[:64]):
        err_msg = f"invalid taproot script path signature for key {pub_key.hex()}"
        raise BTClibValueError(err_msg)
    return b"", Witness([signature, script, control_block])


def _witness_v0_script_code(psbt_in: PsbtIn, script: bytes) -> bytes:
    """Return the script code BIP143 signs the segwit v0 input against.

    For p2wsh it is the witness script, which the input carries; for
    p2wpkh it is the p2pkh script for the same hash160, which is in no
    transaction and is built here. b"" is "the input does not say", i.e.
    a p2wsh input with no witness script.
    """
    if is_p2wpkh(script):
        _, payload = type_and_payload(script)
        return serialize(
            ["OP_DUP", "OP_HASH160", payload, "OP_EQUALVERIFY", "OP_CHECKSIG"]
        )
    return psbt_in.witness_script


def _sig_hash_from_psbt_in(
    psbt_in: PsbtIn, tx: Tx, vin_i: int, hash_type: int
) -> bytes | None:
    """Return the hash the input's partial signatures commit to, or None.

    Covered is every kind of input a PSBT_IN_PARTIAL_SIG can belong to:
    the legacy ones (p2pk, p2pkh, bare multisig), p2sh, p2wpkh, p2wsh,
    and either witness kind wrapped in p2sh -- wrapped ones because what
    the wrapper commits to is the redeem script, which is what the
    dispatch below looks at once it has unwrapped it.

    None is "this input does not say what is being signed", which is not
    the same as "the signature is wrong": there is no utxo, or a p2sh
    input carries no redeem script, or a p2wsh one no witness script. A
    taproot input is None too, and for good: its signatures are schnorr
    and travel in the taproot fields, so a partial signature beside a
    p2tr script_pub_key is not a signature this hash would check.

    A non-witness spend described by a witness utxo alone is the case
    that raises instead, being neither of those: the input says what is
    signed and says it on no authority. `PSBT_IN_WITNESS_UTXO` "should
    only be present for inputs which spend segwit outputs, including P2SH
    embedded ones", and nothing ties one to the outpoint it claims to be
    -- BIP174's Signer checks `sha256d(non_witness_utxo)` against that
    outpoint and has no such line to write for the other field, so its
    own algorithm signs from a witness utxo only where the script is
    p2wpkh or p2wsh. Bitcoin Core's `SignPSBTInput` says it as
    `require_witness_sig`, and refuses the input when the signature it
    produced is not a witness one. A legacy sig_hash taken from those
    bytes commits to a script_pub_key nobody vouched for, so the answer
    is an error rather than a hash, and rather than the None that would
    have the Finalizer skip the very signature it is checking.

    sig_hash.from_tx is the same dispatch for a *signed* transaction, and
    cannot serve here: it reads the redeem script out of the input's
    script_sig and the witness script off its witness stack, and a psbt's
    unsigned transaction has neither -- they are the psbt's own fields,
    which is the whole point of the format.
    """
    prev_out = _prev_out(psbt_in)
    if prev_out is None:
        return None

    script = prev_out.script_pub_key.script
    if is_p2sh(script):
        script = psbt_in.redeem_script

    if is_p2wpkh(script) or is_p2wsh(script):
        script_code = _witness_v0_script_code(psbt_in, script)
        if not script_code:
            return None
        return sig_hash.segwit_v0(script_code, tx, vin_i, hash_type, prev_out.value)

    if not script or is_p2tr(script):
        return None
    if psbt_in.non_witness_utxo is None:
        err_msg = f"input {vin_i}: a witness utxo alone does not say what a "
        err_msg += "non-witness spend signs"
        raise BTClibValueError(err_msg)
    return sig_hash.legacy(script, tx, vin_i, hash_type)


def ecdsa_sig_hash(psbt: Psbt, vin_i: int, *, hash_type: int | None = None) -> bytes:
    """Return the hash an ECDSA spend of one input signs.

    What a Signer puts in `PSBT_IN_PARTIAL_SIG` is a signature of this,
    with the hash type appended; `taproot_sig_hash` is the same question
    for the schnorr signatures of a taproot input, and the two are the
    split `finalize` dispatches on.

    hash_type defaults to the type the input asks for, and to
    SIGHASH_ALL when it asks for none. An input asking for
    SIGHASH_DEFAULT is refused: 0 is a taproot type, no ECDSA signature
    carries it, and a psbt asking for it is one no partial signature can
    finalize -- which is what `_assert_sig_hash_type` says from the
    Finalizer's end.

    Every kind a partial signature can belong to is covered, the wrapped
    ones included: `_sig_hash_from_psbt_in` is the dispatch and says how.
    Where it answers None this raises, and the difference is the caller:
    a Finalizer checking a signature it was handed learns nothing from a
    psbt that does not say what was signed, while a Signer about to make
    one has to stop. Where it raises -- a non-witness spend described by
    a witness utxo alone -- every caller stops, that being an input no
    role may sign, verify or finalize.
    """
    psbt_in = psbt.inputs[vin_i]
    if hash_type is None:
        hash_type = ALL if psbt_in.sig_hash_type is None else psbt_in.sig_hash_type
    assert_valid_hash_type(hash_type)
    if hash_type == DEFAULT:
        raise BTClibValueError("SIGHASH_DEFAULT is not an ECDSA sig_hash type")

    if is_p2tr(_spent_script(psbt_in)):
        err_msg = f"input {vin_i} is taproot: its message is taproot_sig_hash's"
        raise BTClibValueError(err_msg)

    msg_hash = _sig_hash_from_psbt_in(psbt_in, psbt.tx, vin_i, hash_type)
    if msg_hash is None:
        err_msg = f"input {vin_i} does not say what is being signed: "
        err_msg += "no utxo, no redeem script, or no witness script"
        raise BTClibValueError(err_msg)
    return msg_hash


class KeyManager(Protocol):
    """A signature over a hash, by public key or origin: what `sign` asks.

    `sign` has no key of its own; a KeyManager is where the keys are, and
    each method answers what `sign` cannot -- is this key one you hold,
    and if so, what does it sign msg_hash with. None answers "not mine"
    rather than raising, which is what lets one signer of an m-of-n
    answer for its own key alone: an input none of its keys can answer
    for is somebody else's turn, not an error.

    Both pub_key and origin travel on every call, in the order a psbt
    itself gives them precedence: a key match is a fact, an origin only
    a claim about a four-byte fingerprint, which collides. The claim is
    what a watch-only-shaped manager -- one xprv, many children it has
    never derived -- needs to answer at all, having no way to recognize
    a child key it has not yet computed.

    What comes back is the bare signature -- DER for ECDSA, 64 bytes
    r||s for schnorr -- with no sig_hash type appended. `sign` appends
    it, being the one that fixed the hash and therefore the type the
    signature answers for; the secret stays inside the manager, which is
    what lets a hardware backend implement this same contract without
    `sign` ever holding what signs for it.
    """

    def sign_ecdsa(
        self, pub_key: bytes, origin: BIP32KeyOrigin | None, msg_hash: bytes
    ) -> bytes | None:
        """Return the DER signature of msg_hash by pub_key, or None."""
        ...

    def sign_schnorr(
        self,
        pub_key: bytes,
        origin: BIP32KeyOrigin | None,
        msg_hash: bytes,
        merkle_root: bytes,
    ) -> bytes | None:
        """Return the BIP340 signature of msg_hash by pub_key, or None.

        pub_key is the taproot internal key, x-only and untweaked, and
        the signature has to be the tweaked output key's: merkle_root is
        `PSBT_IN_TAP_MERKLE_ROOT`, empty for a key-path-only output, and
        tweaking by it is the manager's to do, `sign` never holding what
        tweaking a private key needs.
        """
        ...


def _sign_ecdsa_input(psbt: Psbt, vin_i: int, key_manager: KeyManager) -> bool:
    """Write every partial signature key_manager gives for one input.

    hd_key_paths is the candidate list: what a psbt names for an ECDSA
    spend is a public key, never an address, and usually an origin
    beside it. A key already in partial_sigs is left alone rather than
    asked for again, and the message is computed at most once and only
    once there is a candidate to ask for it -- an input key_manager
    holds nothing for never reaches `ecdsa_sig_hash` to be refused for a
    reason that is not key_manager's.
    """
    psbt_in = psbt.inputs[vin_i]
    hash_type = ALL if psbt_in.sig_hash_type is None else psbt_in.sig_hash_type
    msg_hash: bytes | None = None
    signed = False
    for pub_key, origin in psbt_in.hd_key_paths.items():
        if pub_key in psbt_in.partial_sigs:
            continue
        if msg_hash is None:
            msg_hash = ecdsa_sig_hash(psbt, vin_i, hash_type=hash_type)
        sig = key_manager.sign_ecdsa(pub_key, origin, msg_hash)
        if sig is None:
            continue
        psbt_in.partial_sigs[pub_key] = sig + hash_type.to_bytes(1, "big")
        signed = True
    return signed


def _sign_taproot_key_path(psbt: Psbt, vin_i: int, key_manager: KeyManager) -> bool:
    """Write the taproot key path signature key_manager gives, if any.

    One candidate, the internal key, already signed or absent being the
    two reasons there is nothing to ask for. Its origin is whichever
    taproot_hd_key_paths entry is filed under it, and absent where the
    Updater wrote none -- BIP371 does not require one, and key_manager
    is left the pub_key alone to answer from.
    """
    psbt_in = psbt.inputs[vin_i]
    if not psbt_in.taproot_internal_key or psbt_in.taproot_key_spend_signature:
        return False
    origin = psbt_in.taproot_hd_key_paths.get(psbt_in.taproot_internal_key)
    msg_hash = taproot_sig_hash(psbt, vin_i)
    sig = key_manager.sign_schnorr(
        psbt_in.taproot_internal_key,
        origin[1] if origin else None,
        msg_hash,
        psbt_in.taproot_merkle_root,
    )
    if sig is None:
        return False
    hash_type = psbt_in.sig_hash_type or DEFAULT
    if hash_type:
        sig += hash_type.to_bytes(1, "big")
    psbt_in.taproot_key_spend_signature = sig
    return True


def sign(psbt: Psbt, key_manager: KeyManager) -> tuple[Psbt, list[int]]:
    """Run the Signer role over every input key_manager answers for.

    Per input the candidates are what the psbt itself names: hd_key_paths
    for an ECDSA spend, the taproot internal key and its own
    taproot_hd_key_paths entry for a taproot one. None from key_manager
    skips the key rather than raising -- one signer of an m-of-n holds
    one key, and an input it cannot answer for is not an error but
    somebody else's turn. What comes back besides the copy is which
    inputs got a new signature, since a caller collecting a quorum needs
    to tell "there was nothing for me" from "done".

    Taproot is limited to the key path: MuSig2's own Signer is
    `btclib.psbt.musig2`, and a script path spend needs a leaf and a
    control block `sign` does not choose between. Every other kind is
    whatever `_finalized_input` can close over -- p2pk, p2pkh, p2wpkh,
    p2sh-p2wpkh, p2wsh, bare and wrapped multisig.

    Raises where the psbt cannot be signed at all -- `assert_signable`'s
    question -- and where a candidate's own hash cannot be computed,
    which is `ecdsa_sig_hash` refusing to guess at a caller's stop. A key
    key_manager has nothing to say about is a different question and
    does not raise.
    """
    psbt = deepcopy(psbt)
    psbt.assert_signable()
    signed_vins: list[int] = []
    for vin_i, psbt_in in enumerate(psbt.inputs):
        if is_p2tr(_spent_script(psbt_in)):
            if _sign_taproot_key_path(psbt, vin_i, key_manager):
                signed_vins.append(vin_i)
            continue
        if _sign_ecdsa_input(psbt, vin_i, key_manager):
            signed_vins.append(vin_i)
    return psbt, signed_vins


# the input fields a signer's answer may add to, and the only ones:
# everything else it carries has to be what was sent. That is what makes
# `assert_signatures_only` a check on an answer rather than a merge of
# two opinions -- `combine` is the merge, and BIP174 lets it resolve a
# conflict by picking either side, which is the wrong instinct entirely
# when one side came from somebody else.
#
# The two musig2 maps are here because BIP373 puts a session's rounds in
# them: a public nonce in round 1 and a partial signature in round 2 are
# what that signer's answer *is*.
_SIGNATURE_FIELDS = frozenset(
    {
        "partial_sigs",
        "taproot_key_spend_signature",
        "taproot_script_spend_signatures",
        "musig2_pub_nonces",
        "musig2_partial_sigs",
    }
)


def _assert_unchanged(
    request_map: PsbtIn | PsbtOut, returned_map: PsbtIn | PsbtOut, what: str
) -> None:
    """Raise unless every field that is not a signature came back as sent.

    Walked with `dataclasses.fields` and not from a list of its own, so
    that a field added to `PsbtIn` or `PsbtOut` has to come back
    unchanged by default: the safe answer for a field nobody has thought
    about yet is that an external signer may not touch it.

    Equality and not "was not overwritten", which is what `combine`
    settles for: a signer that adds a `witness_utxo` the request did not
    carry, or a `redeem_script`, is playing Updater as well, and a caller
    who wants that has `combine` and no illusion that it was checked.
    That is also how the two decisions about `unknown` and the finalized
    scripts are kept -- neither is a signature, so both must be equal,
    and an answer that finalizes an input or adds a vendor field is
    refused here rather than merged.
    """
    for field in fields(request_map):
        if field.name in _SIGNATURE_FIELDS:
            continue
        if getattr(returned_map, field.name) != getattr(request_map, field.name):
            raise BTClibValueError(f"{what}: {field.name} was changed")


def _assert_signatures_added_only(
    request_in: PsbtIn, returned_in: PsbtIn, vin_i: int
) -> None:
    """Raise unless the signature fields only gained entries.

    A signature the request already carried must come back as it was, and
    dropping one is refused too: the answer is meant to be the request
    plus what this signer had to add, and `combine` would put a dropped
    signature back without anybody noticing that it had been taken out.
    """
    for name in sorted(_SIGNATURE_FIELDS):
        was, now = getattr(request_in, name), getattr(returned_in, name)
        if isinstance(was, dict):
            for key, value in was.items():
                if key not in now:
                    err_msg = f"input {vin_i}: {name} of {key.hex()} was dropped"
                    raise BTClibValueError(err_msg)
                if now[key] != value:
                    err_msg = f"input {vin_i}: {name} of {key.hex()} was changed"
                    raise BTClibValueError(err_msg)
        elif was and now != was:
            raise BTClibValueError(f"input {vin_i}: {name} was changed")


def _assert_new_ecdsa_sigs_verify(
    request_in: PsbtIn, returned_in: PsbtIn, tx: Tx, vin_i: int
) -> None:
    """Raise unless each partial signature that arrived verifies.

    Where `_assert_partial_sigs_verify` leaves an unverifiable signature
    alone, this refuses it, and the difference is who is asking: the
    Finalizer learns nothing about a signature from a psbt that does not
    say what was signed, while here a signature that cannot be checked is
    the one thing that must not be merged.

    lower_s=False for the Finalizer's reason: the question is whether that
    key made that signature, the low-s rule being policy the script engine
    applies under its flags.
    """
    for pub_key, sig in returned_in.partial_sigs.items():
        if pub_key in request_in.partial_sigs:
            continue
        msg_hash = _sig_hash_from_psbt_in(returned_in, tx, vin_i, sig[-1])
        if msg_hash is None:
            err_msg = f"input {vin_i}: cannot verify the signature of "
            err_msg += f"{pub_key.hex()}, the psbt does not say what was signed"
            raise BTClibValueError(err_msg)
        if not dsa.verify_(msg_hash, pub_key, sig[:-1], lower_s=False):
            err_msg = f"input {vin_i}: invalid signature for pub_key {pub_key.hex()}"
            raise BTClibValueError(err_msg)


def _assert_new_taproot_sigs_verify(request: Psbt, returned: Psbt, vin_i: int) -> None:
    """Raise unless each taproot signature that arrived verifies.

    The Finalizer's own checks, asked one role earlier: a key path
    signature against the output key being spent, a script path one
    against the key its tapleaf hash names. The sig_hash type each
    commits to has to be the type the input asks for, which is what
    `_assert_taproot_sig_hash_type` answers and what decides the message.

    A taproot signature beside an input that does not spend a taproot
    output is refused rather than verified: there is no output key to
    check it against, and an answer carrying one is describing some other
    input.
    """
    request_in, returned_in = request.inputs[vin_i], returned.inputs[vin_i]
    new_key_sig = returned_in.taproot_key_spend_signature and (
        not request_in.taproot_key_spend_signature
    )
    new_script_sigs = {
        key_data: sig
        for key_data, sig in returned_in.taproot_script_spend_signatures.items()
        if key_data not in request_in.taproot_script_spend_signatures
    }
    if not new_key_sig and not new_script_sigs:
        return

    script = _spent_script(returned_in)
    if not is_p2tr(script):
        err_msg = f"input {vin_i}: a taproot signature for an input spending "
        err_msg += "no taproot output"
        raise BTClibValueError(err_msg)

    if new_key_sig:
        sig = returned_in.taproot_key_spend_signature
        hash_type = _assert_taproot_sig_hash_type(
            sig, returned_in, "taproot key path signature"
        )
        msg = taproot_sig_hash(returned, vin_i, hash_type=hash_type)
        output_key = type_and_payload(script)[1]
        if not ssa.verify_(msg, output_key, sig[:64]):
            err_msg = f"input {vin_i}: invalid taproot key path signature for "
            err_msg += f"output key {output_key.hex()}"
            raise BTClibValueError(err_msg)

    for key_data, sig in new_script_sigs.items():
        pub_key, leaf_hash = key_data[:LEAF_HASH_SIZE], key_data[LEAF_HASH_SIZE:]
        hash_type = _assert_taproot_sig_hash_type(
            sig, returned_in, "taproot script path signature"
        )
        msg = taproot_sig_hash(
            returned, vin_i, leaf_hash=leaf_hash, hash_type=hash_type
        )
        if not ssa.verify_(msg, pub_key, sig[:64]):
            err_msg = f"input {vin_i}: invalid taproot script path signature for "
            err_msg += f"key {pub_key.hex()}"
            raise BTClibValueError(err_msg)


def assert_signatures_only(request: Psbt, returned: Psbt) -> None:
    """Raise unless `returned` is `request` with signatures added, and no more.

    What a caller has to know before merging an answer from somebody
    else -- an external signer, a hardware device, a cosigner -- because
    `combine` will not tell them: BIP174's Combiner takes the union of
    what it is given and may resolve a conflict by picking either side,
    so it compares only the psbt's identifier and merges the rest. Which
    leaves three ways for an answer to change what was sent: adding a
    field the request left empty, overwriting one entry of a field that
    is a map, and -- in a version 2 psbt, whose identifier zeroes every
    sequence -- changing a sequence.

    The rule here is one sentence. Everything that is not a signature
    comes back as it was sent; the signature fields may only gain
    entries; every signature that arrived is verified before anything is
    merged. `_SIGNATURE_FIELDS` is the second clause, `_assert_unchanged`
    the first, and both walk the fields a map declares rather than a list
    kept beside them.

    The transaction being signed is compared whole, `Psbt.tx` being
    computed from the fields of either version: that is what catches the
    changed sequence of a version 2 psbt, which `unique_id` cannot see,
    and it makes the input and output counts equal without a check of
    their own.

    `tx_modifiable` is the one field an answer may legitimately change,
    a Signer clearing a bit when it adds a signature that a change would
    break. What it may not do is loosen one, and the rule for that is
    `_combined_tx_modifiable`'s already: an answer no more permissive
    than the request is one the two combine into unchanged.

    The two musig2 maps are permitted additions and are not verified
    here. A BIP327 partial signature is checked against the session's
    aggregate nonce, which needs every participant's nonce, and a psbt
    mid-session need not carry them yet; `musig2.partial_sigs_agg`
    refuses an aggregate that does not verify, which is the check that
    can be made once the session is complete.
    """
    returned.assert_valid()

    if returned.version != request.version:
        err_msg = f"mismatched psbt version: {returned.version} vs {request.version}"
        raise BTClibValueError(err_msg)
    if returned.tx != request.tx:
        raise BTClibValueError("the transaction being signed was changed")
    if returned.fallback_lock_time != request.fallback_lock_time:
        raise BTClibValueError("fallback_lock_time was changed")
    if returned.hd_key_paths != request.hd_key_paths:
        raise BTClibValueError("the global hd_key_paths were changed")
    if returned.unknown != request.unknown:
        raise BTClibValueError("the global unknown fields were changed")
    if _combined_tx_modifiable([request, returned]) != returned.tx_modifiable:
        raise BTClibValueError("tx_modifiable is more permissive than the request's")

    # read once, as `finalize` reads it once: every signature of every
    # input is against the same transaction
    tx = returned.tx
    for vin_i, (request_in, returned_in) in enumerate(
        zip(request.inputs, returned.inputs, strict=True)
    ):
        _assert_unchanged(request_in, returned_in, f"input {vin_i}")
        _assert_signatures_added_only(request_in, returned_in, vin_i)
        _assert_sig_hash_type(returned_in)
        _assert_new_ecdsa_sigs_verify(request_in, returned_in, tx, vin_i)
        _assert_new_taproot_sigs_verify(request, returned, vin_i)

    for vout_i, (request_out, returned_out) in enumerate(
        zip(request.outputs, returned.outputs, strict=True)
    ):
        _assert_unchanged(request_out, returned_out, f"output {vout_i}")


def _assert_sig_hash_type(psbt_in: PsbtIn) -> None:
    """Raise unless each signature commits to the type the input asks for.

    BIP174 on the Input Finalizer: "If the input has a
    PSBT_IN_SIGHASH_TYPE field, the Input Finalizer must fail to finalize
    that input if any signature does not match the specified sighash
    type". Without the check a psbt finalizes into a transaction whose
    signatures commit to something other than the input asked for -- and
    the input is what the other participants agreed to.

    The type a signature commits to is the byte appended to its DER
    encoding, which is where the script engine reads it too.

    Presence is `is not None` rather than truthiness: 0 is
    SIGHASH_DEFAULT, which an input may ask for and no ECDSA signature
    carries, so an input asking for it is exactly an input no partial
    signature can finalize.
    """
    if psbt_in.sig_hash_type is None:
        return
    for sig in psbt_in.partial_sigs.values():
        if sig[-1] != psbt_in.sig_hash_type:
            err_msg = "mismatched sig_hash type: "
            err_msg += f"{hex(sig[-1])} vs {hex(psbt_in.sig_hash_type)}"
            raise BTClibValueError(err_msg)


def _assert_partial_sigs_verify(psbt_in: PsbtIn, tx: Tx, vin_i: int) -> None:
    """Raise unless each partial signature verifies against its own key.

    The Finalizer is where the check belongs, and PsbtIn.assert_valid is
    not: a signature commits to the whole transaction, which a per-field
    validator does not have, while the role BIP174 charges with deciding
    "if the input has enough data to pass validation" holds it.

    An input whose sig_hash is not computable is left alone rather than
    refused: what is missing there is the utxo or a script, which is not
    evidence against the signature. A non-witness spend carrying a
    witness utxo alone is the exception, and raises out of
    `_sig_hash_from_psbt_in`: there the input does say what was signed,
    on bytes nothing vouches for, so skipping the check would finalize
    exactly the input whose signature cannot be believed.

    lower_s=False because the question here is whether that key made that
    signature: the low-s rule is policy, applied by the script engine
    under its flags, and Bitcoin Core's CPubKey::Verify normalizes s
    before verifying for this very reason.
    """
    # the hash is the input's and the hash type's, never the key's, so an
    # n-of-m input whose signatures agree on the type -- which is the
    # ordinary case, they are signing one thing -- serializes the
    # transaction once instead of n times. None is a value worth caching
    # too, so membership and not truthiness says whether it is computed
    sig_hashes: dict[int, bytes | None] = {}
    for pub_key, sig in psbt_in.partial_sigs.items():
        hash_type = sig[-1]
        if hash_type not in sig_hashes:
            sig_hashes[hash_type] = _sig_hash_from_psbt_in(
                psbt_in, tx, vin_i, hash_type
            )
        msg_hash = sig_hashes[hash_type]
        if msg_hash is None:
            continue
        if not dsa.verify_(msg_hash, pub_key, sig[:-1], lower_s=False):
            err_msg = f"invalid partial signature for pub_key {pub_key.hex()}"
            raise BTClibValueError(err_msg)


# what a finalized input keeps, BIP174's rule being that everything else
# goes: "All other data except the UTXO and unknown fields in the input
# key-value map should be cleared from the PSBT". Three groups, and the
# BIP names only the first two --
#
# - the utxo and `unknown`, exempted by that sentence: the utxo so that
#   "Transaction Extractors [can] verify the final network serialized
#   transaction", and the unknown fields because no reader here knows
#   what dropping one would cost;
# - the two finalized scripts, which are what finalizing produced;
# - BIP370's transaction fields, which are not "data" about how the input
#   is spent but the input *itself*: clearing `previous_tx_id` and
#   `output_index` would leave a version 2 psbt naming no outpoint, and
#   the sequence and the two required lock times are what its unsigned
#   transaction is computed from.
#
# A keep list and not a clear list, so that a field added to PsbtIn is
# cleared by default: BIP174's sentence is about everything, and a new
# field that has to survive finalization is the exception worth writing
# down here.
_FINALIZED_KEEPS = frozenset(
    {
        "non_witness_utxo",
        "witness_utxo",
        "unknown",
        "final_script_sig",
        "final_script_witness",
        "previous_tx_id",
        "output_index",
        "sequence",
        "required_time_lock_time",
        "required_height_lock_time",
    }
)


def _clear_finalized(psbt_in: PsbtIn) -> None:
    """Drop everything finalizing the input made redundant.

    One rule for both kinds of input, which is the point of it being one
    function: a taproot input cleared nothing at all, so a finalized psbt
    went on publishing that input's key origins -- master fingerprint and
    derivation path, per key -- where an ECDSA input published none. The
    asymmetry was not a wrong spend, the witness being built already, but
    no reader could state what the rule was.

    Each field is set to what a fresh `PsbtIn` has, rather than to a
    literal per field: the empty value of a field is the constructor's
    business, and spelling it twice is how the two drift.

    btclib is stricter than Bitcoin Core here, whose
    `PSBTInput::FromSignatureData` clears `partial_sigs`, `hd_keypaths`,
    `redeem_script` and `witness_script` and leaves the taproot fields,
    the sighash type and the preimages in place. BIP174's sentence covers
    those too, and what they buy after finalization is nothing: the
    preimage a hash-locked script needs is in the witness by then.
    """
    empty = PsbtIn(check_validity=False)
    for field in fields(psbt_in):
        if field.name not in _FINALIZED_KEEPS:
            setattr(psbt_in, field.name, getattr(empty, field.name))


def finalize(psbt: Psbt) -> Psbt:
    """Finalize the Psbt.

    The Input Finalizer must only accept a PSBT.

    For each input, the Input Finalizer determines if the input has
    enough data to pass validation. If it does, it must construct the
    0x07 Finalized scriptSig and 0x08 Finalized scriptWitness and place
    them into the input key-value map.

    All other data except the UTXO and unknown fields in the input key-
    value map should be cleared from the PSBT. The UTXO should be kept
    to allow Transaction Extractors to verify the final network
    serialized transaction. `_FINALIZED_KEEPS` is that list, and one list
    for both kinds of input is what keeps the two from drifting apart.

    Deciding that an input has enough data is two checks beyond the
    presence of a signature, and both are per input: the sighash type
    each signature commits to is the one the input asks for, and each
    signature verifies against the key it is filed under.

    What is then built is the spend the input's own kind asks for, which
    is what _finalized_input dispatches on: a witness script alone does
    not say, being absent from every single-key segwit input.

    An input that is already finalized is left alone rather than refused,
    so finalizing twice is finalizing once. "The Input Finalizer
    determines if the input has enough data" and one carrying its final
    scripts has more than enough; Bitcoin Core's `SignPSBTInput` skips it
    too. Refusing it would mean a psbt whose signer finalized one input
    could not be finalized at all -- the rest of it would raise "missing
    signatures" for the input that is already done.
    """
    psbt = deepcopy(psbt)
    psbt.assert_valid()
    # read once: the transaction is what the fields make, so asking the
    # psbt for it inside the loop would build it once per input, and
    # every signature is against the same one
    tx = psbt.tx
    for vin_i, psbt_in in enumerate(psbt.inputs):
        if psbt_in.final_script_sig or psbt_in.final_script_witness:
            continue

        # a taproot input is finalized from its own fields and not from
        # partial_sigs, which is keyed by compressed key and holds ECDSA
        # signatures: a schnorr signature travels in PSBT_IN_TAP_KEY_SIG
        # or PSBT_IN_TAP_SCRIPT_SIG, and BIP373 is what writes the
        # aggregate signature of a MuSig2 session into them
        if is_p2tr(_spent_script(psbt_in)):
            script_sig, witness = _finalized_taproot_input(psbt, vin_i)
        else:
            if not psbt_in.partial_sigs:
                raise BTClibValueError("missing signatures")
            _assert_sig_hash_type(psbt_in)
            _assert_partial_sigs_verify(psbt_in, tx, vin_i)
            script_sig, witness = _finalized_input(psbt_in)

        _clear_finalized(psbt_in)
        psbt_in.final_script_sig = script_sig
        psbt_in.final_script_witness = witness
    return psbt


def extract_tx(psbt: Psbt, *, check_validity: bool = True) -> Tx:
    """Extract the Tx fro the Psbt.

    The Transaction Extractor must only accept a PSBT. It checks whether
    all inputs have complete scriptSigs and scriptWitnesses by checking
    for the presence of 0x07 Finalized scriptSig and 0x08 Finalized
    scriptWitness typed records.

    If they do, the Transaction Extractor should construct complete
    scriptSigs and scriptWitnesses and encode them into network
    serialized transactions. Otherwise the Extractor must not modify the
    PSBT.

    The Extractor should produce a fully valid, network serialized
    transaction if all inputs are complete.

    Extracting needs no script interpretation; an Extractor that can
    interpret scripts may also validate the transaction it extracts,
    as BIP174 allows.
    """
    if check_validity:
        psbt.assert_valid()

    # a copy, computed from the psbt's fields: the finalized scripts are
    # written into the transaction being extracted and not into the psbt,
    # which the Extractor "must not modify"
    tx = psbt.tx
    for tx_in, psbt_input in zip(tx.vin, psbt.inputs, strict=True):
        tx_in.script_sig = psbt_input.final_script_sig
        if psbt_input.final_script_witness:
            tx_in.script_witness = psbt_input.final_script_witness

    if check_validity:
        tx.assert_valid()
    return tx


_TypeA = TypeVar("_TypeA")


def _sort_or_shuffle(
    sequence: Sequence[_TypeA],
    ordering_func: Callable[[_TypeA], int] | None = None,
) -> list[_TypeA]:
    """Return the sequence sorted by ordering_func, or shuffled.

    One sequence only: an input's outpoint and sequence are fields of
    the input itself, so there is no second list to keep in step with
    the first.
    """
    items = list(sequence)
    if ordering_func is None:
        secrets.SystemRandom().shuffle(items)
    else:
        items.sort(key=ordering_func)
    return items


def _ensure_consistency(psbts: Sequence[Psbt]) -> None:
    """Check validity of each psbt and conflicts in key_paths or unknown."""
    key_paths: dict[bytes, BIP32KeyOrigin] = {}
    r_key_paths: dict[BIP32KeyOrigin, bytes] = {}
    unknown: dict[bytes, bytes] = {}
    for psbt in psbts:
        psbt.assert_valid()

        if any(
            pub_key in key_paths and key_origin != key_paths[pub_key]
            for pub_key, key_origin in psbt.hd_key_paths.items()
        ):
            raise BTClibValueError("hd_key_paths: same pub_key, different key_origin")
        key_paths.update(psbt.hd_key_paths)

        if any(
            key_origin in r_key_paths and pub_key != r_key_paths[key_origin]
            for pub_key, key_origin in psbt.hd_key_paths.items()
        ):
            raise BTClibValueError("hd_key_paths: same key_origin, different pub_key")
        r_key_paths.update(
            {key_origin: pub_key for pub_key, key_origin in psbt.hd_key_paths.items()}
        )

        if any(
            key in unknown and value != unknown[key]
            for key, value in psbt.unknown.items()
        ):
            raise BTClibValueError("unknown: same key, different value")
        unknown.update(psbt.unknown)


def join(
    psbts: Sequence[Psbt],
    enforce_same_tx_version: bool,
    enforce_same_tx_lock_time: bool,
    shuffle_inp: bool,
    shuffle_out: bool,
    sort_inp: Callable[[PsbtIn], int] | None = None,
    sort_out: Callable[[PsbtOut], int] | None = None,
) -> Psbt:
    """Join multiple psbts into a single one by merging inputs and outputs.

    inputs/outputs are shuffled by default. If shuffle_{in|out}=False,
    they are concatenated in the same order as psbts are
    specified. A specific ordering can be specified via sort_{inp|out},
    which overwrite shuffle when present.

    Outputs are concatenated and never merged, and there is no parameter
    asking for it: coalescing two outputs that pay the same script is a
    change to the output *set*, so every signature already made over the
    old one stops verifying -- and, after the shuffle or sort above, the
    result would depend on the order the merge ran in. A caller who wants
    one output where there were two builds it that way before signing,
    which is the only point at which it is safe.

    Joining is a Constructor adding inputs and outputs to each of the
    psbts at once, so a version 2 psbt has to allow both: every psbt
    joined is asked for its two modifiable flags, and the joined psbt
    carries what all of them still allow. The versions must be the same,
    for the reason `combine` gives.

    The joined psbt shares nothing with the ones joined, for the reason
    `combine` copies: the input and output maps below are taken from
    every psbt in the sequence, so without the copy the joined psbt's
    inputs *are* theirs, and an Updater filling one in afterwards fills
    in a psbt somebody else is still holding.
    """
    _ensure_consistency(psbts)
    psbts = deepcopy(list(psbts))

    version = psbts[0].version
    for psbt in psbts[1:]:
        if psbt.version != version:
            err_msg = f"mismatched psbt version: {psbt.version} vs {version}"
            raise BTClibValueError(err_msg)
    for psbt in psbts:
        _assert_modifiable(psbt, inputs=True)
        _assert_modifiable(psbt, inputs=False)

    inputs = [inp for psbt in psbts for inp in psbt.inputs]
    outputs = [outp for psbt in psbts for outp in psbt.outputs]
    hd_key_paths: dict[Octets, BIP32KeyOrigin] = {
        k: v for psbt in psbts for k, v in psbt.hd_key_paths.items()
    }
    unknown: dict[Octets, Octets] = {
        k: v for psbt in psbts for k, v in psbt.unknown.items()
    }

    tx_version = max(psbt.tx_version for psbt in psbts)
    if enforce_same_tx_version and any(psbt.tx_version != tx_version for psbt in psbts):
        raise BTClibValueError("Version numbers are not the same")

    # the lock time that is compared is the one the transaction will
    # have, which is what the signatures commit to; the fallback is
    # merely where a psbt with no input requiring one keeps it, so it is
    # the maximum of the fallbacks there are and absent when there are
    # none -- a psbt that never carried the field does not gain one
    lock_time = max(psbt.lock_time for psbt in psbts)
    if enforce_same_tx_lock_time and any(psbt.lock_time != lock_time for psbt in psbts):
        raise BTClibValueError("Lock times are not the same")
    fallbacks = [
        psbt.fallback_lock_time for psbt in psbts if psbt.fallback_lock_time is not None
    ]
    fallback_lock_time = max(fallbacks) if fallbacks else None

    # what tx.join refuses, asked of the outpoints themselves: one
    # transaction cannot spend one output twice, and the joined psbt
    # would be exactly that
    outpoints = {(inp.previous_tx_id, inp.output_index) for inp in inputs}
    if len(outpoints) != len(inputs):
        raise BTClibValueError("common inputs")

    psbt = Psbt(
        tx_version,
        inputs,
        outputs,
        version,
        hd_key_paths,
        unknown,
        fallback_lock_time,
        _combined_tx_modifiable(psbts),
    )
    if shuffle_inp or sort_inp:
        psbt.sort_inputs(sort_inp)
    if shuffle_out or sort_out:
        psbt.sort_outputs(sort_out)

    psbt.assert_valid()
    return psbt
