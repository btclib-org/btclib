#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Partially Signed Bitcoin Transaction (Psbt) dataclass and functions.

https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from io import BytesIO
from math import ceil
from typing import Any, TypeVar, cast

from btclib.alias import BinaryData, Octets, ScriptList, String
from btclib.bip32 import (
    BIP32KeyOrigin,
    HdKeyPaths,
    assert_valid_hd_key_paths,
    decode_from_bip32_derivs,
    decode_hd_key_paths,
    encode_to_bip32_derivs,
)
from btclib.ecc import dsa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, sha256
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_out import PsbtOut
from btclib.psbt.psbt_size import estimated_input_sizes
from btclib.psbt.psbt_utils import (
    PSBT_SEPARATOR,
    assert_valid_unknown,
    decode_dict_bytes_bytes,
    deserialize_int,
    deserialize_map,
    deserialize_tx,
    encode_dict_bytes_bytes,
    serialize_bytes,
    serialize_dict_bytes_bytes,
    serialize_hd_key_paths,
)
from btclib.script import (
    Witness,
    is_p2pkh,
    is_p2sh,
    is_p2tr,
    is_p2wpkh,
    is_p2wsh,
    serialize,
    sig_hash,
    type_and_payload,
)
from btclib.tx import Tx, TxIn, TxOut, join_txs
from btclib.utils import bytesio_from_binarydata

# the whole of BIP174's <magic>, five bytes: the four of "psbt" and the
# 0xff that makes a psbt fail to deserialize as a transaction. It is one
# constant and one check because it is one header -- the 0xff is no more
# optional than the "p" -- and because the alternative is a second thing
# called a separator, which the 0x00 that ends a map already is
PSBT_MAGIC_BYTES = b"psbt\xff"

PSBT_GLOBAL_UNSIGNED_TX = b"\x00"
PSBT_GLOBAL_XPUB = b"\x01"
PSBT_GLOBAL_VERSION = b"\xfb"
# 0xfc is reserved for proprietary use, and needs no constant of its own:
# explicit support for proprietary (and por) is unnecessary,
# see https://github.com/bitcoin/bips/pull/1038


def _assert_valid_version(version: int) -> None:
    # must be a 4-bytes int
    if not 0 <= version <= 0xFFFFFFFF:
        raise BTClibValueError(f"invalid version: {version}")
    # actually the only version that is currently handled is zero
    if version != 0:
        raise BTClibValueError(f"invalid non-zero version: {version}")


def _signable_payload(psbt_in: PsbtIn, tx_in: TxIn) -> bytes:
    """Return the hash the input's script_pub_key commits to.

    Which utxo the input carries is which kind of input it is. A
    witness_utxo is the spent output itself, and it has to be a segwit
    one: p2sh is accepted only as the wrapper, so what is typed then is
    the redeem script, while the payload stays the p2sh one -- the
    hash160 the caller checks that redeem script against. A
    non_witness_utxo is the whole previous transaction, and the output
    being spent is the one the outpoint names.
    """
    if witness_utxo := psbt_in.witness_utxo:
        script_type, payload = type_and_payload(witness_utxo.script_pub_key.script)
        if script_type == "p2sh":
            script_type, _ = type_and_payload(psbt_in.redeem_script)
        if script_type not in ("p2wpkh", "p2wsh"):
            raise BTClibValueError("script type not in ('p2wpkh', 'p2wsh')")
        return payload

    if psbt_in.non_witness_utxo:
        script_pub_key = psbt_in.non_witness_utxo.vout[
            tx_in.prev_out.vout
        ].script_pub_key
        _, payload = type_and_payload(script_pub_key.script)
        return payload

    err_msg = "missing script_pub_key"
    raise BTClibValueError(err_msg)


def _assert_input_signable(psbt_in: PsbtIn, tx_in: TxIn) -> None:
    """Raise an exception unless the input carries what a Signer needs.

    Each script the input provides has to be the one the level above it
    commits to: the redeem script the hash160 in the script_pub_key
    names, and the witness script the sha256 in whichever of the two is
    the level above *it* -- the redeem script when the input is wrapped,
    the script_pub_key when it is native.
    """
    payload = _signable_payload(psbt_in, tx_in)
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
    tx: Tx
    inputs: list[PsbtIn]
    outputs: list[PsbtOut]
    version: int
    hd_key_paths: HdKeyPaths
    unknown: dict[bytes, bytes]

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
        vin: list[TxIn] = []
        # strict=True costs nothing: a psbt whose inputs and vin are of
        # different lengths is one assert_valid refuses
        for i, (psbt_in, tx_in) in enumerate(
            zip(self.inputs, self.tx.vin, strict=True)
        ):
            try:
                script_sig_size, witness_sizes = estimated_input_sizes(psbt_in, tx_in)
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
        placeholder = Tx(
            self.tx.version, self.tx.lock_time, vin, self.tx.vout, check_validity=False
        )
        return placeholder.weight

    @property
    def estimated_vsize(self) -> int:
        """Return the virtual size the transaction will have once signed.

        The name Bitcoin Core's `analyzepsbt` reports it under, and the
        `Tx.vsize` arithmetic: a quarter of the weight, rounded up.
        """
        return ceil(self.estimated_weight / 4)

    def __init__(
        self,
        tx: Tx,
        inputs: Sequence[PsbtIn],
        outputs: Sequence[PsbtOut],
        version: int,
        hd_key_paths: Mapping[Octets, BIP32KeyOrigin],
        unknown: Mapping[Octets, Octets] | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.tx = tx
        self.inputs = list(inputs)
        self.outputs = list(outputs)
        self.version = version
        self.hd_key_paths = decode_hd_key_paths(hd_key_paths)
        self.unknown = dict(sorted(decode_dict_bytes_bytes(unknown).items()))

        if check_validity:
            self.assert_valid()

    def assert_valid(self) -> None:
        """Assert logical self-consistency."""
        # the global unsigned tx is incomplete by construction, so it is
        # checked as a template: no "at least one input", no "at least one
        # output", either of which would refuse the two psbts BIP174 lists
        # as valid with no inputs (issue 170). deserialize_tx checks it
        # the same way on the way in
        self.tx.assert_valid(unsigned_template=True)

        # ensure the tx is unsigned
        if any(tx_in.script_sig or tx_in.script_witness for tx_in in self.tx.vin):
            raise BTClibValueError("non empty script_sig or witness")

        if len(self.tx.vin) != len(self.inputs):
            err_msg = "mismatched number of psb.tx.vin and psb.inputs: "
            err_msg += f"{len(self.tx.vin)} vs {len(self.inputs)}"
            raise BTClibValueError(err_msg)

        for psbt_in in self.inputs:
            psbt_in.assert_valid()

        if any(
            psbt_in.non_witness_utxo
            and psbt_in.non_witness_utxo.id != tx_in.prev_out.tx_id
            for psbt_in, tx_in in zip(self.inputs, self.tx.vin, strict=True)
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
            and tx_in.prev_out.vout >= len(psbt_in.non_witness_utxo.vout)
            for psbt_in, tx_in in zip(self.inputs, self.tx.vin, strict=True)
        ):
            err_msg = "outpoint vout out of range for the non-witness utxo"
            raise BTClibValueError(err_msg)

        if len(self.tx.vout) != len(self.outputs):
            err_msg = "mismatched number of psb.tx.vout and psbt.outputs: "
            err_msg += f"{len(self.tx.vout)} vs {len(self.outputs)}"
            raise BTClibValueError(err_msg)

        for psbt_out in self.outputs:
            psbt_out.assert_valid()

        _assert_valid_version(self.version)
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

        if not self.tx.vin:
            raise BTClibValueError("nothing to sign: no inputs")

        # strict=True costs nothing here: assert_valid above has just
        # refused a psbt whose inputs and vin are of different lengths
        for psbt_in, tx_in in zip(self.inputs, self.tx.vin, strict=True):
            _assert_input_signable(psbt_in, tx_in)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        return {
            # check_validity=False for the same reason as in serialize:
            # a template, already validated by assert_valid above
            "tx": self.tx.to_dict(check_validity=False),
            "inputs": [
                psbt_in.to_dict(check_validity=False) for psbt_in in self.inputs
            ],
            "outputs": [
                psbt_out.to_dict(check_validity=False) for psbt_out in self.outputs
            ],
            "version": self.version,
            "bip32_derivs": encode_to_bip32_derivs(self.hd_key_paths),
            "unknown": dict(sorted(encode_dict_bytes_bytes(self.unknown).items())),
        }

    @classmethod
    def from_dict(
        cls: type[Psbt], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Psbt:
        hd_key_paths = cast(
            Mapping[Octets, BIP32KeyOrigin],
            decode_from_bip32_derivs(dict_["bip32_derivs"]),
        )
        return cls(
            # check_validity=False, as for every other element here: the
            # global unsigned tx is a template, and Psbt.assert_valid below
            # checks it as one. Validating it here as a complete transaction
            # would refuse the two zero-input psbts BIP174 lists as valid
            # (issue 170)
            Tx.from_dict(dict_["tx"], check_validity=False),
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
            check_validity=check_validity,
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
        if check_validity:
            self.assert_valid()

        psbt_bin: list[bytes] = [PSBT_MAGIC_BYTES]

        # check_validity=False: Psbt.assert_valid above has already
        # validated it, as the template it is, and Tx.serialize would
        # otherwise re-check it as a complete transaction and refuse the
        # two zero-input psbts BIP174 lists as valid (issue 170)
        temp = self.tx.serialize(include_witness=False, check_validity=False)
        psbt_bin.append(serialize_bytes(PSBT_GLOBAL_UNSIGNED_TX, temp))
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
        psbt_bin.extend(psbt_in.serialize() for psbt_in in self.inputs)
        psbt_bin.extend(psbt_out.serialize() for psbt_out in self.outputs)
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
        # None until the global map yields one, which BIP174 requires it to:
        # "The unsigned transaction must be provided". Not a
        # Tx(check_validity=False) placeholder: an empty transaction is
        # indistinguishable from a *parsed* one with no inputs, so a check
        # refusing the placeholder would also refuse the two zero-input
        # psbts BIP174 lists as valid (issue 170)
        tx: Tx | None = None
        version = 0
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        unknown: dict[Octets, Octets] = {}

        stream = bytesio_from_binarydata(data)

        if stream.read(5) != PSBT_MAGIC_BYTES:
            raise BTClibValueError("malformed psbt: missing magic bytes")

        global_map = deserialize_map(stream)
        for k, v in global_map.items():
            if k[:1] == PSBT_GLOBAL_UNSIGNED_TX:
                tx = deserialize_tx(
                    k, v, "global unsigned tx", False, unsigned_template=True
                )
            elif k[:1] == PSBT_GLOBAL_VERSION:
                version = deserialize_int(k, v, "global version")
            elif k[:1] == PSBT_GLOBAL_XPUB:
                hd_key_paths[k[1:]] = BIP32KeyOrigin.parse(v)
            else:  # unknown
                unknown[k] = v

        if tx is None:
            raise BTClibValueError("malformed psbt: missing global unsigned tx")

        inputs = [PsbtIn.parse(stream) for _ in tx.vin]
        outputs = [PsbtOut.parse(stream) for _ in tx.vout]

        # what is left in a caller's stream is the caller's; what is left
        # in octets is malleability, two buffers deserializing to the one
        # object that serializes back to only the shorter of them
        if not isinstance(data, BytesIO):
            trailing = stream.read()
            if trailing:
                err_msg = f"malformed psbt: {len(trailing)} bytes after the psbt"
                raise BTClibValueError(err_msg)

        return cls(
            tx,
            inputs,
            outputs,
            version,
            hd_key_paths,
            unknown,
            check_validity=check_validity,
        )

    def b64encode(self, *, check_validity: bool = True) -> str:
        psbt_bin = self.serialize(check_validity=check_validity)
        return base64.b64encode(psbt_bin).decode("ascii")

    @classmethod
    def b64decode(
        cls: type[Psbt], psbt_str: String, *, check_validity: bool = True
    ) -> Psbt:
        if isinstance(psbt_str, str):
            psbt_str = psbt_str.strip()

        psbt_decoded = base64.b64decode(psbt_str)

        return cls.parse(psbt_decoded, check_validity=check_validity)

    @classmethod
    def from_tx(cls: type[Psbt], tx: Tx, *, check_validity: bool = True) -> Psbt:
        for tx_in in tx.vin:
            tx_in.script_sig = b""
            tx_in.script_witness = Witness()
        inputs = [PsbtIn() for _ in tx.vin]
        outputs = [PsbtOut() for _ in tx.vout]

        psbt_version = 0
        hd_key_paths: dict[Octets, BIP32KeyOrigin] = {}
        unknown: dict[Octets, Octets] = {}

        return cls(
            tx,
            inputs,
            outputs,
            psbt_version,
            hd_key_paths,
            unknown,
            check_validity=check_validity,
        )

    def sort_inputs(self, ordering_func: Callable[[PsbtIn], int] | None = None) -> None:
        """Sort psbt inputs.

        sorting logic is ordering_func if present, shuffle otherwise.
        """
        self.inputs, self.tx.vin = _sort_or_shuffle_together(
            self.inputs, self.tx.vin, ordering_func
        )

    def sort_outputs(
        self, ordering_func: Callable[[PsbtOut], int] | None = None
    ) -> None:
        """Sort psbt outputs.

        sorting logic is ordering_func if present, shuffle otherwise.
        """
        self.outputs, self.tx.vout = _sort_or_shuffle_together(
            self.outputs, self.tx.vout, ordering_func
        )


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


def combine_psbts(psbts: Sequence[Psbt]) -> Psbt:
    """Merge Psbt data from multiple Psbts with same TxId.

    Basically used to merge signatures.
    """
    final_psbt = psbts[0]
    tx_id = psbts[0].tx.id
    for psbt in psbts[1:]:
        if psbt.tx.id != tx_id:
            raise BTClibValueError(f"mismatched psbt.tx.id: {psbt.tx.id.hex()}")

    final_psbt.version = max(psbt.version for psbt in psbts)
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

        for i, out in enumerate(final_psbt.outputs):
            _combine_field(psbt.outputs[i], out, "redeem_script")
            _combine_field(psbt.outputs[i], out, "witness_script")
            _combine_field(psbt.outputs[i], out, "hd_key_paths")
            _combine_field(psbt.outputs[i], out, "unknown")

        _combine_field(psbt, final_psbt, "tx")
        _combine_field(psbt, final_psbt, "hd_key_paths")
        _combine_field(psbt, final_psbt, "unknown")

    return final_psbt


def _prev_out(psbt_in: PsbtIn, tx_in: TxIn) -> TxOut | None:
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
    if psbt_in.non_witness_utxo and tx_in.prev_out.vout < len(
        psbt_in.non_witness_utxo.vout
    ):
        return psbt_in.non_witness_utxo.vout[tx_in.prev_out.vout]
    return None


def _spent_script(psbt_in: PsbtIn, tx_in: TxIn) -> bytes:
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
    prev_out = _prev_out(psbt_in, tx_in)
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


def _finalized_input(psbt_in: PsbtIn, tx_in: TxIn) -> tuple[bytes, Witness]:
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
    sigs: list[bytes] = list(psbt_in.partial_sigs.values())
    # https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki#motivation
    cmds: list[bytes] = [b""] if len(sigs) > 1 else []
    cmds += sigs
    redeem_script: list[bytes] = (
        [psbt_in.redeem_script] if psbt_in.redeem_script else []
    )

    script = _spent_script(psbt_in, tx_in)

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


def _witness_v0_script_code(psbt_in: PsbtIn, script: bytes) -> bytes:
    """Return the script code BIP-143 signs the segwit v0 input against.

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

    sig_hash.from_tx is the same dispatch for a *signed* transaction, and
    cannot serve here: it reads the redeem script out of the input's
    script_sig and the witness script off its witness stack, and a psbt's
    unsigned transaction has neither -- they are the psbt's own fields,
    which is the whole point of the format.
    """
    prev_out = _prev_out(psbt_in, tx.vin[vin_i])
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
    return sig_hash.legacy(script, tx, vin_i, hash_type)


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
    evidence against the signature.

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


def finalize_psbt(psbt: Psbt) -> Psbt:
    """Finalize the Psbt.

    The Input Finalizer must only accept a PSBT.

    For each input, the Input Finalizer determines if the input has
    enough data to pass validation. If it does, it must construct the
    0x07 Finalized scriptSig and 0x08 Finalized scriptWitness and place
    them into the input key-value map.

    All other data except the UTXO and unknown fields in the input key-
    value map should be cleared from the PSBT. The UTXO should be kept
    to allow Transaction Extractors to verify the final network
    serialized transaction.

    Deciding that an input has enough data is two checks beyond the
    presence of a signature, and both are per input: the sighash type
    each signature commits to is the one the input asks for, and each
    signature verifies against the key it is filed under.

    What is then built is the spend the input's own kind asks for, which
    is what _finalized_input dispatches on: a witness script alone does
    not say, being absent from every single-key segwit input.
    """
    psbt = deepcopy(psbt)
    psbt.assert_valid()
    for vin_i, (psbt_in, tx_in) in enumerate(
        zip(psbt.inputs, psbt.tx.vin, strict=True)
    ):
        if not psbt_in.partial_sigs:
            raise BTClibValueError("missing signatures")
        _assert_sig_hash_type(psbt_in)
        _assert_partial_sigs_verify(psbt_in, psbt.tx, vin_i)
        script_sig, witness = _finalized_input(psbt_in, tx_in)
        psbt_in.final_script_sig = script_sig
        psbt_in.final_script_witness = witness
        psbt_in.partial_sigs = {}
        psbt_in.sig_hash_type = None
        psbt_in.redeem_script = b""
        psbt_in.witness_script = b""
        psbt_in.hd_key_paths = {}
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

    The Transaction Extractor does not need to know how to interpret
    scripts in order to extract the network serialized transaction.
    However it may be able to in order to validate the network
    serialized transaction at the same time.
    """
    if check_validity:
        psbt.assert_valid()

    tx = psbt.tx
    for tx_in, psbt_input in zip(tx.vin, psbt.inputs, strict=True):
        tx_in.script_sig = psbt_input.final_script_sig
        if psbt_input.final_script_witness:
            tx_in.script_witness = psbt_input.final_script_witness

    if check_validity:
        tx.assert_valid()
    return tx


TypeA = TypeVar("TypeA")
TypeB = TypeVar("TypeB")


def _sort_or_shuffle_together(
    sequence_a: Sequence[TypeA],
    sequence_b: Sequence[TypeB],
    ordering_func: Callable[[TypeA], int] | None = None,
) -> tuple[list[TypeA], list[TypeB]]:
    """Sort together with ordering_func if provided, else shuffle together.

    Sort is on TypeA, both sequences must have same length.
    """
    if len(sequence_a) != len(sequence_b):
        raise BTClibValueError("sequences must have same length")

    tmp = list(zip(sequence_a, sequence_b, strict=True))
    if ordering_func is None:
        secrets.SystemRandom().shuffle(tmp)
    else:
        tmp.sort(key=lambda t: ordering_func(t[0]))
    tuple_a, tuple_b = zip(*tmp, strict=True)
    return list(tuple_a), list(tuple_b)


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


def join_psbts(
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
    they are simply concatenated in the same order as psbts are
    specified. A specific ordering can be specified via sort_{inp|out},
    which overwrite shuffle when present.

    Outputs are concatenated and never merged, and there is no parameter
    asking for it: coalescing two outputs that pay the same script is a
    change to the output *set*, so every signature already made over the
    old one stops verifying -- and, after the shuffle or sort above, the
    result would depend on the order the merge ran in. A caller who wants
    one output where there were two builds it that way before signing,
    which is the only point at which it is safe.
    """
    _ensure_consistency(psbts)

    inputs = [inp for psbt in psbts for inp in psbt.inputs]
    outputs = [outp for psbt in psbts for outp in psbt.outputs]
    hd_key_paths: dict[Octets, BIP32KeyOrigin] = {
        k: v for psbt in psbts for k, v in psbt.hd_key_paths.items()
    }
    unknown: dict[Octets, Octets] = {
        k: v for psbt in psbts for k, v in psbt.unknown.items()
    }
    version = max(psbt.version for psbt in psbts)

    # the transaction is joined unshuffled: the psbt's inputs and its vin
    # are one sequence in two lists, so whatever reorders them has to
    # reorder both, which is what sort_inputs and sort_outputs below do
    merged_tx = join_txs(
        [psbt.tx for psbt in psbts],
        enforce_same_tx_version,
        enforce_same_tx_lock_time,
        False,
        False,
    )

    psbt = Psbt(merged_tx, inputs, outputs, version, hd_key_paths, unknown)
    if shuffle_inp or sort_inp:
        psbt.sort_inputs(sort_inp)
    if shuffle_out or sort_out:
        psbt.sort_outputs(sort_out)

    psbt.assert_valid()
    return psbt
