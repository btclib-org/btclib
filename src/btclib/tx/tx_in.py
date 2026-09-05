# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The TxIn dataclass and input_weight; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from btclib import var_bytes
from btclib.alias import BinaryData, Octets
from btclib.consensus import WITNESS_SCALE_FACTOR
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import Witness, script_from_dict, script_to_dict
from btclib.tx.out_point import OutPoint
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
    is_integer,
    read_exactly,
)

__all__ = [
    "TX_IN_COMPARES_WITNESS",
    "TxIn",
    "input_weight",
]

TX_IN_COMPARES_WITNESS = True


@dataclass
class TxIn:
    """One input of a transaction.

    The outpoint it spends, the script_sig, the sequence, and the
    witness -- which serialize omits and parse leaves empty, the wire
    placing all witnesses after the inputs: Tx.serialize and Tx.parse
    are what write and read them. Mutable, a transaction being built
    input by input; TxIn() is the placeholder a builder starts from,
    its prev_out the coinbase marker.
    """

    prev_out: OutPoint
    script_sig: bytes
    # 0xFFFFFFFF (final) on every input makes Tx.lock_time irrelevant;
    # 0xFFFFFFFE enables the lock time (e.g. against fee sniping) while
    # opting out of Replace-By-Fee, whose customary opt-in is 0xFFFFFFFD.
    # BIP68 relative lock times need a sequence below 0xFFFFFFFD, so every
    # sequence-locked transaction is also opting into RBF.
    sequence: int
    script_witness: Witness = field(compare=TX_IN_COMPARES_WITNESS)

    @property
    def outpoint(self) -> OutPoint:
        """Return the outpoint OutPoint for compatibility with CTxIn."""
        return self.prev_out

    @property
    def scriptSig(self) -> bytes:
        """Return the scriptSig bytes for compatibility with CTxIn."""
        return self.script_sig

    @property
    def nSequence(self) -> int:
        """Return the nSequence int for compatibility with CTxIn."""
        return self.sequence

    def __init__(
        self,
        prev_out: OutPoint | None = None,
        script_sig: Octets = b"",
        sequence: int = 0,
        script_witness: Witness | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        # a default argument is evaluated once, at definition time: an
        # OutPoint() or Witness() default would be one object shared by
        # every TxIn built without them, and mutating it through any of
        # them would corrupt all the others
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.prev_out = OutPoint() if prev_out is None else prev_out
        self.script_sig = bytes_from_octets(script_sig)
        self.sequence = sequence
        self.script_witness = Witness() if script_witness is None else script_witness

        if check_validity:
            self.assert_valid()

    @property
    def is_segwit(self) -> bool:
        """Answer whether the input carries a witness.

        The input alone can only answer for what it holds: whether the
        spent output demands a witness is written in that output's
        script_pub_key, which is not here.
        """
        # self.prev_out has no segwit information
        return bool(self.script_witness.stack)

    @property
    def is_coinbase(self) -> bool:
        """Answer whether the input is a coinbase, spending nothing."""
        return self.prev_out.is_coinbase

    def assert_valid(self) -> None:
        """Refuse an invalid prev_out, sequence, or witness.

        The script_sig is deliberately not judged; the comment below
        carries the reasoning.
        """
        self.prev_out.assert_valid()

        # as everywhere an int field is range-checked: True would be a
        # sequence of one, and a sequence is where a locktime-enabled
        # input is told from a final one
        if not is_integer(self.sequence):
            err_msg = f"invalid sequence type: {type(self.sequence).__name__}"
            raise BTClibTypeError(err_msg)

        # script_sig is deliberately not looked at, and the marker asking
        # for a check (issue 183) is answered by where the answers already
        # are. An input's validity is not its script's:
        #
        # - a script_sig that does not parse is a valid input. It fails
        #   *evaluation*, which is script_engine's answer to give, and the
        #   only size limit consensus puts on it is the interpreter's
        #   10000 bytes over the script being evaluated
        # - the 1650 bytes and push-only of Core's IsStandardTx --
        #   MAX_STANDARD_SCRIPTSIG_SIZE, "scriptsig-size" and
        #   "scriptsig-not-pushonly" -- are relay policy. A transaction
        #   breaking either is mined and valid, so refusing it here would
        #   refuse a valid transaction, and policy is not what assert_valid
        #   means anywhere else in the package
        # - the one consensus rule at this level is the coinbase's 2..100
        #   bytes, and Tx.assert_valid enforces it, which is the only place
        #   that can: it takes a coinbase *transaction*, while a lone TxIn
        #   with the null prev_out is the placeholder every builder starts
        #   from -- TxIn() itself is one, with an empty script_sig
        #
        # TxOut made the same call for script_pub_key, for the reason in
        # the comment there

        # must be a 4-bytes int
        if not 0 <= self.sequence <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid sequence: {self.sequence}")

        self.script_witness.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        """Return the input as a dict of json-friendly values.

        The script_sig enters as script_to_dict renders it -- asm and
        hex -- and from_dict reads the same shape back; validation runs
        once here, not again in the fields.
        """
        if check_validity:
            self.assert_valid()

        return {
            "prev_out": self.prev_out.to_dict(check_validity=False),
            "scriptSig": script_to_dict(self.script_sig),
            "sequence": self.sequence,
            "txinwitness": self.script_witness.to_dict(check_validity=False),
        }

    @classmethod
    def from_dict(
        cls: type[TxIn], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> TxIn:
        """Build a TxIn from the dict shape to_dict writes."""
        dict_ = fields_from_json_object(dict_, "transaction input")
        return cls(
            OutPoint.from_dict(dict_["prev_out"], check_validity=False),
            script_from_dict(dict_["scriptSig"]),
            dict_["sequence"],
            Witness.from_dict(dict_["txinwitness"], check_validity=False),
            check_validity=check_validity,
        )

    def _serialized_size(self) -> int:
        """Return what serialize writes, without writing it.

        The witness is not counted here, for the reason serialize does
        not write it: Tx puts every witness after the outputs.
        """
        return self.prev_out._serialized_size() + var_bytes._size(self.script_sig) + 4

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the wire serialization: prev_out, script_sig, sequence.

        The witness is not here, the wire putting every input's
        witness after the outputs: Tx.serialize writes them there.
        """
        if check_validity:
            self.assert_valid()

        out = self.prev_out.serialize(check_validity=check_validity)
        out += var_bytes.serialize(self.script_sig)
        out += self.sequence.to_bytes(4, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: type[TxIn], data: BinaryData, *, check_validity: bool = True
    ) -> TxIn:
        """Build a TxIn by parsing its wire serialization.

        The witness comes back empty, sitting elsewhere on the wire;
        Tx.parse fills it in.
        """
        stream = bytesio_from_binarydata(data)
        prev_out = OutPoint.parse(stream, check_validity=check_validity)
        script_sig = var_bytes.parse(stream)
        sequence = int.from_bytes(
            read_exactly(stream, 4, "sequence"), byteorder="little", signed=False
        )
        assert_no_trailing(data, stream, "transaction input")

        return cls(
            prev_out, script_sig, sequence, Witness(), check_validity=check_validity
        )


def input_weight(script_sig: Octets, witness: Witness | None = None) -> int:
    """Return the weight one input adds to a transaction, per BIP141.

    Bitcoin Core's `calculate_input_weight`, of
    test/functional/test_framework/wallet_util.py, whose revision
    `TF2.md` pins: the non-witness bytes weigh WITNESS_SCALE_FACTOR each
    -- the 36-byte outpoint, the script_sig behind its var_int length,
    the 4-byte sequence -- and the serialized witness stack weighs one
    each. Which output is spent and what the sequence says do not enter
    the answer, both fields being fixed-width, so neither is an
    argument.

    It is computable before the input exists, which is the point: a fee
    is chosen before the transaction is signed, so the weight the fee is
    computed from cannot be read off the finished transaction.
    `Tx.weight` is the same arithmetic over one already built.

    `witness` is `None` for an input of a transaction with no witness
    section and a `Witness` for one of a transaction that has it --
    `Witness()` being the empty stack a non-segwit input carries there.
    The two differ by a byte, that stack still serializing the var_int
    announcing no elements, and a caller that cannot tell them apart
    misprices an input by one. Core, taking a list of hex items, has to
    document the distinction as a rule about `None`; here it is the
    type's.
    """
    # a TxIn measured rather than its fixed 40 bytes restated here: what
    # an outpoint and a sequence weigh is _serialized_size's to know, and
    # building the input is what Core does for the same reason
    weight = TxIn(script_sig=script_sig)._serialized_size() * WITNESS_SCALE_FACTOR
    # `is not None` and not a truth test: Witness defines __len__, so the
    # empty stack is falsy, and it is exactly the case that must not be
    # read as no witness at all
    if witness is not None:
        weight += witness._serialized_size()
    return weight
