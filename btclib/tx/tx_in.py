#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Transaction Input (TxIn) dataclass.

Dataclass encapsulating prev_out, script_sig, sequence, and
script_witness.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from btclib import var_bytes
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibValueError
from btclib.script import Witness, script_from_dict, script_to_dict
from btclib.tx.out_point import OutPoint
from btclib.utils import bytes_from_octets, bytesio_from_binarydata

TX_IN_COMPARES_WITNESS = True


@dataclass
class TxIn:
    prev_out: OutPoint
    script_sig: bytes
    # If all TxIns have final (0xffffffff) sequence numbers
    # then Tx lock_time is irrelevant.
    #
    # Set to 0xFFFFFFFE to enables nLocktime (e.g. to discourage fee sniping)
    # and disables Replace-By-Fee (RBF).
    #
    # RBF txs typically have the sequence of each input set to 0xFFFFFFFD.
    #
    # Because sequence locks require that the sequence field be set
    # lower than 0xFFFFFFFD to be meaningful,
    # all sequence locked transactions are opting into RBF.
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

    def is_segwit(self) -> bool:
        # self.prev_out has no segwit information
        return bool(self.script_witness.stack)

    def is_coinbase(self) -> bool:
        return self.prev_out.is_coinbase()

    def assert_valid(self) -> None:
        self.prev_out.assert_valid()

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

        if self.script_witness:
            self.script_witness.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
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
        return cls(
            OutPoint.from_dict(dict_["prev_out"], check_validity=False),
            script_from_dict(dict_["scriptSig"]),
            dict_["sequence"],
            Witness.from_dict(dict_["txinwitness"], check_validity=False),
            check_validity=check_validity,
        )

    def serialize(self, *, check_validity: bool = True) -> bytes:
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
        stream = bytesio_from_binarydata(data)
        prev_out = OutPoint.parse(stream, check_validity=check_validity)
        script_sig = var_bytes.parse(stream)
        sequence = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        return cls(
            prev_out, script_sig, sequence, Witness(), check_validity=check_validity
        )
