#!/usr/bin/env python3

# Copyright (C) 2020-2022 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

"""Transaction Input (TxIn) dataclass.

Dataclass encapsulating prev_out, script_sig, sequence, and script_witness.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Type

from btclib import var_bytes
from btclib.alias import BinaryData, Octets
from btclib.exceptions import BTClibValueError
from btclib.script.witness import Witness
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
        "Return the outpoint OutPoint for compatibility with CTxIn."
        return self.prev_out

    @property
    def scriptSig(self) -> bytes:  # pylint: disable=invalid-name
        "Return the scriptSig bytes for compatibility with CTxIn."
        return self.script_sig

    @property
    def nSequence(self) -> int:  # pylint: disable=invalid-name
        "Return the nSequence int for compatibility with CTxIn."
        return self.sequence

    def __init__(
        self,
        prev_out: OutPoint = OutPoint(),
        script_sig: Octets = b"",
        sequence: int = 0,
        script_witness: Witness = Witness(),
        check_validity: bool = True,
    ) -> None:

        self.prev_out = prev_out
        self.script_sig = bytes_from_octets(script_sig)
        self.sequence = sequence
        self.script_witness = script_witness

        if check_validity:
            self.assert_valid()

    def is_segwit(self) -> bool:
        # self.prev_out has no segwit information
        return self.script_witness.stack != []

    def is_coinbase(self) -> bool:
        return self.prev_out.is_coinbase()

    def assert_valid(self) -> None:
        self.prev_out.assert_valid()

        # TODO check script_sig

        # must be a 4-bytes int
        if not 0 <= self.sequence <= 0xFFFFFFFF:
            raise BTClibValueError(f"invalid sequence: {self.sequence}")

        if self.script_witness:
            self.script_witness.assert_valid()

    def to_dict(self, check_validity: bool = True) -> Dict[str, Any]:

        if check_validity:
            self.assert_valid()

        return {
            "prev_out": self.prev_out.to_dict(False),
            # TODO make it { "asm": "", "hex": "" }
            "scriptSig": self.script_sig.hex(),
            "sequence": self.sequence,
            "txinwitness": self.script_witness.to_dict(False),
        }

    @classmethod
    def from_dict(
        cls: Type["TxIn"], dict_: Mapping[str, Any], check_validity: bool = True
    ) -> "TxIn":

        return cls(
            OutPoint.from_dict(dict_["prev_out"], False),
            dict_["scriptSig"],
            dict_["sequence"],
            Witness.from_dict(dict_["txinwitness"], False),
            check_validity,
        )

    def serialize(self, check_validity: bool = True) -> bytes:

        if check_validity:
            self.assert_valid()

        out = self.prev_out.serialize(check_validity)
        out += var_bytes.serialize(self.script_sig)
        out += self.sequence.to_bytes(4, byteorder="little", signed=False)
        return out

    @classmethod
    def parse(
        cls: Type["TxIn"], data: BinaryData, check_validity: bool = True
    ) -> "TxIn":

        stream = bytesio_from_binarydata(data)
        prev_out = OutPoint.parse(stream, check_validity)
        script_sig = var_bytes.parse(stream)
        sequence = int.from_bytes(stream.read(4), byteorder="little", signed=False)

        return cls(prev_out, script_sig, sequence, Witness(), check_validity)
