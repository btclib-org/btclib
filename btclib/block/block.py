#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Block dataclass.

Dataclass encapsulating BlockHeader and list[Tx].
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from math import ceil
from typing import Any

from btclib import var_bytes, var_int
from btclib.alias import BinaryData
from btclib.block.block_header import BlockHeader
from btclib.exceptions import BTClibValueError
from btclib.hashes import (
    hash256,
    merkle_root_and_mutated,
    merkle_root_and_mutated_from_hashes,
)
from btclib.tx import Tx
from btclib.utils import bytesio_from_binarydata, decode_num

_HF = hash256

# BIP141: OP_RETURN, a 36-byte push, and the aa21a9ed header of it; the
# 32 bytes that follow are the commitment.
_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")
_COMMITMENT_LENGTH = len(_COMMITMENT_PREFIX) + 32


@dataclass
class Block:
    header: BlockHeader
    transactions: list[Tx]

    @property
    def size(self) -> int:
        return len(self.serialize(check_validity=False))

    @property
    def weight(self) -> int:
        return sum(t.weight for t in self.transactions)

    @property
    def vsize(self) -> int:
        return ceil(self.weight / 4)

    @property
    def height(self) -> int | None:
        """Return the height committed into a BIP34 coinbase script_sig.

        Version 2 blocks commit block height into the coinbase
        script_sig.

        https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki
        Block 227,835 (2013-03-24 15
        :49: 13 GMT) was the last version 1 block.
        """
        if not self.transactions[0].is_coinbase():
            raise BTClibValueError("first transaction is not a coinbase")

        if self.header.version == 1:
            return None

        # Height is "serialized CScript": first byte is number of bytes,
        # followed by the _signed_ little-endian representation of the height
        # (genesis block is height zero).
        coinbase_script = self.transactions[0].vin[0].script_sig
        height_ = var_bytes.parse(coinbase_script)
        return decode_num(height_)

    def __init__(
        self,
        header: BlockHeader,
        transactions: Sequence[Tx] | None = None,
        *,
        check_validity: bool = True,
    ) -> None:
        self.header = header

        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        self.transactions = list(transactions) if transactions else []

        if check_validity:
            self.assert_valid()

    def to_dict(self, *, check_validity: bool = True) -> dict[str, Any]:
        if check_validity:
            self.assert_valid()

        return {
            "header": self.header.to_dict(check_validity=False),
            "transactions": [
                tx.to_dict(check_validity=False) for tx in self.transactions
            ],
        }

    @classmethod
    def from_dict(
        cls: type[Block], dict_: Mapping[str, Any], *, check_validity: bool = True
    ) -> Block:
        return cls(
            BlockHeader.from_dict(dict_["header"], check_validity=False),
            [Tx.from_dict(tx, check_validity=False) for tx in dict_["transactions"]],
            check_validity=check_validity,
        )

    def has_segwit_tx(self) -> bool:
        return any(tx.is_segwit() for tx in self.transactions)

    def assert_valid_merkle_root(self) -> None:
        data = [
            tx.serialize(include_witness=False, check_validity=False)
            for tx in self.transactions
        ]
        root, mutated = merkle_root_and_mutated(data, _HF)
        merkle_root_ = root[::-1]
        if merkle_root_ != self.header.merkle_root:
            err_msg = f"invalid merkle root: {self.header.merkle_root.hex()}"
            err_msg += f" instead of: {merkle_root_.hex()}"
            raise BTClibValueError(err_msg)
        if mutated:
            # CVE-2012-2459: two equal siblings mean a shorter transaction
            # list has this very same root, so the header does not commit
            # to the list at hand and the block hash can be kept while its
            # content changes. Core checks the same flag, right after
            # comparing the root, and rejects the block as
            # bad-txns-duplicate; the order is kept so that a block failing
            # both reports the same reason it does.
            raise BTClibValueError("duplicate transaction")

    @property
    def witness_commitment(self) -> bytes | None:
        """Return the BIP141 witness commitment, if the coinbase has one.

        It is the 32 bytes following the 6a24aa21a9ed prefix in the
        *last* coinbase output carrying it, as Core's
        GetWitnessCommitmentIndex does: were the first one to win, an
        output appended to the coinbase could not be told from one the
        miner meant, and the rule has to be the same one everybody else
        applies anyway.
        """
        commitments = [
            script[len(_COMMITMENT_PREFIX) : _COMMITMENT_LENGTH]
            for script in (
                out.script_pub_key.script for out in self.transactions[0].vout
            )
            if len(script) >= _COMMITMENT_LENGTH
            and script.startswith(_COMMITMENT_PREFIX)
        ]
        return commitments[-1] if commitments else None

    def assert_valid_witness_commitment(self) -> None:
        """Assert that the coinbase commits to the witness data (BIP141).

        The merkle root of the header is computed over txids, which by
        segwit's design leave every witness out: without this check the
        witnesses of a block can be replaced wholesale, header and root
        untouched, and the signatures they carry are worth nothing.
        """
        if not self.has_segwit_tx():
            # Nothing to commit to, and nothing to check it against: this
            # is a block as a legacy node sees it, witnesses stripped by
            # the serialization, which btclib parses and this library
            # must keep accepting. Not a hole an attacker can climb into
            # by stripping the witnesses of a segwit block: strip some
            # and the check below runs on the rest, whose wtxids no
            # longer match; strip them all and there is no witness left
            # to be taken on trust.
            return

        commitment = self.witness_commitment
        if commitment is None:
            # Core's unexpected-witness: witness data in a block that
            # does not commit to it is unverifiable, hence not allowed.
            raise BTClibValueError("unexpected witness")

        # The other half of the commitment preimage, a 32-byte nonce the
        # miner chooses, lives in the coinbase witness. Core checks the
        # size (bad-witness-nonce-size) because a shorter one would make
        # the preimage ambiguous.
        witness_stack = self.transactions[0].vin[0].script_witness.stack
        if len(witness_stack) != 1 or len(witness_stack[0]) != 32:
            sizes = [len(element) for element in witness_stack]
            err_msg = f"invalid witness nonce: {sizes} stack element size(s)"
            err_msg += " instead of: [32]"
            raise BTClibValueError(err_msg)

        # The coinbase leaf is all zeros, its own wtxid being unknowable
        # here: it would have to commit to the very value it contains.
        hashes = [b"\x00" * 32] + [
            _HF(tx.serialize(include_witness=True, check_validity=False))
            for tx in self.transactions[1:]
        ]
        # The mutation flag of the witness tree is redundant, as Core
        # notes: the tree has the shape of the txid one, and two equal
        # wtxids mean two equal transactions, hence two equal txids that
        # assert_valid_merkle_root has already rejected.
        witness_root = merkle_root_and_mutated_from_hashes(hashes, _HF)[0]
        witness_commitment_ = _HF(witness_root + witness_stack[0])
        if witness_commitment_ != commitment:
            err_msg = f"invalid witness commitment: {commitment.hex()}"
            err_msg += f" instead of: {witness_commitment_.hex()}"
            raise BTClibValueError(err_msg)

    def assert_valid(self) -> None:
        self.header.assert_valid()
        # the header alone does not assert this: a header being mined is
        # structurally valid and has no proof-of-work yet, so requiring one
        # left no way to build a candidate. A Block is not a candidate --
        # it carries the transactions the work commits to -- and Bitcoin
        # Core draws the line in the same place, CheckBlock calling
        # CheckProofOfWork with fCheckPOW defaulted to true.
        # It is also what makes the vendored block_*.bin files verify
        # themselves: Block.parse recomputes the hash from the bytes
        self.header.assert_valid_pow()

        # every block carries a coinbase, so an empty list is not a block
        # that happens to be empty: it is not a block. Refused here, or
        # transactions[0] below answers it with an IndexError -- and a
        # var_int of zero where the transaction count goes is all it takes
        # to serialize one
        if not self.transactions:
            raise BTClibValueError("block with no transactions")

        if not self.transactions[0].is_coinbase():
            raise BTClibValueError("first transaction is not a coinbase")

        for transaction in self.transactions[1:]:
            # Bitcoin Core's bad-cb-multiple, asked immediately after the
            # same first-transaction question: a coinbase is a claim on
            # the subsidy, so a second one is a second claim, and it is
            # the *shape* of the block that is wrong rather than anything
            # about that transaction on its own -- which is all
            # assert_valid below can see.
            # Unreachable from a serialized block, and added anyway: the
            # proof-of-work checked above already refuses one from the
            # wire, and a coinbase cannot be added to a real block
            # without moving the merkle root the header commits to, so no
            # well-formed vector can carry two. What has no work yet is a
            # block being assembled -- the toy mining of issue #188, and
            # any candidate-block path after it -- and that is exactly
            # where nothing else says no
            if transaction.is_coinbase():
                raise BTClibValueError("more than one coinbase")
            transaction.assert_valid()

        self.assert_valid_merkle_root()
        self.assert_valid_witness_commitment()

    def serialize(
        self, include_witness: bool = True, *, check_validity: bool = True
    ) -> bytes:
        if check_validity:
            self.assert_valid()

        out = self.header.serialize(check_validity=check_validity)
        out += var_int.serialize(len(self.transactions))
        return out + b"".join(
            [
                t.serialize(include_witness, check_validity=check_validity)
                for t in self.transactions
            ]
        )

    @classmethod
    def parse(
        cls: type[Block], data: BinaryData, *, check_validity: bool = True
    ) -> Block:
        """Return a Block by parsing binary data."""
        stream = bytesio_from_binarydata(data)
        header = BlockHeader.parse(stream, check_validity=check_validity)
        n = var_int.parse(stream)
        transactions = [
            Tx.parse(stream, check_validity=check_validity) for _ in range(n)
        ]

        return cls(header, transactions, check_validity=check_validity)
