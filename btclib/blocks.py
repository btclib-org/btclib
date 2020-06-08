#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict

from transactions import Transaction, TxIn, TxOut
import varint


class BlockHeader(TypedDict):
    version: int = 0
    previousblockhash: str = ""
    merkleroot: str = ""
    time: int = 1
    bits: int = 0
    nonce: int = 0


def deserialize_block_header(data: bytes):
    header = BlockHeader()
    header.version = int.from_bytes(data[0:4], "little")
    header.prev_block = data[4:36]
    header.merkleroot = data[36:68]
    header.timestamp = int.from_bytes(data[68:72], "little")
    header.bits = int.from_bytes(data[72:76], "little")
    header.nonce = int.from_bytes(data[76:80], "little")
    return header


def serialize_block_header(header: BlockHeader):
    out = header.version.to_bytes(4, "little")
    out += bytes.fromhex(header.previousblockhash)
    out += bytes.fromhex(header.merkleroot)
    out += header.timestamp.to_bytes(4, "little")
    out += header.bits.to_bytes(4, "little")
    out += header.nonce.to_bytes(4, "little")
    return out


# class Block:
#     def __init__(self):
#         self.header = BlockHeader()
#         self.transaction_count = 0
#         self.transactions = []
#
#     @classmethod
#     def from_bytes(cls, data):
#         if len(data) < 81:
#             raise Exception("Too little data")
#         block = cls()
#         block.header = BlockHeader.from_bytes(data[:80])
#         if varint.byte_size(data[80:]) + 80 > len(data):  # not enough bytes
#             raise Exception("Too little data")
#         else:
#             block.transaction_count = varint.decode(data[80:])
#
#         data = data[80 + varint.byte_size(data[80:]) :]
#         for x in range(block.transaction_count):
#             transaction = Transaction.from_bytes(data)
#             block.transactions.append(transaction)
#             data = data[len(transaction.to_bytes()) :]
#
#         return block
#
#     def to_bytes(self):
#         out = self.header.to_bytes()
#         out += varint.encode(self.transaction_count)
#         for transaction in self.transactions:
#             out += transaction.to_bytes()
#         return out
