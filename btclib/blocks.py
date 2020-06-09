#!/usr/bin/env python3

# Copyright (C) 2017-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

from typing import TypedDict, List
from hashlib import sha256

from btclib.transactions import (
    Transaction,
    transaction_deserialize,
    transaction_serialize,
)
from . import varint


class BlockHeader(TypedDict):
    version: int = 0
    previousblockhash: str = ""
    merkleroot: str = ""
    time: int = 1
    bits: int = 0
    nonce: int = 0


def deserialize_block_header(data: bytes):
    header = BlockHeader()
    header["version"] = int.from_bytes(data[0:4], "little")
    header["previousblockhash"] = data[4:36][::-1].hex()
    header["merkleroot"] = data[36:68][::-1].hex()
    header["timestamp"] = int.from_bytes(data[68:72], "little")
    header["bits"] = int.from_bytes(data[72:76], "little")
    header["nonce"] = int.from_bytes(data[76:80], "little")
    header["hash"] = (
        sha256(sha256(serialize_block_header(header)).digest()).digest()[::-1].hex()
    )
    return header


def serialize_block_header(header: BlockHeader):
    out = header["version"].to_bytes(4, "little")
    out += bytes.fromhex(header["previousblockhash"])[::-1]
    out += bytes.fromhex(header["merkleroot"])[::-1]
    out += header["timestamp"].to_bytes(4, "little")
    out += header["bits"].to_bytes(4, "little")
    out += header["nonce"].to_bytes(4, "little")
    return out


class Block(TypedDict):
    header: BlockHeader
    transactions: List[Transaction] = []


def generate_merkle_root(transactions: List[Transaction]):
    hashes = [bytes.fromhex(tx["txid"])[::-1] for tx in transactions]
    hashes_buffer = []
    while len(hashes) != 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
        for x in range(len(hashes) // 2):
            hashes_buffer.append(
                sha256(sha256(hashes[2 * x] + hashes[2 * x + 1]).digest()).digest()
            )
        hashes = hashes_buffer[:]
    return hashes[0]


def deserialize_block(data: bytes):
    block = Block()
    block["header"] = deserialize_block_header(data[:80])
    data = data[80:]
    transaction_count = varint.decode(data)
    data = data[len(varint.encode(transaction_count)) :]
    block["transactions"] = []
    for x in range(transaction_count):
        transaction = transaction_deserialize(data)
        block["transactions"].append(transaction)
        data = data[len(transaction_serialize(transaction)) :]

    return block


def serialize_block(block: Block):
    out = serialize_block_header(block["header"])
    out += varint.encode(len(block["transactions"]))
    for tx in block["transactions"]:
        out += transaction_serialize(tx)
    return out
