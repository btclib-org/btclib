# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Blocks: header and block, their rules, proof of work, merkle proofs."""

from btclib.block import build, merkle_proof, mining, proof_of_work
from btclib.block.block import (
    Block,
    bip34_commitment,
    coinbase_witness_commitment,
    merkle_root_and_mutated_from_transactions,
    witness_commitment_output,
)
from btclib.block.block_context import BlockContext
from btclib.block.block_filter import BasicBlockFilter, prevout_scripts_from_utxos
from btclib.block.block_header import BlockHeader
from btclib.block.genesis import genesis_block
from btclib.block.header_context import (
    ParentOf,
    header_at_height,
    median_time_past,
    next_bits_required,
)
from btclib.block.partial_merkle_tree import PartialMerkleTree

# btclib.block.limits is not here, as btclib.script.limits is not in
# btclib.script: a caller reading a consensus constant names the module it
# comes from, which is what says the number is Core's and not this
# library's.
# merkle_root_and_mutated_from_transactions is, beside the bip34_commitment
# defined next to it: both are what a header commits to, and this one is
# the single implementation the builder and the validator share -- mining
# builds a candidate header from it and Block.assert_valid compares the
# header against it -- so a caller checking a block by hand needs the same
# function rather than a second one written from the BIP. Same reasoning
# for coinbase_witness_commitment and witness_commitment_output, the pair
# assert_valid_witness_commitment and build.build_block share. ParentOf,
# header_at_height, median_time_past, next_bits_required and genesis_block
# are flattened the same way rather than left under their own modules:
# each is the one operation a caller reaches for, not a namespace of
# related constants the way proof_of_work and mining are
__all__ = [
    "BasicBlockFilter",
    "Block",
    "BlockContext",
    "BlockHeader",
    "ParentOf",
    "PartialMerkleTree",
    "bip34_commitment",
    "build",
    "coinbase_witness_commitment",
    "genesis_block",
    "header_at_height",
    "median_time_past",
    "merkle_proof",
    "merkle_root_and_mutated_from_transactions",
    "mining",
    "next_bits_required",
    "prevout_scripts_from_utxos",
    "proof_of_work",
    "witness_commitment_output",
]
