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
# assert_valid_witness_commitment and build.build_block share
__all__ = [
    "BasicBlockFilter",
    "Block",
    "BlockContext",
    "BlockHeader",
    "bip34_commitment",
    "build",
    "coinbase_witness_commitment",
    "merkle_proof",
    "merkle_root_and_mutated_from_transactions",
    "mining",
    "prevout_scripts_from_utxos",
    "proof_of_work",
    "witness_commitment_output",
]
