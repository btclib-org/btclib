# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Build a coinbase and a block; mining.py keeps the header search.

`block/mining.py` already builds a candidate header and searches its
nonce; what it does not build is what that header commits to -- a
coinbase paying the chain's own subsidy, and a block over a list of
transactions with a witness commitment where one is owed. That
asymmetry, and not a preference for one file over two, is why this is a
module of its own beside `mining.py` rather than an addition to it: a
builder is the first code in `block/` that decides what a block *is*,
where every other function there reads one somebody else built.

`build_coinbase` validates what it returns by default, `check_validity`
`False` the escape -- the rule every constructor of this library already
has, `Block`, `Tx` and `BlockHeader` among them. `build_block` carries no
such parameter, and still validates everything a pre-mining candidate
can be asked for: `Block.assert_valid_structure` is every rule
`Block.assert_valid` asks except the header's own two -- which a
candidate cannot pass, and which `mining.candidate_block_header` has
already asked of the header the same way `BlockHeader` always does.
`build_block`'s own docstring has why the two remaining rules are left
to the caller. A caller wanting a block that is invalid on purpose, the
way Bitcoin Core's own `test_framework.blocktools.create_block` is
meant to be driven into invalid states, builds a `Tx` or a `Block` by
hand with `check_validity=False` and mutates the result, exactly as a
caller already does for a regtest block whose proof-of-work `mainnet`'s
own default limit would refuse.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from btclib import var_bytes
from btclib.alias import Octets
from btclib.block.block import (
    Block,
    bip34_commitment,
    witness_commitment_output,
)
from btclib.block.mining import VERSION, candidate_block_header
from btclib.consensus import subsidy
from btclib.script.witness import Witness
from btclib.tx import OutPoint, Tx, TxIn, TxOut

__all__ = [
    "build_block",
    "build_coinbase",
]

# BIP141's own default, and Bitcoin Core's: `GenerateCoinbaseCommitment`
# (`src/validation.cpp`, at bitcoin/bitcoin@9be056a8a7) writes an
# all-zero nonce into every block it assembles, nothing here reading a
# random one back -- a real miner's privacy is not what the nonce is for
_ZERO_WITNESS_NONCE = b"\x00" * 32


def build_coinbase(
    height: int,
    script_pub_key: Octets,
    *,
    fees: int = 0,
    halving_interval: int = 210_000,
    extra_nonce: Octets = b"",
    version: int = 1,
    lock_time: int = 0,
    check_validity: bool = True,
) -> Tx:
    """Return a coinbase transaction paying the subsidy at `height`, plus fees.

    Bitcoin Core's `create_coinbase`
    (`test/functional/test_framework/blocktools.py`, at
    bitcoin/bitcoin@9be056a8a7): a null-outpoint input committing to
    `height` (BIP34, `bip34_commitment`) and one output paying
    `consensus.subsidy(height, halving_interval) + fees` to
    `script_pub_key`. `halving_interval` defaults to mainnet's own;
    a caller building for another network passes that network's own row
    -- `CONSENSUS_PARAMS[name].subsidy_halving_interval`, regtest's 150
    among them -- rather than this function asserting a chain's
    schedule for it.

    `extra_nonce` is pushed onto the script_sig after the height
    commitment, empty by default and padding a height of sixteen or
    below's one-byte commitment out to the two bytes a coinbase
    script_sig must carry: `var_bytes.serialize(b"")` is one more byte
    on its own, an empty push rather than nothing pushed at all. A
    caller mining several candidates from one height rolls this the way
    a real miner does once the header's own four nonce bytes are
    exhausted -- `mining.mine`'s own docstring has the reason -- a
    different `extra_nonce` being a different script_sig and hence a
    different merkle root to search under.
    """
    script_sig = bip34_commitment(height) + var_bytes.serialize(extra_nonce)
    value = subsidy(height, halving_interval) + fees
    return Tx(
        version=version,
        lock_time=lock_time,
        vin=[TxIn(OutPoint(), script_sig, 0xFFFFFFFF)],
        vout=[TxOut(value, script_pub_key)],
        check_validity=check_validity,
    )


def _coinbase_with_commitment(coinbase: Tx, transactions: Sequence[Tx]) -> Tx:
    """Return a copy of `coinbase` carrying the BIP141 witness commitment.

    `witness_commitment_output` computes the output from `transactions`,
    the same implementation `Block.assert_valid_witness_commitment`
    checks a commitment against; the coinbase's own input gets the other
    half of the preimage, `_ZERO_WITNESS_NONCE`, in its witness stack.
    The caller's `coinbase` is not touched, `mining.mine` leaving its own
    argument alone for the same reason: a builder handing back a value
    the caller already holds a reference to is a builder inviting the
    two to drift apart under an edit meant for one of them alone.
    """
    committed_in = TxIn(
        prev_out=coinbase.vin[0].prev_out,
        script_sig=coinbase.vin[0].script_sig,
        sequence=coinbase.vin[0].sequence,
        script_witness=Witness([_ZERO_WITNESS_NONCE], check_validity=False),
        check_validity=False,
    )
    commitment_out = witness_commitment_output(transactions, _ZERO_WITNESS_NONCE)
    return Tx(
        version=coinbase.version,
        lock_time=coinbase.lock_time,
        vin=[committed_in],
        vout=[*coinbase.vout, commitment_out],
        check_validity=False,
    )


def build_block(
    previous_block_hash: Octets,
    transactions: Sequence[Tx],
    time: datetime,
    bits: Octets,
    *,
    version: int = VERSION,
) -> Block:
    """Return the unsolved block over `transactions`, ready for `mining.mine`.

    `transactions[0]` is the coinbase -- `build_coinbase`'s own shape, or
    a caller's -- and the rest are what it is paid to include. Where any
    of them carries a witness, the coinbase this returns is not the
    caller's own: it is a copy carrying the BIP141 commitment Bitcoin
    Core's `GenerateCoinbaseCommitment` writes into every block it
    assembles, `_coinbase_with_commitment`'s docstring has the pair this
    is built from. A block with no witness among its transactions gets
    neither the output nor the coinbase's own witness stack, the way a
    legacy block never carried one.

    `mining.candidate_block_header` is what builds the header, over the
    transactions actually carried rather than the caller's own copies of
    them: the merkle root it commits to and the one
    `Block.assert_valid_merkle_root` checks are the same computation,
    which is the whole of what makes a built block a block.

    No `check_validity`, unlike `build_coinbase`: what this returns has
    no proof-of-work, nonce zero rather than one that satisfies `bits`,
    and `Block.assert_valid` always asks for one, so there is no state
    in which the *complete* check could pass. That is not every check,
    though, and this still runs the rest: `Block.assert_valid_structure`
    is `assert_valid` minus the header's own two rules --
    `candidate_block_header` has already asked those of the header, the
    same way `BlockHeader` always does -- so a caller handing this two
    coinbases, an over-weight block or a malformed transaction is
    refused here rather than handed back a `Block` nothing has looked
    at. `mining.mine` is this function's own next step, and
    `Block.assert_valid(pow_limit_bits)` is the caller's once it returns
    a solved header -- the one check this cannot itself perform.
    """
    transactions = list(transactions)
    if (
        transactions
        and transactions[0].vin
        and any(tx.is_segwit for tx in transactions)
    ):
        transactions[0] = _coinbase_with_commitment(transactions[0], transactions)

    header = candidate_block_header(
        previous_block_hash, transactions, time, bits, version=version
    )
    block = Block(header, transactions, check_validity=False)
    block.assert_valid_structure()
    return block
