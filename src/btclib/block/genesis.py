# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Build the genesis block of a network, on demand rather than at import.

`Network.genesis_block` is 32 bytes -- the hash a header's
`previous_block_hash` is checked against -- not a `Block`. It cannot be
one: `block.block` already reaches `btclib.network` transitively, through
`btclib.tx`'s `TxOut.script_pub_key` importing `btclib.script`'s
`script_pub_key` module for the address tables, so a `Network` field
holding a `Block` would close the cycle issue #147 is about. This module
is where a caller who wants the actual block gets one instead -- built
here, on request, rather than carried as a field of `Network` or of
`NETWORKS`.

`build.build_block` does the header assembly and every structural check a
pre-mining candidate can pass; what this adds is the one coinbase shape
it cannot build. `build.build_coinbase` always commits to a height
(BIP34), and every network's genesis predates that rule: its script_sig
is the literal timestamp message Bitcoin Core's `CreateGenesisBlock`
hardcodes (`kernel/chainparams.cpp`, at bitcoin/bitcoin@9be056a8a7), not
a general-purpose builder's output. `mainnet`, `testnet`, `regtest` and
`signet` share that message, the same public key, and `OP_CHECKSIG` --
`tests/block/build_test.py`'s own mainnet vector already builds that
shape -- and differ only in the header's own time, bits, nonce and
version, plus the reward `consensus.subsidy` already gives at height
zero regardless of a chain's halving interval. `testnet4` does not: Core
gives it its own timestamp text and an output script that pays to
thirty-three zero bytes and `OP_CHECKSIG` rather than to that key, and
`_GENESIS_PARAMS` below carries both shapes rather than assuming the one
mainnet uses is universal.

Every result is checked against the network's own bits before it is
returned -- `Block.assert_valid`, at that network's `pow_limit_bits`
rather than mainnet's default, which a regtest or signet genesis would
fail. `tests/block/genesis_test.py` is the check this module exists for:
every network's built genesis hashes to the value `NETWORKS` already
ships for it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone

from btclib.block.block import Block
from btclib.block.build import build_block
from btclib.consensus import subsidy
from btclib.network import NETWORKS, network_from_name
from btclib.script.script import serialize
from btclib.tx import OutPoint, Tx, TxIn, TxOut

__all__ = ["genesis_block"]

# Satoshi's own message and pubkey, shared by mainnet, testnet, regtest
# and signet -- the fourth reproduced here even though nothing mines
# against it, so that the same table serves every built-in network the
# same way. "FFFF001D" and b"\x04" are two of the three pushes Bitcoin
# Core's CreateGenesisBlock always writes -- 486604799 (0x1D00FFFF) and
# the message's own byte count -- fixed regardless of the network's own
# bits, which is why they are not read from `_GenesisParams.bits` below.
_STANDARD_MESSAGE = (
    b"The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
)
_STANDARD_PUBKEY = (
    "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
    "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f"
)
_STANDARD_SCRIPT_PUB_KEY = serialize([_STANDARD_PUBKEY, "OP_CHECKSIG"])

# testnet4's own text and output script, neither shared with the other
# four: pays to thirty-three zero bytes rather than to Satoshi's pubkey,
# a script nothing can spend.
_TESTNET4_MESSAGE = (
    b"03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
)
_TESTNET4_SCRIPT_PUB_KEY = serialize([b"\x00" * 33, "OP_CHECKSIG"])


@dataclass(frozen=True)
class _GenesisParams:
    """The fields one network's genesis coinbase and header need.

    Everything `build_block` cannot infer on its own: the header's own
    time, bits and nonce (its version is always 1, every genesis
    predating BIP9), and the coinbase's own message and output script,
    which are not always the same across networks -- testnet4's are not.
    """

    time: int  # unix seconds
    bits: str  # display-order hex, as Network.consensus and BlockHeader hold it
    nonce: int
    message: bytes
    script_pub_key: bytes


# time, bits and nonce transcribed from Bitcoin Core's own
# kernel/chainparams.cpp, at bitcoin/bitcoin@9be056a8a7, one
# CreateGenesisBlock call per network; message and script_pub_key from
# the same file, standard for four of the five and testnet4's own for
# the fifth
_GENESIS_PARAMS: dict[str, _GenesisParams] = {
    "mainnet": _GenesisParams(
        1231006505, "1d00ffff", 2083236893, _STANDARD_MESSAGE, _STANDARD_SCRIPT_PUB_KEY
    ),
    "testnet": _GenesisParams(
        1296688602, "1d00ffff", 414098458, _STANDARD_MESSAGE, _STANDARD_SCRIPT_PUB_KEY
    ),
    "regtest": _GenesisParams(
        1296688602, "207fffff", 2, _STANDARD_MESSAGE, _STANDARD_SCRIPT_PUB_KEY
    ),
    "signet": _GenesisParams(
        1598918400, "1e0377ae", 52613770, _STANDARD_MESSAGE, _STANDARD_SCRIPT_PUB_KEY
    ),
    "testnet4": _GenesisParams(
        1714777860,
        "1d00ffff",
        393743547,
        _TESTNET4_MESSAGE,
        _TESTNET4_SCRIPT_PUB_KEY,
    ),
}


def genesis_block(network: str = "mainnet") -> Block:
    """Return the genesis block of `network`, built rather than looked up.

    A caller wanting only the hash already has it, cheaply, at
    `network_from_name(network).genesis_block`; this is for a caller that
    needs the block itself -- a `datadir` seeding a fresh node, a test
    fixture -- and is willing to pay for one coinbase transaction and one
    header assembly to get it, in place of a field this library cannot
    carry without closing issue #147's cycle.

    The block is checked against the network's own easiest target before
    it is returned (`Block.assert_valid`, at that network's
    `pow_limit_bits`), and reproduces the hash `Network.genesis_block`
    already carries for the same network -- verified for all five in
    `tests/block/genesis_test.py`.
    """
    net = network_from_name(network)
    name = next(candidate for candidate, value in NETWORKS.items() if value is net)
    params = _GENESIS_PARAMS[name]

    script_sig = serialize(["FFFF001D", b"\x04", params.message])
    genesis_tx = Tx(
        version=1,
        lock_time=0,
        vin=[TxIn(OutPoint(), script_sig, 0xFFFFFFFF)],
        vout=[TxOut(subsidy(0), params.script_pub_key)],
    )

    time = datetime.fromtimestamp(params.time, tz=timezone.utc)
    block = build_block(b"\x00" * 32, [genesis_tx], time, params.bits, version=1)
    block.header = replace(block.header, nonce=params.nonce)
    block.assert_valid(pow_limit_bits=net.consensus.pow_limit_bits)
    return block
