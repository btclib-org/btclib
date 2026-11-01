# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The p2p message start of each network, and of a custom signet.

Every p2p message begins with four octets that name its network: Bitcoin
Core's `pchMessageStart`. `magic_from_network` answers for each network
`NETWORKS` names. Signet's answer there is the default signet's. Any other
signet reports the same chain name and has its own message start, derived
from its block challenge: `magic_from_signet_challenge` answers for it.

That is why `Network` has no `magic` field: a field keyed by the name
"signet" would be wrong for every custom signet.

The values are transcribed from `src/kernel/chainparams.cpp` at Bitcoin
Core v31.1 (bitcoin/bitcoin@9be056a8a7), and `tests/p2p/magic_test.py`
holds each one to that transcription. Signet's entry is a copy of the
derived value rather than a derivation at import: the test derives it
from `DEFAULT_SIGNET_CHALLENGE`.
"""

from types import MappingProxyType
from typing import Final

from btclib.alias import Octets
from btclib.hashes import hash256
from btclib.network import validated_network_name
from btclib.var_bytes import serialize

__all__ = [
    "DEFAULT_SIGNET_CHALLENGE",
    "magic_from_network",
    "magic_from_signet_challenge",
]

# `pchMessageStart` per network, chainparams.cpp lines 125-128 (main),
# 251-254 (testnet3), 359-362 (testnet4) and 599-602 (regtest); signet's
# is the derivation of lines 507-511 applied to the default challenge
_MAGIC_FROM_NETWORK: Final = MappingProxyType(
    {
        "mainnet": bytes.fromhex("f9beb4d9"),
        "testnet": bytes.fromhex("0b110907"),
        "testnet4": bytes.fromhex("1c163f28"),
        "signet": bytes.fromhex("0a03cf40"),
        "regtest": bytes.fromhex("fabfb5da"),
    }
)

# the block challenge of the default signet, the one a Bitcoin Core node
# started without -signetchallenge uses: SigNetParams in
# src/kernel/chainparams.cpp, line 442 at v31.1
DEFAULT_SIGNET_CHALLENGE: Final = bytes.fromhex(
    # split at a push boundary: OP_1 and the first key, then the second key
    # with OP_2 and OP_CHECKMULTISIG, a 1-of-2 multisig. The allowlist
    # comments are for the secret scanner: these are two public keys
    "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430"  # pragma: allowlist secret
    "210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"  # pragma: allowlist secret
)


def magic_from_network(network: str = "mainnet") -> bytes:
    """Return the p2p message start of one of btclib's networks.

    `network` is a `NETWORKS` name in any case and with ASCII whitespace
    around it, as everywhere a network is named. Signet's answer is the
    default signet's: `magic_from_signet_challenge` answers for any other.

    A name no network has leaves as a `BTClibValueError`, and a value that
    is no name at all as a `BTClibTypeError`.
    """
    return _MAGIC_FROM_NETWORK[validated_network_name(network)]


def magic_from_signet_challenge(challenge: Octets) -> bytes:
    """Return the p2p message start a signet's block challenge determines.

    Core: "message start is defined as the first 4 bytes of the sha256d of
    the block script", the script serialized with its CompactSize length
    (chainparams.cpp lines 507-511 at v31.1). BIP325 defines the challenge.

    `challenge` is hex, as a config file and `getblockchaininfo` write it,
    or the octets a parser holds. Core reads any hex for
    `-signetchallenge`, the empty string included, and so does this.
    """
    return hash256(serialize(challenge))[:4]
