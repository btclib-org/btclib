# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Where the p2p message start comes from, which btclib does not hold.

`btclib/network.py` decided this before there was a p2p package, and its
`Network` docstring is where the decision is: "No consensus parameter
lives here, and no p2p one: the message start belongs to the code that
speaks to a node, `bitcoin_core_rpc.magic_from_chain` being where it is,
because a custom signet's is a function of its challenge and therefore
not a field any table can hold."

So the question this module answers is not which of two designs to
choose. Giving `Network` a `magic` field would contradict a docstring
that states its own reason, and the reason is the fifth network:
`NETWORKS` is an encoding table fixed at import, every field of which is
the same for every deployment of the network it describes, while a custom
signet's message start is the first four octets of the sha256d of its
block challenge and differs between two deployments that report the same
chain. A field would be right for four networks and a lie for the fifth,
which is an annotation accepting the mistake rather than refusing it.
`btclib.fetch.transport` re-exports the same package's HTTP transport on
the same reasoning: a second copy is a second thing to keep true.

`magic_from_chain` and `magic_from_signet_challenge` are therefore
aliases and not wrappers -- the package's own objects, so
`btclib.p2p.magic_from_chain is bitcoin_core_rpc.magic_from_chain` -- and
they take Core's vocabulary: a chain name, "main", "test", "testnet4",
"signet" or "regtest", and a challenge as the hex a config file writes or
the octets a parser holds. Their exceptions are the package's too, as
`btclib.fetch.transport` says of the transport it re-exports: an unknown
chain leaves as `BtcRpcValueError`, which is not a class
`btclib.exceptions` declares.

`magic_from_network` is what btclib's own vocabulary reaches, and it is
here because that vocabulary is not Core's: `NETWORKS` is keyed by the
BIP network names -- "mainnet", "testnet" -- where Core says "main" and
"test", so a caller holding a `Network` and passing its name straight to
`magic_from_chain` is told its network is unknown.
`bitcoin_core_rpc.chain_from_network` is the bridge, and
`btclib.fetch.bitcoin_core` uses it exactly this way: "chain_from_network
on the way in, client_errors on the way out".

On the way out there is nothing to translate, and that is by
construction rather than by luck. `network._validated_network_name` is
what the name goes through first -- the `strip().lower()` tolerance
issue #216 decided every `network: str` parameter keeps -- so what
reaches `chain_from_network` is a key of `NETWORKS`, and every one of
those is a chain Core has. What could raise the package's class is
therefore refused before the call, by btclib's own converter and with
btclib's own exceptions; a `try`/`except` around the call would be a
second check of what the first has already settled, which is the guard
this tree does not write. `tests/p2p/magic_test.py` walks `NETWORKS` and
asserts the property instead, which is where it can go stale visibly.
"""

from bitcoin_core_rpc import (
    chain_from_network,
    magic_from_chain,
    magic_from_signet_challenge,
)

from btclib.network import _validated_network_name

__all__ = [
    "magic_from_chain",
    "magic_from_network",
    "magic_from_signet_challenge",
]


def magic_from_network(network: str = "mainnet") -> bytes:
    """Return the p2p message start of one of btclib's networks.

    The four octets every message on that network begins with, from
    Bitcoin Core's `pchMessageStart` per chain. `network` is a `NETWORKS`
    name in any case and spaced how it likes, as everywhere a network is
    named; signet's answer is the *default* signet's, another signet
    being identified by its challenge rather than by a name, and
    `magic_from_signet_challenge` is what answers for that one.

    A name no network has leaves as a `BTClibValueError` and a value that
    is no name at all as a `BTClibTypeError`, both from the converter
    this shares with the rest of the library rather than from the package
    the table is in.
    """
    return magic_from_chain(chain_from_network(_validated_network_name(network)))
