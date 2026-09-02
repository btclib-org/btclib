# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.p2p.

**The p2p wire format, and nothing that speaks it.** This package turns a
message into bytes and bytes back into a message; it is handed the octets
and hands octets back, and no line of it opens a socket, resolves a name
or waits on one. `btclib.fetch` is the one place that goes and asks, and
its `transport` is where a socket already is: nothing here imports that
package, and nothing there imports this one -- a fetcher asks a server a
question, a peer is a party to a protocol, and the only thing the two
would share is the socket this package refuses to hold.

**The envelope, with the payload as opaque bytes.** `Message` is the
header Bitcoin Core's `CMessageHeader` describes together with the
payload it announces, and it reads a command it knows nothing about
exactly as it reads one it knows: an envelope that refused an unknown
command could not have been written before the payload types, and one
that stopped doing so now would refuse the next BIP.

**A payload type is a class that knows its own command**, and
`Payload.to_message` is what puts one in an envelope; `btclib.p2p.payload`
is where that decision is argued and where what it costs the payload
types still to come (issue #1083) is written down. There is no table
mapping a command to a type -- reading a message back into a typed
payload is `Version.parse(message.payload)` under the caller's own
`if`, which is the shape `net_processing.cpp` has too.

**The message start is published without being imported.**
`magic_from_chain`, `magic_from_network` and `magic_from_signet_challenge`
are `btclib.p2p.magic`'s, and that module reaches the `bitcoin-core-rpc`
package's `chains` vocabulary, which depends on nothing beyond the
standard library -- `urllib.request`, and `ssl` and `socket` under it,
live in that package's `client` and `transport` instead, which a
message-start lookup never reaches. README.md states the property this
keeps: "No module loads `urllib.request` on its way to anything else."
`__getattr__` below still answers the three lazily, the same pattern
`btclib/script/__init__.py` uses for `sig_hash` and `engine`: `import
btclib.p2p` stays what a parser needs and nothing else, whether or not
the module behind a lazy name would itself have been free.

`btclib.p2p.limits` is not published at all, as `btclib.block.limits` is
not published from `btclib.block`: a caller reading a protocol constant
names the module it comes from, which is what says the number is Core's
and not this library's.
"""

from typing import Any

from btclib.p2p.address import (
    Addr,
    NetworkAddress,
    ServiceFlags,
    TimestampedNetworkAddress,
)
from btclib.p2p.addrv2 import AddrV2, BIP155Network, NetworkAddressV2, SendAddrV2
from btclib.p2p.block_filters import (
    BlockFilterType,
    CFCheckpt,
    CFHeaders,
    CFilter,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
)
from btclib.p2p.compact_blocks import (
    CMPCTBLOCKS_VERSION,
    BlockTxn,
    CmpctBlock,
    GetBlockTxn,
    PartialBlock,
    PrefilledTransaction,
    SendCmpct,
    reconstruct,
)
from btclib.p2p.data import BlockPayload, TxPayload
from btclib.p2p.handshake import Verack, Version
from btclib.p2p.inventory import (
    GetBlocks,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    InventoryType,
    NotFound,
)
from btclib.p2p.keepalive import Ping, Pong
from btclib.p2p.message import Message
from btclib.p2p.negotiation import (
    FeeFilter,
    GetAddr,
    Mempool,
    SendHeaders,
    SendTxRcncl,
    WtxidRelay,
)
from btclib.p2p.payload import Payload

__all__ = [
    "CMPCTBLOCKS_VERSION",
    "Addr",
    "AddrV2",
    "BIP155Network",
    "BlockFilterType",
    "BlockPayload",
    "BlockTxn",
    "CFCheckpt",
    "CFHeaders",
    "CFilter",
    "CmpctBlock",
    "FeeFilter",
    "GetAddr",
    "GetBlockTxn",
    "GetBlocks",
    "GetCFCheckpt",
    "GetCFHeaders",
    "GetCFilters",
    "GetData",
    "GetHeaders",
    "Headers",
    "Inv",
    "Inventory",
    "InventoryType",
    "Mempool",
    "Message",
    "NetworkAddress",
    "NetworkAddressV2",
    "NotFound",
    "PartialBlock",
    "Payload",
    "Ping",
    "Pong",
    "PrefilledTransaction",
    "SendAddrV2",
    "SendCmpct",
    "SendHeaders",
    "SendTxRcncl",
    "ServiceFlags",
    "TimestampedNetworkAddress",
    "TxPayload",
    "Verack",
    "Version",
    "WtxidRelay",
    "magic_from_chain",
    "magic_from_network",
    "magic_from_signet_challenge",
    "reconstruct",
]

# what `btclib.p2p.magic` holds, published here and imported on demand:
# see the docstring for what importing it eagerly would cost
_ON_DEMAND = (
    "magic_from_chain",
    "magic_from_network",
    "magic_from_signet_challenge",
)


def __getattr__(published: str) -> Any:
    """Return a message start function, importing its module the first time.

    PEP 562, as `btclib/__init__.py` and `btclib/script/__init__.py` do
    it, and for a name rather than a submodule: this answers
    `btclib.p2p.magic_from_chain` on a package that imported neither the
    module nor `bitcoin_core_rpc` behind it, which is how a walker
    reading `__all__` descends and how `from btclib.p2p import *` binds.
    `from btclib.p2p.magic import magic_from_chain` never reaches here,
    importing the module itself.

    `Any` and not a narrower type, the three signatures differing: what
    that costs is one attribute lookup's worth of strictness on this
    package, which `btclib/__init__.py` weighs the same way. A caller who
    wants mypy to hold them to their signatures names the module.
    """
    if published in _ON_DEMAND:
        from btclib.p2p import magic  # noqa: PLC0415

        return getattr(magic, published)
    raise AttributeError(f"module {__name__!r} has no attribute {published!r}")


def __dir__() -> list[str]:
    """Answer with the published names beside what is already here.

    The PEP 562 asymmetry `btclib/__init__.py` answers the same way:
    `dir()` reads the namespace, so a name `__getattr__` has not been
    asked for yet is missing from it, and interactive completion would
    hide three supported spellings.
    """
    return sorted({*__all__, *globals()})
