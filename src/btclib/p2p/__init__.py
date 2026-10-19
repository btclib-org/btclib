# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Module btclib.p2p.

**The p2p wire format and protocol logic, and no socket.** This package
turns a message into bytes and bytes back into a message; it is handed the
octets and hands octets back, and no line of it opens a socket, resolves a
name or waits on one. `btclib_wallet.fetch` is the one place that goes and
asks, and its `transport` is where a socket already is: nothing here imports
that package, and nothing there imports this one -- a fetcher asks a server a
question, a peer is a party to a protocol, and the only thing the two
would share is the socket this package refuses to hold.

**Protocol logic: the low-work headers sync.**
`btclib.p2p.headers_sync` is Bitcoin Core's low-work headers sync: it is
handed headers and the time, and hands back headers and a locator. Its
names are not published here. `State` and `ProcessingResult` are names
Core nests in `HeadersSyncState`, and they say nothing outside their
module, so a caller names the module.

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

**The message start is btclib's.** `btclib.p2p.magic` holds Bitcoin
Core's `pchMessageStart` per network and derives a custom signet's from
its challenge; `magic_from_network` and `magic_from_signet_challenge`
are published here.

`btclib.p2p.limits` is not published at all, as `btclib.block.limits` is
not published from `btclib.block`: a caller reading a protocol constant
names the module it comes from, which is what says the number is Core's
and not this library's.
"""

from btclib.p2p.address import (
    Addr,
    NetworkAddress,
    ServiceFlags,
    TimestampedNetworkAddress,
)
from btclib.p2p.addrv2 import (
    AddrV2,
    BIP155Network,
    NetworkAddressV2,
    SendAddrV2,
    addr_entry,
    can_addrv1,
    is_embedded_ipv6,
    network_address,
    peer_from_addr_entry,
)
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
from btclib.p2p.magic import magic_from_network, magic_from_signet_challenge
from btclib.p2p.merkleblock import MerkleBlock
from btclib.p2p.message import Message
from btclib.p2p.negotiation import (
    Feature,
    FeeFilter,
    GetAddr,
    Mempool,
    SendHeaders,
    SendTxRcncl,
    WtxidRelay,
)
from btclib.p2p.payload import Payload
from btclib.p2p.reject import Reject, RejectCode

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
    "Feature",
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
    "MerkleBlock",
    "Message",
    "NetworkAddress",
    "NetworkAddressV2",
    "NotFound",
    "PartialBlock",
    "Payload",
    "Ping",
    "Pong",
    "PrefilledTransaction",
    "Reject",
    "RejectCode",
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
    "addr_entry",
    "can_addrv1",
    "is_embedded_ipv6",
    "magic_from_network",
    "magic_from_signet_challenge",
    "network_address",
    "peer_from_addr_entry",
    "reconstruct",
]
