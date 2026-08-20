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
exactly as it reads one it knows: the payload types are separate work
(issue #1083), and an envelope that refused an unknown command could not
be written before them.

`magic_from_chain` and `magic_from_signet_challenge` are the
`bitcoin-core-rpc` package's under btclib's name, `magic_from_network`
the one line that takes a btclib network name instead of Core's chain
name; `btclib.p2p.magic` is where the reason btclib keeps no table of its
own is written down, and `btclib/network.py` is where it was decided.

`btclib.p2p.limits` is not exported here, as `btclib.block.limits` is not
exported from `btclib.block`: a caller reading a protocol constant names
the module it comes from, which is what says the number is Core's and not
this library's.
"""

from btclib.p2p.magic import (
    magic_from_chain,
    magic_from_network,
    magic_from_signet_challenge,
)
from btclib.p2p.message import Message

__all__ = [
    "Message",
    "magic_from_chain",
    "magic_from_network",
    "magic_from_signet_challenge",
]
