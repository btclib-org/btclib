# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The protocol limit on a p2p message, with Bitcoin Core's name.

A module of its own, as `block/limits.py` and `script/limits.py` are and
for the same reason: `message.py` is the dataclass and its serialization,
while the name here is a rule about a message being *accepted*, and a
caller naming this module is saying the number is Core's rather than this
library's.

Core declares it in src/net.h, among the constants of peer management and
not among the consensus ones, which is where it belongs: nothing about a
block or a transaction changes with it, and what it bounds is the buffer
a node allocates for a length field a peer chose.

An envelope without it is what btclib_node has -- `verify_headers` reads
the four octets and waits for `24 + payload_len` with nothing between the
peer's number and the buffer -- and the bound is the difference between
refusing such a header at once and holding whatever the peer dribbles in
against a length it will never reach.
"""

__all__ = [
    "MAX_PROTOCOL_MESSAGE_LENGTH",
]

# Maximum length of incoming protocol messages, spelled as Core spells it:
# decimal and not binary, its comment reading "no message over 4 MB is
# currently acceptable".
#
# Its own name and not `btclib.consensus.MAX_BLOCK_WEIGHT`, which is the
# same number today and is not the same constant: one bounds what a peer
# may announce over a socket and the other what a block may weigh, and
# either can move without the other. An import would read as tidy and be
# a bug the day Core changes one of them.
MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000
