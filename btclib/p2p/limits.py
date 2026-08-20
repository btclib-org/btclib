# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The protocol limits on a p2p message, with Bitcoin Core's names.

A module of its own, as `block/limits.py` and `script/limits.py` are and
for the same reason: the other modules here are the dataclasses and their
serializations, while the names here are rules about a message being
*accepted*, and a caller naming this module is saying the numbers are
Core's rather than this library's.

Core declares them among the constants of peer management and not among
the consensus ones, which is where they belong: nothing about a block or
a transaction changes with them, and what each bounds is what a node
allocates for a count or a length a peer chose. None of the three is a
consensus rule, so none of them is in `btclib.consensus` -- and
`MAX_PROTOCOL_MESSAGE_LENGTH` is 4,000,000 as `consensus.MAX_BLOCK_WEIGHT`
is, which is the coincidence this module exists to keep from becoming an
import.

An envelope without the first is what btclib_node has -- `verify_headers`
reads the four octets and waits for `24 + payload_len` with nothing
between the peer's number and the buffer -- and the bound is the
difference between refusing such a header at once and holding whatever
the peer dribbles in against a length it will never reach. The third has
the same shape one layer up: `Addr.parse` reads a count before it builds
anything, where btclib_node's `Addr.deserialize` loops over whatever
`var_int.parse` allowed it, and btclib's own var_int cap is 33,554,432.
"""

__all__ = [
    "MAX_ADDR_TO_SEND",
    "MAX_PROTOCOL_MESSAGE_LENGTH",
    "MAX_SUBVERSION_LENGTH",
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

# The longest user agent a `version` message may carry, Core's src/net.h
# again, where it is the bound of the LIMITED_STRING net_processing.cpp
# reads `strSubVer` through. Its own name and not a reuse of the one
# above for the same reason that one is not `MAX_BLOCK_WEIGHT`.
MAX_SUBVERSION_LENGTH = 256

# The most addresses one `addr` message may carry, Core's
# src/net_processing.cpp, where it bounds both what is sent and what is
# accepted: `vAddr.size() > MAX_ADDR_TO_SEND` is a Misbehaving there,
# which is the receiving half and the one this library can hold.
#
# net_processing.cpp and not net.h, which is where the other two are:
# Core keeps this one beside the address relay that uses it, and the
# citation is what says where to look when the number moves.
MAX_ADDR_TO_SEND = 1000
