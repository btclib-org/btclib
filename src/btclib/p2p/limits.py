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
allocates for a count or a length a peer chose. Not one of them is a
consensus rule, so none of them is in `btclib.consensus` -- and
`MAX_PROTOCOL_MESSAGE_LENGTH` is 4,000,000 as `consensus.MAX_BLOCK_WEIGHT`
is, which is the coincidence this module exists to keep from becoming an
import.

An envelope without `MAX_PROTOCOL_MESSAGE_LENGTH` is what btclib_node has
-- `verify_headers` reads the four octets and waits for `24 +
payload_len` with nothing between the peer's number and the buffer -- and
the bound is the difference between refusing such a header at once and
holding whatever the peer dribbles in against a length it will never
reach. Every count bound here has the same shape one layer up: `parse`
reads the count before it builds anything, where btclib_node's own
message classes loop over whatever `var_int.parse` allowed them, and
btclib's var_int cap is 33,554,432.

Not every name here is checked by something, and BIP157's are where the
difference shows: a bound on a *range* whose far end is a block hash
cannot be applied without the chain that turns the hash into a height,
so `MAX_GETCFILTERS_SIZE` is published for the caller holding one and
checked nowhere. Publishing it is what keeps such a caller from writing
the number down a second time.
"""

__all__ = [
    "CFCHECKPT_INTERVAL",
    "MAX_ADDRV2_SIZE",
    "MAX_ADDR_TO_SEND",
    "MAX_BLOCK_TX_INDEX",
    "MAX_FEATUREDATA_LENGTH",
    "MAX_FEATUREID_LENGTH",
    "MAX_GETCFHEADERS_SIZE",
    "MAX_GETCFILTERS_SIZE",
    "MAX_HEADERS_RESULTS",
    "MAX_INV_SZ",
    "MAX_LOCATOR_SZ",
    "MAX_PROTOCOL_MESSAGE_LENGTH",
    "MAX_SUBVERSION_LENGTH",
    "MIN_FEATUREID_LENGTH",
    "PROTOCOL_VERSION",
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

# The protocol version this library's own `version` messages announce,
# Core's own name and own value: `static const int PROTOCOL_VERSION =
# 70016` of src/node/protocol_version.h, WTXID_RELAY_VERSION's number and
# the one BIP37's threshold in `btclib.p2p.handshake` is read against.
# Not consumed by `parse`, which reads whatever a peer sent rather than
# what this library would have sent, and not a bound: unlike every other
# name in this module, a `version` carrying a different number is not
# refused for it, being a fact a peer states about itself rather than a
# limit on what it may send.
PROTOCOL_VERSION = 70016

# The most addresses one `addr` message may carry, Core's
# src/net_processing.cpp, where it bounds both what is sent and what is
# accepted: `vAddr.size() > MAX_ADDR_TO_SEND` is a Misbehaving there,
# which is the receiving half and the one this library can hold.
#
# net_processing.cpp and not net.h, which is where the other two are:
# Core keeps this one beside the address relay that uses it, and the
# citation is what says where to look when the number moves.
#
# `addrv2` is held to this one and not to a second constant of its own:
# BIP155 says "One message can contain up to 1,000 addresses. Clients
# SHOULD reject messages with more addresses", and Core reads both
# commands through the one `ProcessMessage` branch and the one check.
# The same number under two names is what `MAX_PROTOCOL_MESSAGE_LENGTH`
# above refuses, and this is the other case: one rule, so one constant.
MAX_ADDR_TO_SEND = 1000

# The longest address an `addrv2` entry may carry, BIP155's own bound:
# "Field addr has a variable length, with a maximum of 512 bytes (4096
# bits). Clients SHOULD reject messages with longer addresses,
# irrespective of the network ID." Core holds the same number under
# `CNetAddr::MAX_ADDRV2_SIZE` of src/netaddress.h, which is the name
# spelled here.
#
# Irrespective of the network id is what makes it a bound rather than a
# validity rule: the length a known id fixes is checked against the table
# in `btclib.p2p.addrv2`, and this is what stands in front of the octets
# an id nobody has heard of may claim -- `var_bytes` reads a length the
# peer chose, and btclib's var_int allows 33,554,432 of them.
MAX_ADDRV2_SIZE = 512

# The most entries one `inv` or `getdata` may carry, Core's
# src/net_processing.cpp, where the comment reads "The maximum number of
# entries in an 'inv' protocol message" and both handlers answer a longer
# vector with a `Misbehaving`.
#
# `notfound` is the third message of that shape and Core bounds it
# differently -- it reads an over-long one and ignores what is in it --
# so this is the bound btclib holds it to as well, on the argument that a
# `notfound` answers a `getdata` and cannot name more than one held.
# btclib.p2p.inventory's `NotFound` says so where a caller reads it.
MAX_INV_SZ = 50000

# The most headers one `headers` message carries, Core's
# src/net_processing.h, whose comment adds what the number is load-
# bearing for: "We rely on the assumption that if a peer sends less than
# this number, we reached its tip. Changing this value is a protocol
# upgrade."
#
# net_processing.h and not the .cpp, where MAX_INV_SZ and MAX_LOCATOR_SZ
# are: Core publishes this one in the header because its own test
# framework overrides it -- `max_headers_result` among the options -- and
# the citation is what says where to look when the number moves.
MAX_HEADERS_RESULTS = 2000

# The most blocks one `getcfilters` may ask the filters of, Core's
# src/net_processing.cpp: "Maximum number of compact filters that may be
# requested with one getcfilters. See BIP 157." The BIP states it as a
# rule about the range -- "the difference MUST be strictly less than
# 1000" -- and that is what makes it a constant published rather than
# checked: the far end of the range is a hash, and turning a hash into a
# height needs the chain. `btclib.p2p.block_filters` holds none, so
# `GetCFilters` carries the citation and the caller with a chain applies
# the number.
MAX_GETCFILTERS_SIZE = 1000

# The most blocks one `getcfheaders` may ask the filter hashes of, Core's
# src/net_processing.cpp again and BIP157's "strictly less than 2,000".
# Unchecked in `GetCFHeaders` for the reason above -- and checked in
# `CFHeaders`, which is where the same number is a count rather than a
# range: "FilterHashesLength MUST NOT be greater than 2,000", read off
# the payload before the loop that allocates on it.
MAX_GETCFHEADERS_SIZE = 2000

# The block height interval between the filter headers a `cfcheckpt`
# carries, Core's src/index/blockfilterindex.h: "Interval between compact
# filter checkpoints. See BIP 157." BIP157 spells the same rule as "the
# block height is a multiple of 1,000 greater than 0", which is what
# `CFCheckpt.heights` reads off the vector.
#
# An interval and not a bound, which is why nothing here caps that
# vector: what bounds it in the BIP is the length of the chain.
CFCHECKPT_INTERVAL = 1000

# The widest transaction index a BIP152 compact block can name, and with
# it the most transactions such a block can be of: Core's
# src/blockencodings.h, where `PrefilledTransaction::index` and the
# element of `BlockTransactionsRequest`'s `std::vector<uint16_t> indexes`
# are sixteen bits, and where the same bound is spelled out twice --
# `DifferenceFormatter::Unser` throws "differential value overflow" on a
# running index past it, and `CBlockHeaderAndShortTxIDs`'s deserializer
# throws "indexes overflowed 16 bits" on a `BlockTxCount()` past it.
#
# **The name is this library's, where every other name here is Core's**,
# and saying so is better than a citation that does not exist: Core has
# no constant for this, writing `std::numeric_limits<uint16_t>::max()`
# inline at both checks. One name and not two, because it is one fact --
# a compact block's transaction index is a `uint16_t` -- read once as a
# bound on a value and once as a bound on a count, which is how Core
# reads it as well.
#
# Core applies a second bound on the same count in
# `PartiallyDownloadedBlock::InitData`, `MAX_BLOCK_WEIGHT /
# MIN_SERIALIZABLE_TRANSACTION_WEIGHT`, and it is not published here: at
# a hundred thousand it is the weaker of the two and can never be the one
# that refuses anything, so a constant for it would be a number to keep
# true for nothing. `btclib.block.block` holds that expression already,
# where it bounds a `block` message's own transaction count and where the
# sixteen bits below have no say.
MAX_BLOCK_TX_INDEX = (1 << 16) - 1

# The three lengths BIP434 bounds a `feature` message's two fields by.
# The BIP's own footnote on the two maxima is what those are for: they
# "serve only to bound the volume of the feature message payload,
# particularly as this data will be automatically advertised even to
# peers that do not support the features in question".
#
# The two maxima are Core's names, `MAX_FEATUREID_LENGTH` and
# `MAX_FEATUREDATA_LENGTH` of src/protocol.h, read there through a
# `LIMITED_STRING` and a `LIMITED_VECTOR` that throw before the field is
# built. `MIN_FEATUREID_LENGTH` is Core's test framework's name --
# test/functional/p2p_bip434_feature.py -- for a four its C++ writes
# inline at both the send check and `feature_id.size() < 4`, and the BIP
# says where the four comes from: it "corresponds with a 'BIPx' string
# for BIPs in the range 1-9".
#
# A bound on the octets and not on a value, which is why
# `btclib.p2p.negotiation` refuses a `feature` outside them where it
# parses a `feefilter` outside the money range: BIP434 states these as a
# MUST on the encoding -- "The string length MUST be between 4 and 80,
# inclusive", "The byte-vector size MUST NOT be more than 512 bytes" --
# and Core answers a payload past either with a disconnect.
MIN_FEATUREID_LENGTH = 4
MAX_FEATUREID_LENGTH = 80
MAX_FEATUREDATA_LENGTH = 512

# The most block hashes a `getblocks` or `getheaders` locator may carry,
# Core's src/net_processing.cpp: "The maximum number of entries in a
# locator". Small, and it can be: `LocatorEntries` of src/chain.cpp
# doubles the step back after the first ten entries, so what a hundred
# and one of them span is a chain no height is in sight of. Exceeding it
# is a peer Core disconnects.
MAX_LOCATOR_SZ = 101
