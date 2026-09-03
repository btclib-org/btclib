# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BOLT9: the assigned Lightning feature flags.

https://github.com/lightning/bolts/blob/master/09-features.md

Feature bits are assigned in pairs, the odd bit of a pair optional and
the even one compulsory, so a reader that meets a bit it does not know
must fail on the even one and may ignore the odd one -- "it's ok to be
odd". Answering that is a lookup in BOLT9's own assignment table, which
is the whole of this module: BOLT11's `9` field, BOLT1's `init` message
and BOLT7's announcements each carry a feature vector, and the rule for
reading one is the same in all three.

**A bit is known here when BOLT9 assigns it, whichever fields its Context
column names.** That column says where a feature may appear -- `9` is a
BOLT11 invoice -- and reading it as the criterion refuses invoices the
BOLT itself calls valid: its "supports features 8, 14 and 99" example
sets two even bits, 8 (`var_onion_optin`) and 14 (`payment_secret`),
whose Context column is empty.

**A bit this table names is one a reader can look up, not one a payer
implements.** `unknown_even_bits` is the codec's half of the rule -- an
even bit nothing has been told how to support -- and a wallet acting on
an invoice takes the other half itself, checking the assigned even bits
against what it has implemented, with `FEATURE_NAMES` as its table too.

**A feature's dependencies are the features BOLT9 says a vector setting
it must set too**, listed in the same table's Dependencies column, and
the BOLT's own rationale is that setting them is what makes a feature
vector well-formed. `unmet_dependencies` answers that from the table
alone, so it is the codec's half by the same division: nothing about it
asks what the reader supports. A feature counts as set where either bit
of its pair is, the odd half being the optional way of stating it.

The table is a copy of a document that grows, pinned at the revision
`tests/_data/README.md` records for it beside the vendored files, so a
pair assigned upstream after that revision reads as unknown here until
the pin moves. `.github/workflows/vendored-vectors.yml` reads that file
weekly and opens an issue where a pin is no longer upstream's tip.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from btclib.alias import Integer
from btclib.exceptions import BTClibValueError
from btclib.utils import int_from_integer

__all__ = [
    "FEATURE_DEPENDENCIES",
    "FEATURE_NAMES",
    "unknown_even_bits",
    "unmet_dependencies",
]

# BOLT9's table, transcribed: the even bit of each assigned pair, and the
# name the BOLT gives that pair. Every gap in the numbering is a gap in
# that table
_feature_names: dict[int, str] = {
    0: "option_data_loss_protect",
    4: "option_upfront_shutdown_script",
    6: "gossip_queries",
    8: "var_onion_optin",
    10: "gossip_queries_ex",
    12: "option_static_remotekey",
    14: "payment_secret",
    16: "basic_mpp",
    18: "option_support_large_channel",
    22: "option_anchors",
    24: "option_route_blinding",
    26: "option_shutdown_anysegwit",
    28: "option_dual_fund",
    34: "option_quiesce",
    36: "option_attribution_data",
    38: "option_onion_messages",
    40: "zero_fee_commitments",
    42: "option_provide_storage",
    44: "option_channel_type",
    46: "option_scid_alias",
    48: "option_payment_metadata",
    50: "option_zeroconf",
    60: "option_simple_close",
    62: "option_splice",
    66: "option_onion_messages_only_channels",
}

# a mapping and not a dict, the way network.NETWORKS is one: a caller
# reads this table to name a bit or to ask whether it is assigned, and an
# entry added at run time would be an assignment BOLT9 has not made
FEATURE_NAMES: Mapping[int, str] = MappingProxyType(_feature_names)

# the Dependencies column of that same table, as the even bit of a pair
# and the even bits of the pairs its cell names. A cell naming nothing is
# no entry here, so a feature absent from this mapping depends on nothing
_feature_dependencies: dict[int, tuple[int, ...]] = {
    16: (14,),  # basic_mpp -> payment_secret
    40: (44,),  # zero_fee_commitments -> option_channel_type
    50: (46,),  # option_zeroconf -> option_scid_alias
    60: (26,),  # option_simple_close -> option_shutdown_anysegwit
    66: (38,),  # option_onion_messages_only_channels -> option_onion_messages
}

FEATURE_DEPENDENCIES: Mapping[int, tuple[int, ...]] = MappingProxyType(
    _feature_dependencies
)


def _bit_vector(features: Integer) -> int:
    """Return `features` as an int, refusing a negative one.

    A feature vector is a string of bits and has no sign, where
    `int_from_integer` reads one.
    """
    value = int_from_integer(features)
    if value < 0:
        raise BTClibValueError(f"negative feature vector: {value}")
    return value


def _walk_dependencies(
    dependencies: Mapping[int, tuple[int, ...]], value: int
) -> tuple[tuple[int, int], ...]:
    """Return the pairs of `dependencies` that `value` leaves unset.

    The walk is transitive: a feature the vector must set for one it does
    set is itself asked for, so a chain through the table is followed to
    its end. What ends the walk is the table having no cycle, and
    `tests/bolt9_test.py` is what holds BOLT9's own to that.
    """
    unmet: set[tuple[int, int]] = set()
    pending = [bit for bit in dependencies if value >> bit & 0b11]
    while pending:
        bit = pending.pop()
        for required in dependencies.get(bit, ()):
            if not value >> required & 0b11:
                unmet.add((bit, required))
                pending.append(required)
    return tuple(sorted(unmet))


def unknown_even_bits(features: Integer) -> tuple[int, ...]:
    """Return the even bits `features` sets that BOLT9 does not assign.

    Lowest first, and never an odd bit: that is the half a reader may
    ignore, whether or not the table names it.
    """
    value = _bit_vector(features)
    return tuple(
        bit
        for bit in range(0, value.bit_length(), 2)
        if value >> bit & 1 and bit not in FEATURE_NAMES
    )


def unmet_dependencies(features: Integer) -> tuple[tuple[int, int], ...]:
    """Return what `features` depends on and does not set, lowest first.

    Each pair is a feature the vector states and one BOLT9's Dependencies
    column requires beside it, transitively: a dependency's own
    dependencies come back too. Either bit of a pair states its feature,
    so the optional half meets a dependency as the compulsory half does.
    """
    return _walk_dependencies(FEATURE_DEPENDENCIES, _bit_vector(features))
