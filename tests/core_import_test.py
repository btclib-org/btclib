# Copyright (c) The btclib developers
#
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.core_import` module.

The oracle is Bitcoin Core's `ProcessDescriptorImport`, in
`src/wallet/rpc/backup.cpp`: every refusal here is one it makes, and the
field names and defaults are the ones its `importdescriptors` help
declares. No value is copied from it -- what is mirrored is a set of
rules, so there is nothing to pin in `tests/_data/README.md` and nothing
to refresh; a rule that changes there is a rule this module gets wrong,
which is what the citations in the module docstring are for.

Every request built here is checked to be json, because that is what it is
for: a dict Python is happy with and `json.dumps` refuses is a request
that fails at the rpc boundary rather than here.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from btclib.core_import import (
    DEFAULT_RANGE,
    NOW,
    account_import_requests,
    import_request,
)
from btclib.descriptors import (
    Descriptor,
    account_descriptors,
    add_checksum,
    from_address,
    parse,
)
from btclib.exceptions import BTClibValueError

# the "abandon abandon ... about" root of BIP39, which BIP84 publishes:
# the same key `tests/bip44_test.py` walks, so the account descriptors
# below are the ones whose addresses are checked against BIP84's vectors
XPRV_ROOT = (
    "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRR"
    "uL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"
)
ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"


def account_pair() -> tuple[Descriptor, Descriptor]:
    """Return the BIP84 account pair of the root key above."""
    return account_descriptors(XPRV_ROOT, "m/84h/0h/0h")


def as_json(request: dict[str, Any]) -> dict[str, Any]:
    """Return the request as it arrives at a node: through json."""
    return json.loads(json.dumps(request))  # type: ignore[no-any-return]


def test_the_account_pair_is_two_requests() -> None:
    """The receiving chain, and the change chain marked internal.

    Which is the whole reason the pair is one function: change imported as
    a receiving chain is money the wallet reports as incoming payments,
    and nothing about the two requests otherwise differs.
    """
    receive, change = account_pair()
    requests = account_import_requests(receive, change)

    assert [as_json(request) for request in requests] == [
        {
            "desc": add_checksum(str(receive)),
            "timestamp": NOW,
            "internal": False,
            "active": True,
            "range": [0, 999],
        },
        {
            "desc": add_checksum(str(change)),
            "timestamp": NOW,
            "internal": True,
            "active": True,
            "range": [0, 999],
        },
    ]
    # the two descriptors differ in the chain step and in nothing else
    assert requests[0]["desc"].replace("/0/*", "/1/*") != requests[1]["desc"]
    assert parse(requests[1]["desc"]).key_expressions[0].der_path == (1,)


def test_the_descriptor_carries_its_checksum() -> None:
    """Core parses an imported descriptor with require_checksum = true.

    Text is taken as well as a `Descriptor`, and a checksum already there
    is verified rather than appended twice -- `add_checksum` being what
    does both.
    """
    receive = account_pair()[0]
    checksummed = add_checksum(str(receive))
    for descriptor in (receive, str(receive), checksummed):
        assert import_request(descriptor)["desc"] == checksummed

    with pytest.raises(BTClibValueError, match="invalid descriptor checksum"):
        import_request(f"{receive!s}#00000000")
    # and text that is no descriptor at all is refused here rather than by
    # the node, which is a rescan away
    with pytest.raises(BTClibValueError, match="unknown descriptor function"):
        import_request("nope(0)")


def test_the_timestamp_is_where_the_rescan_starts() -> None:
    """A number is Unix time and the string is Core's "do not rescan"."""
    receive = account_pair()[0]
    assert import_request(receive)["timestamp"] == "now"
    assert import_request(receive, 1455191478)["timestamp"] == 1455191478
    # 0 is a whole-chain rescan, which is a caller's decision and not a
    # default: it is passed through as given
    assert import_request(receive, 0)["timestamp"] == 0


def test_an_active_descriptor_must_be_ranged() -> None:
    """Core's own rule: an unranged descriptor is no source of addresses.

    So a watch of one script is imported with active=False, which is what
    `addr()` and any fixed-key descriptor take.
    """
    single = from_address(ADDRESS)
    with pytest.raises(BTClibValueError, match="active descriptor must be ranged"):
        import_request(single)

    request = import_request(single, active=False, key_range=None)
    assert as_json(request) == {
        "desc": add_checksum(single),
        "timestamp": NOW,
        "internal": False,
        "active": False,
    }
    assert "range" not in request


def test_a_range_belongs_to_a_ranged_descriptor() -> None:
    """And it is inclusive at both ends, as Core reads it."""
    receive = account_pair()[0]
    assert import_request(receive, key_range=(5, 20))["range"] == [5, 20]
    assert import_request(receive)["range"] == list(DEFAULT_RANGE)
    # None leaves the field out, which makes Core fall back to its keypool
    # size with a warning -- allowed, and only for an unranged descriptor
    assert "range" not in import_request(receive, active=False, key_range=None)

    with pytest.raises(BTClibValueError, match="unranged descriptor takes no range"):
        import_request(from_address(ADDRESS), active=False)
    for key_range in ((5, 1), (-1, 5)):
        with pytest.raises(BTClibValueError, match="invalid range"):
            import_request(receive, key_range=key_range)


def test_next_index_is_inside_the_range() -> None:
    """Where an active ranged descriptor hands out its next address."""
    receive = account_pair()[0]
    assert import_request(receive, key_range=(0, 20), next_index=5)["next_index"] == 5
    assert "next_index" not in import_request(receive, key_range=(0, 20))

    with pytest.raises(BTClibValueError, match=r"next_index 21 is not in \[0, 20\]"):
        import_request(receive, key_range=(0, 20), next_index=21)
    with pytest.raises(BTClibValueError, match="next_index without a range"):
        import_request(
            from_address(ADDRESS), active=False, key_range=None, next_index=0
        )


def test_a_label_goes_with_neither_change_nor_a_range() -> None:
    """Core refuses both, and a ranged descriptor is what an account is."""
    receive = account_pair()[0]
    with pytest.raises(BTClibValueError, match="ranged descriptor takes no label"):
        import_request(receive, label="account")
    # internal is the mark and not the descriptor: what a request says is
    # change is what Core keeps out of its incoming payments
    with pytest.raises(BTClibValueError, match="change descriptor takes no label"):
        import_request(
            from_address(ADDRESS),
            active=False,
            key_range=None,
            internal=True,
            label="account",
        )

    labelled = import_request(
        from_address(ADDRESS), active=False, key_range=None, label="cold"
    )
    assert labelled["label"] == "cold"
    # an empty label is no label: Core takes "" as the default and a field
    # carrying it would be a label on a descriptor that has none
    assert "label" not in import_request(
        from_address(ADDRESS), active=False, key_range=None
    )


def test_a_multipath_descriptor_is_the_pair_instead() -> None:
    """Core takes one; btclib splits one, and says which function does it.

    `parse` refuses a `<a;b>` step outright, so a request cannot be built
    around one here: what this module has is the two objects, which say the
    same thing as the one Core would read.
    """
    receive, change = account_pair()
    multipath = str(receive).replace("/0/*", "/<0;1>/*")
    with pytest.raises(BTClibValueError, match="multipath key expression"):
        import_request(multipath)

    requests = account_import_requests(receive, change)
    assert [request["internal"] for request in requests] == [False, True]


def test_the_pair_passes_its_arguments_through() -> None:
    """One timestamp, one range, one active flag, for both chains."""
    receive, change = account_pair()
    requests = account_import_requests(
        receive, change, 1455191478, active=False, key_range=(3, 8)
    )
    for request in requests:
        assert request["timestamp"] == 1455191478
        assert request["active"] is False
        assert request["range"] == [3, 8]
