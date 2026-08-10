# Copyright (c) The btclib developers
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

The replies read back are Core's too, `listdescriptors` and
`importdescriptors` as their help declares them; what a node really
answers, and what it does with a range it was asked for, is
`tests/integration/regtest_test.py`, where a node is what says so.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from btclib.core_import import (
    DEFAULT_RANGE,
    NOW,
    account_import_requests,
    assert_imported,
    import_request,
    watched_range,
    widened_range,
)
from btclib.descriptors import (
    Descriptor,
    account_descriptors,
    add_checksum,
    from_address,
    parse,
)
from btclib.exceptions import BTClibRuntimeError, BTClibValueError

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


def test_the_timestamp_is_a_number_or_the_word_now() -> None:
    """`GetImportTimestamp` takes those two and refuses every other value.

    Core compares the string against "now" and answers `Expected number
    or "now" timestamp value for key` to anything else, which fails the
    whole request: the case of the letters is the whole difference
    between a working import and an rpc error after the descriptors were
    built.

    A bool is refused for the reason every integer field of the library
    refuses one: `True` is an `int` to Python, and Core reads a json
    boolean as neither a number nor a string.
    """
    receive = account_pair()[0]
    for timestamp in ("NOW", "Now", "yesterday", "", "1455191478", True):
        with pytest.raises(BTClibValueError, match="expected a number"):
            import_request(receive, timestamp)


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


def test_both_ends_of_the_range_are_bounded_as_core_bounds_them() -> None:
    """`ParseDescriptorRange`'s two bounds, on the widths either side of them.

    `high >> 31` is "End of range is too high" and `high >= low + 1000000`
    is "Range is too large", so 2**31 - 1 is the highest end and a million
    indexes the widest span -- both of them accepted here, and the next
    value along refused. Core's own keypool default is a thousand, so what
    these catch is a range computed wrongly rather than one meant.
    """
    receive = account_pair()[0]

    top = 2**31 - 1
    assert import_request(receive, key_range=(top - 1, top))["range"] == [top - 1, top]
    with pytest.raises(BTClibValueError, match="end of range is too high"):
        import_request(receive, key_range=(0, 2**31))

    widest = 999_999
    assert import_request(receive, key_range=(0, widest))["range"] == [0, widest]
    assert import_request(receive, key_range=(7, 7 + widest))["range"] == [7, 1_000_006]
    with pytest.raises(BTClibValueError, match="range is too large: 1000001 indexes"):
        import_request(receive, key_range=(0, 1_000_000))
    # the span and not the end: a range high up is refused for its width
    with pytest.raises(BTClibValueError, match="range is too large"):
        import_request(receive, key_range=(1000, 1000 + 1_000_000))


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


def listed(*entries: dict[str, Any]) -> dict[str, Any]:
    """Return the entries as the reply `listdescriptors` wraps them in.

    A wallet name and the list, which is the shape of the answer and the
    reason the whole reply is what is passed: a caller hands on what the
    node said rather than the one field of it that is read.
    """
    return {"wallet_name": "watcher", "descriptors": list(entries)}


def entry(
    descriptor: Descriptor | str, key_range: list[int] | None = None, **fields: Any
) -> dict[str, Any]:
    """Return one entry of that reply, checksummed as Core echoes it."""
    text = descriptor if isinstance(descriptor, str) else str(descriptor)
    listing: dict[str, Any] = {
        "desc": add_checksum(text),
        "timestamp": 1455191478,
        "active": False,
        **fields,
    }
    if key_range is not None:
        listing["range"] = key_range
        listing["next"] = 0
    return listing


def test_a_descriptor_the_wallet_does_not_hold_has_no_watched_range() -> None:
    """Which is the descriptor about to be imported for the first time."""
    receive, change = account_pair()
    assert watched_range(receive, listed()) is None
    assert watched_range(receive, listed(entry(change, [0, 999]))) is None


def test_the_watched_range_is_matched_past_the_checksum_and_the_hardening() -> None:
    """Core echoes the checksum it computed and the symbol it was given.

    A wallet imported by another tool can hold the very same descriptor
    spelled with apostrophes: read as one never seen, it would be imported
    again over a range Core refuses to narrow, which is a failed import
    rather than a wrong number -- and the failure is of the whole request.
    """
    receive = account_pair()[0]
    apostrophes = str(receive).replace("h/", "'/")
    assert apostrophes != str(receive)

    assert watched_range(receive, listed(entry(apostrophes, [0, 999]))) == (0, 999)
    # the text of a descriptor asks the same question as the object does,
    # a checksum on either side being no part of the comparison
    assert watched_range(str(receive), listed(entry(receive, [0, 5]))) == (0, 5)
    # and an entry this library would refuse to parse is another
    # descriptor's, not an answer to the question asked
    multipath = str(receive).replace("/0/*", "/<0;1>/*")
    assert watched_range(receive, listed(entry(multipath, [0, 999]))) is None


def test_an_unranged_entry_watches_one_script_and_no_range() -> None:
    """So there is nothing for the next import to have to include."""
    address = from_address(ADDRESS)
    assert watched_range(address, listed(entry(address))) is None


def test_the_watched_range_is_the_union_of_the_entries_that_match() -> None:
    """A wallet can hold one expression twice, as both of its chains.

    `listdescriptors` tells the two apart by `internal`, which Core defines
    for an active descriptor alone, so which entry an import is checked
    against is not always readable: the union is the range that no entry
    can be narrowed by.
    """
    receive = account_pair()[0]
    reply = listed(
        entry(receive, [0, 999], active=True, internal=False),
        entry(receive, [5, 1500], active=True, internal=True),
    )
    assert watched_range(receive, reply) == (0, 1500)


def test_a_first_import_asks_for_the_keypool_core_would_widen_it_to() -> None:
    """A range narrower than the keypool is a range Core overrides.

    Asked for, the reply states which indexes were imported; left to Core,
    the caller has a warning to read and a keypool size to assume.
    """
    assert widened_range((0, 0)) == DEFAULT_RANGE
    assert widened_range((0, 0), None) == DEFAULT_RANGE
    # and a caller wanting more than the keypool gets what it wanted
    assert widened_range((0, 1500)) == (0, 1500)


def test_a_later_import_asks_for_the_union_with_what_is_watched() -> None:
    """Core's refusal is "New range must include current range", avoided here.

    The committed span grows, the wallet's range only grows with it, and an
    import of a span already inside the range is not a narrowing of it.
    """
    assert widened_range((0, 1500), (0, 999)) == (0, 1500)
    assert widened_range((0, 0), (0, 1500)) == (0, 1500)
    assert widened_range((0, 1500), (0, 1500)) == (0, 1500)
    # both ends, an entry imported from an index that is not zero being
    # one this has to include too
    assert widened_range((7, 20), (5, 30)) == (5, 30)
    # a node whose keypool is under Core's default needs no allowance: what
    # it widened to is what is measured, and the union with it is asked for
    assert widened_range((0, 3), (0, 499)) == (0, 499)


def test_the_range_wanted_is_the_one_a_request_would_be_refused_for() -> None:
    """Refused where it is written, and not where min and max hide it.

    An inverted range unioned with the keypool is a valid range and not the
    one asked for, which is a caller's arithmetic gone wrong reported as a
    successful import of something else.
    """
    with pytest.raises(BTClibValueError, match=r"invalid range: \[20, 5\]"):
        widened_range((20, 5))
    with pytest.raises(BTClibValueError, match="end of range is too high"):
        widened_range((0, 2**31))
    with pytest.raises(BTClibValueError, match="range is too large"):
        widened_range((0, 1_000_000))


def test_an_import_the_node_refused_is_not_read_as_one_it_did() -> None:
    """`importdescriptors` reports a refusal inside a reply of its own.

    A wallet that imported nothing goes on answering every balance with
    what it does watch, so the deposit it never heard of is missing from a
    number nobody has reason to doubt: the reply is the one place that says
    so, and the request is what names which descriptor it was.
    """
    requests = account_import_requests(*account_pair())
    assert_imported(requests, [{"success": True}, {"success": True}])
    # warnings are what Core says about a request it did honour
    assert_imported(requests, [{"success": True, "warnings": ["odd"]}] * 2)

    refused: list[dict[str, Any]] = [
        {"success": True},
        {"success": False, "error": {"message": "no"}},
    ]
    with pytest.raises(BTClibRuntimeError, match="import refused for wpkh"):
        assert_imported(requests, refused)
    with pytest.raises(BTClibRuntimeError, match="'message': 'no'"):
        assert_imported(requests, refused)
    # an answer that says nothing is not one that said yes
    with pytest.raises(BTClibRuntimeError, match="import refused"):
        assert_imported(requests, [{}, {}])


def test_a_reply_of_the_wrong_length_answered_something_else() -> None:
    """One answer per request is the shape of the reply, and the check.

    Read in step with anything else, the answers name the wrong
    descriptors -- an import refused for the change chain reported as one
    refused for the receiving chain.
    """
    requests = account_import_requests(*account_pair())
    with pytest.raises(BTClibRuntimeError, match="2 import requests, 1 answers"):
        assert_imported(requests, [{"success": True}])
