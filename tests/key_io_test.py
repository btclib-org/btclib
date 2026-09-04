# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Core's key_io vectors, over addresses and WIFs.

The vectors are Core's `src/test/data/key_io_valid.json` and
`key_io_invalid.json`, entire and byte for byte; tests/_data/README.md
pins the revision of each.

What they bring that `b58_test.py` and `b32_test.py` do not is an oracle
btclib did not write. Those two carry values this project produced, so a
round trip through them agrees with itself by construction; here the
scriptPubKey of an address, and the key behind a WIF, are Core's answer.

One module for the two files, rather than one per entry point they
reach. A row is a bare string with no field saying which encoding it
uses, so the reader that decides is the same reader `b58` (twice over,
an address and a WIF being two of its own functions), `b32` and
`ScriptPubKey.from_address` would each need, and splitting the files
would write it four times while leaving no module able to say what the
whole of either file covers. The invalid half makes that plain: what it
asserts is that *all four* refuse the string, which is not a claim any
one of those modules could hold.
"""

from __future__ import annotations

import pytest
from bitcoin_core_rpc import network_from_chain

from btclib import b32, b58
from btclib.exceptions import BTClibValueError
from btclib.network import network_type_from_network
from btclib.script import ScriptPubKey
from tests import load, vector_id

# the `chain` of each vector is Core's name for it, as its `-chain=`
# argument spells it, and btclib's name is what the encoders here take:
# `network_from_chain` is the pair, which lives with the rest of
# Core's vocabulary in the module that speaks Core's protocol -- and
# imports nothing of btclib, so a key-encoding test reads it without
# acquiring `btclib.fetch`.
#
# It raises on a name it does not know, which is the property wanted at
# collection time: a chain Core adds to this file later stops the run
# naming itself, rather than reaching an encoder as a network btclib has
_VALID = load("_data", "key_io_valid.json")

ADDRESS_VECTORS = [
    pytest.param(
        string,
        hexed,
        network_from_chain(meta["chain"]),
        id=vector_id(index, string),
    )
    for index, (string, hexed, meta) in enumerate(_VALID)
    if not meta["isPrivkey"]
]

WIF_VECTORS = [
    pytest.param(
        string,
        hexed,
        network_from_chain(meta["chain"]),
        meta["isCompressed"],
        id=vector_id(index, string),
    )
    for index, (string, hexed, meta) in enumerate(_VALID)
    if meta["isPrivkey"]
]

# `tryCaseFlip` marks the bech32 rows, the encoding being the only one of
# the two that is case insensitive
CASE_FLIP_VECTORS = [
    pytest.param(string, hexed, id=vector_id(index, string))
    for index, (string, hexed, meta) in enumerate(_VALID)
    if meta.get("tryCaseFlip")
]

REFUSED_VECTORS = [
    pytest.param(string, id=vector_id(index, string))
    for index, (string,) in enumerate(load("_data", "key_io_invalid.json"))
]


@pytest.mark.parametrize("address, script_pub_key, network", ADDRESS_VECTORS)
def test_address_script(address: str, script_pub_key: str, network: str) -> None:
    """The address decodes to the scriptPubKey Core encodes it from."""
    spk = ScriptPubKey.from_address(address)
    assert spk.script.hex() == script_pub_key
    # the network *type*, not the name: see test_address_network below
    assert network_type_from_network(spk.network) == network_type_from_network(network)


@pytest.mark.parametrize("address, script_pub_key, network", ADDRESS_VECTORS)
def test_address_network(address: str, script_pub_key: str, network: str) -> None:
    """Which chain the address itself can name, which is not all of them.

    The test networks share one pair of base58 version bytes, and all but
    regtest share the hrp `tb`, so the reverse lookup answers with the
    first network holding the value: "testnet" for a testnet4, signet or
    base58 regtest string alike (issue #207). `bcrt` is the one test
    prefix that is nobody else's. Core has the same ambiguity and
    resolves it from the chain the node was started on, which is not in
    the string either -- so this is what the encoding carries, not a
    disagreement about what it means.
    """
    if network == "mainnet":
        expected = "mainnet"
    elif address.startswith("bcrt1"):
        expected = "regtest"
    else:
        expected = "testnet"
    assert ScriptPubKey.from_address(address).network == expected


@pytest.mark.parametrize("address, script_pub_key, network", ADDRESS_VECTORS)
def test_address_payload(address: str, script_pub_key: str, network: str) -> None:
    """The codec layer reads a payload and writes the address back.

    `b58` and `b32` are what `ScriptPubKey.from_address` calls, so the
    script above already goes through them; asked directly they answer a
    payload rather than a script, and re-encoding that payload on the
    chain the metadata names is the round trip belonging to this layer.
    """
    if b32.is_segwit_prefixed(address):
        wit_ver, wit_prg, _ = b32.witness_from_address(address)
        assert b32.address_from_witness(wit_ver, wit_prg, network) == address
    else:
        script_type, h160, _ = b58.h160_from_address(address)
        assert b58.address_from_h160(script_type, h160, network) == address


@pytest.mark.parametrize("address, script_pub_key, network", ADDRESS_VECTORS)
def test_address_from_script(address: str, script_pub_key: str, network: str) -> None:
    """Core's scriptPubKey renders back to Core's address, every row of it.

    Six types answer for the 54: p2pkh, p2sh, p2wpkh, p2wsh, p2tr, and
    `witness_unknown` for the eight rows whose witness version is 2, 3 or
    16. That last one is why there is no "renders to nothing" branch
    here: a witness program btclib cannot spend still has an address, and
    `b32` writes any version 0 to 16 (issue #251).
    """
    assert ScriptPubKey(script_pub_key, network).address == address


@pytest.mark.parametrize("address, script_pub_key", CASE_FLIP_VECTORS)
def test_address_case_flip(address: str, script_pub_key: str) -> None:
    """`tryCaseFlip`: bech32 in upper case is the same address."""
    assert ScriptPubKey.from_address(address.upper()).script.hex() == script_pub_key


@pytest.mark.parametrize("wif, prv_key, network, compressed", WIF_VECTORS)
def test_wif(wif: str, prv_key: str, network: str, compressed: bool) -> None:
    """The key Core encoded, its compression flag, and the WIF written back."""
    data = b58.prv_key_data_from_wif(wif, network)
    assert f"{data.q:064x}" == prv_key
    assert data.compressed == compressed
    assert data.network == network
    assert b58.wif_from_prv_key(data.q, network, compressed) == wif


@pytest.mark.parametrize("wif, prv_key, network, compressed", WIF_VECTORS)
def test_wif_without_a_network(
    wif: str, prv_key: str, network: str, compressed: bool
) -> None:
    """What the version byte alone says, which is less than Core's chain.

    0x80 is mainnet's and 0xef is testnet's, regtest's, signet's and
    testnet4's alike, so a WIF read without a network argument answers
    "testnet" for every one of them -- the oldest network holding the
    prefix, issue #207 again. Naming the chain is what the argument above
    is for, and passing it is not a workaround: `_wif_network` checks the
    prefix against that network rather than comparing lookup names, so
    every one of the sixteen rows is accepted on the chain Core names.
    Nothing else moves -- the key and the compression flag are the
    payload, and the payload is unambiguous.
    """
    data = b58.prv_key_data_from_wif(wif)
    assert f"{data.q:064x}" == prv_key
    assert data.compressed == compressed
    assert data.network == ("mainnet" if network == "mainnet" else "testnet")


@pytest.mark.parametrize("string", REFUSED_VECTORS)
def test_refused(string: str) -> None:
    """All four entry points turn the string down.

    Four and not one, because a string arrives without a label: an
    application handed one of these has no way to know it was meant as
    an address rather than as a key, and tries what it has. A refusal
    from `ScriptPubKey.from_address` is worth nothing if `b58` then
    accepts the same bytes as a WIF.

    BTClibValueError covers `NotAPrvKeyError` and `InvalidPrvKeyError`,
    which is the whole of the contract here: the string is refused, and
    which of the two reasons a private key path gives for it is that
    path's business.
    """
    with pytest.raises(BTClibValueError):
        ScriptPubKey.from_address(string)
    with pytest.raises(BTClibValueError):
        b58.h160_from_address(string)
    with pytest.raises(BTClibValueError):
        b32.witness_from_address(string)
    with pytest.raises(BTClibValueError):
        b58.prv_key_data_from_wif(string)
