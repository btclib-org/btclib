# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.tx_out` module."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from btclib.exceptions import BTClibValueError
from btclib.script import ScriptPubKey
from btclib.tx import Tx, TxOut
from tests.conftest import JsonGolden


def test_tx_out() -> None:
    """Round-trip serialization, dict and address forms of an output."""
    tx_out = TxOut(0, b"")
    assert tx_out.value == 0
    assert tx_out.script_pub_key.script == b""
    assert tx_out.script_pub_key.type == "unknown"
    assert tx_out.script_pub_key.network == "mainnet"
    assert tx_out.script_pub_key.addresses == [""]
    assert tx_out.nValue == tx_out.value
    assert tx_out.scriptPubKey == tx_out.script_pub_key.script
    assert tx_out == TxOut.parse(tx_out.serialize())
    assert tx_out == TxOut.from_dict(tx_out.to_dict())

    value = 3259343370
    script = "0020ed8e9600561000f722bd26e850be7d80f24d174fabeff98baef967325e2b5a86"
    tx_out = TxOut(value, script)
    assert tx_out.value == value
    assert tx_out.script_pub_key.script.hex() == script
    assert tx_out.script_pub_key.type == "p2wsh"
    assert tx_out.script_pub_key.network == "mainnet"
    addr = "bc1qak8fvqzkzqq0wg4aym59p0nasrey696040hlnzawl9nnyh3tt2rqzgmhmv"
    assert tx_out.script_pub_key.addresses == [addr]
    assert tx_out.nValue == tx_out.value
    assert tx_out.scriptPubKey == tx_out.script_pub_key.script
    assert tx_out == TxOut.parse(tx_out.serialize())
    assert tx_out == TxOut.from_dict(tx_out.to_dict())
    assert tx_out == TxOut.from_address(
        tx_out.value, tx_out.script_pub_key.addresses[0]
    )


def test_frozen() -> None:
    """Verify TxOut is frozen all the way down, and hashable with it."""
    tx_out = TxOut(1, "0014751e76e8199196d454941c45d1b3a323f1433bd6")

    with pytest.raises(FrozenInstanceError):
        tx_out.value = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        tx_out.script_pub_key = ScriptPubKey(b"")  # type: ignore[misc]

    # and not merely skin-deep: freezing a dataclass is shallow, so were
    # Script a plain dataclass the script could be rebound *through* a
    # frozen TxOut -- corrupting whatever else held that ScriptPubKey,
    # which is the whole class of bug issue 139 is about. Script and
    # ScriptPubKey are frozen too (issue 165)
    with pytest.raises(FrozenInstanceError):
        tx_out.script_pub_key.script = b""  # type: ignore[misc]
    assert tx_out.script_pub_key.script != b""

    # frozen buys the generated __hash__, and it reaches the ScriptPubKey
    # field: an unhashable one made hashing the TxOut a TypeError, which
    # is issue 416. Equal outputs hash equal, so a TxOut is the value of
    # the dict an OutPoint keys
    same = TxOut(1, "0014751e76e8199196d454941c45d1b3a323f1433bd6")
    assert same == tx_out
    assert hash(same) == hash(tx_out)
    assert len({tx_out, same, TxOut(2, tx_out.script_pub_key)}) == 2


def test_invalid_tx_out() -> None:
    """Refuse a negative satoshi amount."""
    with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
        script = "0020ed8e9600561000f722bd26e850be7d80f24d174fabeff98baef967325e2b5a86"
        TxOut(-1, script)


def test_an_eight_byte_value_round_trips_and_is_refused() -> None:
    """The octets survive an unchecked round trip, and validation refuses them.

    Every amount a valid output carries is below MoneyRange, hence below
    2^63, where a signed and an unsigned reading of the field agree -- so
    the octets that tell the two apart reach the conversion only with the
    check off. btclib reads the field as Core's `CAmount` does, signed,
    settling issue 388: the highest bit set parses as -1, not as a
    satoshi count twice MAX_MONEY, and the buffer comes back byte for
    byte, so one buffer stays one object rather than two. The checked
    parse refuses the amount either way, negative or merely too large.
    """
    highest_bit_set = b"\xff" * 8 + b"\x00"  # the value, then an empty script

    tx_out = TxOut.parse(highest_bit_set, check_validity=False)
    assert tx_out.value == -1
    assert tx_out.serialize(check_validity=False) == highest_bit_set

    with pytest.raises(BTClibValueError, match="invalid satoshi amount: "):
        TxOut.parse(highest_bit_set)


def test_tx_out_from_address() -> None:
    """Verify from_address keeps the address and infers the network."""
    address = "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej"
    assert TxOut.from_address(0, address).script_pub_key.addresses == [address]
    assert TxOut.from_address(0, address).script_pub_key.network == "mainnet"
    address = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
    assert TxOut.from_address(0, address).script_pub_key.addresses == [address]
    assert TxOut.from_address(0, address).script_pub_key.network == "testnet"


def test_dataclasses_json_dict(json_golden: JsonGolden) -> None:
    """Round-trip a parsed output's dict, held to the committed json."""
    fname = "d4f3c2c3c218be868c77ae31bedb497e2f908d6ee5bbbe91e4933e6da680c970.bin"
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as binary_file_:
        temp = Tx.parse(binary_file_.read())

    tx_out_data = temp.vout[0]

    # dataclass
    assert isinstance(tx_out_data, TxOut)

    # Tx to/from dict
    tx_out_dict = tx_out_data.to_dict()
    assert isinstance(tx_out_dict, dict)
    assert tx_out_data == TxOut.from_dict(tx_out_dict)

    # against the json committed beside this module, not written to it
    json_golden("tx_out.json", tx_out_dict)


def test_script_pub_key_is_rendered_as_asm_and_hex() -> None:
    """Core's shape on the way out, and both shapes on the way in.

    `scriptPubKey` gets the rendering `scriptSig` gets, because the two
    are the two scripts of one transaction and `Tx.to_dict` would
    otherwise print them in two different shapes.
    """
    script = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    tx_out = TxOut(1, script)

    dict_ = tx_out.to_dict()
    assert dict_["scriptPubKey"] == {
        "asm": "OP_0 751E76E8199196D454941C45D1B3A323F1433BD6",
        "hex": script,
    }
    assert TxOut.from_dict(dict_) == tx_out

    # the shape to_dict wrote before it wrote that one
    assert TxOut.from_dict({**dict_, "scriptPubKey": script}) == tx_out

    with pytest.raises(BTClibValueError, match="asm does not match hex: "):
        TxOut.from_dict({**dict_, "scriptPubKey": {"asm": "OP_1", "hex": script}})


def test_req_sigs_is_gone() -> None:
    """As it is gone from Bitcoin Core, since v22 (bitcoin/bitcoin#20286).

    It answered for a bare multisig and for nothing else, so btclib's was
    a literal `None` in every case: a key whose value was a constant, read
    as "signatures needed to spend this" by anyone who trusted the name.
    """
    tx_out = TxOut(1, "0014751e76e8199196d454941c45d1b3a323f1433bd6")
    assert "reqSigs" not in tx_out.to_dict()

    # a dict that still carries it is read all the same: from_dict never
    # looked at the key, so dropping it breaks no stored dict
    assert TxOut.from_dict({**tx_out.to_dict(), "reqSigs": None}) == tx_out


def test_a_pre_built_script_pub_key_is_validated_as_octets_are() -> None:
    """The object branch of __init__ asks what octets are asked (issue 684).

    A `TxOut` carries a script into a `Tx`'s outputs, a `Block`'s
    transactions and `PsbtIn.witness_utxo`, and one that passes its own
    `assert_valid` is taken as sound by all three. What is asked is the
    network name and that the script is bytes -- not that the script
    parses, which `Script.assert_valid` explains nothing asks, five
    transactions in blocks carrying scripts a parse refuses.

    The sibling constructors were audited with it and need nothing:
    `Tx.assert_valid` walks every `TxIn` and `TxOut`, `Block.assert_valid`
    the header and every transaction, `PsbtIn.assert_valid` both utxo
    fields, and `PsbtOut.assert_valid` each of its own. `OutPoint` and
    `TxIn` are the exceptions `src/btclib/utils.py` documents: their fields are
    the widths the parse enforces, so the check is unreachable by design.
    """
    bad = ScriptPubKey(b"\x51", "notanetwork", check_validity=False)
    err_msg = "unknown network: 'notanetwork'"

    with pytest.raises(BTClibValueError, match=err_msg):
        TxOut(1000, bad)

    # check_validity=False defers the question, and asking it later gets
    # the same answer: the pair is what a caller building a TxOut by hand
    # and validating it afterwards writes, and it used to pass what the
    # constructor alone refused
    tx_out = TxOut(1000, bad, check_validity=False)
    with pytest.raises(BTClibValueError, match=err_msg):
        tx_out.assert_valid()

    # and there is no third case, the class being frozen: a field
    # reassigned behind either check is what `test_frozen` above refuses
