# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what `parse`, `serialize`, `to_dict` and `from_dict` take.

CONTRIBUTING.md's "Every public function validates its inputs", at the
boundary where an object meets octets, text or json: a value of a type
the signature does not declare leaves as a `BTClibTypeError`, a value of
a declared type that no valid input carries as a `BTClibValueError`.
Issue #867 is where the family was measured.

**Not the contract `parse_contract_test.py` holds.** That file asks where
the bytes end -- a field is as long as its encoding says, a complete octet
string is one whole object, a caller's stream is the caller's -- and this
one asks what type the argument is. The two are different questions about
the same methods, which is why the walk that finds every one of them is
`tests/__init__.py`'s and neither file's.

**`from_dict` is where the hazard is sharpest**, and it had no gate at
all: it is the json boundary, so its input is whatever a schema mistake
produced, and every one of the twelve walked the mapping before asking
whether it was one. A `None` was "not subscriptable", a `str` was "string
indices must be integers", and a mapping missing a field was a `KeyError`
-- which is neither a `BTClibException` nor a `ValueError`, so a caller
catching either never caught it. `utils.fields_from_json_object` is the
one line that answers both, and `utils.list_from_json_array` the arrays
it walks: `Sequence[Any]` accepts a `str` and a `Mapping`, so an input
handed where the list of them was meant was as many inputs as it had
characters -- issue #856's "annotation that accepts the mistake", at the
boundary that reads a file.

**`to_dict`, `serialize` and `b64encode` mostly have nothing to drive**:
their input is the object, which `check_validity_test.py` and
`built_object_contract_test.py` own between them. The exceptions are the
arguments `_EXTRA_ARGUMENTS` records, and the last test is what keeps
that record honest -- one more added to this family fails here until it
is driven.

**Parametric above the byte boundary, mono-format at it.** `ec` and
`hf` are arguments everywhere arithmetic and protocol take them --
`sign`, `verify`, `key_agg` -- and nowhere in this family: no `parse`
or `serialize` here declares either, and
`test_the_family_takes_no_ec_or_hf` is what turns that from an
agreement into a gate (issue #1084). The reason is not efficiency, and
nothing parametric is given up for it: the *object* keeps its curve
regardless -- `ssa.Sig` declares `ec: Curve = secp256k1` as a field, so
a signature on `ec13_11` is built, validated, signed and verified
exactly as one on secp256k1. What it cannot do is round-trip through a
format that curve was never defined over. The encoding does not name
its curve or its hash function, so `parse(data, ec=...)` would not be
parsing -- it would be decoding under instruction, accepting in
silence a caller who names the wrong one and handing back a
well-formed object built from octets that meant something else. That
is issue #856's "annotation that accepts the mistake", at the one
boundary where the input is a file, a peer or another implementation.

`_EXTRA_ARGUMENTS` records what that rule decided, and does not decide
it -- a data shape in a test, cited as though it were a law during PR
#1079, and it is not one: it maps `(class, method)` to a single string
because no member of the family has needed two, and is changeable to a
tuple the day one does.

`check_validity` is not driven anywhere in this file: it is a flag that
decides whether a check runs rather than what is computed, so it is read
for its truth, and `check_validity_test.py` owns that convention.
`dsa.Sig.parse`'s `strict` is the same kind of flag and the same
exemption, recorded below beside the arguments that are not --
`bool_parameter_test.py` is where that classification is decided, for
every flag in the library and with the reason for each.
"""

from __future__ import annotations

import json
import pkgutil
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from importlib import import_module
from inspect import signature
from typing import Any

import pytest

import btclib
from btclib import bip322, var_bytes, var_int
from btclib.bip21 import Bip21
from btclib.bip32.bip32 import BIP32KeyData
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.block import BasicBlockFilter, Block, BlockHeader
from btclib.descriptors import descriptors, miniscript
from btclib.ecc import bms, dsa, ecies, ssa
from btclib.ecc.borromean import BorromeanSig
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS, Network
from btclib.p2p import (
    Addr,
    AddrV2,
    BlockPayload,
    BlockTxn,
    CFCheckpt,
    CFHeaders,
    CFilter,
    CmpctBlock,
    FeeFilter,
    GetAddr,
    GetBlocks,
    GetBlockTxn,
    GetCFCheckpt,
    GetCFHeaders,
    GetCFilters,
    GetData,
    GetHeaders,
    Headers,
    Inv,
    Inventory,
    Mempool,
    Message,
    NetworkAddress,
    NetworkAddressV2,
    NotFound,
    Ping,
    Pong,
    PrefilledTransaction,
    SendAddrV2,
    SendCmpct,
    SendHeaders,
    TimestampedNetworkAddress,
    TxPayload,
    Verack,
    Version,
    WtxidRelay,
)
from btclib.psbt import Psbt, PsbtIn, PsbtOut
from btclib.psbt.psbt_utils import PSBT_V0, PSBT_V2
from btclib.script import Witness, script, taproot
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests import load_bin, public_classes_with
from tests.psbt import psbt_cases

# a value of no type any of these positions declares. `Any`, because
# every position they are handed to declares something narrower: what
# these tests are about is the caller who has not run mypy
_WRONG_TYPES: tuple[Any, ...] = (None, 1.5, [1, 2])

# and the two iterables that are not a json array: each is walked element
# by element unless it is asked about whole, so what fails is the element
# rather than the argument
_NOT_AN_ARRAY: tuple[Any, ...] = (*_WRONG_TYPES, "ab", {"a": 1})

# and the same list where `None` is a type the position declares, which is
# a statement about the signature rather than an exemption from the rule
_NOT_NONE: tuple[Any, ...] = tuple(w for w in _WRONG_TYPES if w is not None)

_TX_ID = "01" * 32

_TX = Tx(1, 0x12345678, [TxIn(OutPoint(_TX_ID, 0), b"", 0xFFFFFFFF)], [TxOut(1, b"")])
_BLOCK = Block.parse(load_bin("block", "_data", "block_1.bin"))
# a published psbt rather than one built here: what makes the json cases
# worth running is a mapping with something in it, and the BIP174 vectors
# are where a psbt carrying derivations, scripts and signatures comes from
_PSBT = next(
    psbt
    for psbt in (
        Psbt.b64decode(case["encoded psbt"])
        for case in psbt_cases("bip174_test_vectors.json", "valid psbts")
    )
    if any(psbt_in.hd_key_paths for psbt_in in psbt.inputs)
)
# framed rather than encrypted: `ecies.encrypt` takes a block cipher this
# library does not carry, and the framing is all this file is about
_ENVELOPE = ecies.Envelope.from_ciphertext(
    pub_keyinfo_from_prv_key(1)[0], b"\x00" * 16, b"key material"
)


@dataclass(frozen=True)
class _JsonCase:
    """A class with a `to_dict`/`from_dict` pair, and one valid object."""

    label: str
    cls: type[Any]
    obj: Any


# every public class with a json boundary, which the last test is what
# makes a promise: one of these per `from_dict` in the library
_JSON_CASES = (
    _JsonCase("OutPoint", OutPoint, _TX.vin[0].prev_out),
    _JsonCase("TxIn", TxIn, _TX.vin[0]),
    _JsonCase("TxOut", TxOut, _TX.vout[0]),
    _JsonCase("Tx", Tx, _TX),
    _JsonCase("BlockHeader", BlockHeader, _BLOCK.header),
    _JsonCase("Block", Block, _BLOCK),
    _JsonCase("Psbt", Psbt, _PSBT),
    _JsonCase("PsbtIn", PsbtIn, _PSBT.inputs[0]),
    _JsonCase("PsbtOut", PsbtOut, _PSBT.outputs[0]),
    _JsonCase("Witness", Witness, Witness([b"\x51", b"\x52\x53"])),
    _JsonCase("BIP32KeyOrigin", BIP32KeyOrigin, BIP32KeyOrigin("deadbeef", "m/44h/0h")),
    _JsonCase("Network", Network, NETWORKS["mainnet"]),
)

_JSON_IDS = tuple(case.label for case in _JSON_CASES)

# the arrays a `from_dict` walks, one per key: the class, the key, and
# nothing else -- what a wrong value there costs is stated in the test
_JSON_ARRAYS = (
    ("Tx", Tx, _TX, "vin"),
    ("Tx", Tx, _TX, "vout"),
    ("Block", Block, _BLOCK, "transactions"),
    ("Psbt", Psbt, _PSBT, "inputs"),
    ("Psbt", Psbt, _PSBT, "outputs"),
    ("Psbt", Psbt, _PSBT, "bip32_derivs"),
    ("PsbtIn", PsbtIn, _PSBT.inputs[0], "bip32_derivs"),
    ("PsbtOut", PsbtOut, _PSBT.outputs[0], "taproot_hd_key_paths"),
    ("Witness", Witness, Witness([b"\x51"]), "stack"),
)

_ARRAY_IDS = tuple(f"{label}-{key}" for label, _, _, key in _JSON_ARRAYS)

# what reads octets: every `parse` but Bip21's, a URI being text. The
# class and the method name, so that the walk at the end can say which
# decoders are covered
_OCTETS_DECODERS = (
    ("OutPoint.parse", OutPoint, "parse"),
    ("TxIn.parse", TxIn, "parse"),
    ("TxOut.parse", TxOut, "parse"),
    ("Tx.parse", Tx, "parse"),
    ("BlockHeader.parse", BlockHeader, "parse"),
    ("Block.parse", Block, "parse"),
    ("BasicBlockFilter.parse", BasicBlockFilter, "parse"),
    ("Psbt.parse", Psbt, "parse"),
    ("PsbtIn.parse", PsbtIn, "parse"),
    ("PsbtOut.parse", PsbtOut, "parse"),
    ("Witness.parse", Witness, "parse"),
    ("BIP32KeyData.parse", BIP32KeyData, "parse"),
    ("BIP32KeyOrigin.parse", BIP32KeyOrigin, "parse"),
    ("BorromeanSig.parse", BorromeanSig, "parse"),
    ("bms.Sig.parse", bms.Sig, "parse"),
    ("ssa.Sig.parse", ssa.Sig, "parse"),
    ("dsa.Sig.parse", dsa.Sig, "parse"),
    ("ecies.Envelope.parse", ecies.Envelope, "parse"),
    ("Message.parse", Message, "parse"),
    ("NetworkAddress.parse", NetworkAddress, "parse"),
    ("TimestampedNetworkAddress.parse", TimestampedNetworkAddress, "parse"),
    ("Addr.parse", Addr, "parse"),
    ("NetworkAddressV2.parse", NetworkAddressV2, "parse"),
    ("AddrV2.parse", AddrV2, "parse"),
    ("SendAddrV2.parse", SendAddrV2, "parse"),
    ("GetCFilters.parse", GetCFilters, "parse"),
    ("CFilter.parse", CFilter, "parse"),
    ("GetCFHeaders.parse", GetCFHeaders, "parse"),
    ("CFHeaders.parse", CFHeaders, "parse"),
    ("GetCFCheckpt.parse", GetCFCheckpt, "parse"),
    ("CFCheckpt.parse", CFCheckpt, "parse"),
    ("Version.parse", Version, "parse"),
    ("Verack.parse", Verack, "parse"),
    ("GetAddr.parse", GetAddr, "parse"),
    ("Mempool.parse", Mempool, "parse"),
    ("SendHeaders.parse", SendHeaders, "parse"),
    ("WtxidRelay.parse", WtxidRelay, "parse"),
    ("FeeFilter.parse", FeeFilter, "parse"),
    ("Ping.parse", Ping, "parse"),
    ("Pong.parse", Pong, "parse"),
    ("Inventory.parse", Inventory, "parse"),
    ("Inv.parse", Inv, "parse"),
    ("GetData.parse", GetData, "parse"),
    ("NotFound.parse", NotFound, "parse"),
    ("GetBlocks.parse", GetBlocks, "parse"),
    ("GetHeaders.parse", GetHeaders, "parse"),
    ("Headers.parse", Headers, "parse"),
    ("SendCmpct.parse", SendCmpct, "parse"),
    ("PrefilledTransaction.parse", PrefilledTransaction, "parse"),
    ("CmpctBlock.parse", CmpctBlock, "parse"),
    ("GetBlockTxn.parse", GetBlockTxn, "parse"),
    ("BlockTxn.parse", BlockTxn, "parse"),
    ("TxPayload.parse", TxPayload, "parse"),
    ("BlockPayload.parse", BlockPayload, "parse"),
)

_OCTETS_IDS = tuple(label for label, _, _ in _OCTETS_DECODERS)

# and what reads text: the base64 and base58 decoders, and the one
# `parse` whose argument is a string
_TEXT_DECODERS = (
    ("Bip21.parse", Bip21, "parse"),
    ("BIP32KeyData.b58decode", BIP32KeyData, "b58decode"),
    ("Psbt.b64decode", Psbt, "b64decode"),
    ("bms.Sig.b64decode", bms.Sig, "b64decode"),
    ("bip322.Sig.b64decode", bip322.Sig, "b64decode"),
    ("ecies.Envelope.b64decode", ecies.Envelope, "b64decode"),
)

_TEXT_IDS = tuple(label for label, _, _ in _TEXT_DECODERS)

# what any of these methods takes beyond the object it is about, the
# octets or the mapping it reads, and the `check_validity` that
# `check_validity_test.py` owns. Few of them over the whole family,
# which is its shape: the object is the input, and this is everything
# else a caller can get wrong.
#
# Each is driven below except `strict`, which is a flag deciding whether a
# check runs -- Bitcoin Core's IsValidSignatureEncoding, and `dsa.Sig.parse`
# says where it does it -- and is therefore read for its truth, as
# `check_validity` is
_EXTRA_ARGUMENTS = {
    ("btclib.tx.tx.Tx", "serialize"): "include_witness",
    ("btclib.block.block.Block", "serialize"): "include_witness",
    ("btclib.block.block_filter.BasicBlockFilter", "parse"): "block_hash",
    ("btclib.ecc.borromean.BorromeanSig", "parse"): "rsizes",
    ("btclib.psbt.psbt_in.PsbtIn", "serialize"): "psbt_version",
    ("btclib.psbt.psbt_in.PsbtIn", "parse"): "psbt_version",
    ("btclib.psbt.psbt_out.PsbtOut", "serialize"): "psbt_version",
    ("btclib.psbt.psbt_out.PsbtOut", "parse"): "psbt_version",
    ("btclib.ecc.ecies.Envelope", "parse"): "magic",
    ("btclib.ecc.ecies.Envelope", "b64decode"): "magic",
    ("btclib.ecc.dsa.Sig", "parse"): "strict",
    # BIP152 encodes an index as the difference from the one before it,
    # so writing one and reading one back both need that previous index:
    # `btclib.p2p.compact_blocks` is where holding the absolute index and
    # taking the difference at the boundary is argued
    ("btclib.p2p.compact_blocks.PrefilledTransaction", "parse"): "previous_index",
    ("btclib.p2p.compact_blocks.PrefilledTransaction", "serialize"): "previous_index",
}

# the eight names issue #867 measured, which is what the walk runs over,
# split by which of them is handed an encoding: a reader takes one as its
# first argument, a writer starts from the object and takes none
_READERS = ("parse", "from_dict", "b64decode", "b58decode")
_WRITERS = ("serialize", "to_dict", "b64encode", "b58encode")
_FAMILY = (*_READERS, *_WRITERS)

# and the same family where it is a module function rather than a method:
# four codecs with no class between them and the encoding. Each is driven
# on what it converts, which is its first argument
_MODULE_READERS = (
    ("var_int.parse", var_int.parse, "invalid octets type"),
    ("var_bytes.parse", var_bytes.parse, "invalid octets type"),
    ("script.parse", script.parse, "invalid octets type"),
    ("taproot.parse", taproot.parse, "invalid octets type"),
    ("descriptors.parse", descriptors.parse, "invalid descriptor type"),
    ("miniscript.parse", miniscript.parse, "invalid miniscript type"),
)

_MODULE_READER_IDS = tuple(label for label, _, _ in _MODULE_READERS)

# the writers, each with what it converts and what is not one of those.
# A command sequence takes the two iterables that a `Sequence[Command]`
# accepts and a caller never means: `serialize("OP_DUP")` is six
# one-character commands and `serialize(b"\x76")` one integer command per
# byte, which is a script and the wrong one
_MODULE_WRITERS = (
    ("var_int.serialize", var_int.serialize, 1, (None, 1.5, "1", b"\x01")),
    ("var_bytes.serialize", var_bytes.serialize, b"\x01", (None, 1.5, [1, 2])),
    (
        "script.serialize",
        script.serialize,
        ["OP_DUP"],
        (None, 1.5, "OP_DUP", b"\x76", bytearray(b"\x76"), memoryview(b"\x76")),
    ),
    (
        "taproot.serialize",
        taproot.serialize,
        ["OP_DUP"],
        (None, 1.5, "OP_DUP", b"\x76", bytearray(b"\x76"), memoryview(b"\x76")),
    ),
)

_MODULE_WRITER_IDS = tuple(label for label, _, _, _ in _MODULE_WRITERS)

# what those ten take besides the thing they convert, and what drives
# each: five of the six were ungated when this file was written and issue
# #872 is where they were measured. `forbid_zero_size` is the one that is
# driven by nothing, being a flag that decides whether a check runs and
# therefore read for its truth, as `check_validity` is
_MODULE_EXTRA_ARGUMENTS = {
    ("btclib.var_int", "parse"): ["max_size"],
    ("btclib.var_bytes", "parse"): ["forbid_zero_size"],
    ("btclib.script.taproot", "parse"): ["exit_on_op_success"],
    ("btclib.descriptors.descriptors", "parse"): ["network", "prv_keys"],
    ("btclib.descriptors.miniscript", "parse"): ["context", "prv_keys"],
}


def _as_json(obj: Any) -> dict[str, Any]:
    """Return what `to_dict` wrote, round-tripped through json itself.

    Through `json` and not straight from `to_dict`: what these tests
    drive is the boundary a stored file arrives at, and a dict that
    never went through a serializer is one whose tuples are still tuples
    and whose ints are still ints of Python's making.
    """
    dict_: dict[str, Any] = json.loads(json.dumps(obj.to_dict()))
    return dict_


@pytest.mark.parametrize("case", _JSON_CASES, ids=_JSON_IDS)
def test_the_json_round_trip_is_exact(case: _JsonCase) -> None:
    """The fixture is valid, which is what makes a refusal below a finding.

    Without this a case whose object had gone stale would pass every test
    in this file by refusing everything it is handed.
    """
    assert case.cls.from_dict(_as_json(case.obj)) == case.obj


@pytest.mark.parametrize("case", _JSON_CASES, ids=_JSON_IDS)
def test_from_dict_refuses_what_is_no_json_object(case: _JsonCase) -> None:
    """The first rule at the json boundary: a `Mapping` or nothing.

    A `str` is the one worth naming: it is not a mapping and is
    subscriptable, so it reached `dict_["version"]` and left as "string
    indices must be integers" -- a complaint about a builtin, and about
    the key rather than about the argument.
    """
    for wrong in (*_WRONG_TYPES, "a string"):
        with pytest.raises(BTClibTypeError, match="dict type"):
            case.cls.from_dict(wrong)


@pytest.mark.parametrize("case", _JSON_CASES, ids=_JSON_IDS)
def test_from_dict_names_the_field_it_has_not_got(case: _JsonCase) -> None:
    """The second rule: a mapping without the field is a wrong value.

    Every key in turn, and a key `from_dict` ignores -- a transaction's
    txid, a header's difficulty, the psbt's derived "tx" -- is one whose
    absence is no error at all, which is why the assertion is on what a
    failure may be rather than on which keys fail. What must never happen
    is a bare `KeyError` reaching the caller: `exceptions.py`'s guarantee
    is that no public function lets a native exception through, and this
    is the family the guarantee has to hold for.

    The count is asserted too, or a `from_dict` that stopped reading its
    mapping would pass this by never failing.
    """
    dict_ = _as_json(case.obj)
    refused = []
    for key in dict_:
        without = {k: v for k, v in dict_.items() if k != key}
        try:
            case.cls.from_dict(without)
        except BTClibValueError as e:
            refused.append((key, str(e)))
    assert refused, f"{case.label}.from_dict requires none of its fields"
    for key, err_msg in refused:
        assert key in err_msg


@pytest.mark.parametrize("label, cls, obj, key", _JSON_ARRAYS, ids=_ARRAY_IDS)
def test_a_json_array_is_asked_before_it_is_walked(
    label: str, cls: type[Any], obj: Any, key: str
) -> None:
    """A list field, driven with what a schema mistake puts there.

    The two iterables are the point: a `str` is a list of its characters
    and a `Mapping` a list of its keys, so one input handed where the
    array of them was meant was as many inputs as it had characters --
    each refused for what it is not, which reports the wrong mistake.
    `Witness`'s stack is worse than that and was the finding here: its
    constructor reads `stack or []`, so a `None` was a witness of no
    elements rather than an error.
    """
    dict_ = _as_json(obj)
    for wrong in _NOT_AN_ARRAY:
        broken = deepcopy(dict_)
        broken[key] = wrong
        with pytest.raises(BTClibTypeError):
            cls.from_dict(broken)


def test_the_two_fields_from_dict_converts_itself() -> None:
    """The two fields no constructor sees as they were written.

    A header's time and a network's curve. Every other field of every
    `from_dict` here is handed to a constructor, which is where
    `assert_valid` asks about it; these two
    are converted first -- one by `datetime.fromisoformat`, which
    refuses what is not a string with a TypeError of its own and an
    unreadable one with a bare ValueError, and one by a lookup in
    `CURVES`, which answers an unknown name with a `KeyError` and an
    unhashable one with a TypeError about dict keys.
    """
    header = _as_json(_BLOCK.header)
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid time type"):
            BlockHeader.from_dict({**header, "time": wrong})
    with pytest.raises(BTClibValueError, match="invalid time"):
        BlockHeader.from_dict({**header, "time": "the block after genesis"})

    network = _as_json(NETWORKS["mainnet"])
    for wrong in (*_WRONG_TYPES, {"a": 1}):
        with pytest.raises(BTClibTypeError, match="invalid curve name type"):
            Network.from_dict({**network, "curve": wrong})
    with pytest.raises(BTClibValueError, match="unknown curve"):
        Network.from_dict({**network, "curve": "secp256k2"})


def test_a_json_null_is_not_an_amount() -> None:
    """The one field value that arrived through a convention, not a gap.

    `valid_sats_amount` reads `None` as zero, for the caller it was
    written for and with its own reasoning; at the json boundary the same
    value is a field the file has not filled in, and it built an output of
    zero satoshi. Legal -- an OP_RETURN pays one -- so nothing downstream
    refused it and the transaction that came back said something the file
    did not.

    The two spellings a hand-edited file is likelier to carry were refused
    already, which is what made `null` the one worth closing: it is the
    only one json itself produces.
    """
    dict_ = _as_json(_TX.vout[0])
    assert TxOut.from_dict(dict_).value == 1

    with pytest.raises(BTClibValueError, match="null transaction output value"):
        TxOut.from_dict({**dict_, "value": None})
    for wrong in ("", "null"):
        with pytest.raises(BTClibValueError, match="invalid BTC amount"):
            TxOut.from_dict({**dict_, "value": wrong})

    # a missing key is the other question, and the gate above answers it
    with pytest.raises(BTClibValueError, match="missing transaction output field"):
        TxOut.from_dict({k: v for k, v in dict_.items() if k != "value"})

    # and the psbt output, where None is the field being absent and stays
    # a value the boundary takes
    psbt_out = _as_json(_PSBT.outputs[0])
    assert PsbtOut.from_dict({**psbt_out, "amount": None}).amount is None


@pytest.mark.parametrize("label, cls, method", _OCTETS_DECODERS, ids=_OCTETS_IDS)
def test_the_octets_boundary_refuses_what_is_no_octets(
    label: str, cls: type[Any], method: str
) -> None:
    """`bytes_from_octets` is the one coercion, and it is the one refusal."""
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid octets type"):
            getattr(cls, method)(wrong)


@pytest.mark.parametrize("label, cls, method", _TEXT_DECODERS, ids=_TEXT_IDS)
def test_the_text_boundary_refuses_what_is_no_text(
    label: str, cls: type[Any], method: str
) -> None:
    """The same rule where the encoding is text rather than octets.

    Three of these left a native exception: the base64 decoders handed
    what is neither `str` nor `bytes` to `base64` -- "argument should be
    a bytes-like object or ASCII string" -- or to `.strip`, and
    `b58decode` to the cache in front of `base58.decode`, which keys on
    the argument and so refused an unhashable one for being unhashable.
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="type"):
            getattr(cls, method)(wrong)


@pytest.mark.parametrize(
    "label, function, err_msg", _MODULE_READERS, ids=_MODULE_READER_IDS
)
def test_a_codec_that_is_a_function_refuses_a_wrong_type_too(
    label: str, function: Callable[..., Any], err_msg: str
) -> None:
    """The same rule where there is no class between the two sides.

    The four octet codecs went through `bytes_from_octets` already; the
    two descriptor parsers went through nothing, and left "'NoneType'
    object has no attribute 'partition'" and "object of type 'float' has
    no len()".
    """
    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match=err_msg):
            function(wrong)


@pytest.mark.parametrize(
    "label, function, valid, wrong_values", _MODULE_WRITERS, ids=_MODULE_WRITER_IDS
)
def test_a_codec_that_is_a_function_asks_what_it_is_given_to_write(
    label: str,
    function: Callable[..., Any],
    valid: Any,
    wrong_values: tuple[Any, ...],
) -> None:
    """The writing half, where the argument is the thing being converted.

    The valid call is asserted for the reason every case in
    `built_object_contract_test.py` asserts one: a function that refused
    everything would pass the rest of this by refusing these too.
    """
    assert function(valid)

    for wrong in wrong_values:
        with pytest.raises(BTClibTypeError):
            function(wrong)


def test_a_transaction_says_which_serialization_it_is_asked_for() -> None:
    """`include_witness` decides what is computed, so it is a bool.

    The line `built_object_contract_test.py` draws, and the cost of not
    drawing it here is the sharpest there is: read for its truth, a value
    of no boolean type answers the stripped serialization -- which is
    what the transaction id is computed over -- where the wire one was
    asked for.
    """
    assert Tx.parse(_TX.serialize(include_witness=True)) == _TX
    assert _TX.serialize(False) != _TX.serialize(True) or not _TX.is_segwit
    assert Block.parse(_BLOCK.serialize(include_witness=True)) == _BLOCK

    for wrong in (*_WRONG_TYPES, 0, 1):
        with pytest.raises(BTClibTypeError, match="invalid include_witness type"):
            _TX.serialize(wrong)
        with pytest.raises(BTClibTypeError, match="invalid include_witness type"):
            _BLOCK.serialize(wrong)


@pytest.mark.parametrize("cls", [PsbtIn, PsbtOut], ids=["PsbtIn", "PsbtOut"])
def test_a_map_is_written_and_read_as_a_version_that_exists(cls: type[Any]) -> None:
    """`psbt_version` decides which fields a map carries, so it is asked.

    Every version that is not 0 wrote and read the BIP370 fields, so a
    `None`, a 3 or a string was a version 2 map and said nothing -- and
    the psbt they belong to holds its own version to `PSBT_V0` or
    `PSBT_V2` already, which is the same question one layer up.
    """
    map_ = _PSBT.inputs[0] if cls is PsbtIn else _PSBT.outputs[0]
    for version in (PSBT_V0, PSBT_V2):
        assert cls.parse(map_.serialize(psbt_version=version), psbt_version=version)

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid version type"):
            map_.serialize(psbt_version=wrong)
        with pytest.raises(BTClibTypeError, match="invalid version type"):
            cls.parse(map_.serialize(), psbt_version=wrong)

    for wrong_value in (1, 3):
        with pytest.raises(BTClibValueError, match="invalid psbt version"):
            map_.serialize(psbt_version=wrong_value)
        with pytest.raises(BTClibValueError, match="invalid psbt version"):
            cls.parse(map_.serialize(), psbt_version=wrong_value)


def test_a_block_filter_is_read_against_the_hash_of_its_block() -> None:
    """The block hash a filter is keyed by, which its octets do not carry.

    BIP157 names the block beside the filter rather than inside it, so
    the hash is an argument of `parse`; the SipHash key every element is
    hashed with is derived from it, so a value of no bytes type is no
    key, and it is refused as the octets it is not.
    """
    block_filter = BasicBlockFilter(_BLOCK.header.hash, 0, b"")
    serialized = block_filter.serialize()
    assert BasicBlockFilter.parse(serialized, _BLOCK.header.hash) == block_filter

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid octets type"):
            BasicBlockFilter.parse(serialized, block_hash=wrong)


def test_an_envelope_is_read_against_magic_bytes_that_are_bytes() -> None:
    """An argument of this family that is neither a flag nor a version.

    Compared against the first four octets of the buffer, so a magic of
    no bytes type is unequal to whatever is there: every envelope was
    refused, and for the bytes it does carry rather than for the argument
    that cannot be any.
    """
    armor = _ENVELOPE.b64encode()
    assert ecies.Envelope.b64decode(armor) == _ENVELOPE
    assert ecies.Envelope.parse(_ENVELOPE.serialize(), magic=b"BIE1") == _ENVELOPE

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid magic type"):
            ecies.Envelope.parse(_ENVELOPE.serialize(), magic=wrong)
        with pytest.raises(BTClibTypeError, match="invalid magic type"):
            ecies.Envelope.b64decode(armor, magic=wrong)


def test_a_tapscript_says_which_answer_it_is_asked_for() -> None:
    """`exit_on_op_success` decides what is computed, so it is a bool.

    Core's pre-scan and a parse are two readings of the same bytes, and
    the flag chooses between them: read for its truth, a value of no
    boolean type answered the marker where the commands were asked for.
    """
    script_bytes = bytes([0x50, 0x76])  # OP_SUCCESS80, then one byte
    assert taproot.parse(script_bytes) == ["OP_SUCCESS80", b"v"]
    assert taproot.parse(script_bytes, exit_on_op_success=True) == ["OP_SUCCESS"]

    for wrong in (*_WRONG_TYPES, 0, 1):
        with pytest.raises(BTClibTypeError, match="invalid exit_on_op_success type"):
            taproot.parse(script_bytes, exit_on_op_success=wrong)


def test_a_var_bytes_flag_is_read_for_its_truth() -> None:
    """And the one on the other side of that line, which stays there.

    `forbid_zero_size` adds a refusal and changes no answer, so it is
    read as `check_validity` is: what it must not do is refuse a value
    of its own, which would make the two conventions one.
    """
    assert var_bytes.parse(b"\x01\x02") == b"\x02"
    for wrong in _WRONG_TYPES:
        assert var_bytes.parse(b"\x01\x02", forbid_zero_size=wrong) == b"\x02"


def test_a_descriptor_is_parsed_for_a_network_that_exists() -> None:
    """The two arguments `descriptors.parse` takes besides the text.

    A name no network has was carried into the `Descriptor` and refused
    by whichever encoder came to use it, one call later than the argument
    that was wrong; `prv_keys` was walked with `in` and `[]`, so a list
    of pairs answered "not found" for every key rather than saying it is
    not a mapping. `None` is a type it declares, so it is asserted to
    work rather than driven -- a statement about the signature, and the
    one `built_object_contract_test.py` records as `optional`.
    """
    descriptor = f"pk({pub_keyinfo_from_prv_key(1)[0].hex()})"
    assert descriptors.parse(descriptor, "testnet").network == "testnet"
    assert descriptors.parse(descriptor, prv_keys={}).network == "mainnet"
    assert descriptors.parse(descriptor, prv_keys=None).network == "mainnet"
    # and normalized, which is what going through the library's own
    # question buys beyond refusing what is not one
    assert descriptors.parse(descriptor, " TestNet ").network == "testnet"

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="not a network name"):
            descriptors.parse(descriptor, wrong)
    for wrong in _NOT_NONE:
        with pytest.raises(BTClibTypeError, match="invalid prv_keys type"):
            descriptors.parse(descriptor, prv_keys=wrong)
    with pytest.raises(BTClibValueError, match="unknown network"):
        descriptors.parse(descriptor, "mainet")


def test_a_miniscript_is_parsed_in_a_context_that_exists() -> None:
    """The same pair for the miniscript parser, its own first argument.

    Every rule reads the context by asking whether it is `TAPSCRIPT`, so
    a third value was the p2wsh one silently: the expression was
    type-checked and sized under rules it was not offered to.
    """
    expression = f"pk({pub_keyinfo_from_prv_key(1)[0].hex()})"
    for context in (miniscript.P2WSH, miniscript.TAPSCRIPT):
        assert miniscript.parse(expression, context).context == context
    assert miniscript.parse(expression, prv_keys=None).context == miniscript.P2WSH

    for wrong in _WRONG_TYPES:
        with pytest.raises(BTClibTypeError, match="invalid context type"):
            miniscript.parse(expression, wrong)
    for wrong in _NOT_NONE:
        with pytest.raises(BTClibTypeError, match="invalid prv_keys type"):
            miniscript.parse(expression, prv_keys=wrong)
    with pytest.raises(BTClibValueError, match="unknown spend context"):
        miniscript.parse(expression, "P2SH")


def test_every_json_boundary_is_covered() -> None:
    """The inventory is a promise only if omission is what fails.

    A `to_dict`/`from_dict` pair added to btclib and forgotten here is
    the failure this catches: the tests above would go on passing on the
    classes they were given. The pair is asserted as a pair, a class that
    writes json and does not read it back being a finding of its own.
    """
    covered = {f"{case.cls.__module__}.{case.cls.__qualname__}" for case in _JSON_CASES}
    assert public_classes_with("from_dict") == covered
    assert public_classes_with("to_dict") == covered


def test_every_decoder_is_covered() -> None:
    """The same promise for what reads octets and what reads text.

    No exclusion list, which is the state to keep: every decoder in the
    library takes an argument of a declared type, and refusing what is
    not of it is a rule with no exception to state.
    """
    covered = {
        f"{cls.__module__}.{cls.__qualname__}.{method}"
        for _, cls, method in (*_OCTETS_DECODERS, *_TEXT_DECODERS)
    }
    found = {
        f"{name}.{method}"
        for method in ("parse", "b64decode", "b58decode")
        for name in public_classes_with(method)
    }
    assert found == covered


def test_every_codec_that_is_a_function_is_covered() -> None:
    """And the same promise where the family is a module function.

    The walk that finds the methods finds classes, so these ten would be
    invisible to it: a `parse` or a `serialize` added to a module of this
    library is held to nothing until it appears in one of the two tables
    above.

    What each takes besides the encoding is recorded rather than driven,
    every one of them being a parameter behind a default -- which is
    issue #868's census and the line this file stops at.
    """
    covered = {
        f"{function.__module__}.{function.__name__}"
        for _, function, _ in _MODULE_READERS
    } | {
        f"{function.__module__}.{function.__name__}"
        for _, function, _, _ in _MODULE_WRITERS
    }
    found = {}
    for module_name in (
        "btclib",
        *(module.name for module in pkgutil.walk_packages(btclib.__path__, "btclib.")),
    ):
        module = import_module(module_name)
        for method in _FAMILY:
            function = getattr(module, method, None)
            if not callable(function) or isinstance(function, type):
                continue
            if getattr(function, "__module__", "") != module_name:
                continue
            parameters = list(signature(function).parameters)
            found[f"{module_name}.{method}"] = parameters[1:]

    assert set(found) == covered
    assert {
        (name.rsplit(".", 1)[0], name.rsplit(".", 1)[1]): extra
        for name, extra in found.items()
        if extra
    } == _MODULE_EXTRA_ARGUMENTS


def test_the_family_takes_no_argument_this_file_does_not_drive() -> None:
    """What the eight methods take, beyond the object and `check_validity`.

    Read off the signatures rather than listed, which is what makes
    `_EXTRA_ARGUMENTS` a record instead of a wish: an argument added to
    any `parse`, `serialize`, `to_dict` or `from_dict` in the library
    fails here until it is driven above or given a reason of its own.

    The argument this walk does not count is the object's own: the
    encoding a reader is handed -- `data`, `dict_`, `uri`, `address` --
    which the tests above drive for every class carrying one, and which a
    writer does not have at all, the object being what it writes.
    """
    found: dict[tuple[str, str], str] = {}
    for method in _FAMILY:
        for name in public_classes_with(method):
            module_name, _, class_name = name.rpartition(".")
            cls = getattr(import_module(module_name), class_name)
            parameters = [
                parameter
                for parameter in signature(getattr(cls, method)).parameters
                # `cls` is gone already, a classmethod read off the class
                # being bound to it; `self` is not, an instance method read
                # off the class being the plain function
                if parameter not in ("self", "cls", "check_validity")
            ]
            # then the encoding, which is the first argument of a reader
            # and is not an argument at all for a writer: what a writer
            # converts is the object it is called on
            extra = parameters[1:] if method in _READERS else parameters
            assert len(extra) <= 1, f"{name}.{method} takes {extra}"
            for parameter in extra:
                found[name, method] = parameter

    assert found == _EXTRA_ARGUMENTS


def test_the_family_takes_no_ec_or_hf() -> None:
    """No member of the family takes a curve or a hash function.

    Parametric above the byte boundary, mono-format at it: `parse`
    reads the curve and the hash function the format is defined over,
    not ones a caller names, so neither is ever a parameter here --
    the module docstring is the reason. No exclusion list, the same
    state `test_every_decoder_is_covered` keeps: an `ec` or an `hf`
    added to any member of this family, class method or module
    function, fails here rather than waiting for a reader to notice.
    """
    # unconditional, so that every line here runs whether or not a name
    # is ever found offending: the branch this test is for is the one
    # below, and a codebase with nothing to catch must not leave a line
    # of its own catcher uncovered
    found: dict[str, set[str]] = {}
    for method in _FAMILY:
        for name in public_classes_with(method):
            module_name, _, class_name = name.rpartition(".")
            cls = getattr(import_module(module_name), class_name)
            found[f"{name}.{method}"] = set(signature(getattr(cls, method)).parameters)

    for module_name in (
        "btclib",
        *(module.name for module in pkgutil.walk_packages(btclib.__path__, "btclib.")),
    ):
        module = import_module(module_name)
        for method in _FAMILY:
            function = getattr(module, method, None)
            if not callable(function) or isinstance(function, type):
                continue
            if getattr(function, "__module__", "") != module_name:
                continue
            found[f"{module_name}.{method}"] = set(signature(function).parameters)

    offenders = {name for name, params in found.items() if params & {"ec", "hf"}}
    assert not offenders
