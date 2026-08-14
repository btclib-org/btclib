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
four arguments `_EXTRA_ARGUMENTS` records, and the last test is what
keeps that record honest -- a fifth added to this family fails here until
it is driven.

`check_validity` is not driven anywhere in this file: it is a flag that
decides whether a check runs rather than what is computed, so it is read
for its truth, and `check_validity_test.py` owns that convention.
`dsa.Sig.parse`'s `strict` is the same kind of flag and the same
exemption, recorded below beside the arguments that are not.
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
from btclib.block import Block, BlockHeader
from btclib.descriptors import descriptors, miniscript
from btclib.ecc import bms, dsa, ecies, ssa
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.network import NETWORKS, Network
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
    ("Psbt.parse", Psbt, "parse"),
    ("PsbtIn.parse", PsbtIn, "parse"),
    ("PsbtOut.parse", PsbtOut, "parse"),
    ("Witness.parse", Witness, "parse"),
    ("BIP32KeyData.parse", BIP32KeyData, "parse"),
    ("BIP32KeyOrigin.parse", BIP32KeyOrigin, "parse"),
    ("bms.Sig.parse", bms.Sig, "parse"),
    ("ssa.Sig.parse", ssa.Sig, "parse"),
    ("dsa.Sig.parse", dsa.Sig, "parse"),
    ("ecies.Envelope.parse", ecies.Envelope, "parse"),
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
# `check_validity_test.py` owns. Nine arguments over seventy methods,
# which is the shape of the family: the object is the input, and this is
# everything else a caller can get wrong.
#
# Each is driven below except `strict`, which is a flag deciding whether a
# check runs -- Bitcoin Core's IsValidSignatureEncoding, and `dsa.Sig.parse`
# says where it does it -- and is therefore read for its truth, as
# `check_validity` is
_EXTRA_ARGUMENTS = {
    ("btclib.tx.tx.Tx", "serialize"): "include_witness",
    ("btclib.block.block.Block", "serialize"): "include_witness",
    ("btclib.psbt.psbt_in.PsbtIn", "serialize"): "psbt_version",
    ("btclib.psbt.psbt_in.PsbtIn", "parse"): "psbt_version",
    ("btclib.psbt.psbt_out.PsbtOut", "serialize"): "psbt_version",
    ("btclib.psbt.psbt_out.PsbtOut", "parse"): "psbt_version",
    ("btclib.ecc.ecies.Envelope", "parse"): "magic",
    ("btclib.ecc.ecies.Envelope", "b64decode"): "magic",
    ("btclib.ecc.dsa.Sig", "parse"): "strict",
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
    ("script.serialize", script.serialize, ["OP_DUP"], (None, 1.5, "OP_DUP", b"\x76")),
    (
        "taproot.serialize",
        taproot.serialize,
        ["OP_DUP"],
        (None, 1.5, "OP_DUP", b"\x76"),
    ),
)

_MODULE_WRITER_IDS = tuple(label for label, _, _, _ in _MODULE_WRITERS)

# what those ten take besides the thing they convert. Every one of them
# is a parameter behind a default, which is issue #868's census and not
# this file's: `max_size` and `context` are asked where they are read,
# `forbid_zero_size` and `exit_on_op_success` are flags, and `network`
# and `prv_keys` are the descriptor family's own inputs
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
    is the `KeyError` that used to: `exceptions.py` lists it as one of
    the native exceptions still reaching a caller, and this family was
    where it did.

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


def test_an_envelope_is_read_against_magic_bytes_that_are_bytes() -> None:
    """The one argument of this family that is neither a flag nor a version.

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
