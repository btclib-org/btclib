# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the `btclib.psbt.psbt_view` module.

A view answers about a stream what `Psbt` answers about an object, so the
first tests are that the two agree, on every psbt the suite has: the
globals, each map, the transaction being built, its lock time, the
outputs being spent and both sig_hashes, over the BIP174, BIP370, BIP371
and BIP373 vectors, and over the invalid psbts of those files and of
btclib's own. What the rest of the file is about is where a view is not
the object -- what it refuses one map later, what it reads and what it
leaves in the stream -- and each of those names the property rather than
the psbt it uses.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest
from typing_extensions import override

from btclib import var_int
from btclib.exceptions import BTClibValueError
from btclib.psbt import Psbt, PsbtView, ecdsa_sig_hash, taproot_sig_hash
from btclib.psbt.psbt import prevouts
from btclib.psbt.psbt_view import _read_var_int
from btclib.script import sig_hash
from btclib.tx import OutPoint, Tx, TxIn, TxOut
from tests.psbt import psbt_cases, psbt_vectors

_BIP_FILES = (
    "bip174_test_vectors.json",
    "bip370_test_vectors.json",
    "bip371_test_vectors.json",
    "bip373_test_vectors.json",
)

# every valid psbt the suite has, whatever BIP published it: what a view
# is held to is the object model's own answers, so the psbts to hold it to
# are all of them rather than two or three chosen here
_VALID = [
    vector for fname in _BIP_FILES for vector in psbt_vectors(fname, "valid psbts")
]
_VALID_CASES = [
    case for fname in _BIP_FILES for case in psbt_cases(fname, "valid psbts")
]

# and every invalid one, btclib's own file included, that being where the
# psbts nobody published are. `btclib_test_vectors.json` has no valid
# psbts, which is why the two lists are not one comprehension over one
# tuple of file names
_INVALID_FILES = (*_BIP_FILES, "btclib_test_vectors.json")
_INVALID = [
    vector
    for fname in _INVALID_FILES
    for vector in psbt_vectors(fname, "invalid psbts")
]
_INVALID_CASES = [
    case for fname in _INVALID_FILES for case in psbt_cases(fname, "invalid psbts")
]

# the one invalid psbt a view refuses for another reason than `Psbt.parse`
# does, with the reason: BIP174 published it for the two-octet
# PSBT_IN_SIGHASH_TYPE key in its second input map, and it carries 104
# octets after its last map as well. A view walks the maps before it parses
# any of them, so what it reports is the trailing data -- the same psbt
# refused, for something that is true of it
_REFUSED_EARLIER = "PSBT with invalid input sig_hash type typed key"


def _raw(vector: dict[str, Any]) -> bytes:
    """Return the octets of a vector's psbt."""
    return base64.b64decode(vector["encoded psbt"])


def _named(fragment: str) -> bytes:
    """Return the octets of the valid psbt whose description holds this."""
    return _raw(next(case for case in _VALID_CASES if fragment in case["description"]))


def _answer(question: Callable[..., Any], *args: Any) -> Any:
    """Return what the question answers, or the message it refuses with.

    The two readers are compared on the psbts that are valid and on the
    psbts that are not, so "raises this" has to be a value: without it
    every assertion below would hold only where both sides answered.
    """
    try:
        return question(*args)
    except BTClibValueError as e:
        return str(e)


def _read_everything(view: PsbtView) -> None:
    """Ask a view for everything it can be asked, in a signer's order.

    The transaction first, that being what a signer shows before it reads
    a key: for a version 2 psbt it reads every map to build it, and for a
    version 0 one it is the transaction the psbt carries, so the maps are
    then read by the loops below.
    """
    assert view.tx.version == view.tx_version
    for i in range(view.input_count):
        view.input(i)
    # `no branch` on the loop: every caller is an invalid vector inside
    # `pytest.raises`, so the walk is stopped by the refusal it is there
    # to provoke and never reaches the end of the outputs
    for i in range(view.output_count):  # pragma: no branch
        view.output(i)


@pytest.mark.parametrize("test_vector", _VALID)
def test_the_view_reads_what_the_object_reads(test_vector: dict[str, Any]) -> None:
    """A view and a `Psbt` answer the same questions about the same psbt.

    check_validity=False on the object, and no `assert_valid` anywhere:
    one of these vectors is BIP370's psbt whose inputs require a height
    and a time both, which has no transaction at all, so `_answer` is
    what keeps that case a comparison rather than an exclusion.
    """
    raw = _raw(test_vector)
    psbt = Psbt.parse(raw, check_validity=False)
    view = PsbtView(raw)

    assert view.version == psbt.version
    assert view.tx_version == psbt.tx_version
    assert view.fallback_lock_time == psbt.fallback_lock_time
    assert view.tx_modifiable == psbt.tx_modifiable
    assert view.signed_message == psbt.signed_message
    assert view.hd_key_paths == psbt.hd_key_paths
    assert view.unknown == psbt.unknown
    assert view.input_count == len(psbt.inputs)
    assert view.output_count == len(psbt.outputs)
    assert _answer(lambda: view.lock_time) == _answer(lambda: psbt.lock_time)
    assert _answer(lambda: view.tx) == _answer(lambda: psbt.tx)

    for i in range(view.input_count):
        assert view.input(i, check_validity=False) == psbt.inputs[i]
        assert _answer(view.ecdsa_sig_hash, i) == _answer(ecdsa_sig_hash, psbt, i)
        assert _answer(view.taproot_sig_hash, i) == _answer(taproot_sig_hash, psbt, i)
    for i in range(view.output_count):
        assert view.output(i, check_validity=False) == psbt.outputs[i]


@pytest.mark.parametrize("test_vector", _VALID)
def test_the_outputs_being_spent_are_the_objects(test_vector: dict[str, Any]) -> None:
    """`prevouts` read one input at a time is `prevouts` read whole.

    Its own test because the object's answer needs the psbt to be valid --
    `prevouts` validates before it reads, a taproot signature committing
    to every input's amount and script -- while a view validates one map
    at a time and never the whole. So this one is checked, where the test
    above compares the two readers on psbts the object model refuses as
    well.
    """
    raw = _raw(test_vector)
    # a lambda around the view's, `prevouts` being a property there: what
    # `_answer` needs is something it can call *after* the try, and a
    # property has already answered by the time it is passed
    assert _answer(lambda: PsbtView(raw).prevouts) == _answer(prevouts, Psbt.parse(raw))


@pytest.mark.parametrize("test_vector", _INVALID)
def test_the_view_refuses_what_the_object_refuses(test_vector: dict[str, Any]) -> None:
    """Every psbt `Psbt.parse` refuses, a view refuses too.

    Not always at the same moment: a view reads a map when it is asked
    for it, so a malformation inside one is found when that map is read
    and not at construction. What this asserts is that reading the whole
    psbt through the view reaches the same refusal, with the message the
    vector file records -- and `_REFUSED_EARLIER` names the one case where
    a view has a different true thing to say first.
    """
    if test_vector["description"] == _REFUSED_EARLIER:
        with pytest.raises(BTClibValueError, match="104 bytes after the psbt"):
            PsbtView(_raw(test_vector))
        return

    with pytest.raises(BTClibValueError) as excinfo:
        _read_everything(PsbtView(_raw(test_vector)))
    assert test_vector["error message"] in str(excinfo.value)


def test_a_psbt_is_read_from_a_file(tmp_path: Path) -> None:
    """The stream a view is for: one the psbt was never held whole from.

    `alias.BinaryData` is a `BytesIO`, which is the psbt in memory with an
    object model still to be built on top of it; a file is the case a view
    exists for, so it is a case the tests have to run. The taproot
    sig_hash because it is the answer that commits to every input, and so
    the one that has to have read the whole file to be right.
    """
    raw = _named("P2TR key only input with internal key and its")
    path = tmp_path / "unsigned.psbt"
    path.write_bytes(raw)

    with path.open("rb") as file_:
        view = PsbtView(file_)
        from_file = [view.taproot_sig_hash(i) for i in range(view.input_count)]
        assert view.input(0) == PsbtView(raw).input(0)
        assert view.tx == PsbtView(raw).tx

    in_memory = PsbtView(raw)
    assert from_file == [
        in_memory.taproot_sig_hash(i) for i in range(in_memory.input_count)
    ]


def test_a_stream_may_carry_more_than_the_psbt() -> None:
    """A view starts where the cursor is and stops after the last map.

    Which is `parse`'s half of the same contract, and what makes a psbt
    readable out of a stream carrying something else as well: here the
    something else is a second psbt, read by a second view from where the
    first one left the stream.
    """
    first = _named("PSBT with one P2PKH input. Outputs are empty")
    second = _named("1 input, 2 output PSBTv2, required fields only")
    stream = BytesIO(b"before" + first + second + b"after")
    stream.seek(len(b"before"))

    view = PsbtView(stream)
    assert view.offset == len(b"before")
    assert stream.tell() == len(b"before") + len(first)
    assert view.input(0) == Psbt.parse(first).inputs[0]

    stream.seek(len(b"before") + len(first))
    second_view = PsbtView(stream)
    assert second_view.version == 2
    assert stream.tell() == len(b"before") + len(first) + len(second)
    assert second_view.input(0) == Psbt.parse(second).inputs[0]


def test_octets_are_one_whole_psbt() -> None:
    """What follows the last map in octets is refused, however they are held.

    Every spelling `Octets` names, because the octets used to have to be
    `bytes` or a hex `str` to be octets at all. A psbt handed over as a
    bytearray or a memoryview -- a slice of a larger buffer being
    exactly what a caller reaches for here -- was taken for the stream
    it is not, and died on `AttributeError: 'bytearray' object has no
    attribute 'seekable'`. The trailing-octets check behind it asked the
    same narrow question a second time, so it would have been skipped
    too (issue #1238).
    """
    raw = _named("PSBT with one P2PKH input. Outputs are empty")
    assert PsbtView(raw).input_count == 1
    assert PsbtView(bytearray(raw)).input_count == 1
    assert PsbtView(memoryview(raw)).input_count == 1

    for trailing in (b"\x00", b"junk"):
        for spelling in (
            raw + trailing,
            (raw + trailing).hex(),
            bytearray(raw + trailing),
            memoryview(raw + trailing),
        ):
            with pytest.raises(BTClibValueError, match="bytes after the psbt"):
                PsbtView(spelling)


def test_no_prefix_of_a_psbt_is_a_view() -> None:
    """Every truncation is refused, at every offset.

    The parse contract's first property, asked of the walk a view is built
    by: the maps are not read, but where each of them ends is, so a psbt
    that stops in the middle of one has nowhere for the next to start.
    """
    raw = _named("1 input, 2 output updated PSBTv2, with all PSBTv2 fields")
    for size in range(len(raw)):
        with pytest.raises(BTClibValueError):
            PsbtView(raw[:size])


def _large_utxo() -> Tx:
    """Return a transaction large enough that not reading it is measurable.

    A non-witness utxo is a whole previous transaction, which is what
    makes a psbt larger than the maps a signer needs from it: a thousand
    outputs here, so that "the view did not read it" is a statement about
    tens of kilobytes rather than about rounding.
    """
    return Tx(
        1,
        0,
        [TxIn(OutPoint("11" * 32, 0), b"\x51", 0xFFFFFFFF)],
        [TxOut(1000, b"\x51" * 32) for _ in range(1000)],
    )


def _psbt_with_a_large_utxo() -> tuple[bytes, int]:
    """Return such a psbt, and the size of the utxo its first input holds."""
    prev_tx = _large_utxo()
    tx = Tx(
        2,
        0,
        [TxIn(OutPoint(prev_tx.id, i), b"", 0xFFFFFFFF) for i in range(3)],
        [TxOut(500, b"\x51" * 22)],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    return psbt.serialize(), len(prev_tx.serialize(include_witness=False))


class _CountingStream(BytesIO):
    """A BytesIO that remembers how many octets have been read from it."""

    def __init__(self, initial_bytes: bytes) -> None:
        super().__init__(initial_bytes)
        self.read_count = 0

    @override
    def read(self, size: int | None = -1, /) -> bytes:
        data = super().read(size)
        self.read_count += len(data)
        return data


def test_only_the_maps_asked_for_are_read() -> None:
    """The property the whole module is for, counted in octets.

    A view reads the global map, the lengths of every map after it, and
    then whichever map it is asked for; `Psbt.parse` reads the psbt. So a
    caller asking for the two small inputs of the psbt below never reads
    the large utxo of the first, and the count says so -- where the object
    model has read every octet before it can answer anything.
    """
    raw, utxo_size = _psbt_with_a_large_utxo()

    stream = _CountingStream(raw)
    view = PsbtView(stream)
    view.input(1)
    view.input(2)
    view.output(0)
    assert stream.read_count < utxo_size

    stream = _CountingStream(raw)
    Psbt.parse(stream)
    assert stream.read_count > utxo_size


def test_a_map_is_read_again_rather_than_kept() -> None:
    """Two reads of one input are two objects, so neither of them is held.

    What a view keeps between calls is in its module docstring, and a map
    is not on that list: an input handed to a caller is theirs to change,
    and changing it changes nothing the next caller of the same view sees.
    """
    view = PsbtView(_named("PSBT with one P2PKH input. Outputs are empty"))
    first, second = view.input(0), view.input(0)
    assert first == second
    assert first is not second

    first.sig_hash_type = 0x81
    assert view.input(0) == second


def _psbt_with_taproot_inputs(count: int = 3) -> bytes:
    """Return a psbt of `count` taproot inputs, which no vector file has.

    Every published taproot psbt has one input, and one input is exactly
    the case that cannot tell a hash computed per input from a hash
    computed once: BIP341 commits each of them to the amounts and scripts
    of all of them.
    """
    script_pub_key = b"\x51\x20" + b"\x01" * 32  # OP_1 <32 bytes>, a p2tr output
    tx = Tx(
        2,
        0,
        [TxIn(OutPoint(f"{i + 1:064x}", i), b"", 0xFFFFFFFF) for i in range(count)],
        [TxOut(1000, script_pub_key)],
    )
    psbt = Psbt.from_tx(tx)
    for i, psbt_in in enumerate(psbt.inputs):
        psbt_in.witness_utxo = TxOut(2000 + i, script_pub_key)
    return psbt.serialize()


def test_the_transaction_wide_hashes_are_computed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Signing N inputs hashes the whole transaction once, not N times.

    BIP341 commits every input to the same five hashes over the whole
    transaction, so a psbt whose inputs are what does not fit in memory is
    exactly the psbt that must not hash them once per input (issue #164 is
    the same arithmetic for the object model). Counted rather than timed,
    and the answers are asserted to be the object model's: a
    precomputation that changed one of them would be an optimization
    around the wrong hash.
    """
    raw = _psbt_with_taproot_inputs()
    psbt = Psbt.parse(raw)
    view = PsbtView(raw)
    built = 0

    def counted(tx: Tx, spent: list[TxOut]) -> sig_hash.PrecomputedTxData:
        nonlocal built
        built += 1
        return sig_hash.PrecomputedTxData(tx, spent)

    monkeypatch.setattr("btclib.psbt.psbt_view.PrecomputedTxData", counted)

    for i in range(view.input_count):
        assert view.taproot_sig_hash(i) == taproot_sig_hash(psbt, i)

    assert view.input_count == 3
    assert built == 1


def test_the_transaction_and_the_outputs_spent_are_copies() -> None:
    """What `tx` and `prevouts` hand back is not what the next answer uses.

    `Psbt.tx` promises the same thing by computing the transaction at
    every access; a view keeps one, so a copy is where the promise is kept
    -- and it is worth keeping, a sig_hash built from a caller's edit
    being a signature over a transaction nobody agreed to. A `TxOut` is
    frozen, so what is written below is what a caller still can write: a
    field of the transaction, and an element of either list.
    """
    view = PsbtView(_psbt_with_taproot_inputs())
    before = view.taproot_sig_hash(0)
    elsewhere = TxOut(1, b"\x51")

    tx = view.tx
    tx.lock_time += 1
    tx.vout[0] = elsewhere
    spent = view.prevouts
    spent[0] = elsewhere

    assert view.tx.lock_time != tx.lock_time
    assert view.tx.vout[0] != elsewhere
    assert view.prevouts[0] != elsewhere
    assert view.taproot_sig_hash(0) == before


def test_an_index_no_map_of_this_psbt_has_is_refused() -> None:
    """A position in a stream, so counting from the end is not one.

    Zero included, by the psbt with no inputs and no outputs BIP174
    publishes as valid: an empty psbt has no map 0 either.
    """
    view = PsbtView(_named("PSBT with one P2PKH input. Outputs are empty"))
    for index in (-1, view.input_count):
        with pytest.raises(BTClibValueError, match="invalid input index"):
            view.input(index)
    for index in (-1, view.output_count):
        with pytest.raises(BTClibValueError, match="invalid output index"):
            view.output(index)

    empty = PsbtView(_named("0 inputs and 0 outputs"))
    assert (empty.input_count, empty.output_count) == (0, 0)
    with pytest.raises(BTClibValueError, match="the psbt has 0"):
        empty.input(0)
    with pytest.raises(BTClibValueError, match="the psbt has 0"):
        empty.output(0)


def test_a_stream_that_cannot_seek_is_refused() -> None:
    """A view reads a map when it is asked for it, which is a seek.

    Refused at construction and with what it needs said: without the
    check, the first seek fails from underneath the library, and for a
    pipe or a socket it fails with the psbt already half read.
    """

    class Pipe(BytesIO):
        @override
        def seekable(self) -> bool:
            return False

    with pytest.raises(BTClibValueError, match="needs a seekable stream"):
        PsbtView(Pipe(_named("PSBT with one P2PKH input. Outputs are empty")))


def test_the_magic_bytes_are_the_whole_header() -> None:
    """The five octets, the 0xff included, as `Psbt.parse` asks for them."""
    raw = _named("PSBT with one P2PKH input. Outputs are empty")
    with pytest.raises(BTClibValueError, match="missing magic bytes"):
        PsbtView(b"psbt\x00" + raw[5:])
    with pytest.raises(BTClibValueError, match="missing magic bytes"):
        PsbtView(b"")


def test_a_map_is_validated_when_it_is_read_and_not_before() -> None:
    """`check_validity` is per map, which is the only place a view can ask.

    Which fields a version requires of a map is a question about that map
    alone, so it is asked when the map is read; BIP370's two psbts below
    are invalid for exactly that reason, and unchecked they are read back
    as the maps they are -- an input with no outpoint, an output with no
    amount.
    """
    missing_txid = next(
        case
        for case in _INVALID_CASES
        if "missing PSBT_IN_PREVIOUS_TXID" in case["description"]
    )
    view = PsbtView(_raw(missing_txid))
    with pytest.raises(
        BTClibValueError, match="input 0: missing PSBT_IN_PREVIOUS_TXID"
    ):
        view.input(0)
    assert view.input(0, check_validity=False).previous_tx_id == b""

    missing_amount = next(
        case
        for case in _INVALID_CASES
        if "missing PSBT_OUT_AMOUNT" in case["description"]
    )
    view = PsbtView(_raw(missing_amount))
    with pytest.raises(BTClibValueError, match="output 0: missing PSBT_OUT_AMOUNT"):
        view.output(0)
    assert view.output(0, check_validity=False).amount is None


def _psbt_with_a_mismatched_utxo(*, wrong_id: bool) -> bytes:
    """Return a psbt whose non-witness utxo is not what its outpoint names."""
    prev_tx = Tx(1, 0, [TxIn(OutPoint("22" * 32, 0), b"\x51", 0)], [TxOut(9, b"\x51")])
    tx_id = "11" * 32 if wrong_id else prev_tx.id
    tx = Tx(
        2, 0, [TxIn(OutPoint(tx_id, 0 if wrong_id else 7), b"", 0)], [TxOut(1, b"\x51")]
    )
    psbt = Psbt.from_tx(tx, check_validity=False)
    psbt.inputs[0].non_witness_utxo = prev_tx
    return psbt.serialize(check_validity=False)


@pytest.mark.parametrize(
    "wrong_id, err_msg",
    [
        (True, "mismatched non-witness utxo / outpoint tx_id"),
        (False, "outpoint vout out of range for the non-witness utxo"),
    ],
)
def test_the_utxo_of_an_input_is_the_transaction_its_outpoint_names(
    err_msg: str, *, wrong_id: bool
) -> None:
    """Both halves of that, asked of one input rather than of the psbt.

    `Psbt.assert_valid` asks them of every input, which a view cannot;
    what it can do is ask them of the map it has just read, and an
    outpoint naming an output the transaction does not have is the case
    that would otherwise be an IndexError out of the sig_hash.
    """
    view = PsbtView(_psbt_with_a_mismatched_utxo(wrong_id=wrong_id))
    with pytest.raises(BTClibValueError, match=err_msg):
        view.input(0)


def test_a_lock_time_no_transaction_can_have_is_refused() -> None:
    """One input requiring a height and another a time, read one at a time.

    BIP370's own psbt, and the answer `Psbt.lock_time` gives it: the
    inputs stream past `_lock_time` rather than reaching it as a list, so
    what this pins is that streaming them reaches the same refusal.
    """
    case = next(
        case
        for case in psbt_cases("bip370_test_vectors.json", "lock time psbts")
        if case["lock time"] is None
    )
    view = PsbtView(_raw(case))
    with pytest.raises(BTClibValueError, match="no lock time satisfies every input"):
        _ = view.lock_time


@pytest.mark.parametrize("value", [0, 0xFC, 0xFD, 0xFFFF, 0x1_0000, var_int.MAX_SIZE])
def test_a_compact_size_is_read_and_no_more_than_it(value: int) -> None:
    """The one number a view reads with no `BytesIO` under it.

    A key or a value longer than 252 octets carries a prefix, and the
    cursor has to be left on the octet after the number rather than after
    the window it was read out of: an off-by-one there misreads every map
    that follows. The psbts above exercise the one-octet form thousands of
    times over, and these are the two prefixed forms a length can reach --
    the third needs a number above `var_int.MAX_SIZE`, which is not a
    length any psbt has.
    """
    stream = BytesIO(var_int.serialize(value) + b"tail")
    assert _read_var_int(stream) == value
    assert stream.read() == b"tail"
