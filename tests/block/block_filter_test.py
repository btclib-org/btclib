# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP158's Golomb-coded set, and the filter API around it.

`blockfilters_test.py` holds Core's ten vectors, and every claim about
what the filter of a real block contains is answered there. What is here
is the other half: the coding read back against the pseudocode of the
BIP, the shapes a hostile serialization can take, and the two ways a
caller states the previous output scripts a block does not carry.

The bit strings below are written out by `_delta`, which is BIP158's
`golomb_encode` transcribed -- a quotient in unary, the zero that ends
it, and the remainder in P bits. A test that built them with the
module's own encoder would only say that the module agrees with itself.
"""

from __future__ import annotations

from collections.abc import Sequence
from io import BytesIO
from pathlib import Path
from typing import Any, cast

import pytest

from btclib.block import BasicBlockFilter, Block, prevout_scripts_from_utxos
from btclib.block.block_filter import BASIC_FILTER_M, BASIC_FILTER_P
from btclib.block.block_filter import MAX_FILTER_ELEMENT_COUNT as MAX_COUNT
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.tx import TxOut

# any thirty-two octets: what the block hash decides is the SipHash key,
# and none of the tests below asks what an element hashes to
_BLOCK_HASH = bytes(range(32))


def _octets(bits: str) -> bytes:
    """Return the octets of a bit string, zero padded as BIP158 pads."""
    padded = bits + "0" * (-len(bits) % 8)
    return bytes(int(padded[i : i + 8], 2) for i in range(0, len(padded), 8))


def _delta(value: int) -> str:
    """Return BIP158's golomb_encode of one delta, as a string of bits."""
    quotient, remainder = divmod(value, 1 << BASIC_FILTER_P)
    return "1" * quotient + "0" + format(remainder, f"0{BASIC_FILTER_P}b")


def _encoded(values: Sequence[int]) -> bytes:
    """Return the Golomb-Rice coded set of those values."""
    bits = ""
    last_value = 0
    for value in sorted(values):
        bits += _delta(value - last_value)
        last_value = value
    return _octets(bits)


def _filter(values: Sequence[int]) -> BasicBlockFilter:
    """Return the filter holding those element hashes."""
    return BasicBlockFilter(_BLOCK_HASH, len(values), _encoded(values))


def _block_170() -> Block:
    """Return the first block with a transaction, one input to resolve."""
    filename = Path(__file__).parent / "_data" / "block_170.bin"
    with filename.open("rb") as file_:
        return Block.parse(file_.read())


@pytest.mark.parametrize(
    "values",
    [
        [],
        [0],
        [1],
        [(1 << BASIC_FILTER_P) - 1],
        [1 << BASIC_FILTER_P],
        [0, 0, 0],
        [7, 3, 1],
        [0, BASIC_FILTER_M, 2 * BASIC_FILTER_M],
    ],
    ids=str,
)
def test_the_coding_round_trips(values: list[int]) -> None:
    """Read back what BIP158's golomb_encode wrote.

    The remainder boundary is where a coding goes wrong: one below
    `2 ** P` is the largest value with an empty unary quotient, and
    `2 ** P` is the smallest with a quotient of one. A repeated value is
    a delta of zero, which two distinct scripts hashing alike produce
    and which the encoding has to survive.
    """
    block_filter = _filter(values)
    assert block_filter.element_count == len(values)
    assert block_filter.element_hashes == sorted(values)

    serialized = block_filter.serialize()
    assert BasicBlockFilter.parse(serialized, _BLOCK_HASH) == block_filter
    assert BasicBlockFilter.parse(BytesIO(serialized), _BLOCK_HASH) == block_filter


def test_a_truncated_unary_quotient_is_refused() -> None:
    """A stream of ones that never reaches its terminating zero.

    Core's helpers read a bit past the end of the buffer as a zero,
    which turns a truncated filter into a filter with different
    contents; the stream here has no bits left to give and says so.
    """
    with pytest.raises(BTClibValueError, match="not enough binary data"):
        BasicBlockFilter(_BLOCK_HASH, 1, b"\xff")


def test_a_truncated_remainder_is_refused() -> None:
    """A terminating zero with fewer than P bits behind it."""
    with pytest.raises(BTClibValueError, match="not enough binary data"):
        BasicBlockFilter(_BLOCK_HASH, 1, _octets("0" * 8))


def test_a_count_the_set_cannot_fill_is_refused() -> None:
    """More elements declared than there are deltas coded."""
    with pytest.raises(BTClibValueError, match="not enough binary data"):
        BasicBlockFilter(_BLOCK_HASH, 3, _encoded([1, 2]))


def test_non_zero_padding_is_refused() -> None:
    """A pad bit that is not zero, which is a second spelling of one filter.

    BIP158 pads the stream "with 0's to the nearest byte boundary", so
    the bits after the last remainder are fixed. Left unchecked, every
    filter whose deltas do not end on an octet boundary would have as
    many serializations as its padding has values, all of them decoding
    alike -- and the filter header commits to the octets.
    """
    encoded = bytearray(_encoded([1]))
    encoded[-1] |= 1
    with pytest.raises(BTClibValueError, match="non-zero padding"):
        BasicBlockFilter(_BLOCK_HASH, 1, bytes(encoded))


def test_an_octet_after_the_set_is_refused() -> None:
    """Core's "encoded_filter contains excess data"."""
    with pytest.raises(BTClibValueError, match="bytes after the block filter"):
        BasicBlockFilter(_BLOCK_HASH, 1, _encoded([1]) + b"\x00")


def test_an_element_out_of_range_is_refused() -> None:
    """A delta sum reaching `F = N * M`, which no construction produces.

    `hash_to_range` maps into `[0, F)`, so the largest value a filter of
    N elements can hold is `N * M - 1`: a set whose deltas add up past
    it decodes without complaint and matches nothing, which is a filter
    that lies rather than one that is malformed.
    """
    with pytest.raises(BTClibValueError, match="block filter element out of range"):
        _filter([BASIC_FILTER_M])


def test_a_non_canonical_element_count_is_refused() -> None:
    """The var_int rule, which a filter is not exempt from."""
    serialized = b"\xfd\x01\x00" + _encoded([1])
    with pytest.raises(BTClibValueError, match="non-canonical var_int"):
        BasicBlockFilter.parse(serialized, _BLOCK_HASH)


def test_an_impossible_element_count_is_refused() -> None:
    """A count above what a block has inputs and outputs to fill.

    Refused by `parse` before it decodes -- the cap is var_int's, so
    nine hostile octets cannot ask for a loop of 2**64 iterations -- and
    refused again by `assert_valid`, which is what a caller building the
    dataclass by hand meets.
    """
    serialized = b"\xfe" + (MAX_COUNT + 1).to_bytes(4, "little")
    with pytest.raises(BTClibValueError, match="var_int too big"):
        BasicBlockFilter.parse(serialized, _BLOCK_HASH)

    for count in (-1, MAX_COUNT + 1):
        with pytest.raises(BTClibValueError, match="invalid element count: "):
            BasicBlockFilter(_BLOCK_HASH, count, b"")


def test_a_count_that_is_not_a_number_is_refused() -> None:
    """A bool is not an element count, `is_integer` being the predicate."""
    with pytest.raises(BTClibTypeError, match="invalid element count type: bool"):
        BasicBlockFilter(_BLOCK_HASH, True, b"")


def test_a_block_hash_of_the_wrong_width_is_refused() -> None:
    """The key of the SipHash is the first sixteen octets of thirty-two."""
    with pytest.raises(BTClibValueError, match="invalid block hash length: "):
        BasicBlockFilter(b"\x00" * 31, 0, b"")


def test_a_previous_header_of_the_wrong_width_is_refused() -> None:
    """The header chains onto another one, which is thirty-two octets."""
    with pytest.raises(BTClibValueError, match="invalid size: "):
        _filter([1]).header(b"\x00" * 31)


def test_the_previous_output_scripts_are_counted_against_the_block() -> None:
    """A caller that resolves the wrong number of inputs is told so.

    The one place a wrong filter would otherwise be silent: the block
    says how many non-coinbase inputs it has, so a list of any other
    length is a resolution that went wrong, and a filter built from it
    would differ from the network's with nothing to show for it.
    """
    block = _block_170()
    script = block.transactions[0].vout[0].script_pub_key.script

    with pytest.raises(BTClibValueError, match="invalid previous output script count"):
        BasicBlockFilter.from_block(block, [])
    with pytest.raises(BTClibValueError, match="invalid previous output script count"):
        BasicBlockFilter.from_block(block, [script, script])

    assert BasicBlockFilter.from_block(block, [script]).element_count


def test_one_script_is_not_a_list_of_scripts() -> None:
    """Octets are a Sequence too, and iterating one yields its octets.

    A caller passing the single script it resolved, rather than a list
    holding it, would otherwise have its length counted as a number of
    inputs -- and for a block with that many, a filter built from
    single characters. A hex string is the half mypy cannot refuse: `str`
    is a `Sequence[str]` and `str` is `Octets`, so the annotation admits
    it and only the guard does not.
    """
    block = _block_170()
    script = block.transactions[0].vout[0].script_pub_key.script

    for wrong in (cast("Any", script), script.hex()):
        with pytest.raises(
            BTClibTypeError, match="invalid previous output scripts type"
        ):
            BasicBlockFilter.from_block(block, wrong)


def test_a_utxo_mapping_resolves_the_same_scripts() -> None:
    """The typed adapter, against the list `from_block` takes.

    A caller holding a utxo set keys it by `OutPoint`, which is frozen
    and hashable for exactly that; what `from_block` needs out of it is
    one script per non-coinbase input, in the order the block spends
    them, and the two spellings must build the one filter.
    """
    block = _block_170()
    script = block.transactions[0].vout[0].script_pub_key.script
    spending = [tx for tx in block.transactions if not tx.is_coinbase]
    utxos = {
        tx_in.prev_out: TxOut(5000000000, script) for tx in spending for tx_in in tx.vin
    }

    assert prevout_scripts_from_utxos(block, utxos) == [script]
    assert BasicBlockFilter.from_block(
        block, prevout_scripts_from_utxos(block, utxos)
    ) == BasicBlockFilter.from_block(block, [script])


def test_an_unresolved_previous_output_is_refused() -> None:
    """A mapping that does not answer for an input the block spends.

    Named rather than skipped: an element missing from a filter is not
    visible in the filter, so a caller silently handed a short mapping
    would publish a filter that is wrong and passes every check here.
    """
    block = _block_170()
    with pytest.raises(BTClibValueError, match="unresolved previous output: "):
        prevout_scripts_from_utxos(block, {})
