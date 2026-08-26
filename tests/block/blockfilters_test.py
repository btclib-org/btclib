# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The ten testnet blocks Bitcoin Core carries in `blockfilters.json`.

`src/test/data/blockfilters.json` is Core's BIP158 vector file, and each
of its rows opens with a height, a block hash and a whole serialized
block before the filter columns begin; tests/_data/README.md pins the
revision. Every column is read here. The first three are the block
vector, and the four after them are the vector for
`btclib.block.block_filter`: the previous output scripts a filter needs
and a block cannot supply, the previous filter header, and the two
answers -- the serialized basic filter and the basic header chained onto
it.

Core chose the rows for the shapes their scripts have, and they are
shapes nothing else in this suite holds. The four blocks of
`_data/block_*.bin` are mainnet and ordinary; these are testnet and
deliberately odd -- a coinbase output script no parser can read, two
empty output scripts, duplicate pushdata. What the file does not add is
an *invalid* block: every row is a block the chain accepted, and the
negative vectors remain the seven of `checkblock_test.py`.

The `Notes` column is Core's own, and 15007's is the row it does not
describe: "non-standard OP_RETURN output" names a script that is in
neither half of that row, whose block is one coinbase paying to p2pk and
whose previous output script list is empty. The rows that do exercise
the exclusion are 926485 and 1263442, where the output left out of the
filter is the BIP141 witness commitment.
"""

from __future__ import annotations

from typing import Any, cast

import pytest

from btclib.block import BasicBlockFilter, Block, BlockContext
from btclib.exceptions import BTClibTypeError, BTClibValueError
from tests import load, vector_id

_HEADER_ROW = 1  # "Block Height,Block Hash,Block,[Prev Output Scripts ..."

# Core's chainparams for testnet3, which these ten blocks are from: the
# four rows below it predate the rule, and are the reason the gate exists
# -- checking bad-cb-height at every height would refuse four blocks the
# chain accepted
_TESTNET_BIP34_HEIGHT = 21_111

# the op code BIP158 excludes an output script by, which is its first
# byte and not the standard nulldata shape: `block_filter.py` says why
_OP_RETURN = b"\x6a"

# a p2wpkh script paying to a hash of zeros, which is a shape no row of
# the file holds and a filter must therefore answer False for. A match
# is probabilistic, so a script that is absent can still hit: this one
# does not, over all ten filters, and the file is pinned
_ABSENT_SCRIPT = bytes.fromhex("0014" + "00" * 20)

# the legacy sigop count of each row, which is the arithmetic and not the
# limit: 21 in all, against a cost cap of 20,000 checks. 987,876 is the
# zero, its coinbase output script ending in an OP_CHECKSIG inside a push
# that runs past the end of the script -- an op code no implementation
# reaches
_SIG_OP_COUNT = {
    0: 1,
    2: 1,
    3: 1,
    15007: 1,
    49291: 2,
    180480: 8,
    926485: 6,
    987876: 0,
    1263442: 1,
    1414221: 0,
}


def _rows() -> list[Any]:
    """Return the vector rows, the header row of column names dropped."""
    rows: list[Any] = load("block", "_data", "blockfilters.json")
    return rows[_HEADER_ROW:]


def params() -> list[Any]:
    """Return one pytest.param per row, labelled by height and notes."""
    return [
        pytest.param(height, block_hash, serialization, id=vector_id(height, notes))
        for height, block_hash, serialization, _, _, _, _, notes in _rows()
    ]


def filter_params() -> list[Any]:
    """Return one pytest.param per row, the filter columns included.

    Columns two through six: the serialized block, the previous output
    scripts, the previous filter header, the serialized basic filter and
    the basic header.
    """
    return [pytest.param(*row[2:7], id=vector_id(row[0], row[7])) for row in _rows()]


def row_at(height: int) -> Any:
    """Return the row of that height, whole."""
    return next(row for row in _rows() if row[0] == height)


def block_at(height: int) -> Block:
    """Return the row of that height, parsed under the full validity check."""
    return Block.parse(row_at(height)[2])


def filter_at(height: int) -> BasicBlockFilter:
    """Return the basic filter built from the row of that height."""
    row = row_at(height)
    return BasicBlockFilter.from_block(Block.parse(row[2]), row[3])


def scripts_at(height: int) -> list[bytes]:
    """Return every script of the row: its output scripts and its prevouts.

    The raw list, duplicates and empty scripts and OP_RETURN outputs
    included, which is what the contents rule is applied *to*.
    """
    block = block_at(height)
    scripts = [
        out.script_pub_key.script for tx in block.transactions for out in tx.vout
    ]
    return scripts + [bytes.fromhex(script) for script in row_at(height)[3]]


@pytest.mark.parametrize("height, block_hash, serialization", params())
def test_blockfilters_block(height: int, block_hash: str, serialization: str) -> None:
    """Parse each row's block, round-trip it, and check its two claims.

    The hash the row states is what the parsed header must hash to, and
    the height is the second independent claim in the file: from BIP34
    on, a block commits its own height into the coinbase script_sig, so
    `Block.height` can be held to a number btclib did not compute. The
    four version 1 rows -- genesis, 2, 3 and 15007 -- predate BIP34 and
    commit nothing, which is `None` here.
    """
    block = Block.parse(serialization)
    assert block.serialize().hex() == serialization
    assert block == Block.parse(block.serialize())
    assert block.header.hash.hex() == block_hash

    expected_height = None if block.header.version == 1 else height
    assert block.height == expected_height

    assert block.sig_op_count == _SIG_OP_COUNT[height]


@pytest.mark.parametrize("height, block_hash, serialization", params())
def test_blockfilters_coinbase_height(
    height: int, block_hash: str, serialization: str
) -> None:
    """Core's bad-cb-height over ten real testnet blocks.

    Six of the rows are at or above testnet3's activation height and
    commit their own height in the bytes Core builds; the four below it
    are version 1 blocks that commit nothing, and they are what says the
    activation height has to be part of the context. Asked through
    `assert_valid_contextual`, so that the gate is what decides and not
    the test: the same call over the same block passes below the
    activation height and asks the question above it.
    """
    block = Block.parse(serialization)
    context = BlockContext(
        height=height,
        now=block.header.time,
        bip34_height=_TESTNET_BIP34_HEIGHT,
    )
    assert context.is_bip34_active == (height >= _TESTNET_BIP34_HEIGHT)
    block.assert_valid_contextual(context)

    if not context.is_bip34_active:
        # the commitment is absent, so asking for it directly is what
        # measures that the gate above is doing the work
        with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
            block.assert_valid_coinbase_height(height)
        return

    # and above it, the block is refused for any other height
    with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
        block.assert_valid_coinbase_height(height + 1)


def test_an_output_script_can_be_empty() -> None:
    """Core's "pays to empty output script", and the "empty data" row.

    A zero-length script_pub_key is a var_bytes of zero and nothing
    else, so it is the shape a length-driven parser is most likely to
    mishandle -- and it is spendable by anyone, which is why the chain
    holds so few of them.
    """
    empty = [
        (out.value, out.script_pub_key.script)
        for height in (49291, 1414221)
        for tx in block_at(height).transactions
        for out in tx.vout
        if not out.script_pub_key.script
    ]
    assert empty == [(50000000, b""), (78125000, b"")]


def test_a_coinbase_output_script_need_not_parse() -> None:
    """Core's row for a coinbase output script no parser can read.

    A script_pub_key is bytes the consensus rules never execute unless
    something spends it, so a block carrying one that no parser can read
    is valid: the block-level checks are over the bytes. btclib says so
    twice -- `assert_valid` accepts the block, and the rendering marks
    where the opcodes stop making sense rather than raising.
    """
    coinbase = block_at(987876).transactions[0]
    assert coinbase.is_coinbase
    script_pub_key = coinbase.vout[0].script_pub_key
    assert script_pub_key.asm[-2:] == ["UNKNOWN_OP_CODE_216", "[error]"]
    assert script_pub_key.type == "unknown"


def test_the_witness_row_commits_to_its_witnesses() -> None:
    """Core's "includes witness data", the one segwit row of the file.

    `Block.parse` above already asserted it, `assert_valid` checking the
    BIP141 commitment for any block with a witness; naming it here is
    what says the row was chosen for that and would be missed if it went.
    """
    block = block_at(1263442)
    assert block.is_segwit
    assert block.witness_commitment is not None


@pytest.mark.parametrize(
    "serialization, prevout_scripts, previous_header, basic_filter, basic_header",
    filter_params(),
)
def test_blockfilters_basic_filter(
    serialization: str,
    prevout_scripts: list[str],
    previous_header: str,
    basic_filter: str,
    basic_header: str,
) -> None:
    """Rebuild each row's basic filter and chain its header onto the previous.

    The four filter columns at once, because they are one answer: the
    filter is the serialization Core states, its hash together with the
    previous header is the basic header Core states, and parsing those
    stated bytes back yields the filter that was just built. Nothing
    here is btclib checked against itself -- every value compared is
    Core's.
    """
    block = Block.parse(serialization)
    block_filter = BasicBlockFilter.from_block(block, prevout_scripts)

    assert block_filter.serialize().hex() == basic_filter
    assert block_filter.header(previous_header).hex() == basic_header

    parsed = BasicBlockFilter.parse(basic_filter, block.header.hash)
    assert parsed == block_filter
    assert parsed.serialize().hex() == basic_filter
    assert parsed.element_hashes == block_filter.element_hashes


@pytest.mark.parametrize(
    "serialization, prevout_scripts, previous_header, basic_filter, basic_header",
    filter_params(),
)
def test_blockfilters_match(
    serialization: str,
    prevout_scripts: list[str],
    previous_header: str,
    basic_filter: str,
    basic_header: str,
) -> None:
    """Query each row's filter for what the contents rule put in it.

    Every element matches on its own and the whole set matches at once;
    what the rule leaves out does not match, and neither does a script
    no row holds. A match is probabilistic -- one query in M is a false
    positive -- but the ten filters and the queries below are fixed, so
    the negatives here are as reproducible as the positives.
    """
    block = Block.parse(serialization)
    block_filter = BasicBlockFilter.parse(basic_filter, block.header.hash)
    scripts = [
        out.script_pub_key.script for tx in block.transactions for out in tx.vout
    ]
    scripts += [bytes.fromhex(script) for script in prevout_scripts]

    included = [s for s in scripts if s and not s.startswith(_OP_RETURN)]
    for script in included:
        assert block_filter.match(script)
    assert block_filter.match_any(included) == bool(included)

    for script in [s for s in scripts if not s or s.startswith(_OP_RETURN)]:
        assert not block_filter.match(script)
    assert not block_filter.match(_ABSENT_SCRIPT)
    assert not block_filter.match_any([_ABSENT_SCRIPT, _ABSENT_SCRIPT[::-1]])
    assert not block_filter.match_any([])

    if included:
        with pytest.raises(BTClibTypeError, match="invalid elements type"):
            block_filter.match_any(cast("Any", included[0]))


def test_a_coinbase_input_has_no_previous_output_script() -> None:
    """The one input BIP158 excludes, over every row of the file.

    A coinbase spends nothing, so the scripts Core states per row are
    one per input that is not a coinbase's -- which is the count
    `from_block` holds its caller to, and the reason a caller cannot
    hand it the block's inputs and be right by accident.
    """
    for row in _rows():
        block = Block.parse(row[2])
        coinbases = [tx for tx in block.transactions if tx.is_coinbase]
        assert len(coinbases) == 1
        spent = sum(len(tx.vin) for tx in block.transactions) - len(coinbases[0].vin)
        assert len(row[3]) == spent


def test_a_duplicate_script_weighs_once() -> None:
    """Core's "duplicate pushdata" row: the filter elements are a set.

    That row's block and previous output scripts hold the same script
    more than once, and BIP158 puts scripts in a set: what the filter
    declares is the number of distinct scripts the contents rule keeps,
    not the number of outputs and inputs they came from.
    """
    scripts = scripts_at(926485)
    kept = [s for s in scripts if s and not s.startswith(_OP_RETURN)]
    assert len(kept) > len(set(kept))
    assert filter_at(926485).element_count == len(set(kept))


def test_an_op_return_output_is_left_out() -> None:
    """The two rows whose blocks carry an OP_RETURN output.

    Both outputs are BIP141 witness commitments, which is the OP_RETURN
    almost every block since segwit carries. BIP158 excludes an output
    by its leading op code and not by the standardness of what follows
    it, so the commitment is neither an element nor a match.
    """
    for height in (926485, 1263442):
        block_filter = filter_at(height)
        nulldata = [s for s in scripts_at(height) if s.startswith(_OP_RETURN)]
        assert nulldata
        for script in nulldata:
            assert not block_filter.match(script)


def test_an_empty_script_is_never_an_element() -> None:
    """BIP158's "nil" items, on both sides of the contents rule.

    49291 pays to an empty output script and 180480 spends from empty
    ones, and neither shape reaches the filter: the count is of the
    distinct non-empty scripts, and the empty script does not match.
    """
    for height in (49291, 180480):
        scripts = scripts_at(height)
        assert [s for s in scripts if not s]
        assert filter_at(height).element_count == len({s for s in scripts if s})
        assert not filter_at(height).match(b"")


def test_a_filter_can_hold_no_elements() -> None:
    """Core's "empty data" row, the one filter of the file that is empty.

    Its single output pays to an empty script, so the contents rule
    leaves nothing to encode: the serialization is the var_int zero and
    no set at all, and every query is False.
    """
    block_filter = filter_at(1414221)
    assert block_filter.element_count == 0
    assert block_filter.element_hashes == []
    assert block_filter.serialize() == b"\x00"
    assert not block_filter.match(b"")
    assert not block_filter.match(_ABSENT_SCRIPT)


def test_a_witness_is_not_a_filter_element() -> None:
    """Core's witness row, read as a filter rather than as a block.

    BIP158's elements are output scripts, so what the one segwit row
    contributes is the p2wsh script its single input spends and the
    scripts it pays to. The witness stack that satisfies the first is
    the script's *input*, and nothing in it is in the filter.
    """
    block_filter = filter_at(1263442)
    assert block_filter.match(row_at(1263442)[3][0])

    stack = [
        item
        for tx in block_at(1263442).transactions
        if not tx.is_coinbase
        for tx_in in tx.vin
        for item in tx_in.script_witness.stack
    ]
    assert stack
    for item in stack:
        assert not block_filter.match(item)
