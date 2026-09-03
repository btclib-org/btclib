# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The block rules that need something the block does not carry.

`Block.assert_valid` is Bitcoin Core's `CheckBlock`, and these are the
reachable part of `ContextualCheckBlockHeader` and `ContextualCheckBlock`:
`time-too-new`, which needs a clock; `bad-cb-height`, which needs the
height the block is being accepted at and the height BIP34 binds from;
and, where the caller has walked the chain for them,
`bad-diffbits` and `time-too-old`. `BlockContext` is what carries all
five, and each rule but the last two is also a method taking the datum
it reads, so a caller holding half a context asks the half it can
answer -- `bad-diffbits` and `time-too-old` are read directly off the
context instead, `median_time_past` and `required_bits` already being
the answer rather than something to compute from a height.

The blocks are the vendored ones, which is what makes these vectors and
not fixtures: block 481,824 is a mainnet block above BIP34's activation
height, so its coinbase commitment is one the whole network agreed on.
"""

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from btclib.block import Block, BlockContext, bip34_commitment
from btclib.block.block_context import BIP34_HEIGHT
from btclib.block.limits import MAX_FUTURE_BLOCK_TIME
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import serialize
from btclib.tx import TxIn

_MAINNET_BIP34_HEIGHT = 227_931


def block_of(fname: str) -> Block:
    """Parse a vendored block from this directory's `_data`."""
    filename = Path(__file__).parent / "_data" / fname
    with filename.open("rb") as file_:
        return Block.parse(file_.read())


def test_the_activation_height_is_cores() -> None:
    """The default is mainnet's, and mainnet's is 227,931.

    `BlockContext` defaults to it because everything else in btclib
    defaults to mainnet; testnet3 is 21,111 and testnet4, signet and
    regtest are 1, which a caller passes. Written out here rather than
    only imported, so that the number is asserted and not merely reused.
    """
    assert BIP34_HEIGHT == _MAINNET_BIP34_HEIGHT
    now = datetime.now(timezone.utc)
    assert BlockContext(height=0, now=now).bip34_height == _MAINNET_BIP34_HEIGHT

    # the gate is a comparison, and the activation height is the first
    # height it lets through
    for height, active in (
        (0, False),
        (_MAINNET_BIP34_HEIGHT - 1, False),
        (_MAINNET_BIP34_HEIGHT, True),
        (_MAINNET_BIP34_HEIGHT + 1, True),
    ):
        assert BlockContext(height=height, now=now).is_bip34_active is active

    # regtest has BIP34 in force from its first block, which is why the
    # one-byte encodings below are the mainline case and not an edge
    assert BlockContext(height=1, now=now, bip34_height=1).is_bip34_active


def test_a_context_is_a_height_and_an_instant() -> None:
    """What BlockContext refuses, and why each refusal is there."""
    now = datetime.now(timezone.utc)

    # a naive datetime has no instant attached to it: timestamp() reads it
    # as local time, so the same block would be too far in the future on
    # one machine and not on another
    err_msg = "naive current time \\(no time zone\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        BlockContext(height=0, now=now.replace(tzinfo=None))

    # a height is a position in a chain: there is no negative one
    with pytest.raises(BTClibValueError, match="invalid height: -1"):
        BlockContext(height=-1, now=now)
    with pytest.raises(BTClibValueError, match="invalid bip34_height: -1"):
        BlockContext(height=0, now=now, bip34_height=-1)

    # a float would compare fine and read as a height, so it is reported
    # rather than coerced
    with pytest.raises(BTClibTypeError, match="invalid height type: float"):
        BlockContext(height=1.0, now=now)  # type: ignore[arg-type]
    err_msg = "invalid bip34_height type: float"
    with pytest.raises(BTClibTypeError, match=err_msg):
        BlockContext(height=0, now=now, bip34_height=1.0)  # type: ignore[arg-type]

    with pytest.raises(BTClibTypeError, match="invalid now type: int"):
        BlockContext(height=0, now=0)  # type: ignore[arg-type]

    # frozen, as Script and Witness are: the two rules that read a context
    # must not see it change between them
    context = BlockContext(height=0, now=now)
    with pytest.raises(AttributeError):
        context.height = 1  # type: ignore[misc]

    # and a context nobody checks can still be built, as everywhere else
    # in the library
    assert BlockContext(height=-1, now=now, check_validity=False).height == -1


def test_median_time_past_and_required_bits_default_to_none_and_are_skipped() -> None:
    """The two chain-state fields are optional, and refused only when given.

    None is what a caller that has not walked the chain for them passes
    -- which is every context built above, none of them naming either --
    and it is not a value the type or range checks below ever see.
    """
    now = datetime.now(timezone.utc)
    context = BlockContext(height=0, now=now)
    assert context.median_time_past is None
    assert context.required_bits is None
    context.assert_valid()

    with pytest.raises(BTClibTypeError, match="invalid median_time_past type: str"):
        BlockContext(height=0, now=now, median_time_past="0")  # type: ignore[arg-type]
    with pytest.raises(BTClibValueError, match="invalid median_time_past: -1"):
        BlockContext(height=0, now=now, median_time_past=-1)

    with pytest.raises(BTClibTypeError, match="invalid required_bits type: str"):
        BlockContext(height=0, now=now, required_bits="1d00ffff")  # type: ignore[arg-type]
    err_msg = "invalid required_bits length: 3 bytes instead of 4"
    with pytest.raises(BTClibValueError, match=err_msg):
        BlockContext(height=0, now=now, required_bits=b"\x1d\x00\xff")

    # a well-formed pair is accepted and read back unchanged
    valid = BlockContext(
        height=0, now=now, median_time_past=0, required_bits=b"\x1d\x00\xff\xff"
    )
    assert valid.median_time_past == 0
    assert valid.required_bits == b"\x1d\x00\xff\xff"


def test_the_height_is_committed_as_core_writes_it() -> None:
    """BIP34's commitment is the shortest encoding, op codes included.

    Core builds `CScript() << nHeight`, so zero is OP_0 and one to sixteen
    are OP_1 to OP_16 -- one byte, no push at all -- where
    `script.serialize([height])` pushes the number as data and warns that
    an op code says the same. From seventeen up the two agree, which is
    why the vendored mainnet coinbases match either way and regtest, with
    BIP34 in force from height 1, does not.
    """
    assert bip34_commitment(0) == b"\x00"
    assert bip34_commitment(1) == b"\x51"
    assert bip34_commitment(16) == b"\x60"
    # the first height the two encodings agree on
    assert bip34_commitment(17) == bytes.fromhex("0111")

    with pytest.warns(UserWarning, match="consider using OP_1 instead"):
        assert serialize([1]) == bytes.fromhex("0101")
    assert serialize([17]) == bip34_commitment(17)

    # the two vendored coinbases above the activation height, byte for byte
    assert bip34_commitment(200_000) == bytes.fromhex("03400d03")
    assert bip34_commitment(481_824) == bytes.fromhex("03205a07")


def test_the_coinbase_commitment_is_compared_as_bytes() -> None:
    """Core's bad-cb-height compares bytes, not the number they decode to.

    The coinbase script_sig must *start with* the commitment, so a height
    pushed any other way than the shortest is refused although
    `Block.height` reads the right number out of it: four bytes of
    little-endian 481,824 decode to 481,824 and are not what the network
    committed to.
    """
    block = block_of("block_481824_complete.bin")
    assert block.height == 481_824
    block.assert_valid_coinbase_height(481_824)

    # the height of the block before it, and of the one after
    for height in (481_823, 481_825):
        err_msg = "invalid coinbase height: 03205a07 instead of: "
        with pytest.raises(BTClibValueError, match=err_msg):
            block.assert_valid_coinbase_height(height)

    coinbase = block.transactions[0]
    script_sig = coinbase.vin[0].script_sig
    non_minimal = bytes([4]) + (481_824).to_bytes(4, "little")
    coinbase.vin[0] = TxIn(
        coinbase.vin[0].prev_out,
        non_minimal + script_sig[4:],
        coinbase.vin[0].sequence,
        coinbase.vin[0].script_witness,
    )
    assert block.height == 481_824
    err_msg = "invalid coinbase height: 04205a07 instead of: 03205a07"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_coinbase_height(481_824)


def test_the_commitment_is_only_asked_where_bip34_binds() -> None:
    """Block 200,000 commits its height and is 27,931 blocks too early.

    BIP34 activated by supermajority, so version 2 blocks carrying the
    commitment predate the height Core enforces it from: block 200,000 is
    one of them. The commitment is there and correct -- the rule passes
    when it is asked -- and the contextual path does not ask it, which is
    the gate doing its job on a real mainnet block.

    Block 481,824 is the case above the activation height, where the
    contextual path does ask.
    """
    early = block_of("block_200000.bin")
    now = early.header.time
    early.assert_valid_coinbase_height(200_000)
    early.assert_valid_contextual(BlockContext(height=200_000, now=now))
    # and a height that is not this block's is not asked about either
    early.assert_valid_contextual(BlockContext(height=1, now=now))
    # unless the chain enforces BIP34 from the start, as regtest does
    with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
        early.assert_valid_contextual(BlockContext(height=1, now=now, bip34_height=1))

    block = block_of("block_481824_complete.bin")
    now = block.header.time
    block.assert_valid_contextual(BlockContext(height=481_824, now=now))
    with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
        block.assert_valid_contextual(BlockContext(height=481_825, now=now))


def test_a_timestamp_may_be_two_hours_ahead_and_no_more() -> None:
    """Core's time-too-new, at the second the bound is drawn on.

    The clock is the caller's: `datetime.now()` read inside the library
    would have one machine accept the block another refuses, and would
    make this test depend on the day it runs on. Block 1's own timestamp
    is the block's, and `now` moves around it.
    """
    block = block_of("block_1.bin")
    header = block.header
    two_hours = timedelta(seconds=MAX_FUTURE_BLOCK_TIME)
    assert two_hours == timedelta(hours=2)

    # the instant the block was mined, and the last instant a node could
    # have refused it for its timestamp: the bound may be reached
    header.assert_valid_time(header.time)
    header.assert_valid_time(header.time - two_hours)

    err_msg = "invalid timestamp \\(too far in the future\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        header.assert_valid_time(header.time - two_hours - timedelta(seconds=1))

    # the whole block, through the carrier: height 1 leaves bad-cb-height
    # out of it on mainnet, so the timestamp is what answers
    now = header.time - two_hours - timedelta(seconds=1)
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(BlockContext(height=1, now=now))

    # a naive `now` is refused where it arrives, the context being only
    # one of the two ways in
    err_msg = "naive current time \\(no time zone\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        header.assert_valid_time(header.time.replace(tzinfo=None))

    # and what is no datetime at all reaches `.tzinfo` no longer: an
    # AttributeError is neither a ValueError nor a TypeError, so nothing
    # this library tells a caller to catch would have caught it
    for not_a_datetime in ("nope", 12345, None, header.time.date()):
        with pytest.raises(BTClibTypeError, match="invalid current time type: "):
            header.assert_valid_time(not_a_datetime)  # type: ignore[arg-type]


def test_bad_diffbits_compares_the_header_against_required_bits() -> None:
    """`assert_valid_contextual` refuses a header not carrying `required_bits`.

    Block 1 carries `1d00ffff`, the genesis target: a context naming that
    same value accepts it, and a context naming a stricter one refuses it
    by the bytes each side carries.
    """
    block = block_of("block_1.bin")
    now = block.header.time
    assert block.header.bits == bytes.fromhex("1d00ffff")

    block.assert_valid_contextual(
        BlockContext(height=1, now=now, required_bits=bytes.fromhex("1d00ffff"))
    )

    err_msg = "proof-of-work target not the required one: 1d00ffff"
    err_msg += " instead of 1c00ffff"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(
            BlockContext(height=1, now=now, required_bits=bytes.fromhex("1c00ffff"))
        )

    # None is what leaves the rule unchecked, not a value that happens
    # to equal every header's own bits
    block.assert_valid_contextual(BlockContext(height=1, now=now))


def test_time_too_old_compares_the_header_against_the_median_past() -> None:
    """`assert_valid_contextual` refuses a header at or before the median."""
    block = block_of("block_1.bin")
    now = block.header.time
    time = int(block.header.time.timestamp())

    # strictly after the median is required, so the median itself refuses
    err_msg = f"invalid timestamp \\(not after the median past\\): {time} <= {time}"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(
            BlockContext(height=1, now=now, median_time_past=time)
        )
    block.assert_valid_contextual(
        BlockContext(height=1, now=now, median_time_past=time - 1)
    )


def test_bad_diffbits_is_checked_before_time_too_old_and_time_too_new() -> None:
    """Core's own order: bad-diffbits, then time-too-old, then time-too-new.

    A context wrong on all three raises for the first of them, which is
    what a caller reading the exception alone is told is wrong.
    """
    block = block_of("block_1.bin")
    now = block.header.time
    time = int(block.header.time.timestamp())
    context = BlockContext(
        height=1,
        now=now - timedelta(days=1),
        median_time_past=time,
        required_bits=bytes.fromhex("1c00ffff"),
    )
    with pytest.raises(BTClibValueError, match="proof-of-work target not the required"):
        block.assert_valid_contextual(context)


def test_the_contextual_rules_are_not_asked_by_assert_valid() -> None:
    """Two questions, and a block answers the first one on its own.

    `Block.parse` calls `assert_valid` with no context to pass it, which
    is the whole reason these rules are a second entry point: a block
    read off the wire is checked for what its bytes say, and the caller
    that knows where it sits in a chain asks the rest.
    """
    block = block_of("block_1.bin")
    block.assert_valid()

    # a context that refuses it, and an assert_valid that does not
    now = block.header.time - timedelta(days=1)
    with pytest.raises(BTClibValueError, match="invalid timestamp "):
        block.assert_valid_contextual(BlockContext(height=1, now=now))
    block.assert_valid()

    # a coinbase is what both halves read, so both say so in the same
    # words -- and the height rule can be asked of a block that has none
    empty = Block(block.header, [], check_validity=False)
    for err_msg in ("block with no transactions",):
        with pytest.raises(BTClibValueError, match=err_msg):
            empty.assert_valid_coinbase_height(1)
        with pytest.raises(BTClibValueError, match=err_msg):
            _ = empty.height
