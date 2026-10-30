# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The block rules that need something the block does not carry.

`Block.assert_valid` is Bitcoin Core's `CheckBlock`, and these are
`ContextualCheckBlockHeader` and `ContextualCheckBlock`, the timewarp
rule apart: `time-too-new`, which needs a clock; `bad-version`,
`bad-txns-nonfinal`, `bad-cb-height` and the witness rules, which need
the height and the chain's activation heights; and, where the caller has
walked the chain for them, `bad-diffbits` and `time-too-old`.
`BlockContext` carries all of it.

The blocks are the vendored ones, which is what makes these vectors and
not fixtures: block 481,824 is a mainnet block above BIP34's activation
height, so its coinbase commitment is one the whole network agreed on.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from btclib.block import (
    Block,
    BlockContext,
    bip34_commitment,
    witness_commitment_output,
)
from btclib.block.limits import MAX_BLOCK_WEIGHT, MAX_FUTURE_BLOCK_TIME
from btclib.consensus import CONSENSUS_PARAMS
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.script import serialize
from btclib.script.witness import Witness
from btclib.tx import TxIn
from tests import vendored_block

_MAINNET = CONSENSUS_PARAMS["mainnet"]
_MAINNET_BIP34_HEIGHT = 227_931
_MAINNET_SEGWIT_HEIGHT = 481_824
_COMMITMENT_PREFIX = bytes.fromhex("6a24aa21a9ed")


def block_of(fname: str) -> Block:
    """Parse a vendored block."""
    return Block.parse(vendored_block(fname))


def test_the_activation_height_is_cores() -> None:
    """The default chain is mainnet's, whose BIP34 height is 227,931.

    `BlockContext` defaults to mainnet because everything else in btclib
    does; another chain is its own `CONSENSUS_PARAMS` row, which a caller
    passes. Written out here rather than only imported, so that the
    number is asserted and not merely reused.
    """
    now = datetime.now(UTC)
    assert BlockContext(height=0, now=now).consensus is _MAINNET
    assert _MAINNET.bip34_height == _MAINNET_BIP34_HEIGHT

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
    regtest = CONSENSUS_PARAMS["regtest"]
    assert BlockContext(height=1, now=now, consensus=regtest).is_bip34_active


def test_a_context_is_a_height_and_an_instant() -> None:
    """What BlockContext refuses, and why each refusal is there."""
    now = datetime.now(UTC)

    # a naive datetime has no instant attached to it: timestamp() reads it
    # as local time, so the same block would be too far in the future on
    # one machine and not on another
    err_msg = "naive current time \\(no time zone\\): "
    with pytest.raises(BTClibValueError, match=err_msg):
        BlockContext(height=0, now=now.replace(tzinfo=None))

    # a height is a position in a chain: there is no negative one
    with pytest.raises(BTClibValueError, match="invalid height: -1"):
        BlockContext(height=-1, now=now)

    # a float would compare fine and read as a height, so it is reported
    # rather than coerced
    with pytest.raises(BTClibTypeError, match="invalid height type: float"):
        BlockContext(height=1.0, now=now)  # type: ignore[arg-type]
    # a chain is its parameter row, not its name
    with pytest.raises(BTClibTypeError, match="invalid consensus type: str"):
        BlockContext(height=0, now=now, consensus="mainnet")  # type: ignore[arg-type]

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
    now = datetime.now(UTC)
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
    bip34_at_1 = replace(_MAINNET, bip34_height=1)
    with pytest.raises(BTClibValueError, match="invalid coinbase height: "):
        early.assert_valid_contextual(
            BlockContext(height=1, now=now, consensus=bip34_at_1)
        )

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

    # a time `timestamp()` cannot place is refused, not left to a plain
    # ValueError: timestamp() of a naive datetime.min fails in every zone
    header.time = datetime.min
    with pytest.raises(BTClibValueError, match="invalid timestamp: "):
        header.assert_valid_time(now)

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


def test_a_median_past_str_cannot_write_is_described() -> None:
    """The refusal names an int past the digit limit by its bit length.

    `str()` refuses such an int with a ValueError of its own, which the
    message quoting it would raise instead (issue #2394).
    """
    block = block_of("block_1.bin")
    context = BlockContext(height=1, now=block.header.time, median_time_past=10**5000)
    err_msg = "not after the median past\\): .* <= an int of 16610 bits"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(context)


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


def test_the_activation_gates_are_comparisons_on_the_height() -> None:
    """Each rule binds from its activation height on, as Core's buried ones do.

    `DeploymentActiveAfter` for a buried deployment is the height being
    at or above the deployment's: the first height a gate lets through is
    the activation height itself.
    """
    now = datetime.now(UTC)
    for name, field in (
        ("is_bip113_active", "csv_height"),
        ("is_segwit_active", "segwit_height"),
    ):
        activation = getattr(_MAINNET, field)
        for height, active in ((activation - 1, False), (activation, True)):
            context = BlockContext(height=height, now=now)
            assert getattr(context, name) is active

    # no floor below BIP34's height, then version 2, 3 from BIP66's, 4
    # from BIP65's
    for height, least in (
        (0, None),
        (_MAINNET.bip34_height - 1, None),
        (_MAINNET.bip34_height, 2),
        (_MAINNET.bip66_height - 1, 2),
        (_MAINNET.bip66_height, 3),
        (_MAINNET.bip65_height - 1, 3),
        (_MAINNET.bip65_height, 4),
    ):
        assert BlockContext(height=height, now=now).min_version == least

    # regtest's genesis is below every one of them, its block 1 above all
    regtest = CONSENSUS_PARAMS["regtest"]
    assert BlockContext(height=0, now=now, consensus=regtest).min_version is None
    assert BlockContext(height=1, now=now, consensus=regtest).min_version == 4


def test_bad_version_refuses_a_version_the_chain_has_outgrown() -> None:
    """Core's bad-version, a header rule, asked before every block rule.

    Block 1 is version 1, which mainnet accepts below BIP34's height and
    refuses from it on. At that height its coinbase does not commit to the
    height either, and bad-version is what answers: the header comes
    first.
    """
    block = block_of("block_1.bin")
    now = block.header.time
    block.assert_valid_contextual(
        BlockContext(height=_MAINNET_BIP34_HEIGHT - 1, now=now)
    )

    err_msg = "invalid version \\(outdated\\): 0x00000001 < 2"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(
            BlockContext(height=_MAINNET_BIP34_HEIGHT, now=now)
        )

    # the version is a signed int32, and Core prints it unsigned
    block.header.version = -1
    err_msg = "invalid version \\(outdated\\): 0xffffffff < 4"
    regtest = CONSENSUS_PARAMS["regtest"]
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(
            BlockContext(height=1, now=now, consensus=regtest)
        )


def test_bad_version_sets_no_floor_below_bip34() -> None:
    """Below BIP34's height any version passes, zero and negative included.

    Core's `bad-version` refuses a version only once BIP34, BIP66 or
    BIP65 is active (issue #2833).
    """
    block = block_of("block_1.bin")
    now = block.header.time
    below = BlockContext(height=_MAINNET_BIP34_HEIGHT - 1, now=now)
    at = BlockContext(height=_MAINNET_BIP34_HEIGHT, now=now)
    above = BlockContext(height=_MAINNET.bip65_height, now=now)
    for version, printed in ((0, "0x00000000"), (-1, "0xffffffff")):
        block.header.version = version
        block.assert_valid_contextual(below)
        for context, least in ((at, 2), (above, 4)):
            err_msg = f"invalid version \\(outdated\\): {printed} < {least}"
            with pytest.raises(BTClibValueError, match=err_msg):
                block.assert_valid_contextual(context)


def test_a_transaction_must_be_final_at_the_height() -> None:
    """Core's bad-txns-nonfinal, by height and by time.

    Block 481,824's second transaction is locked to height 481,823 and
    does not opt out of it, so it is final in block 481,824 and in no
    block before. At 481,823 the coinbase's height is wrong too, and
    finality is what answers: Core asks it first.
    """
    block = block_of("block_481824_complete.bin")
    now = block.header.time
    tx = block.transactions[1]
    assert tx.lock_time == _MAINNET_SEGWIT_HEIGHT - 1
    block.assert_valid_contextual(BlockContext(height=_MAINNET_SEGWIT_HEIGHT, now=now))
    err_msg = f"non-final transaction: {tx.id.hex()}"
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(
            BlockContext(height=_MAINNET_SEGWIT_HEIGHT - 1, now=now)
        )

    # a time lock, below BIP113's height: the block's own timestamp is
    # the cutoff, and the lock must be strictly before it
    block = block_of("block_1.bin")
    now = block.header.time
    time = int(block.header.time.timestamp())
    coinbase = block.transactions[0]
    coinbase.vin[0].sequence = 0
    coinbase.lock_time = time - 1
    block.assert_valid_contextual(BlockContext(height=1, now=now))
    coinbase.lock_time = time
    err_msg = "non-final transaction: "
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(BlockContext(height=1, now=now))

    # from BIP113's height the cutoff is the median time past instead,
    # and a time lock is not checked where the context has none
    bip113_at_1 = replace(_MAINNET, csv_height=1)
    context = BlockContext(height=1, now=now, consensus=bip113_at_1)
    block.assert_valid_contextual(context)
    with pytest.raises(BTClibValueError, match=err_msg):
        block.assert_valid_contextual(
            BlockContext(
                height=1, now=now, consensus=bip113_at_1, median_time_past=time - 1
            )
        )
    coinbase.lock_time = time - 2
    block.assert_valid_contextual(
        BlockContext(
            height=1, now=now, consensus=bip113_at_1, median_time_past=time - 1
        )
    )


def test_the_witness_rules_depend_on_the_segwit_height() -> None:
    """Core's CheckWitnessMalleation, either side of the segwit height.

    Block 481,824 is mainnet's first segwit block. At its height the
    commitment is checked; on a chain where segwit binds one block
    later, its witnesses are unexpected.
    """
    block = block_of("block_481824_complete.bin")
    now = block.header.time
    context = BlockContext(height=_MAINNET_SEGWIT_HEIGHT, now=now)
    assert context.is_segwit_active
    block.assert_valid_contextual(context)

    later = replace(_MAINNET, segwit_height=_MAINNET_SEGWIT_HEIGHT + 1)
    early = BlockContext(height=_MAINNET_SEGWIT_HEIGHT, now=now, consensus=later)
    with pytest.raises(BTClibValueError, match="unexpected witness"):
        block.assert_valid_contextual(early)

    # a nonce other than the one committed to
    coinbase_in = block.transactions[0].vin[0]
    coinbase_in.script_witness = Witness([b"\x01" * 32])
    with pytest.raises(BTClibValueError, match="invalid witness commitment: "):
        block.assert_valid_contextual(context)


def test_a_stripped_block_is_refused_where_segwit_binds() -> None:
    """The defect `assert_valid` cannot see: a commitment with no nonce.

    A block serialized without witnesses parses, since `assert_valid` has
    no height and a legacy node's block has no witness to check. Above
    the segwit height the coinbase still commits, so Core asks for the
    nonce, which stripping removed. Below the segwit height the same
    bytes pass.
    """
    block = block_of("block_481824_complete.bin")
    stripped = Block.parse(block.serialize(include_witness=False))
    assert not stripped.is_segwit
    assert stripped.witness_commitment is not None
    now = block.header.time

    err_msg = "invalid witness nonce: \\[\\] stack element size\\(s\\)"
    with pytest.raises(BTClibValueError, match=err_msg):
        stripped.assert_valid_contextual(
            BlockContext(height=_MAINNET_SEGWIT_HEIGHT, now=now)
        )

    later = replace(_MAINNET, segwit_height=_MAINNET_SEGWIT_HEIGHT + 1)
    stripped.assert_valid_contextual(
        BlockContext(height=_MAINNET_SEGWIT_HEIGHT, now=now, consensus=later)
    )


def test_the_weight_is_asked_after_the_witness_rules() -> None:
    """Core's bad-blk-weight closes ContextualCheckBlock.

    46,000 witness bytes on block 481,824's second transaction take it
    over the cap. Its commitment is rewritten to match, so the witness
    rules pass and the weight is what answers.
    """
    block = block_of("block_481824_complete.bin")
    now = block.header.time
    block.transactions[1].vin[0].script_witness = Witness([b"\x00" * 46_000])
    context = BlockContext(height=_MAINNET_SEGWIT_HEIGHT, now=now)
    with pytest.raises(BTClibValueError, match="invalid witness commitment: "):
        block.assert_valid_contextual(context)

    coinbase = block.transactions[0]
    nonce = coinbase.vin[0].script_witness.stack[0]
    position = max(
        i
        for i, out in enumerate(coinbase.vout)
        if out.script_pub_key.script.startswith(_COMMITMENT_PREFIX)
    )
    coinbase.vout[position] = witness_commitment_output(block.transactions, nonce)
    assert block.weight > MAX_BLOCK_WEIGHT
    with pytest.raises(BTClibValueError, match="invalid weight: "):
        block.assert_valid_contextual(context)
