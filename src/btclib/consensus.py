# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The consensus constants and the per-network table, below every package.

Bitcoin Core keeps a consensus rule's numbers in two shapes and so does
this module: the bounds that are the same on every chain, which are
`consensus/consensus.h`, and the ones that are a fact about one network,
which are `Consensus::Params` and are `ConsensusParams` below.

Nothing of btclib is imported here, and that is the whole of why the
table can live at this depth: `btclib.block`, `btclib.tx` and
`btclib.script` all read something of it, `btclib.network` reads the
table to give each `Network` its `consensus` row, and any import back
would close a cycle on a half-initialized package -- issue #147's shape,
and what `tests/imports_test.py` reports.

`MAX_BLOCK_WEIGHT` and `WITNESS_SCALE_FACTOR` are here rather than in
`btclib.block.limits`, which is where the rest of that header is and
where a caller reading a block's own rules goes, because of who else
divides by them: a transaction's input and output counts
(`btclib.tx.limits`) and a witness stack's element count are arithmetic
on `MAX_BLOCK_WEIGHT`. `btclib.block.limits` re-exports both, so nothing
that reads them from there has to move.

`MAX_WITNESS_STACK_ITEMS` is here and not in `btclib.script.limits` for a
second reason on top of the layering. That module holds the caps the
script *engine* enforces, and reading an execution limit in a decoder is
what let a 1443-byte push be refused as unparsable when it was merely
unspendable (issue #123). The bound below is not `MAX_STACK_SIZE`: it
refuses a count no block could carry, not a witness no script could run.

## The per-network table

`CONSENSUS_PARAMS` answers for every network `btclib.network.NETWORKS`
names, and `NETWORKS[name].consensus` is the same row reached from the
encoding side, so the two tables cannot disagree about which networks
exist. A row is what a validator needs and a node's own file has no
claim on: an activation height, the subsidy interval, the easiest target
the network allows, and the exceptions the chain's own history forces.
What identifies a *node* rather than a network -- a port, a DNS seed, a
pruning floor, a custom signet's p2p magic -- is not here, and
`bitcoin_core_rpc` is where the last of those lives.

Every value is transcribed from `src/kernel/chainparams.cpp` at Bitcoin
Core v31.1 (bitcoin/bitcoin@9be056a8a7), with the line it was read at
beside it, and `tests/consensus_test.py` holds each field to that
transcription. A released tag rather than a `master` tip, for two
reasons: these are the numbers a node on the network enforces, and a tag
names a blob that cannot move under a line citation. `master` also no
longer keeps all of them in that one file -- taproot's deployment is
gone from it, buried the way `script_flags_at` below describes.

What a row carries that `chainparams.cpp` does not hold is cited to
`src/validation.cpp` at the same tag: `bip30_exceptions` is
`IsBIP30Repeat` there and `bip30_unspendable` is `IsBIP30Unspendable`.
So is the rule that combines a row's heights into script flags,
`GetBlockScriptFlags`, which `script_flags_at` names.

Fields of `Consensus::Params` that are deliberately absent, so that a
reader looking for one knows it was decided rather than missed:

- `hashGenesisBlock` is `Network.genesis_block`, which every one of these
  rows is reached through
- `BIP34Hash` is the hash Core compares at `bip34_height` to decide
  whether it may stop making the BIP30 check above it. A validator that
  keeps making it answers the same, BIP34 being what makes a duplicate
  coinbase impossible once the coinbase commits to its own height, so
  the field buys work rather than an accept or a reject
- `vDeployments` is BIP9 signalling, which a table of heights does not
  model and no caller of this table asks for
- `MinBIP9WarningHeight` is the height below which a node stays quiet
  about an unknown deployment, which is a warning and not a rule
- `defaultAssumeValid` is what a node skips signature checks below by
  default, which is a startup option and not a fact about the chain
- `signet_challenge` is per deployment rather than per network, which is
  the reason `btclib.network` gives for keeping the p2p magic out too
- `signet_blocks` is the switch in front of the check that reads that
  challenge, so a caller given the one without the other could not act
  on it; whoever holds the challenge holds this with it

A row validates nothing it is built with, alone among this library's
dataclasses: validating means raising a `BTClibTypeError`, which means
importing `btclib.exceptions`, which is the import this module does not
take. Nothing parses a row -- the rows below are constants of this
module -- and the boundary that does read json is `Network.from_dict`,
which asks `Network.assert_valid` whether its `consensus` field is one
of these.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    # the whole dotted path, and the module rather than the name:
    # `btclib.script.engine` re-exports `ScriptFlag`, so the bare name
    # has two targets in the documentation and the `-n` build fails on
    # the ambiguity rather than on anything being missing
    import btclib.script.engine.flags
    from btclib.alias import Octets

__all__ = [
    "CONSENSUS_PARAMS",
    "MAX_BLOCK_WEIGHT",
    "MAX_WITNESS_STACK_ITEMS",
    "WITNESS_SCALE_FACTOR",
    "ConsensusParams",
    "subsidy",
]

# Maximum allowed weight for a block, see BIP141 (network rule)
MAX_BLOCK_WEIGHT = 4_000_000

# The weight of a byte a legacy node sees, and the cost of a legacy sigop
WITNESS_SCALE_FACTOR = 4

# How many elements a witness stack may declare. An element costs at least
# the one octet of the var_int announcing it empty, and a witness octet
# weighs one, so the weight a block may not exceed is the count no witness
# in it can exceed either -- which is what lets a parser refuse a count
# before allocating a Python object per declared element (issue #569)
MAX_WITNESS_STACK_ITEMS = MAX_BLOCK_WEIGHT

# what Core's GetBlockScriptFlags turns on for every block of every chain,
# before a height is consulted at all: P2SH, segwit v0 and taproot are
# enforced from the genesis block down, and the blocks that predate each
# and would fail it are named one by one in `script_flag_exceptions`
# rather than gated on an activation height. A validator that gates them
# on a height instead accepts a P2SH spend Core rejects, in the window
# between the fork's activation and the height it reads
_ALWAYS_ON_FLAGS: tuple[str, ...] = ("P2SH", "WITNESS", "TAPROOT")


def subsidy(height: int, halving_interval: int = 210_000) -> int:
    """Return the block reward at `height`: Bitcoin Core's GetBlockSubsidy.

    Fifty bitcoin, right-shifted once per `halving_interval` blocks and
    forced to zero once that shift is undefined for a native int
    (`src/validation.cpp`, at bitcoin/bitcoin@9be056a8a7). `height` is
    what a block's coinbase pays for building it; `halving_interval`
    defaults to mainnet's own, and a caller building for another network
    passes `CONSENSUS_PARAMS[name].subsidy_halving_interval`, regtest's
    150 among them, rather than this function asserting a chain's
    schedule for it.
    """
    from btclib.exceptions import BTClibTypeError, BTClibValueError  # noqa: PLC0415
    from btclib.utils import is_integer  # noqa: PLC0415

    for name, value in (("height", height), ("halving_interval", halving_interval)):
        if not is_integer(value):
            raise BTClibTypeError(f"invalid {name} type: {type(value).__name__}")
    if height < 0:
        raise BTClibValueError(f"invalid height: {height}")
    if halving_interval < 1:
        raise BTClibValueError(f"invalid halving_interval: {halving_interval}")

    halvings = height // halving_interval
    if halvings >= 64:
        return 0
    return (50 * 100_000_000) >> halvings


@dataclass(frozen=True)
class ConsensusParams:
    """The consensus parameters of one network: heights, limits, exceptions.

    Bitcoin Core's `Consensus::Params` for the fields a validator reads
    off a chain rather than off a block. The module docstring says which
    of Core's fields are deliberately not here, and where each value was
    transcribed from.

    Frozen and hashable, as `Network` is: a row is a value, the rows in
    `CONSENSUS_PARAMS` are read by every caller at once, and a `Network`
    carrying one must stay usable as a dict key.
    """

    # the name this row answers to in CONSENSUS_PARAMS, so that a row
    # says which network it is without being looked up backwards --
    # `Network` carries the row and no name of its own, and `to_dict`
    # writes this
    name: str

    # Core's nSubsidyHalvingInterval: the number of blocks the coinbase
    # reward stays at one level before halving again. `subsidy` above is
    # what reads it; no arithmetic on it is here, so that the halving is
    # stated in one place rather than two
    subsidy_halving_interval: int

    # Core's five buried deployments, i.e. `Consensus::Params`'s
    # DeploymentHeight: the first height at which each rule binds. Buried
    # means the height is hardcoded rather than signalled (BIP90), which
    # is what makes a table of integers the whole answer
    bip34_height: int  # DEPLOYMENT_HEIGHTINCB: the coinbase commits to it
    bip66_height: int  # DEPLOYMENT_DERSIG: strict DER signatures
    bip65_height: int  # DEPLOYMENT_CLTV: OP_CHECKLOCKTIMEVERIFY
    csv_height: int  # DEPLOYMENT_CSV: BIP68, BIP112 and BIP113
    segwit_height: int  # DEPLOYMENT_SEGWIT: BIP141, BIP143 and BIP147

    # Core's powLimit, as the four compact bytes a header carries rather
    # than as the 32 Core holds: `bits_from_target` of Core's own value is
    # what the transcription test compares, and a caller reads the same
    # width `BlockHeader.bits` has
    pow_limit_bits: bytes

    # Core's fPowAllowMinDifficultyBlocks: a block more than two target
    # spacings after its parent may be mined at `pow_limit_bits`, so that
    # a chain nobody is hashing still moves
    pow_allow_min_difficulty_blocks: bool

    # Core's enforce_BIP94: the timewarp mitigation, checked at the first
    # block of a new difficulty period, which may not be timestamped more
    # than MAX_TIMEWARP seconds behind its own parent -- the last block of
    # the period before it -- and, on testnet4 alone, the block storm
    # mitigation that rides the same flag. Data here and a rule elsewhere,
    # as the flags either side of it are: `btclib.block.header_context`
    # is where the header arithmetic that reads it goes
    enforce_bip94: bool

    # Core's fPowNoRetargeting: the target never moves off the one the
    # genesis carries, which is what makes regtest minable at will
    pow_no_retargeting: bool

    # Core's nPowTargetSpacing and nPowTargetTimespan: the block interval
    # a retarget aims at and the window it measures, in seconds. Every
    # network but regtest aims at two weeks of ten-minute blocks; regtest
    # measures one day instead, which is what makes its own
    # difficulty_adjustment_interval 144 rather than 2016 -- a fact the
    # minimum-difficulty walk of `btclib.block.header_context` reads,
    # `pow_no_retargeting` making the number otherwise unobservable there
    pow_target_spacing: int
    pow_target_timespan: int

    # Core's nMinimumChainWork, as the integer `proof_of_work.chain_work`
    # answers rather than as Core's 32 bytes: the work below which a node
    # stays in initial block download whatever its tip's age
    minimum_chain_work: int

    # Core's IsBIP30Repeat: the (height, hash) of every block whose own
    # history already carries a BIP30 violation, exempted from the check
    # rather than failing it. A pair and not a bare height, because Core
    # asks both questions -- a chain that forked below one of these
    # heights has a different block there and is not exempt
    bip30_exceptions: tuple[tuple[int, bytes], ...]

    # Core's IsBIP30Unspendable: the (height, hash) of every block whose
    # coinbase a UTXO-set accumulator leaves out, a later block's
    # duplicate coinbase replacing its outputs in the set before
    # anything spends them. Not the pair above and not a subset of it:
    # that one is the later blocks, whose repeat the BIP30 check waives,
    # this one the earlier blocks whose outputs are never hashed
    bip30_unspendable: tuple[tuple[int, bytes], ...]

    # Core's script_flag_exceptions: the blocks that are consensus-valid,
    # buried, and fail the flags every other block is checked with. The
    # value is the flag names `to_script_flags` accepts, replacing the
    # default set rather than adding to it, which is what
    # GetBlockScriptFlags does with the entry it finds.
    # A tuple of pairs and not a mapping: the row has to stay hashable,
    # and the lookup is over a handful of blocks in the whole chain
    script_flag_exceptions: tuple[tuple[bytes, tuple[str, ...]], ...]

    @property
    def difficulty_adjustment_interval(self) -> int:
        """Return how many blocks a difficulty period holds on this network.

        Core's `Consensus::Params::DifficultyAdjustmentInterval`, a
        derived quantity there too rather than a stored one: 2016 blocks
        on every network but regtest, whose 144 comes from a one-day
        window over the same ten-minute spacing.
        """
        return self.pow_target_timespan // self.pow_target_spacing

    def script_flags_at(
        self, height: int, block_hash: Octets | None = None
    ) -> btclib.script.engine.flags.ScriptFlag:
        """Return the script rules a block at this height is checked with.

        Bitcoin Core's `GetBlockScriptFlags`
        (`src/validation.cpp`, at bitcoin/bitcoin@9be056a8a7), which is
        what `btclib.script.engine.verify_input` takes as its `flags`.

        P2SH, segwit v0 and taproot are on for every block of every
        chain, and the height decides only the four that Core gates on a
        buried deployment: DERSIG, CHECKLOCKTIMEVERIFY,
        CHECKSEQUENCEVERIFY, and NULLDUMMY with segwit. The blocks that
        predate a rule and would fail it are exceptions by hash, not by
        height -- pass `block_hash` to have them answered, and the flags
        such a block gets are the entry's own rather than the default
        set, with the height-gated rules still added on top.

        The standardness flags are never returned: a block breaking one
        of those is valid, which is `btclib.script.engine.flags`'s own
        split between what `ALL_FLAGS` carries and what it leaves off.
        """
        # imported here and not above: `btclib.script.engine` imports
        # `btclib.script.witness`, which imports this module, so an
        # import at module level is issue #147's cycle. Deferring it
        # keeps this module's import graph empty, which is the property
        # `tests/imports_test.py` holds it to, and costs the caller a
        # sys.modules lookup once the engine is loaded -- which it is,
        # anybody asking for these flags being about to run a script
        from btclib.script.engine.flags import to_script_flags  # noqa: PLC0415
        from btclib.utils import bytes_from_octets, is_integer  # noqa: PLC0415

        if not is_integer(height):
            from btclib.exceptions import BTClibTypeError  # noqa: PLC0415

            err_msg = f"invalid height type: {type(height).__name__}"
            raise BTClibTypeError(err_msg)

        names = _ALWAYS_ON_FLAGS
        if block_hash is not None:
            hash_ = bytes_from_octets(block_hash)
            for exception_hash, exception_names in self.script_flag_exceptions:
                if hash_ == exception_hash:
                    names = exception_names
                    break

        # the four Core asks DeploymentActiveAt about, in its order. A
        # height at or above the activation height is where the rule
        # binds, which is the same comparison `BlockContext.is_bip34_active`
        # makes for the fifth buried deployment
        gated = (
            (self.bip66_height, "DERSIG"),
            (self.bip65_height, "CHECKLOCKTIMEVERIFY"),
            (self.csv_height, "CHECKSEQUENCEVERIFY"),
            (self.segwit_height, "NULLDUMMY"),
        )
        names = (*names, *(name for at, name in gated if height >= at))
        return to_script_flags(names)


# Core's mainnet and testnet3 powLimit, 00000000ffff...ffff, and
# regtest's 7fff...ffff and signet's 00000377ae00...00, each as the
# compact form `bits_from_target` answers for it
_POW_LIMIT_BITS_MAIN = b"\x1d\x00\xff\xff"
_POW_LIMIT_BITS_REGTEST = b"\x20\x7f\xff\xff"
_POW_LIMIT_BITS_SIGNET = b"\x1e\x03\x77\xae"

# every network of btclib.network.NETWORKS, in its order. Fixed at
# import and read-only for the reason that catalogue is: a row added
# afterwards would be in one table and in neither the other nor the
# Network instances built from it
_consensus_params: dict[str, ConsensusParams] = {
    # read at lines 84 to 117 of chainparams.cpp, and in validation.cpp for
    # the blocks of 2010 that a duplicate coinbase pairs: IsBIP30Repeat for
    # the ones repeating, IsBIP30Unspendable for the ones repeated
    "mainnet": ConsensusParams(
        name="mainnet",
        subsidy_halving_interval=210_000,
        bip34_height=227_931,
        bip66_height=363_725,
        bip65_height=388_381,
        csv_height=419_328,
        segwit_height=481_824,
        pow_limit_bits=_POW_LIMIT_BITS_MAIN,
        pow_allow_min_difficulty_blocks=False,
        enforce_bip94=False,
        pow_no_retargeting=False,
        pow_target_spacing=10 * 60,  # line 128
        pow_target_timespan=14 * 24 * 60 * 60,  # line 127, two weeks
        minimum_chain_work=0x0000000000000000000000000000000000000001128750F82F4C366153A3A030,
        bip30_exceptions=(
            (
                91_842,
                bytes.fromhex(
                    "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
                ),
            ),
            (
                91_880,
                bytes.fromhex(
                    "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
                ),
            ),
        ),
        bip30_unspendable=(
            (
                91_722,
                bytes.fromhex(
                    "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
                ),
            ),
            (
                91_812,
                bytes.fromhex(
                    "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
                ),
            ),
        ),
        script_flag_exceptions=(
            # the BIP16 exception: a block mined the day P2SH took effect
            # whose spend is not a valid P2SH one, checked with no flag
            # at all
            (
                bytes.fromhex(
                    "00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"
                ),
                (),
            ),
            # the taproot exception: an annex was spent here before the
            # rule refusing it bound, so this block is checked with
            # taproot off and the two older rules on
            (
                bytes.fromhex(
                    "0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad"
                ),
                ("P2SH", "WITNESS"),
            ),
        ),
    ),
    # read at lines 217 to 248 of chainparams.cpp
    "testnet": ConsensusParams(
        name="testnet",
        subsidy_halving_interval=210_000,
        bip34_height=21_111,
        bip66_height=330_776,
        bip65_height=581_885,
        csv_height=770_112,
        segwit_height=834_624,
        pow_limit_bits=_POW_LIMIT_BITS_MAIN,
        pow_allow_min_difficulty_blocks=True,
        enforce_bip94=False,
        pow_no_retargeting=False,
        pow_target_spacing=10 * 60,  # line 252
        pow_target_timespan=14 * 24 * 60 * 60,  # line 251, two weeks
        minimum_chain_work=0x0000000000000000000000000000000000000000000017DDE1C649F3708D14B6,
        bip30_exceptions=(),
        bip30_unspendable=(),
        script_flag_exceptions=(
            # testnet3's own BIP16 exception, the mainnet one's twin
            (
                bytes.fromhex(
                    "00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105"
                ),
                (),
            ),
        ),
    ),
    # read at lines 567 to 596 of chainparams.cpp. Every rule binds at
    # height 1 except
    # segwit, which binds at the genesis block: a chain mined for a test
    # is not a chain with a history to be compatible with
    "regtest": ConsensusParams(
        name="regtest",
        subsidy_halving_interval=150,
        bip34_height=1,
        bip66_height=1,
        bip65_height=1,
        csv_height=1,
        segwit_height=0,
        pow_limit_bits=_POW_LIMIT_BITS_REGTEST,
        pow_allow_min_difficulty_blocks=True,
        # the only row whose value is not written in chainparams.cpp:
        # line 579 assigns `opts.enforce_bip94`, and the option defaults
        # to false at chainparams.h:154, so false is what a regtest node
        # runs unless `-test=bip94` is passed. The same shape as the
        # heights above it, which the file marks "always active unless
        # overridden": the table carries what Core ships, not what a
        # command line can make of it
        enforce_bip94=False,
        pow_no_retargeting=True,
        pow_target_spacing=10 * 60,  # line 581
        # one day, not the two weeks every other network aims at (line
        # 580): DifficultyAdjustmentInterval() is 144 rather than 2016,
        # which is what the minimum-difficulty walk's own stop condition
        # reads on this network
        pow_target_timespan=24 * 60 * 60,
        minimum_chain_work=0,
        bip30_exceptions=(),
        bip30_unspendable=(),
        script_flag_exceptions=(),
    ),
    # read at lines 478 to 491 of chainparams.cpp for the heights and the
    # limit, and at line 447 for the work, which the default signet carries
    # and a custom challenge leaves empty
    "signet": ConsensusParams(
        name="signet",
        subsidy_halving_interval=210_000,
        bip34_height=1,
        bip66_height=1,
        bip65_height=1,
        csv_height=1,
        segwit_height=1,
        pow_limit_bits=_POW_LIMIT_BITS_SIGNET,
        pow_allow_min_difficulty_blocks=False,
        enforce_bip94=False,
        pow_no_retargeting=False,
        pow_target_spacing=10 * 60,  # line 496
        pow_target_timespan=14 * 24 * 60 * 60,  # line 495, two weeks
        minimum_chain_work=0x00000000000000000000000000000000000000000000000000000B463EA0A4B8,
        bip30_exceptions=(),
        bip30_unspendable=(),
        script_flag_exceptions=(),
    ),
    # read at lines 326 to 356 of chainparams.cpp
    "testnet4": ConsensusParams(
        name="testnet4",
        subsidy_halving_interval=210_000,
        bip34_height=1,
        bip66_height=1,
        bip65_height=1,
        csv_height=1,
        segwit_height=1,
        pow_limit_bits=_POW_LIMIT_BITS_MAIN,
        pow_allow_min_difficulty_blocks=True,
        # true here alone, testnet4 being the chain BIP94 was written for
        enforce_bip94=True,
        pow_no_retargeting=False,
        pow_target_spacing=10 * 60,  # line 352
        pow_target_timespan=14 * 24 * 60 * 60,  # line 351, two weeks
        minimum_chain_work=0x0000000000000000000000000000000000000000000009A0FE15D0177D086304,
        bip30_exceptions=(),
        bip30_unspendable=(),
        script_flag_exceptions=(),
    ),
}

# a mapping and not a dict, for the reason NETWORKS is one: `Network`
# instances are built from these rows at import, so a row added
# afterwards would answer here and nowhere else
CONSENSUS_PARAMS: Mapping[str, ConsensusParams] = MappingProxyType(_consensus_params)
