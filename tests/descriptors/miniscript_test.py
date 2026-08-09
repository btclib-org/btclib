# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `btclib.descriptors.miniscript`.

The oracle is Bitcoin Core's, and it is mechanizable:
`tests/_data/miniscript_fixed_tests.json` is the `fixed_tests` case of
`src/test/miniscript_tests.cpp`, one object per `Test()` call in it. Each
carries the expression, the script it compiles to in each of the two
contexts, whether it is valid at all and in which context, and the three
type answers Core checks -- non-malleability, whether a signature is
needed, whether the timelocks mix. Where the call passes them, it also
carries the resource bounds: the ops of a spend, the witness elements, the
elements the stack reaches while it runs, and the witness size in each
context. Every one of those is asserted here, in both contexts, so a
transcription error in the type tables is a red test and not a wrong
answer.

Four of Core's cases are not in that file, being C++ loops rather than
literals: a ``multi_a()`` of twenty-one keys, three chains of ``and_b()``
that pass the p2wsh ops, stack and script-size limits, and a nesting deep
enough to reach a thousand stack elements while it runs. They are built
here the same way, from the same keys -- Core's are the public keys of the
private keys 1 to 255 -- and their expected numbers are the formulas its
own calls pass.

The two spending conditions of issue #187 are checked as their own case:
both are p2wsh multisig with a timelocked recovery branch, taken from a
production custody protocol, and the point of them is that one maps to
miniscript opcode for opcode while the other does not -- ``v:older(n)``
writes ``<n> CHECKSEQUENCEVERIFY VERIFY`` where the script written by
hand had ``<n> CHECKSEQUENCEVERIFY DROP``, so that script is not
miniscript at all. Both answers were confirmed against Bitcoin Core
v31.1: `getdescriptorinfo` accepts each expression and `deriveaddresses`
gives the address of the script computed here.
"""

from __future__ import annotations

from typing import Any

import pytest

from btclib.alias import Octets, ScriptList
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.descriptors import (
    TrDescriptor,
    WshDescriptor,
    miniscript_sizer,
    miniscript_solver,
    satisfaction_sizer,
)
from btclib.descriptors import parse as parse_descriptor
from btclib.descriptors.key_expression import KeyExpression
from btclib.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    SpendContext,
    from_script,
    parse,
)
from btclib.ecc import dsa, ssa
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160, hash256, ripemd160, sha256
from btclib.psbt.psbt import Psbt, finalize, taproot_sig_hash
from btclib.psbt.psbt_in import PsbtIn
from btclib.psbt.psbt_size import estimated_input_sizes
from btclib.script import sig_hash
from btclib.script.engine import verify_transaction
from btclib.script.script import serialize
from btclib.script.script_pub_key import ScriptPubKey
from btclib.script.taproot import leaf_hash
from btclib.script.witness import Witness
from btclib.to_pub_key import pub_keyinfo_from_prv_key
from btclib.tx.out_point import OutPoint
from btclib.tx.tx import Tx
from btclib.tx.tx_in import TxIn
from btclib.tx.tx_out import TxOut
from tests import load, vector_id

VECTORS: list[dict[str, Any]] = load("_data", "miniscript_fixed_tests.json")

# Core's own test keys: the public keys of the private keys 1 to 255, which
# is what its `TestData` generates and what the vectors above name
KEYS = [
    pub_keyinfo_from_prv_key((31 * b"\x00" + bytes([i])).hex())[0].hex()
    for i in range(1, 256)
]

# the six keys of the two custody expressions
CUSTODY_KEYS = [
    "03d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
    "03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556",
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13",
    "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01",
]

KEY = CUSTODY_KEYS[0]
XONLY = KEY[2:]
SHA256 = "6c60f404f8167a38fc70eaf8aa17ac351023bef86bcb9d1086a19afe95bd5333"
HASH160 = "20195b5a3d650c17f0f29f91c33f8f6335193d07"


def key_hashes(node: Miniscript) -> dict[Octets, Octets]:
    """Return the hash160 of every key of the expression, to the key.

    What a ``pk_h()`` leaves in the script is the hash alone, so reading
    one back needs this mapping; Bitcoin Core's own inference asks a
    signing provider the same question. Both spellings of a taproot key
    are entered, the 32 bytes a tapscript hashes and the 33 a
    `KeyExpression` holds.
    """
    hashes: dict[Octets, Octets] = {}
    for key in node.key_expressions:
        sec = key.sec()
        hashes[hash160(sec)] = sec
        hashes[hash160(sec[1:])] = sec[1:]
    return hashes


def is_invalid(vector: dict[str, Any], context: str) -> bool:
    """Whether the vector says the expression is invalid in this context."""
    return (
        not vector["valid"]
        or (vector["p2wsh_invalid"] and context == P2WSH)
        or (vector["tapscript_invalid"] and context == TAPSCRIPT)
    )


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector_id(index, vector["miniscript"]))
        for index, vector in enumerate(VECTORS)
    ],
)
@pytest.mark.parametrize("context", [P2WSH, TAPSCRIPT])
def test_core_fixed_vector(vector: dict[str, Any], context: str) -> None:
    """Answer as Core does: the script, the type, the bounds, both ways back."""
    expression = vector["miniscript"]
    if is_invalid(vector, context):
        with pytest.raises(BTClibValueError):
            parse(expression, context)
        return
    node = parse(expression, context)
    script = node.script()
    assert node.script_size == len(script)
    expected = vector["p2wsh_script" if context == P2WSH else "tapscript_script"]
    if expected is not None:
        assert script.hex() == expected
    assert node.is_non_malleable == vector["non_malleable"]
    assert node.needs_signature == vector["needs_signature"]
    assert node.mixes_timelocks == vector["mixed_timelocks"]
    witness = "witness_size" if context == P2WSH else "tapscript_witness_size"
    for name, bound in (
        ("ops", node.max_ops),
        ("stack_items", node.max_stack_items),
        ("exec_stack_items", node.max_exec_stack_items),
        (witness, node.max_witness_size),
    ):
        if vector[name] is not None:
            assert bound == vector[name], name
    # the two round trips: through the text, and through the script
    assert parse(str(node), context) == node
    assert from_script(script, context, key_hashes(node)).script() == script


def and_b_chain(count: int) -> str:
    """Return `count` keys nested in and_b(), which is Core's large script."""
    nested = "".join(f"and_b(pk({KEYS[i]}),a:" for i in range(count - 1))
    return nested + f"pk({KEYS[count - 1]})" + ")" * (count - 1)


def test_a_multi_a_holds_more_keys_than_a_multi_may() -> None:
    """Read a multi_a() of twenty-one keys, which no multi() could hold."""
    expression = "multi_a(1," + ",".join(KEYS[:21]) + ")"
    node = parse(expression, TAPSCRIPT)
    assert node.max_ops == 22
    assert node.max_stack_items == 21
    assert node.max_exec_stack_items == 22
    assert str(node) == expression
    with pytest.raises(BTClibValueError, match="only allowed in a tapscript"):
        parse(expression, P2WSH)


@pytest.mark.parametrize("count", [99, 110, 200])
def test_a_tapscript_passes_the_p2wsh_limits(count: int) -> None:
    """Reach past the ops, the stack and the script size a p2wsh allows.

    Which a tapscript may: it has no standardness limit on the script or
    the witness, so the three chains Core builds are valid there and
    refused here.
    """
    expression = and_b_chain(count)
    node = parse(expression, TAPSCRIPT)
    assert node.max_ops == count + (count - 1) * 3
    assert node.max_stack_items == count
    assert node.max_exec_stack_items == count + 1
    assert node.within_resource_limits
    with pytest.raises(BTClibValueError, match="too large for P2WSH"):
        parse(expression, P2WSH)


def older_nesting(count: int) -> str:
    """Return the nesting that reaches `count` + 2 elements on the stack."""
    return "and_b(older(1),a:" * count + f"pk({KEYS[0]})" + ")" * count


def test_the_stack_limit_is_reached_during_execution() -> None:
    """Tell a thousand elements on the stack from one more than that.

    Nothing bounds the witness of a tapscript, so what a deep nesting
    runs into is the stack itself: the analysis has to say so before the
    spend does, and one level deeper is the difference.
    """
    node = parse(older_nesting(998), TAPSCRIPT)
    assert node.max_ops == 4 * 998 + 1
    assert node.max_stack_items == 1
    assert node.max_exec_stack_items == 1000
    assert node.within_resource_limits
    deeper = parse(older_nesting(999), TAPSCRIPT)
    assert deeper.max_exec_stack_items == 1001
    assert not deeper.within_resource_limits
    # the script of a nesting no recursion could walk, read back
    assert from_script(deeper.script(), TAPSCRIPT).script() == deeper.script()
    assert str(parse(str(deeper), TAPSCRIPT)) == str(deeper)


# the two production spending conditions of issue #187, each as the
# miniscript it was claimed to be and as the script it was written as
TIMELOCKED_PRIMARY = (
    f"or_i(and_v(v:older(36),multi(2,{CUSTODY_KEYS[0]},{CUSTODY_KEYS[1]}))"
    f",multi(2,{CUSTODY_KEYS[2]},{CUSTODY_KEYS[3]}))"
)
AUTHORIZATION_GATE = (
    f"andor(multi(2,{CUSTODY_KEYS[0]},{CUSTODY_KEYS[1]})"
    f",multi(2,{CUSTODY_KEYS[4]},{CUSTODY_KEYS[5]})"
    f",and_v(v:multi(2,{CUSTODY_KEYS[2]},{CUSTODY_KEYS[3]}),older(144)))"
)


def test_the_authorization_gate_maps_opcode_for_opcode() -> None:
    """Compile issue #187's second custody script, exactly as written.

    ``andor(X,Y,Z)`` is the OP_NOTIF the script was written with, ``v:``
    on a ``multi()`` is the CHECKMULTISIGVERIFY, and the trailing
    ``older(144)`` is the branch's own value: the CHECKSEQUENCEVERIFY
    leaves the sequence on the stack, which is what OP_ELSE tests.
    """
    written = serialize(
        [
            "OP_2",
            CUSTODY_KEYS[0],
            CUSTODY_KEYS[1],
            "OP_2",
            "OP_CHECKMULTISIG",
            "OP_NOTIF",
            "OP_2",
            CUSTODY_KEYS[2],
            CUSTODY_KEYS[3],
            "OP_2",
            "OP_CHECKMULTISIGVERIFY",
            144,
            "OP_CHECKSEQUENCEVERIFY",
            "OP_ELSE",
            "OP_2",
            CUSTODY_KEYS[4],
            CUSTODY_KEYS[5],
            "OP_2",
            "OP_CHECKMULTISIG",
            "OP_ENDIF",
        ]
    )
    node = parse(AUTHORIZATION_GATE)
    assert node.script() == written
    assert node.is_sane
    # and the script is recognized as the very expression it came from
    assert str(from_script(written)) == AUTHORIZATION_GATE


def test_a_checksequenceverify_drop_is_not_miniscript() -> None:
    """Refuse issue #187's first custody script, which no fragment writes.

    Its policy is expressible -- ``and_v(v:older(36),multi(...))`` is that
    condition -- but the script written by hand consumes what
    CHECKSEQUENCEVERIFY leaves with an OP_DROP, and BIP379 has no fragment
    that writes one: ``v:`` appends OP_VERIFY where the last op code has
    no VERIFY form of its own. The two scripts differ in that one byte, so
    an output already paying to the OP_DROP spelling cannot be described
    by a miniscript, whatever the policy behind it.
    """
    branches = [
        "OP_2",
        CUSTODY_KEYS[0],
        CUSTODY_KEYS[1],
        "OP_2",
        "OP_CHECKMULTISIG",
        "OP_ELSE",
        "OP_2",
        CUSTODY_KEYS[2],
        CUSTODY_KEYS[3],
        "OP_2",
        "OP_CHECKMULTISIG",
        "OP_ENDIF",
    ]
    prefix: ScriptList = ["OP_IF", 36, "OP_CHECKSEQUENCEVERIFY"]
    verified = serialize([*prefix, "OP_VERIFY", *branches])
    dropped = serialize([*prefix, "OP_DROP", *branches])
    node = parse(TIMELOCKED_PRIMARY)
    assert node.script() == verified
    assert node.script() != dropped
    assert str(from_script(verified)) == TIMELOCKED_PRIMARY
    with pytest.raises(BTClibValueError, match="closes no fragment"):
        from_script(dropped)


# every fragment written the sugared way, and what it stands for: `str`
# writes the sugar back, so a round trip through the plain spelling is what
# says the two are the same expression
SUGAR = [
    (f"pk({KEY})", f"c:pk_k({KEY})"),
    (f"pkh({KEY})", f"c:pk_h({KEY})"),
    (f"tv:pk({KEY})", f"and_v(v:pk({KEY}),1)"),
    ("l:older(1)", "or_i(0,older(1))"),
    ("u:older(1)", "or_i(older(1),0)"),
    (f"and_n(pk({KEY}),older(1))", f"andor(pk({KEY}),older(1),0)"),
]


@pytest.mark.parametrize(
    "sugared, plain",
    [
        pytest.param(sugared, plain, id=vector_id(index, sugared))
        for index, (sugared, plain) in enumerate(SUGAR)
    ],
)
def test_the_sugar_is_written_back(sugared: str, plain: str) -> None:
    """Read a fragment both ways, and write it back the short one."""
    assert parse(sugared) == parse(plain)
    assert str(parse(plain)) == sugared


def test_a_wrapper_run_writes_one_colon() -> None:
    """Write a run of wrappers as the letters and the one colon they share."""
    threshold = f"thresh(1,pk({KEY}),altv:after(100))"
    assert str(parse(f"thresh(1,c:pk_k({KEY}),altv:after(100))")) == threshold
    assert str(parse(f"j:and_v(v:hash160({HASH160}),older(16))")) == (
        f"j:and_v(v:hash160({HASH160}),older(16))"
    )


def test_the_type_properties_are_the_bip379_table() -> None:
    """Read the type of a fragment off the expression itself."""
    assert parse("older(1)").properties == frozenset("Bzfmxkh")
    assert parse("older(4194305)").properties == frozenset("Bzfmxkg")
    assert parse("after(1)").properties == frozenset("Bzfmxkj")
    assert parse("after(1000000000)").properties == frozenset("Bzfmxki")
    assert parse(f"pk({KEY})").properties >= frozenset("Bdemsu")
    assert parse(f"pk({KEY})", TAPSCRIPT).subs[0].properties >= frozenset("Kn")
    # 'd:' is "u" under tapscript and not under P2WSH: MINIMALIF is
    # consensus for one and policy for the other
    assert "u" in parse("dv:older(1)", TAPSCRIPT).properties
    assert "u" not in parse("dv:older(1)").properties


def test_a_thresh_may_hold_a_dup_if_under_tapscript_alone() -> None:
    """Refuse under P2WSH the thresh() a tapscript accepts."""
    expression = (
        f"thresh(2,dv:older(42),s:pk({CUSTODY_KEYS[4]}),s:pk({CUSTODY_KEYS[5]}))"
    )
    assert parse(expression, TAPSCRIPT).is_sane
    with pytest.raises(BTClibValueError, match="ill-typed"):
        parse(expression, P2WSH)


REFUSED_EXPRESSIONS = [
    # the wrappers and the fragments the language does not have
    ("q:older(1)", "unknown miniscript wrapper"),
    ("nope(1)", "unknown miniscript fragment"),
    ("older", "not a miniscript fragment"),
    ("(1)", "not a miniscript fragment"),
    ("2", "not a miniscript fragment"),
    # the numbers a fragment may not take
    ("older(0)", "invalid older.. value"),
    ("older(2147483648)", "invalid older.. value"),
    ("after(-1)", "invalid after.. number"),
    ("after(+1)", "invalid after.. number"),
    ("older(1x)", "invalid older.. number"),
    # what a thresh() may not be
    (f"thresh(1,pk({KEY})", "unbalanced brackets in thresh"),
    (f"thresh(pk({KEY}))", "thresh.. takes a threshold"),
    (f"thresh(0,pk({KEY}))", "invalid thresh.. threshold"),
    (f"thresh(2,pk({KEY}))", "invalid thresh.. threshold"),
    ("thresh(1", "thresh.. takes a threshold"),
    # and a multi()
    ("multi(1)", "takes a threshold and at least one key"),
    (f"multi(x,{KEY})", "invalid multi.. threshold"),
    (f"multi(2,{KEY})", "invalid k in k-of-n multi"),
    (f"multi_a(1,{KEY})", "only allowed in a tapscript"),
    # the brackets and the commas a combinator needs
    (f"and_v(v:pk({KEY}))", "expected ',' in the miniscript"),
    (f"and_v(v:pk({KEY}),1", r"expected '\)' in the miniscript"),
    (f"pk_k({KEY}", "unbalanced brackets"),
    (f"pk({KEY})x", "unbalanced brackets"),
    ("0)", "trailing characters after the miniscript"),
    # the type system, at the top level and inside
    (f"pk_k({KEY})", "not a miniscript script"),
    ("and_v(1,1)", "ill-typed miniscript"),
    (f"sha256({SHA256[:-2]})", "invalid size"),
]


@pytest.mark.parametrize(
    "expression, message",
    [
        pytest.param(expression, message, id=vector_id(index, expression))
        for index, (expression, message) in enumerate(REFUSED_EXPRESSIONS)
    ],
)
def test_a_refused_expression_says_what_is_wrong(expression: str, message: str) -> None:
    """Refuse each expression, naming what the language does not allow."""
    with pytest.raises(BTClibValueError, match=message):
        parse(expression)


def test_an_expression_too_large_for_its_context_is_refused() -> None:
    """Refuse the expression whose script no p2wsh witness may carry."""
    with pytest.raises(BTClibValueError, match="too large for P2WSH"):
        parse(and_b_chain(120))


def test_a_hand_built_node_is_checked_for_shape() -> None:
    """Refuse the nodes no fragment has the shape of.

    `parse` and `from_script` cannot build one; a caller writing a node
    out by hand can, and what answers is the same check that lets the type
    tables assume their arguments are there.
    """
    one = Miniscript("1")
    key = KeyExpression(pub_key=bytes.fromhex(KEY))
    with pytest.raises(BTClibValueError, match="unknown miniscript fragment"):
        Miniscript("nope")
    with pytest.raises(BTClibValueError, match="takes 2 subexpressions"):
        Miniscript("and_v", subs=(one,))
    with pytest.raises(BTClibValueError, match="at least one subexpression"):
        Miniscript("thresh", threshold=1)
    with pytest.raises(BTClibValueError, match="invalid number of keys"):
        Miniscript("pk_k")
    with pytest.raises(BTClibValueError, match="invalid number of keys"):
        Miniscript("1", keys=(key,))
    with pytest.raises(BTClibValueError, match="invalid number of keys"):
        Miniscript("multi", keys=(key,) * 21, threshold=1)
    with pytest.raises(BTClibValueError, match="invalid number of keys"):
        Miniscript("multi_a", TAPSCRIPT, keys=(), threshold=1)
    with pytest.raises(BTClibValueError, match="bytes of data"):
        Miniscript("sha256", data=b"\x00")
    with pytest.raises(BTClibValueError, match="takes no number"):
        Miniscript("1", threshold=1)
    with pytest.raises(BTClibValueError, match="not allowed in a tapscript"):
        Miniscript("multi", TAPSCRIPT, keys=(key,), threshold=1)
    with pytest.raises(BTClibValueError, match="only allowed in a tapscript"):
        Miniscript("multi_a", keys=(key,), threshold=1)


def test_an_invalid_node_has_no_script() -> None:
    """Refuse to write the script of an expression the rules refuse."""
    node = Miniscript("and_b", subs=(Miniscript("1"), Miniscript("1")))
    assert not node.is_valid
    assert not node.properties
    with pytest.raises(BTClibValueError, match="invalid miniscript"):
        node.script()


def test_a_witness_of_a_hundred_elements_is_too_large_for_a_p2wsh() -> None:
    """Refuse the descriptor whose spend no p2wsh witness may carry.

    Five 20-of-20 multisig branches fit in the 3600 bytes a witness script
    may take, and satisfying all five would put 105 elements in the
    witness where standardness allows a hundred. Nothing else is wrong
    with it: it is a "B" that needs signatures, cannot be malleated and
    repeats no key.
    """
    branches = [
        "multi(20," + ",".join(KEYS[20 * branch : 20 * branch + 20]) + ")"
        for branch in range(5)
    ]
    expression = (
        "thresh(5,"
        + ",".join(
            branch if position == 0 else f"a:{branch}"
            for position, branch in enumerate(branches)
        )
        + ")"
    )
    node = parse(expression)
    assert node.is_valid_top_level
    assert node.needs_signature
    assert node.is_non_malleable
    assert node.max_stack_items == 105
    assert not node.within_resource_limits
    with pytest.raises(BTClibValueError, match="exceed the resource limits"):
        parse_descriptor(f"wsh({expression})")


def test_an_invalid_expression_is_within_no_limits() -> None:
    """Answer that nothing is guaranteed of a script the rules refuse."""
    node = Miniscript("and_b", subs=(Miniscript("1"), Miniscript("1")))
    assert not node.is_valid
    assert not node.within_resource_limits


def test_an_unsatisfiable_expression_has_no_bounds() -> None:
    """Answer None where no satisfaction exists, and say so."""
    node = parse("or_b(0,a:0)")
    assert not node.is_satisfiable
    assert node.max_stack_items is None
    assert node.max_exec_stack_items is None
    assert node.max_ops is None
    assert node.max_witness_size is None
    # and a valid expression is still within the limits it cannot reach
    assert node.within_resource_limits


def test_a_repeated_key_is_not_sane() -> None:
    """Find the same key twice, whatever the fragments that hold it."""
    node = parse(f"and_v(v:pk({KEY}),pk({KEY}))")
    assert node.has_duplicate_keys
    assert not node.is_sane
    assert len(node.key_expressions) == 2
    assert not parse(f"and_v(v:pk({KEY}),pk({CUSTODY_KEYS[1]}))").has_duplicate_keys


def test_the_insane_subexpression_is_the_deepest_one() -> None:
    """Name the part at fault rather than the whole that shows it."""
    node = parse(f"or_i(and_b(after(1),a:after(1000000000)),pk({KEY}))")
    assert node.is_valid_top_level
    assert not node.is_sane
    insane = node.insane_sub
    assert insane is not None
    assert str(insane) == "and_b(after(1),a:after(1000000000))"
    assert parse(f"pk({KEY})").insane_sub is None


REFUSED_SCRIPTS = [
    # a push that is not the shortest way to write itself
    ("0101", "non-minimal push"),
    ("4c0101", "non-minimal push"),
    # and a VERIFY that should have been the op code before it
    (f"21{KEY}ac6951", "non-minimal VERIFY"),
    # what no fragment writes
    ("75", "closes no fragment"),
    ("", "expression is expected"),
    ("6b5168", "op code 0x6b before an OP_ENDIF"),
    ("635168", "an OP_IF wrapping nothing known"),
    ("5168", "the script ends inside an OP_IF"),
    ("51ac", "ill-typed miniscript"),
    ("87", "closes no fragment"),
    ("510087", "invalid thresh.. threshold"),
    # a script that is two expressions and not one
    ("515193", "closes no fragment"),
    # every op code that must be there and is not
    ("9a", "a W expression is expected"),
    # the four fragments a length or a number rules out
    ("4c0120", "non-minimal push"),
    (f"21{KEY}b2", "closes no fragment"),
    ("515151515187", "ill-typed miniscript"),
    # the shape of a hash fragment with a digest of the wrong size
    ("82012088a814" + "00" * 20 + "87", "closes no fragment"),
    # and the ways a thresh(), an OP_NOTIF or an OP_ELSE can end early
    (f"7c21{KEY}ac935187", "ends inside a thresh"),
    ("515287", "invalid thresh.. threshold: 2 of 1"),
    ("645168", "ends inside an OP_NOTIF"),
    ("51675168", "ends inside an OP_ELSE"),
    ("7c51675168", "op code 0x7c before OP_ELSE"),
    ("6b51", "more than one expression"),
    (f"21{KEY}ad", "is a V, not a B"),
    ("6b9a", "closes no fragment"),
    ("7c516c9a", "its first op code is missing"),
    ("6b519a", "its first op code is missing"),
    ("ae", "closes no fragment"),
    ("5151ae", "no number of keys"),
    (f"21{KEY}21{KEY}51ae", "no threshold"),
    (f"5120{XONLY}51ae", "not a multi.. key"),
]


@pytest.mark.parametrize(
    "script, message",
    [
        pytest.param(script, message, id=vector_id(index, script))
        for index, (script, message) in enumerate(REFUSED_SCRIPTS)
    ],
)
def test_a_script_that_is_no_miniscript_is_refused(script: str, message: str) -> None:
    """Refuse each script, naming what is not miniscript about it."""
    with pytest.raises(BTClibValueError, match=message):
        from_script(script)


def test_the_shortest_miniscript_is_a_constant() -> None:
    """Read the one-byte scripts of the two constants, both ways."""
    assert str(from_script("51")) == "1"
    assert str(from_script("00")) == "0"
    assert parse("1").script().hex() == "51"


def test_a_key_hash_without_its_key_cannot_be_read() -> None:
    """Refuse a pk_h() whose key the caller did not supply.

    The script holds the hash and not the key, so the mapping is what
    makes one readable; Bitcoin Core's inference fails the same way with
    no signing provider to ask.
    """
    script = parse(f"pkh({KEY})").script()
    with pytest.raises(BTClibValueError, match="no public key for the hash160"):
        from_script(script)
    node = from_script(script, P2WSH, {hash160(bytes.fromhex(KEY)): KEY})
    assert str(node) == f"pkh({KEY})"


def test_a_script_too_large_for_its_context_is_refused() -> None:
    """Refuse a script no witness of that kind may carry.

    3600 bytes is standardness for a p2wsh witness script. A tapscript has
    no limit of its own, so what bounds it is the weight of a transaction
    that could spend it: 329482 bytes, which is what Bitcoin Core's
    `MaxScriptSize` works out to for that context and the one number here
    that is worth pinning -- nothing a real script does comes near it, so a
    wrong bound would never be met.
    """
    with pytest.raises(BTClibValueError, match="script too large for P2WSH"):
        from_script(b"\x51" * 3601)
    with pytest.raises(BTClibValueError, match="script too large for tapscript"):
        from_script(b"\x51" * 329483, TAPSCRIPT)
    assert parse("1", TAPSCRIPT).is_valid


def test_a_truncated_push_is_not_a_script() -> None:
    """Refuse bytes that stop in the middle of a push."""
    with pytest.raises(BTClibValueError, match="not a script"):
        from_script("21" + KEY[:-2])


# the shapes of a multi_a() that is not one, written as the op codes they
# are rather than as hex: what each says is which of the checks answers,
# and a 32-byte push spelled "20..." reads as nothing at all
X_ONLY = bytes.fromhex(XONLY)
COMPRESSED = bytes.fromhex(KEY)
TAPSCRIPT_ONLY_SCRIPTS: list[tuple[ScriptList, str]] = [
    # a CHECKSIG with no key in front of it, and a CHECKSIGADD with none
    (["OP_CHECKSIG", "OP_1", "OP_NUMEQUAL"], "closes no fragment"),
    (["OP_1", "OP_1", "OP_1", "OP_NUMEQUAL"], "no CHECKSIG for a key"),
    (
        ["OP_CHECKSIGADD", X_ONLY, "OP_CHECKSIGADD", "OP_1", "OP_NUMEQUAL"],
        "the keys end the script",
    ),
    (
        [
            "OP_CHECKSIG",
            X_ONLY,
            "OP_CHECKSIG",
            X_ONLY,
            "OP_CHECKSIGADD",
            "OP_1",
            "OP_NUMEQUAL",
        ],
        "expression is expected",
    ),
    (["OP_NUMEQUAL"], "closes no fragment"),
    # a threshold that is no number, one that is zero, and a key that is
    # not 32 bytes
    ([X_ONLY, "OP_CHECKSIG", COMPRESSED, "OP_NUMEQUAL"], "no threshold"),
    (
        [X_ONLY, "OP_CHECKSIG", X_ONLY, "OP_CHECKSIGADD", "OP_0", "OP_NUMEQUAL"],
        "invalid k in k-of-n multi_a",
    ),
    (
        [X_ONLY, "OP_CHECKSIG", COMPRESSED, "OP_CHECKSIGADD", "OP_1", "OP_NUMEQUAL"],
        "not a multi_a.. key",
    ),
]


@pytest.mark.parametrize(
    "commands, message",
    [
        pytest.param(commands, message, id=vector_id(index, *commands[:3]))
        for index, (commands, message) in enumerate(TAPSCRIPT_ONLY_SCRIPTS)
    ],
)
def test_a_multi_a_read_wrong_is_refused(commands: ScriptList, message: str) -> None:
    """Refuse the multi_a() shapes Core's own edge cases name.

    No key at all, no key before a CHECKSIGADD, and no key before the
    CHECKSIG that ends one.
    """
    with pytest.raises(BTClibValueError, match=message):
        from_script(serialize(commands), TAPSCRIPT)


def test_each_context_reads_its_own_keys_and_fragments() -> None:
    """Refuse in one context what only the other writes."""
    multi = parse(f"multi(1,{KEY})").script()
    with pytest.raises(BTClibValueError, match="not allowed in a tapscript"):
        from_script(multi, TAPSCRIPT)
    multi_a = parse(f"multi_a(1,{KEY})", TAPSCRIPT).script()
    with pytest.raises(BTClibValueError, match="only allowed in a tapscript"):
        from_script(multi_a)
    with pytest.raises(BTClibValueError, match="not a tapscript public key"):
        from_script(f"21{KEY}ac", TAPSCRIPT)


def test_a_tapscript_key_is_x_only_both_ways() -> None:
    """Write 32 bytes and read them back as the key they lift to."""
    node = parse(f"pk({KEY})", TAPSCRIPT)
    assert node.script().hex() == f"20{XONLY}ac"
    assert str(node) == f"pk({KEY})"
    inferred = from_script(node.script(), TAPSCRIPT)
    assert inferred.script() == node.script()
    assert str(inferred) == f"pk({XONLY})"
    assert inferred.key_expressions[0].x_only
    # the parity byte is not in the script, so what comes back is the
    # even-y lift BIP340 says those 32 bytes mean
    assert inferred.key_expressions[0].sec()[0] == 2


def test_a_ranged_key_derives_at_an_index() -> None:
    """Derive the keys of a miniscript the way a descriptor's are derived."""
    xpub = (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoC"
        "u1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )
    node = parse(f"and_v(v:pk({xpub}/0/*),older(1))")
    assert node.key_expressions[0].is_ranged
    assert node.script(0) != node.script(1)
    assert str(node) == f"and_v(v:pk({xpub}/0/*),older(1))"


def test_a_private_key_is_neutered_on_the_way_in() -> None:
    """Keep no key that signs, and hand the private spelling back."""
    xprv = (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJ"
        "xWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    prv_keys: dict[str, str] = {}
    node = parse(f"and_v(v:pk({xprv}/0h/*),older(1))", P2WSH, prv_keys)
    written = str(node)
    assert xprv not in written
    assert written.startswith("and_v(v:pk(xpub")
    assert len(prv_keys) == 1
    # and the hardened step needs the private key back
    with pytest.raises(BTClibValueError):
        node.script(0)
    assert node.script(0, "mainnet", prv_keys)


def test_a_musig_key_is_a_tapscript_key_expression() -> None:
    """Read BIP390's musig() where BIP386's keys are read, and there only."""
    aggregate = f"musig({CUSTODY_KEYS[0]},{CUSTODY_KEYS[1]})"
    node = parse(f"pk({aggregate})", TAPSCRIPT)
    assert node.key_expressions[0].is_aggregate
    assert str(node) == f"pk({aggregate})"
    with pytest.raises(BTClibValueError, match="only allowed in tr"):
        parse(f"pk({aggregate})")


WSH_DESCRIPTORS = [
    f"wsh(and_v(v:pk({KEY}),older(36)))",
    f"wsh(thresh(1,pk({KEY})))",
    f"wsh({AUTHORIZATION_GATE})",
    f"wsh(and_v(v:ripemd160({HASH160}),pk({KEY})))",
]


@pytest.mark.parametrize(
    "descriptor",
    [
        pytest.param(descriptor, id=vector_id(index, descriptor))
        for index, descriptor in enumerate(WSH_DESCRIPTORS)
    ],
)
def test_a_wsh_descriptor_holds_a_miniscript(descriptor: str) -> None:
    """Read wsh(<miniscript>), and answer for the script it pays to."""
    parsed = parse_descriptor(descriptor)
    assert isinstance(parsed, WshDescriptor)
    assert str(parsed) == descriptor
    address = parsed.address()
    assert address.startswith("bc1q")
    # the witness script is the miniscript's own, and the output pays to it
    assert parsed.inner.redeem_script() == parse(descriptor[4:-1]).script()
    assert not parsed.is_ranged


def test_a_miniscript_descriptor_spends_with_a_context() -> None:
    """Spend a wsh(<miniscript>), and refuse where the context does not.

    The witness of a p2wsh spend is the satisfaction and then the witness
    script, which is what every other `wsh()` puts there too; what is new
    is that the elements before it come from the miniscript satisfier, and
    that the lock time the branch needs has to be in the context. Without
    it the same signatures satisfy nothing, which is the honest answer: the
    branch is unspendable until the transaction carries the sequence.
    """
    descriptor = f"wsh(and_v(v:pk({KEY}),older(36)))"
    parsed = parse_descriptor(descriptor)
    assert isinstance(parsed, WshDescriptor)
    signature = "30" * 71 + "01"
    script_sig, witness = parsed.satisfy(
        {KEY: signature}, spend=SpendContext(sequence=36)
    )
    assert script_sig == b""
    assert witness.stack == (bytes.fromhex(signature), parsed.inner.redeem_script())
    # the sequence of the transaction is what says whether the branch is
    # open, and 35 is not 36
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        parsed.satisfy({KEY: signature}, spend=SpendContext(sequence=35))
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        parsed.satisfy({KEY: signature})


def test_a_ranged_miniscript_descriptor_fills_a_psbt() -> None:
    """Update a psbt from a miniscript descriptor, as any other fills one."""
    xpub = (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoC"
        "u1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )
    descriptor = f"wsh(and_v(v:pk([deadbeef/0h]{xpub}/*),older(36)))"
    parsed = parse_descriptor(descriptor)
    assert isinstance(parsed, WshDescriptor)
    assert parsed.is_ranged
    tx = Tx(
        vin=[TxIn(OutPoint(b"\x03" * 32, 0))],
        vout=[TxOut(400, parsed.script_pub_key(1))],
    )
    psbt_out = parsed.update_psbt_output(Psbt.from_tx(tx), 0, 1).outputs[0]
    assert psbt_out.witness_script == parsed.inner.redeem_script(1)
    assert psbt_out.hd_key_paths


REFUSED_DESCRIPTORS = [
    # miniscript is a wsh() expression and nothing else here
    (f"and_v(v:pk({KEY}),older(1))", "unknown descriptor function"),
    (f"sh(and_v(v:pk({KEY}),older(1)))", "unknown descriptor function"),
    (f"wsh(s:pk({KEY}))", "not a miniscript script"),
    # and what a descriptor may not hold, sane or not
    ("wsh(and_b(after(100),a:after(1000000000)))", "without signature exist"),
    (
        f"wsh(and_v(v:pk({KEY}),and_b(after(100),a:after(1000000000))))",
        "mixes timelocks",
    ),
    (f"wsh(and_v(v:pk({KEY}),pk({KEY})))", "repeats a public key"),
    ("wsh(older(1))", "witnesses without signature exist"),
    (f"wsh(or_b(sha256({SHA256}),a:pk({KEY})))", "malleable witnesses exist"),
    (f"wsh(and_b(0,a:pk({KEY})))", "not satisfiable"),
]


@pytest.mark.parametrize(
    "descriptor, message",
    [
        pytest.param(descriptor, message, id=vector_id(index, descriptor))
        for index, (descriptor, message) in enumerate(REFUSED_DESCRIPTORS)
    ],
)
def test_a_refused_descriptor_says_what_is_wrong(descriptor: str, message: str) -> None:
    """Refuse each descriptor, naming the expression and the reason."""
    with pytest.raises(BTClibValueError, match=message):
        parse_descriptor(descriptor)


# Core's TestData, which is what its vectors are named from: the private
# keys 1 to 255, and the four digests of each key's own 32 bytes -- every
# hash fragment in the vectors commits to one of those arrays
PRV_KEYS = [31 * b"\x00" + bytes([i]) for i in range(1, 256)]
SHA256_PREIMAGES: dict[bytes, bytes] = {sha256(k): k for k in PRV_KEYS}
HASH256_PREIMAGES: dict[bytes, bytes] = {hash256(k): k for k in PRV_KEYS}
RIPEMD160_PREIMAGES: dict[bytes, bytes] = {ripemd160(k): k for k in PRV_KEYS}
HASH160_PREIMAGES: dict[bytes, bytes] = {hash160(k): k for k in PRV_KEYS}
SIGNING_KEYS = dict(zip(KEYS, PRV_KEYS, strict=True))

# the four spends a satisfaction is tried against: an absolute lock time
# of each kind, either side of the 500000000 threshold, and a relative one
# of each, either side of BIP68's bit 22. A fragment is met by the kind it
# is written in and by no other, so an expression whose branches want
# different kinds is satisfiable in one of these and not in another --
# which is what makes four of them rather than one
# Each is the largest of its kind, so that a fragment of that kind is met
# whatever value it names: 499999999 is the last lock time read as a block
# height, 2147483647 the largest a script number holds, and 65535 the
# largest relative lock either unit can ask for
SPENDS = [
    (499999999, 0x0000FFFF),
    (499999999, 0x0040FFFF),
    (2147483647, 0x0000FFFF),
    (2147483647, 0x0040FFFF),
]


def spendable(node: Miniscript, locktime: int, sequence: int) -> list[bytes] | None:
    """Satisfy the expression and let the script engine judge the witness.

    Which is the oracle Core's own satisfaction test uses, and the only one
    worth having: a witness is right when the interpreter accepts it. The
    signatures are real, over the sig hash of the very transaction the
    witness goes into, so a CHECKSIG that verifies is a CHECKSIG that
    verified this spend.

    None where the expression cannot be satisfied with what this spend
    offers -- a lock time of the wrong kind, most often.
    """
    script = node.script()
    prevout = TxOut(50_000, ScriptPubKey.p2wsh(script))
    tx = Tx(
        version=2,
        lock_time=locktime,
        vin=[TxIn(OutPoint(b"\x02" * 32, 0), sequence=sequence)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(KEYS[0]))],
    )
    msg_hash = sig_hash.segwit_v0(script, tx, 0, 1, prevout.value)
    signatures: dict[Octets, Octets] = {
        sec: dsa.sign_(msg_hash, SIGNING_KEYS[sec.hex()]).serialize() + b"\x01"
        for sec in {key.sec() for key in node.key_expressions}
    }
    spend = SpendContext(
        sha256_preimages=SHA256_PREIMAGES,
        hash256_preimages=HASH256_PREIMAGES,
        ripemd160_preimages=RIPEMD160_PREIMAGES,
        hash160_preimages=HASH160_PREIMAGES,
        locktime=locktime,
        sequence=sequence,
    )
    try:
        stack = node.satisfy(signatures, spend)
    except BTClibValueError:
        return None
    tx.vin[0].script_witness = Witness([*stack, script])
    verify_transaction([prevout], tx)
    return stack


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector_id(index, vector["miniscript"]))
        for index, vector in enumerate(VECTORS)
        if vector["valid"] and not vector["p2wsh_invalid"]
    ],
)
def test_a_satisfaction_is_a_witness_the_engine_accepts(
    vector: dict[str, Any],
) -> None:
    """Spend each of Core's valid expressions, and have the engine verify it.

    Two properties at once. Every witness this produces is one
    `verify_transaction` accepts, which is what makes the satisfaction
    right rather than plausible; and every *sane* expression is satisfied
    by at least one of the four spends, which is what makes it complete --
    BIP379's guarantee is that a sane miniscript has a non-malleable
    satisfaction whenever its conditions can be met at all.
    """
    node = parse(vector["miniscript"])
    satisfied = [spendable(node, locktime, sequence) for locktime, sequence in SPENDS]
    if node.is_sane and node.is_satisfiable:
        assert any(stack is not None for stack in satisfied)
    # and the bound the analysis promised is one no satisfaction passes
    for stack in satisfied:
        if stack is not None:
            witness = sum(len(element) + 1 for element in stack)
            assert node.max_witness_size is not None
            assert node.max_stack_items is not None
            assert witness <= node.max_witness_size
            assert len(stack) <= node.max_stack_items


def test_what_the_context_does_not_carry_cannot_be_satisfied() -> None:
    """Refuse where a preimage is missing, or a lock time cannot be met.

    Each of these is a branch that exists in the script and not in the
    caller's hands, which is the difference a satisfier has to report: the
    expression is fine, the spend is not.
    """
    signature = "30" * 71 + "01"
    preimage = bytes(32)
    digest = sha256(preimage)
    node = parse(f"and_v(v:pk({KEY}),sha256({digest.hex()}))")
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        node.satisfy({KEY: signature}, SpendContext())
    # the preimage is under the signature: the sha256() runs after the
    # v:pk() and takes its input from further down the stack
    assert node.satisfy(
        {KEY: signature}, SpendContext(sha256_preimages={digest: preimage})
    ) == [preimage, bytes.fromhex(signature)]
    # a digest the mapping does not hold is the same answer as no mapping
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        node.satisfy(
            {KEY: signature}, SpendContext(sha256_preimages={bytes(32): preimage})
        )
    # and BIP68's relative locks are enforced from version 2, so a
    # version-1 transaction opens no older() branch whatever its sequence
    timelocked = parse(f"and_v(v:pk({KEY}),older(36))")
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        timelocked.satisfy({KEY: signature}, SpendContext(sequence=36, version=1))
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        timelocked.satisfy({KEY: signature}, SpendContext(sequence=36 | (1 << 31)))


def test_a_tapscript_multi_a_is_satisfied_with_one_element_per_key() -> None:
    """Satisfy a multi_a(), which counts every key rather than popping some.

    Where OP_CHECKMULTISIG pops the signatures it is given and no more,
    OP_CHECKSIGADD is run once per key: a key that did not sign leaves the
    empty push in its place, so the witness has one element per key and the
    first key's is at the bottom.
    """
    signature = "30" * 64 + "01"
    keys = ",".join(KEYS[:3])
    node = parse(f"multi_a(1,{keys})", TAPSCRIPT)
    stack = node.satisfy({KEYS[1]: signature})
    assert stack == [b"", bytes.fromhex(signature), b""]
    assert len(stack) == len(node.keys)
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        node.satisfy({})


# the shapes a psbt is finalized in below: a timelocked single key, a
# 2-of-2 whose recovery branch is timelocked, a hash lock, and the
# authorization gate of issue #187, which is the one with three branches
SOLVER_EXPRESSIONS = [
    f"and_v(v:pk({KEYS[0]}),older(36))",
    f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))",
    f"and_v(v:pk({KEYS[0]}),sha256({sha256(PRV_KEYS[3]).hex()}))",
    AUTHORIZATION_GATE,
]


def signed_psbt(
    node: Miniscript, keys: list[str], locktime: int, sequence: int
) -> tuple[Psbt, list[TxOut]]:
    """Return a psbt spending a p2wsh miniscript, signed by `keys`.

    The Updater's work is the descriptor's: the witness script and the
    preimages go in the input, which is where the solver reads them from.
    """
    script = node.script()
    prevout = TxOut(50_000, ScriptPubKey.p2wsh(script))
    tx = Tx(
        version=2,
        lock_time=locktime,
        vin=[TxIn(OutPoint(b"\x05" * 32, 0), sequence=sequence)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(KEYS[0]))],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    psbt.inputs[0].witness_script = script
    psbt.inputs[0].sha256_preimages = {sha256(k): k for k in PRV_KEYS[:8]}
    msg_hash = sig_hash.segwit_v0(script, tx, 0, 1, prevout.value)
    psbt.inputs[0].partial_sigs = {
        bytes.fromhex(key): dsa.sign_(msg_hash, SIGNING_KEYS[key]).serialize() + b"\x01"
        for key in keys
    }
    return psbt, [prevout]


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param(expression, id=vector_id(index, expression))
        for index, expression in enumerate(SOLVER_EXPRESSIONS)
    ],
)
def test_the_solver_finalizes_a_miniscript_input(expression: str) -> None:
    """Finalize a p2wsh miniscript input, and run what it built.

    `psbt.finalize` cannot read a miniscript itself -- `descriptors`
    imports `psbt` and not the other way round -- so the solver is what
    closes the circle, and this is the whole flow through it: the witness
    script and the preimages in the input, the signatures over the sig hash
    of the transaction being built, and `verify_transaction` on what comes
    out.
    """
    node = parse(expression)
    signers = [key.sec().hex() for key in node.key_expressions]
    psbt, prevouts = signed_psbt(node, signers, 499999999, 0x0000FFFF)
    final = finalize(psbt, solver=miniscript_solver)
    psbt_in = final.inputs[0]
    assert psbt_in.final_script_sig == b""
    assert psbt_in.final_script_witness.stack[-1] == node.script()
    # the finalized fields are what the extractor puts in the transaction,
    # and the engine is what says the spend is one the network takes
    spending = final.tx
    spending.vin[0].script_witness = psbt_in.final_script_witness
    verify_transaction(prevouts, spending)


def test_the_solver_answers_for_what_is_its_business_and_no_more() -> None:
    """Return None where the input is not a miniscript, and refuse where it is.

    Three answers, and the middle one is the point of a solver returning
    None rather than raising: an input it does not recognize is one the
    generic finalizer still answers for, exactly as it did before.
    """
    node = parse(f"and_v(v:pk({KEYS[0]}),older(36))")
    # a sequence of 35 does not open a branch that wants 36
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 35)
    with pytest.raises(BTClibValueError, match="no satisfaction"):
        finalize(psbt, solver=miniscript_solver)
    # an input with no witness script at all
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 0x0000FFFF)
    psbt.inputs[0].witness_script = b""
    assert miniscript_solver(psbt, 0) is None
    # and one whose witness script is no miniscript
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 0x0000FFFF)
    psbt.inputs[0].witness_script = serialize(["OP_DROP", "OP_1"])
    assert miniscript_solver(psbt, 0) is None


def test_the_solver_reads_a_key_the_input_knows_by_its_hash() -> None:
    """Recognize a pkh() fragment, whose script holds no key.

    The keys an input carries are what makes that readable: the ones that
    signed, and the ones a key origin names. Without either the witness
    script is not a miniscript as far as anything can tell, and the solver
    says so by answering None.
    """
    node = parse(f"or_d(pk({KEYS[0]}),and_v(v:pkh({KEYS[1]}),older(1008)))")
    psbt, _ = signed_psbt(node, [KEYS[1]], 499999999, 1008)
    assert miniscript_solver(psbt, 0) is not None
    # the origin of a key is enough, the psbt knowing the key from it
    psbt, _ = signed_psbt(node, [KEYS[0]], 499999999, 0x0000FFFF)
    assert miniscript_solver(psbt, 0) is None
    psbt.inputs[0].hd_key_paths = {
        bytes.fromhex(KEYS[1]): BIP32KeyOrigin("deadbeef", [0])
    }
    assert miniscript_solver(psbt, 0) is not None


# a tr() whose script tree holds a miniscript leaf beside a key one: the
# recovery branch of a taproot custody, which is the shape BIP379 allows
# inside tr() and #503 could only read as a wsh()
TR_MINISCRIPT = f"tr({KEYS[0]},{{pk({KEYS[1]}),and_v(v:pk({KEYS[2]}),older(36))}})"


def test_a_tr_leaf_may_be_a_miniscript() -> None:
    """Read a miniscript where a tr() takes a leaf, and write it back.

    The tapscript dialect: the keys of the leaf are the 32 bytes a
    tapscript pushes, and the leaf script is the miniscript's own -- which
    is what the tree commits to, so the output key changes with it.
    """
    parsed = parse_descriptor(TR_MINISCRIPT)
    assert isinstance(parsed, TrDescriptor)
    assert str(parsed) == TR_MINISCRIPT
    leaf = parsed.tree[1] if isinstance(parsed.tree, tuple) else None
    assert isinstance(leaf, Miniscript)
    assert leaf.context == TAPSCRIPT
    assert (
        leaf.script() == parse(f"and_v(v:pk({KEYS[2]}),older(36))", TAPSCRIPT).script()
    )
    # the leaf is one of the two the tree commits to, and its keys are the
    # descriptor's own
    assert len(parsed.taproot_leaf_scripts()) == 2
    assert {key.sec().hex() for key in parsed.key_expressions} == set(KEYS[:3])


def test_a_tr_miniscript_leaf_is_spent_on_the_script_path() -> None:
    """Spend the miniscript leaf of a tr(), and have the engine accept it.

    The witness of a script path spend is the satisfaction, the leaf script
    and the control block; what is new is that the elements before the
    script come from the miniscript satisfier, and that the branch wants a
    sequence the transaction has to carry. The signature is a real BIP340
    one over the sig hash of that very spend, and `verify_transaction`
    decides.
    """
    parsed = parse_descriptor(TR_MINISCRIPT)
    prevout = TxOut(50_000, parsed.script_pub_key())
    tx = Tx(
        version=2,
        vin=[TxIn(OutPoint(b"\x07" * 32, 0), sequence=36)],
        vout=[TxOut(49_000, ScriptPubKey.p2wpkh(KEYS[0]))],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].witness_utxo = prevout
    leaf_script = parse(f"and_v(v:pk({KEYS[2]}),older(36))", TAPSCRIPT).script()
    msg_hash = taproot_sig_hash(psbt, 0, leaf_hash=leaf_hash(0xC0, leaf_script))
    signature = ssa.sign_(msg_hash, SIGNING_KEYS[KEYS[2]]).serialize()
    script_sig, witness = parsed.satisfy(
        {KEYS[2]: signature}, spend=SpendContext(sequence=36)
    )
    assert script_sig == b""
    # the satisfaction, the leaf script, the control block
    assert witness.stack[0] == signature
    assert witness.stack[1] == leaf_script
    tx.vin[0].script_witness = witness
    verify_transaction([prevout], tx)
    # and without the sequence the branch is shut, so no leaf is satisfied
    with pytest.raises(BTClibValueError, match="no signature for the tr"):
        parsed.satisfy({KEYS[2]: signature})


def test_a_tr_miniscript_leaf_is_held_to_the_same_sanity() -> None:
    """Refuse a leaf a descriptor would not hold, naming the leaf.

    A tree is several scripts, and one that cannot be spent safely is one
    a wallet should not be handed whatever the others are.
    """
    with pytest.raises(BTClibValueError, match="without signature exist"):
        parse_descriptor(f"tr({KEYS[0]},{{pk({KEYS[1]}),older(36)}})")
    # multi() belongs to P2WSH: inside tr() the fragment is multi_a()
    with pytest.raises(BTClibValueError, match="not allowed in a tapscript"):
        parse_descriptor(f"tr({KEYS[0]},and_v(v:multi(1,{KEYS[1]}),older(36)))")
    with pytest.raises(BTClibValueError, match="ill-typed"):
        parse_descriptor(f"tr({KEYS[0]},and_v(1,1))")


# a tr() with a miniscript leaf and the regtest address Bitcoin Core v31.1
# answers for it, from `getdescriptorinfo` and `deriveaddresses`. The
# address is the output key, which commits to the whole tree, so agreeing
# on it is agreeing on every leaf script: the tapscript dialect of the
# fragments, the 32-byte keys, and the order the tree is built in
CORE_TR_VECTORS = [
    (
        f"tr({CUSTODY_KEYS[0]},and_v(v:pk({CUSTODY_KEYS[1]}),older(36)))",
        "bcrt1pf4p484mdhmu0436mmztpj8594tnpkhytdj0du5w0gvke6a9lr8lqtse22f",
    ),
    (
        f"tr({CUSTODY_KEYS[0]},{{pk({CUSTODY_KEYS[1]}),and_v(v:pk({CUSTODY_KEYS[2]}),older(36))}})",
        "bcrt1p0lw39vec3wgmyyyfvgr5p09ncydezxrmde5e44gjqsk30rwcqk7stm96l7",
    ),
    (
        f"tr({CUSTODY_KEYS[0]},{{and_v(v:multi_a(2,{CUSTODY_KEYS[1]},{CUSTODY_KEYS[2]}),after(1231488000)),pk({CUSTODY_KEYS[2]})}})",
        "bcrt1pxjtajh8f9lf3svdd9qhl542uehfdzh8pewen70ns8j5tzfv55peq88cxuw",
    ),
    (
        f"tr({CUSTODY_KEYS[0]},or_d(pk({CUSTODY_KEYS[1]}),and_v(v:pkh({CUSTODY_KEYS[2]}),older(1008))))",
        "bcrt1prx5z8n0jguw4v7clt4v3wsnksuyxvvaqljwl2qz4gu9lxjuev9wsmfnl08",
    ),
]


@pytest.mark.parametrize(
    "descriptor, address",
    [
        pytest.param(descriptor, address, id=vector_id(index, descriptor))
        for index, (descriptor, address) in enumerate(CORE_TR_VECTORS)
    ],
)
def test_a_tr_miniscript_pays_where_core_says(descriptor: str, address: str) -> None:
    """Pay to the address Bitcoin Core derives for the same tr() descriptor.

    Four trees: one miniscript leaf, one beside a key leaf, one holding a
    ``multi_a()`` inside a miniscript, and one whose branch names its key by
    a hash. Nothing in these is checked by Core's `fixed_tests`, which is
    about expressions rather than about descriptors, and nothing else says
    the tapscript dialect is wired to the right side of a ``tr()``.
    """
    assert parse_descriptor(descriptor, "regtest").address() == address


@pytest.mark.parametrize(
    "vector",
    [
        pytest.param(vector, id=vector_id(index, vector["miniscript"]))
        for index, vector in enumerate(VECTORS)
        if vector["valid"]
    ],
)
@pytest.mark.parametrize("context", [P2WSH, TAPSCRIPT])
def test_the_two_witness_analyses_agree(vector: dict[str, Any], context: str) -> None:
    """Size a witness twice, by two transcriptions, and get one answer.

    `max_witness_size` comes from BIP379's type tables, which compute a
    number and never a witness; `max_witness_stack` walks the satisfaction
    and reports the elements of the largest one. The two are independent
    implementations of the same question -- Core's `CalcWitnessSize` and
    its `ProduceInput` -- so their agreeing on every vector says more about
    both than either says alone: the elements, once given the length prefix
    the transaction writes, weigh exactly what the tables say.

    The element *count* is only bounded, not matched: the two static tables
    maximise different quantities, so the branch that is heaviest in bytes
    need not be the one that puts the most elements on the stack.
    """
    if is_invalid(vector, context):
        return
    node = parse(vector["miniscript"], context)
    stack = node.max_witness_stack
    if stack is None:
        # nothing satisfies it, so there is no witness to weigh either way
        assert node.max_stack_items is None
        return
    assert sum(size + 1 for size in stack) == node.max_witness_size
    assert node.max_stack_items is not None
    assert len(stack) <= node.max_stack_items


def test_the_estimate_needs_neither_signature_nor_preimage() -> None:
    """Size a spend before there is one, which is what an estimate is for.

    Every element of it is known from the expression: a signature is the
    context's largest, a preimage is BIP379's 32 bytes, a key is 33 bytes
    or 32, and the rest are the empty push and the OP_1 a branch selector
    is.
    """
    node = parse(f"and_v(v:pk({KEY}),sha256({SHA256}))")
    assert node.max_witness_stack == (32, 72)
    assert parse(f"pk({KEY})", TAPSCRIPT).max_witness_stack == (65,)
    # the key is on top of the signature, the script reading it first
    assert parse(f"pkh({KEY})").max_witness_stack == (72, 33)
    assert parse(f"multi(2,{KEYS[0]},{KEYS[1]})").max_witness_stack == (0, 72, 72)
    # a branch behind an or_i() carries the selector that picks it
    assert parse(f"or_i(pk({KEYS[0]}),pk({KEYS[1]}))").max_witness_stack == (72, 1)
    # and what nothing satisfies has no witness to size
    assert parse("or_b(0,a:0)").max_witness_stack is None


def test_the_estimate_is_the_largest_branch_and_not_the_cheapest() -> None:
    """Answer with the branch a signer may be pushed onto, not the cheap one.

    `satisfy` reports the witness that will be built where everything is
    available, which is the cheaper branch of this expression: the preimage
    and the dissatisfied multisig. The estimate reports the other one,
    because the cheap branch is the one a missing preimage shuts, and an
    estimate that assumed it would pay too little a fee.
    """
    digest = ripemd160(PRV_KEYS[3]).hex()
    expression = (
        f"c:and_v(or_c(multi(2,{KEYS[0]},{KEYS[1]}),v:ripemd160({digest}))"
        f",pk_k({KEYS[2]}))"
    )
    node = parse(expression)
    assert node.is_sane
    signatures: dict[Octets, Octets] = dict.fromkeys(KEYS[:3], "30" * 71 + "01")
    spend = SpendContext(ripemd160_preimages={ripemd160(PRV_KEYS[3]): PRV_KEYS[3]})
    built = node.satisfy(signatures, spend)
    assert sum(len(element) + 1 for element in built) == 109
    assert node.max_witness_size == 220
    assert sum(size + 1 for size in node.max_witness_stack or ()) == 220


def psbt_input(node: Miniscript) -> tuple[PsbtIn, TxIn]:
    """Return an unsigned p2wsh input of the expression, and its TxIn.

    With the key origins an Updater writes, which is what a `pkh()`
    fragment needs to be readable at all: its script holds the hash of its
    key, so an input carrying neither a signature nor an origin for that
    key is one whose witness script is not miniscript as far as anything
    can tell.
    """
    script = node.script()
    psbt_in = PsbtIn(
        witness_utxo=TxOut(50_000, ScriptPubKey.p2wsh(script)),
        witness_script=script,
        # one origin per key, and a path of its own for each: a psbt refuses
        # two keys claiming the same one
        hd_key_paths={
            key.sec(): BIP32KeyOrigin("deadbeef", [position])
            for position, key in enumerate(node.key_expressions)
        },
    )
    return psbt_in, TxIn(OutPoint(b"\x09" * 32, 0), sequence=36)


@pytest.mark.parametrize(
    "expression",
    [
        pytest.param(expression, id=vector_id(index, expression))
        for index, expression in enumerate(SOLVER_EXPRESSIONS)
    ],
)
def test_the_sizer_answers_before_there_is_a_signature(expression: str) -> None:
    """Size a miniscript input, and pay the fee the spend will need.

    The witness of a p2wsh spend is the satisfaction and then the witness
    script, so that is the list; what makes it an estimate rather than a
    measurement is that no signature exists yet, and what makes it enough
    is that the size of one does not depend on the key.
    """
    node = parse(expression)
    psbt_in, tx_in = psbt_input(node)
    script_sig, witness = estimated_input_sizes(psbt_in, tx_in, sizer=miniscript_sizer)
    assert script_sig == 0
    assert witness == [*(node.max_witness_stack or ()), len(node.script())]
    # the fee is paid on this, so it is the bound and not the cheapest
    assert sum(size + 1 for size in witness[:-1]) == node.max_witness_size
    # and without the sizer there is no estimate to be had
    with pytest.raises(BTClibValueError, match="no estimate for a script"):
        estimated_input_sizes(psbt_in, tx_in)


def test_the_sizer_answers_for_what_is_its_business_and_no_more() -> None:
    """Return None where the input is not a miniscript, as the solver does."""
    node = parse(f"and_v(v:pk({KEY}),older(36))")
    psbt_in, tx_in = psbt_input(node)
    assert miniscript_sizer(psbt_in, tx_in) is not None
    psbt_in.witness_script = b""
    assert miniscript_sizer(psbt_in, tx_in) is None
    psbt_in.witness_script = serialize(["OP_DROP", "OP_1"])
    assert miniscript_sizer(psbt_in, tx_in) is None
    # a script nothing satisfies has no spend to size, which is the answer
    # "not mine" too: the refusal is the caller's to make
    unspendable = parse("or_b(0,a:0)")
    psbt_in.witness_script = unspendable.script()
    assert miniscript_sizer(psbt_in, tx_in) is None


# a primary quorum larger than its timelocked recovery quorum, which is
# issue #547's own shape: which branch a spend takes is decided before
# anything is estimated, and `max_witness_stack` cannot use that
_PRIMARY = f"multi(3,{KEYS[0]},{KEYS[1]},{KEYS[2]},{KEYS[3]},{KEYS[4]})"
_RECOVERY = f"and_v(v:older(36),multi(2,{KEYS[5]},{KEYS[6]}))"


def test_the_satisfaction_sizer_answers_for_the_branch_these_keys_build() -> None:
    """Size the branch a caller knows it will build, not the largest one.

    `max_witness_stack` reports the larger of the two branches -- the
    primary quorum here -- and a recovery spend pays for it too, though it
    never opens that branch. `satisfaction_sizer` given the keys that will
    actually sign reports what that spend builds instead, the same psbt
    input and the same `TxIn` both times: only the signers change.
    """
    node = parse(f"or_i({_RECOVERY},{_PRIMARY})")
    psbt_in, tx_in = psbt_input(node)
    assert node.max_witness_stack == (0, 72, 72, 72, 0)

    primary = estimated_input_sizes(psbt_in, tx_in, sizer=satisfaction_sizer(KEYS[0:3]))
    assert primary == (0, [0, 72, 72, 72, 0, len(node.script())])
    # the primary quorum is the larger branch, so this is what
    # `miniscript_sizer` would have answered too: no savings to find
    assert primary == estimated_input_sizes(psbt_in, tx_in, sizer=miniscript_sizer)

    recovery = estimated_input_sizes(
        psbt_in, tx_in, sizer=satisfaction_sizer(KEYS[5:7])
    )
    assert recovery == (0, [0, 72, 72, 1, len(node.script())])
    # the bytes issue #547 measures: paid on every recovery spend by a
    # sizer that does not know which branch it is, and not on this one
    assert sum(recovery[1][:-1]) < sum(primary[1][:-1])


def test_the_satisfaction_sizer_answers_for_what_is_its_business_and_no_more() -> None:
    """Refuse for the two reasons `miniscript_sizer` does, and a third.

    No witness script and no miniscript are the two they share; building
    no satisfaction at all from the given keys is this sizer's own.
    """
    node = parse(f"and_v(v:pk({KEY}),older(36))")
    psbt_in, tx_in = psbt_input(node)
    assert satisfaction_sizer([KEY])(psbt_in, tx_in) is not None
    psbt_in.witness_script = b""
    assert satisfaction_sizer([KEY])(psbt_in, tx_in) is None
    psbt_in.witness_script = serialize(["OP_DROP", "OP_1"])
    assert satisfaction_sizer([KEY])(psbt_in, tx_in) is None
    # a key that will not sign this quorum builds no satisfaction either
    psbt_in.witness_script = node.script()
    assert satisfaction_sizer([KEYS[0]])(psbt_in, tx_in) is None
