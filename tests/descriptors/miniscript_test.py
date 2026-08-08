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
from btclib.descriptors import WshDescriptor
from btclib.descriptors import parse as parse_descriptor
from btclib.descriptors.key_expression import KeyExpression
from btclib.descriptors.miniscript import (
    P2WSH,
    TAPSCRIPT,
    Miniscript,
    from_script,
    parse,
)
from btclib.exceptions import BTClibValueError
from btclib.hashes import hash160
from btclib.psbt.psbt import Psbt
from btclib.script.script import serialize
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
    """Refuse a script no witness of that kind may carry."""
    with pytest.raises(BTClibValueError, match="script too large for P2WSH"):
        from_script(b"\x51" * 3601)


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


def test_a_miniscript_descriptor_does_not_satisfy_yet() -> None:
    """Refuse to spend, and say what a satisfaction would need.

    The signatures alone cannot choose a branch: a preimage, a locktime
    and the weight of each branch are what a miniscript satisfaction
    reads, and none of them is in the mapping.
    """
    parsed = parse_descriptor(f"wsh(and_v(v:pk({KEY}),older(36)))")
    with pytest.raises(NotImplementedError, match="187"):
        parsed.satisfy({KEY: "00" * 71})


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
