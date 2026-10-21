# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Exception classes.

These exist only to tell an exception raised by btclib from one raised by
any other code: each derives from the built-in that says what kind of
failure it is, and adds nothing to it.

`BTClibException` is what makes that telling apart a single `except`
rather than a tuple of three a caller has to keep in step with this
hierarchy. It is inherited *beside* the built-in and not instead of it,
which is the half that matters: `BTClibValueError` is a `ValueError` as
it always was, so code catching the built-in keeps catching what it
caught, and `json.JSONDecodeError` is the standard library doing the
same. Libraries that give up the built-in -- requests, sqlalchemy and
httpx among them -- leave an `except ValueError` not catching their value
errors, which is the cost this avoids by inheriting from both.

It is caught and never raised: every raise below is one of the three, and
which one answers a question the base cannot carry -- whether the value
was wrong, the type was, or neither was and a check failed anyway. A
caller with something to do about that difference names the specific
class; `except BTClibException` is for the caller who only needs to know
it came from here, and it catches every failure btclib's own code raises:
no public function lets a native `KeyError`, `IndexError` or
`OverflowError` escape uncaught.

What the `btclib_ecc` package raises is not a `BTClibException`. The
curve arithmetic and the schemes other than `bms` are that package's, and
it raises its own classes, `btclib_ecc.exceptions.BTClibEccValueError`,
`BTClibEccTypeError` and `BTClibEccRuntimeError` under
`BTClibEccException`, built the same way beside the same three
built-ins. So a failure raised inside it, whichever btclib function
called in, is caught by `except ValueError` and not by `except
BTClibValueError`. A caller naming one of those classes, or the two that
carry a field, `InvalidContributionError` and `BorromeanRingError`,
imports them from `btclib_ecc.exceptions`.

The exception is the few classes below carrying a field: how many more
octets a p2p message needs, which script error and where. Those are
values a caller acts on, and reading them back out of a message is what
the field spares them, so a caller after one of them still names the
specific class rather than the base.

`ScriptErrorCode` is the one name here that is no exception: it is the
type of `ScriptError`'s `code`, defined beside the class that carries it.

Each of those hands every constructor argument to
`BaseException.__init__` and composes its message in `__str__`, which is
what `subprocess.CalledProcessError` and `UnicodeDecodeError` do, and
what makes it picklable: `BaseException.__reduce__` returns `(cls,
self.args)`, so a class whose `args` is the composed message alone is
rebuilt by calling it with one argument, and one argument is not what it
takes. That is a TypeError out of `pickle`, out of `copy.copy` and out
of `copy.deepcopy` -- and out of a `ProcessPoolExecutor`, which cannot
send the exception back and reports a broken pool instead of the failure
the worker died of. Composing in `__str__` is the half that keeps the
round trip faithful rather than merely possible: a message composed in
`__init__` from an argument that is itself a composed message gains a
second `(command 3, stack depth 2)` every time.

The visible price is `args`, which is a tuple of the arguments now and
not a one-tuple of the message, and `repr`, which names the fields with
it. `str` is the message it always was.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import IntEnum

from typing_extensions import override

__all__ = [
    "BTClibException",
    "BTClibRuntimeError",
    "BTClibTypeError",
    "BTClibUserWarning",
    "BTClibValueError",
    "IncompleteMessageError",
    "InvalidPrvKeyError",
    "NotAPrvKeyError",
    "ScriptError",
    "ScriptErrorCode",
    "ShortIdCollisionError",
]


class BTClibException(Exception):  # noqa: N818 -- a kind, like Exception itself, not a leaf raised
    """Anything btclib raised, whatever kind of failure it is.

    The one name to catch for a caller who handles the standard library's
    exceptions anyway and needs to know which came from here. Never
    raised: the three below it are, and each says which kind of failure
    it was.
    """


class BTClibValueError(BTClibException, ValueError):
    """A value no valid input could carry; the library's usual refusal."""


class BTClibTypeError(BTClibException, TypeError):
    """An input of a type no conversion accepts: a caller error."""


class BTClibRuntimeError(BTClibException, RuntimeError):
    """A check that failed on valid inputs, e.g. a failed verification."""


class IncompleteMessageError(BTClibRuntimeError):
    """A p2p message is not all there yet, and `missing` says by how much.

    What `btclib.p2p.Message.parse` raises where the octets end inside a
    message: fewer than the header's, or a header whose payload length
    the octets after it do not reach. `missing` is how many more would
    take the parse past where this one stopped -- the rest of the header,
    or the rest of the payload once the header has been read -- so a
    caller accumulating from a socket has a number to ask for rather than
    a guess.

    A BTClibRuntimeError and not a BTClibValueError, which is the class
    every other short read in this library raises: nothing the caller
    passed is wrong. `BTClibValueError` is "a value no valid input could
    carry" and these octets are the valid input's own prefix; what failed
    is a check on it, which is what `BTClibRuntimeError` says. Reading
    more can fix it and correcting an argument cannot.

    Not a bare `BTClibRuntimeError`: the whole point is that a socket caller
    tells this from every other refusal `parse` gives, and one class two answers
    share is one a caller cannot branch on. Everything else `parse` raises is
    final -- a magic no further octet changes, a length over
    `btclib.p2p.limits.MAX_PROTOCOL_MESSAGE_LENGTH`, a checksum that does not
    verify -- and the peer that sent it is the thing to drop.
    """

    def __init__(self, message: str, missing: int) -> None:
        self.missing = missing
        super().__init__(message, missing)

    @override
    def __str__(self) -> str:
        return f"{self.args[0]}: {self.missing} more bytes wanted"


class ShortIdCollisionError(BTClibRuntimeError):
    """A compact block's own short ids collide, so it cannot be rebuilt.

    What `btclib.p2p.compact_blocks.reconstruct` raises where two
    positions of a `cmpctblock` carry one short id. Core's `InitData`
    answers `READ_STATUS_FAILED` there, and its caller asks for the whole
    block. The `BTClibValueError`s `reconstruct` raises are Core's
    `READ_STATUS_INVALID`, and its caller punishes the peer for those.

    A BTClibRuntimeError and not a BTClibValueError: the message is valid,
    and BIP152 says nodes "MUST NOT be penalized for such collisions". A
    caller catching `BTClibValueError` as "the peer sent garbage" does
    not catch this. `IncompleteMessageError` is the precedent.
    """


class ScriptErrorCode(IntEnum):
    """Which of Bitcoin Core's script errors a `ScriptError` is.

    Core's `ScriptError_t` (src/script/script_error.h), member for member
    and in its order, so a value is the integer Core gives the same
    error. The names drop Core's `SCRIPT_ERR_` prefix, as `ScriptFlag`
    drops `SCRIPT_VERIFY_`. `SCRIPT_ERR_ERROR_COUNT` is Core's array
    bound and not an error, so it is no member: `len(ScriptErrorCode)` is
    its value.

    `description` is the text Core's `ScriptErrorString`
    (src/script/script_error.cpp) returns for the code, which is what
    Core's own messages quote -- `mempool-script-verify-flag-failed
    (<text>)` among them.
    """

    OK = 0
    UNKNOWN_ERROR = 1
    EVAL_FALSE = 2
    OP_RETURN = 3
    SCRIPTNUM = 4

    # max sizes
    SCRIPT_SIZE = 5
    PUSH_SIZE = 6
    OP_COUNT = 7
    STACK_SIZE = 8
    SIG_COUNT = 9
    PUBKEY_COUNT = 10

    # failed verify operations
    VERIFY = 11
    EQUALVERIFY = 12
    CHECKMULTISIGVERIFY = 13
    CHECKSIGVERIFY = 14
    NUMEQUALVERIFY = 15

    # logical, format and canonical errors
    BAD_OPCODE = 16
    DISABLED_OPCODE = 17
    INVALID_STACK_OPERATION = 18
    INVALID_ALTSTACK_OPERATION = 19
    UNBALANCED_CONDITIONAL = 20

    # CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY
    NEGATIVE_LOCKTIME = 21
    UNSATISFIED_LOCKTIME = 22

    # malleability
    SIG_HASHTYPE = 23
    SIG_DER = 24
    MINIMALDATA = 25
    SIG_PUSHONLY = 26
    SIG_HIGH_S = 27
    SIG_NULLDUMMY = 28
    PUBKEYTYPE = 29
    CLEANSTACK = 30
    MINIMALIF = 31
    SIG_NULLFAIL = 32

    # soft-fork safeness
    DISCOURAGE_UPGRADABLE_NOPS = 33
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 34
    DISCOURAGE_UPGRADABLE_TAPROOT_VERSION = 35
    DISCOURAGE_OP_SUCCESS = 36
    DISCOURAGE_UPGRADABLE_PUBKEYTYPE = 37

    # segregated witness
    WITNESS_PROGRAM_WRONG_LENGTH = 38
    WITNESS_PROGRAM_WITNESS_EMPTY = 39
    WITNESS_PROGRAM_MISMATCH = 40
    WITNESS_MALLEATED = 41
    WITNESS_MALLEATED_P2SH = 42
    WITNESS_UNEXPECTED = 43
    WITNESS_PUBKEYTYPE = 44

    # taproot
    SCHNORR_SIG_SIZE = 45
    SCHNORR_SIG_HASHTYPE = 46
    SCHNORR_SIG = 47
    TAPROOT_WRONG_CONTROL_SIZE = 48
    TAPSCRIPT_VALIDATION_WEIGHT = 49
    TAPSCRIPT_CHECKMULTISIG = 50
    TAPSCRIPT_MINIMALIF = 51
    TAPSCRIPT_EMPTY_PUBKEY = 52

    # constant script code
    OP_CODESEPARATOR = 53
    SIG_FINDANDDELETE = 54

    @property
    def description(self) -> str:
        """Core's `ScriptErrorString` for this code."""
        return _SCRIPT_ERROR_STRINGS[self]


# Core's ScriptErrorString, case for case; UNKNOWN_ERROR is the case that
# breaks out of the switch to the "unknown error" after it
_SCRIPT_ERROR_STRINGS: Mapping[ScriptErrorCode, str] = {
    ScriptErrorCode.OK: "No error",
    ScriptErrorCode.UNKNOWN_ERROR: "unknown error",
    ScriptErrorCode.EVAL_FALSE: (
        "Script evaluated without error but finished with a false/empty top "
        "stack element"
    ),
    ScriptErrorCode.OP_RETURN: "OP_RETURN was encountered",
    ScriptErrorCode.SCRIPTNUM: "Script number overflowed or is non-minimally encoded",
    ScriptErrorCode.SCRIPT_SIZE: "Script is too big",
    ScriptErrorCode.PUSH_SIZE: "Push value size limit exceeded",
    ScriptErrorCode.OP_COUNT: "Operation limit exceeded",
    ScriptErrorCode.STACK_SIZE: "Stack size limit exceeded",
    ScriptErrorCode.SIG_COUNT: "Signature count negative or greater than pubkey count",
    ScriptErrorCode.PUBKEY_COUNT: "Pubkey count negative or limit exceeded",
    ScriptErrorCode.VERIFY: "Script failed an OP_VERIFY operation",
    ScriptErrorCode.EQUALVERIFY: "Script failed an OP_EQUALVERIFY operation",
    ScriptErrorCode.CHECKMULTISIGVERIFY: (
        "Script failed an OP_CHECKMULTISIGVERIFY operation"
    ),
    ScriptErrorCode.CHECKSIGVERIFY: "Script failed an OP_CHECKSIGVERIFY operation",
    ScriptErrorCode.NUMEQUALVERIFY: "Script failed an OP_NUMEQUALVERIFY operation",
    ScriptErrorCode.BAD_OPCODE: "Opcode missing or not understood",
    ScriptErrorCode.DISABLED_OPCODE: "Attempted to use a disabled opcode",
    ScriptErrorCode.INVALID_STACK_OPERATION: (
        "Operation not valid with the current stack size"
    ),
    ScriptErrorCode.INVALID_ALTSTACK_OPERATION: (
        "Operation not valid with the current altstack size"
    ),
    ScriptErrorCode.UNBALANCED_CONDITIONAL: "Invalid OP_IF construction",
    ScriptErrorCode.NEGATIVE_LOCKTIME: "Negative locktime",
    ScriptErrorCode.UNSATISFIED_LOCKTIME: "Locktime requirement not satisfied",
    ScriptErrorCode.SIG_HASHTYPE: "Signature hash type missing or not understood",
    ScriptErrorCode.SIG_DER: "Non-canonical DER signature",
    ScriptErrorCode.MINIMALDATA: "Data push larger than necessary",
    ScriptErrorCode.SIG_PUSHONLY: "Only push operators allowed in signatures",
    ScriptErrorCode.SIG_HIGH_S: (
        "Non-canonical signature: S value is unnecessarily high"
    ),
    ScriptErrorCode.SIG_NULLDUMMY: "Dummy CHECKMULTISIG argument must be zero",
    ScriptErrorCode.PUBKEYTYPE: "Public key is neither compressed or uncompressed",
    ScriptErrorCode.CLEANSTACK: "Stack size must be exactly one after execution",
    ScriptErrorCode.MINIMALIF: "OP_IF/NOTIF argument must be minimal",
    ScriptErrorCode.SIG_NULLFAIL: (
        "Signature must be zero for failed CHECK(MULTI)SIG operation"
    ),
    ScriptErrorCode.DISCOURAGE_UPGRADABLE_NOPS: "NOPx reserved for soft-fork upgrades",
    ScriptErrorCode.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: (
        "Witness version reserved for soft-fork upgrades"
    ),
    ScriptErrorCode.DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: (
        "Taproot version reserved for soft-fork upgrades"
    ),
    ScriptErrorCode.DISCOURAGE_OP_SUCCESS: "OP_SUCCESSx reserved for soft-fork upgrades",
    ScriptErrorCode.DISCOURAGE_UPGRADABLE_PUBKEYTYPE: (
        "Public key version reserved for soft-fork upgrades"
    ),
    ScriptErrorCode.WITNESS_PROGRAM_WRONG_LENGTH: "Witness program has incorrect length",
    ScriptErrorCode.WITNESS_PROGRAM_WITNESS_EMPTY: (
        "Witness program was passed an empty witness"
    ),
    ScriptErrorCode.WITNESS_PROGRAM_MISMATCH: "Witness program hash mismatch",
    ScriptErrorCode.WITNESS_MALLEATED: "Witness requires empty scriptSig",
    ScriptErrorCode.WITNESS_MALLEATED_P2SH: (
        "Witness requires only-redeemscript scriptSig"
    ),
    ScriptErrorCode.WITNESS_UNEXPECTED: "Witness provided for non-witness script",
    ScriptErrorCode.WITNESS_PUBKEYTYPE: "Using non-compressed keys in segwit",
    ScriptErrorCode.SCHNORR_SIG_SIZE: "Invalid Schnorr signature size",
    ScriptErrorCode.SCHNORR_SIG_HASHTYPE: "Invalid Schnorr signature hash type",
    ScriptErrorCode.SCHNORR_SIG: "Invalid Schnorr signature",
    ScriptErrorCode.TAPROOT_WRONG_CONTROL_SIZE: "Invalid Taproot control block size",
    ScriptErrorCode.TAPSCRIPT_VALIDATION_WEIGHT: (
        "Too much signature validation relative to witness weight"
    ),
    ScriptErrorCode.TAPSCRIPT_CHECKMULTISIG: (
        "OP_CHECKMULTISIG(VERIFY) is not available in tapscript"
    ),
    ScriptErrorCode.TAPSCRIPT_MINIMALIF: (
        "OP_IF/NOTIF argument must be minimal in tapscript"
    ),
    ScriptErrorCode.TAPSCRIPT_EMPTY_PUBKEY: "Empty public key in tapscript",
    ScriptErrorCode.OP_CODESEPARATOR: "Using OP_CODESEPARATOR in non-witness script",
    ScriptErrorCode.SIG_FINDANDDELETE: "Signature is found in scriptCode",
}


class ScriptError(BTClibValueError):
    """A script verification failure: which one, and where it happened.

    `code` is the failure as Bitcoin Core names it, a `ScriptErrorCode`,
    so a caller tells one refusal from another without reading the
    message, and quotes Core's own text for it through
    `code.description`.

    `index` and `stack_depth` are where, and only the two interpreter
    loops know them: the op code implementations, handed the stack alone,
    raise with the code and no position, and the loop re-raises adding
    it. A refusal outside the loops -- a witness program that does not
    match, a stack left unclean at the end -- has no command to point at,
    and carries None for both. A BTClibValueError still, so that code
    catching that keeps catching this.
    """

    def __init__(
        self,
        message: str,
        code: ScriptErrorCode,
        index: int | None = None,
        stack_depth: int | None = None,
    ) -> None:
        self.code = code
        self.index = index
        self.stack_depth = stack_depth
        super().__init__(message, code, index, stack_depth)

    @override
    def __str__(self) -> str:
        if self.index is None:
            return str(self.args[0])
        where = f"command {self.index}, stack depth {self.stack_depth}"
        return f"{self.args[0]} ({where})"


class NotAPrvKeyError(BTClibValueError):
    """The input is not in this private key format at all: try the next one.

    A caller resolving a private key has more than one format to try, so
    a failed attempt has to say which kind of failure it was, and this is
    the kind that means "wrong format, keep going". Each raiser asks it
    of the one format it reads: `b58.prv_key_data_from_wif` for text that
    is no WIF, `btclib_wallet.bip38` for a record no version prefix
    claims, `btclib_wallet.minikey` for text of no minikey shape.

    A BTClibValueError, so code catching that keeps catching this.
    """


class InvalidPrvKeyError(BTClibValueError):
    """The format was recognised and the content is wrong: stop here.

    The counterpart of NotAPrvKeyError. A WIF whose version prefix says
    mainnet but whose payload is the wrong size is not something another
    format might accept, so `b58.prv_key_data_from_wif` raising this is
    more use to `b58._pub_keyinfo_from_key` than a "try the next
    spelling" that would end in "not a private key": a WIF, with a fault
    in it. `btclib_wallet.bip32.prv_keyinfo_from_xprv` answers the same
    way about an xprv whose version bytes name a network and whose key
    prefix is not the private one.

    A BTClibValueError, so code catching that keeps catching this.
    """


class BTClibUserWarning(UserWarning):
    """A btclib warning: the call worked, but not the way it should have.

    A plain `warn(...)` defaults to UserWarning, which is also what any
    other library and the application itself emit: a caller wanting to
    silence btclib alone, or to promote it to an error, then has nothing
    to name but the message text or the module. This category is that
    name, and it stays a UserWarning so that code filtering that keeps
    filtering this.

    The test suite relies on it too: `filterwarnings = ["error"]` is only
    worth having if the places that provoke a btclib warning silence that
    warning and nothing else.

    Not a `BTClibException`, though it comes from btclib as much as any
    of them: a warning is not a failure and is not caught but filtered,
    so an `except BTClibException` sweeping one up -- which
    `filterwarnings = ["error"]` is enough to make happen -- would catch
    a call that worked as if it had not.
    """
