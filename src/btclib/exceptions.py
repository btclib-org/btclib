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

The exception is the few classes below carrying a field: what a peer got
wrong, the node's rpc error code, an HTTP status. Those are values a
caller acts on, and reading them back out of a message is what the field
spares them, so a caller after one of them still names the specific
class rather than the base.

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
from typing import Any

from typing_extensions import override

__all__ = [
    "BTClibException",
    "BTClibRuntimeError",
    "BTClibTypeError",
    "BTClibUserWarning",
    "BTClibValueError",
    "FetchError",
    "HttpError",
    "IncompleteMessageError",
    "InconclusiveError",
    "InvalidPrvKeyError",
    "NoDescriptorError",
    "NotAPrvKeyError",
    "RpcError",
    "ScriptError",
    "ScriptErrorCode",
    "ShortIdCollisionError",
    "SignerError",
    "SignerNotFoundError",
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


class FetchError(BTClibRuntimeError):
    """A backend did not answer, or did not answer this.

    A RuntimeError and not a ValueError, which is the distinction worth
    keeping: nothing the caller passed is wrong. The node is down, the
    credentials are stale, the explorer sent html, the transaction is not
    in the index -- retrying later can work, and correcting the argument
    cannot.

    It covers the conversion of an answer too. A backend that replies with
    something which is not a transaction has failed, and reporting that as
    the BTClibValueError `Tx.parse` raised would name the parser rather
    than the host that has to be fixed.

    Declared here rather than taken from `bitcoin_core_rpc`, which raises
    a class of the same name: that package declares zero dependencies and
    imports nothing of btclib's, so its `FetchError` derives from a
    `BTClibRuntimeError` of its own, and an `except BTClibRuntimeError`
    written against this module would not catch it.
    `btclib_wallet.fetch.fetcher.client_errors` is the one place the two meet.
    """


class HttpError(FetchError):
    """A backend failed at the HTTP layer, and `status` is what it said.

    A field because acting on a status is the caller's job and btclib
    retries nothing: a 401 says the credentials are wrong and will stay
    wrong until they are changed, while a 503 from bitcoind says its rpc
    work queue is full and the same request works when the queue drains.
    A caller writing that policy needs to recognise the status, and
    matching on the text of a message is what a field spares them.

    Not every FetchError carries one, and that is the distinction: a
    refused connection and an expired timeout are failures of an exchange
    that never produced a status, and stay a plain FetchError.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, status: int) -> None:
        self.status = status
        super().__init__(message, status)

    @override
    def __str__(self) -> str:
        # the message alone, which is what BaseException returns for a
        # single argument and not for the two this carries
        return str(self.args[0])


class RpcError(FetchError):
    """A backend answered with a JSON-RPC error object, and this is it.

    `code` is the backend's own. From bitcoind, `src/rpc/protocol.h`: -5
    is RPC_INVALID_ADDRESS_OR_KEY, which is what `getrawtransaction`
    returns for a transaction it cannot find -- including every
    non-wallet transaction on a node running without `-txindex`. From an
    Electrum server (`btclib.electrum`), the field carries that server's
    own JSON-RPC 2.0 code instead, nothing here asking anything
    bitcoind-specific of it. A caller that means to tell "no such
    transaction" from "the backend is unreachable" needs the number, and
    parsing it back out of the message is what having a field avoids.

    `data` is JSON-RPC's optional third member of an error object, kept as
    it arrived. Core leaves it out today, so it is None for every error a
    node sends; a method that starts sending one -- or a proxy between the
    two adding its own -- would otherwise have it dropped here, which is
    the one place it cannot be recovered from.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, code: int, data: Any = None) -> None:
        self.code = code
        self.data = data
        super().__init__(message, code, data)

    @override
    def __str__(self) -> str:
        return f"{self.args[0]} (rpc error code {self.code})"


class SignerError(BTClibRuntimeError):
    """An external signer failed, and `code` is the number it gave.

    What `btclib_wallet.psbt_signer`'s contract fails with, and what
    `btclib_wallet.hwi` raises around HWI's structured errors: the JSON CLI
    answers `{"error": <msg>, "code": <n>}`, and the number is the part a
    caller acts on. -14 is ACTION_CANCELED, which is somebody pressing the
    button that says no and is not worth a retry; -3 is DEVICE_CONN_ERROR,
    which is a cable and is worth one; -9 is UNAVAILABLE_ACTION, which
    says this model will never do it. Matching on the text of a message is
    what a field spares a caller writing that policy.

    A RuntimeError for the reason `FetchError` is one: nothing the caller
    passed is wrong. The device is unplugged, locked, busy, or its owner
    said no -- retrying can work, and correcting an argument cannot. The
    numbers HWI reserves for a bad argument (-2, -7) arrive here too, that
    being the one thing the code says and the class cannot.

    `code` is None where the failure produced no number: a backend that
    could not be started, an answer that was not JSON, an output past the
    limit. Those are failures of the exchange rather than of the device.
    """

    def __init__(self, message: str, code: int | None = None) -> None:
        self.code = code
        super().__init__(message, code)

    @override
    def __str__(self) -> str:
        if self.code is None:
            return str(self.args[0])
        return f"{self.args[0]} (signer error code {self.code})"


class SignerNotFoundError(SignerError):
    """The backend an adapter runs is not installed.

    A `SignerError` still, so a caller catching that keeps catching this,
    and separate because it is the one failure that is not about a
    device: nothing is unplugged, locked or busy, and no retry will
    change it. A caller that offers signers of several kinds tells "there
    is no hardware here" from "the hardware could not be reached" on this
    class, and the two are not the same thing to report before a signing
    operation.

    Without it the distinction is not recoverable. `btclib_wallet.hwi` turns
    every `OSError` into a `SignerError` -- a missing executable and a
    permission the udev rules do not grant arrive as one class with one
    `code` of None -- so a caller had to either match on the text of a
    message or look for the executable itself, and looking for it is
    asking a second question that can disagree with the first.

    `code` is None, as for every failure of the exchange rather than of a
    device.
    """


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
    more can fix it and correcting an argument cannot, which is
    `FetchError`'s reasoning for the same base.

    Not a `FetchError` itself, kin though the reasoning is: that class is
    a backend that did not answer, and nothing in `btclib.p2p` goes out
    and asks -- the caller already holds the octets, and holds the socket
    this library never opens. Nor a bare `BTClibRuntimeError`: the whole
    point is that a socket caller tells this from every other refusal
    `parse` gives, and one class two answers share is one a caller cannot
    branch on. Everything else `parse` raises is final -- a magic no
    further octet changes, a length over
    `btclib.p2p.limits.MAX_PROTOCOL_MESSAGE_LENGTH`, a checksum that does
    not verify -- and the peer that sent it is the thing to drop.
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


class InconclusiveError(BTClibValueError):
    """Not invalid, and not something today's rules can call valid.

    BIP322 answers a signature with one of three states rather than two,
    and this is the third: a `to_sign` whose version is neither 0 nor 2,
    an upgradeable NOP, a witness program of an unknown version. Each of
    them satisfies the script as it runs today, and each is what a soft
    fork can give a meaning to, so a validator saying "valid" would be
    speaking for rules it does not have.

    A BTClibValueError, so code catching that keeps catching this, and
    so that `btclib_wallet.bip322.verify` answers False without a second
    `except`: an inconclusive signature is not one that verified. A
    caller that means to tell the two apart names this class.
    """


class NoDescriptorError(BTClibValueError):
    """No output descriptor states this script: it is not that a lift failed.

    What `btclib_wallet.wallet.ScriptWallet.descriptor` refuses with, and
    the one refusal there that is a fact about the wallet rather than about
    the code asking: a script spelling its timelock `<n> OP_CSV OP_DROP`, or
    ordering a quorum after derivation inside a combinator, is a script
    BIP380 to BIP390 cannot write down -- and will still be one at the
    next release. A caller catching this has an answer ("watch these
    addresses instead"), where a caller catching a parse failure has a
    bug report.

    A BTClibValueError, so code catching that keeps catching this: the
    refusal it most often stands in front of is
    `miniscript.from_script`'s, which is one.
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
