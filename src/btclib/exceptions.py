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
it came from here, and it catches every failure of btclib's: no public
function lets a native `KeyError`, `IndexError` or `OverflowError`
escape uncaught.

The exception is the few classes below carrying a field: what a peer got
wrong, the node's rpc error code, an HTTP status. Those are values a
caller acts on, and reading them back out of a message is what the field
spares them, so a caller after one of them still names the specific
class rather than the base.

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

from typing import Any

from typing_extensions import override

__all__ = [
    "BTClibException",
    "BTClibRuntimeError",
    "BTClibTypeError",
    "BTClibUserWarning",
    "BTClibValueError",
    "BorromeanRingError",
    "FetchError",
    "HttpError",
    "IncompleteMessageError",
    "InconclusiveError",
    "InvalidContributionError",
    "InvalidPrvKeyError",
    "NoDescriptorError",
    "NotAPrvKeyError",
    "RpcError",
    "ScriptError",
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
    `btclib.fetch.fetcher.client_errors` is the one place the two meet.
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

    What `btclib.psbt_signer`'s contract fails with, and what
    `btclib.hwi` raises around HWI's structured errors: the JSON CLI
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

    Without it the distinction is not recoverable. `btclib.hwi` turns
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


class ScriptError(BTClibValueError):
    """A script verification failure, and where in the script it happened.

    Only the two interpreter loops know the index of the command being
    executed and the depth of the stack; the op code implementations,
    which are handed the stack alone, do not. They raise a plain
    BTClibValueError with what went wrong, and the loop re-raises it as
    this, adding where. A BTClibValueError still, so that code catching
    that keeps catching this.
    """

    def __init__(self, message: str, index: int, stack_depth: int) -> None:
        self.index = index
        self.stack_depth = stack_depth
        super().__init__(message, index, stack_depth)

    @override
    def __str__(self) -> str:
        where = f"command {self.index}, stack depth {self.stack_depth}"
        return f"{self.args[0]} ({where})"


class NotAPrvKeyError(BTClibValueError):
    """The input is not in this private key format at all: try the next one.

    `to_prv_key` accepts a private key as a BIP32 xprv, octets, or an int,
    and works out which by trying them in turn. That only reads well when
    a failed attempt says which kind of failure it was, and this is the
    kind that means "wrong format, keep going". `b58.prv_key_data_from_wif`
    raises it for text that is no WIF, the same question asked of the one
    format it reads.

    A BTClibValueError, so code catching that keeps catching this.
    """


class InvalidPrvKeyError(BTClibValueError):
    """The format was recognised and the content is wrong: stop here.

    The counterpart of NotAPrvKeyError. An xprv whose version bytes name a
    network and whose key prefix is not the private one is not something
    another format might accept: reporting it is more use than trying the
    input as a hex string and telling the caller it was not a private key.
    A WIF whose version prefix says mainnet but whose payload is the wrong
    size is the same answer from `b58.prv_key_data_from_wif`: a WIF, with
    a fault in it.

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
    so that `btclib.bip322.verify` answers False without a second
    `except`: an inconclusive signature is not one that verified. A
    caller that means to tell the two apart names this class.
    """


class NoDescriptorError(BTClibValueError):
    """No output descriptor states this script: it is not that a lift failed.

    What `wallet.ScriptWallet.descriptor` refuses with, and the one
    refusal there that is a fact about the wallet rather than about the
    code asking: a script spelling its timelock `<n> OP_CSV OP_DROP`, or
    ordering a quorum after derivation inside a combinator, is a script
    BIP380 to BIP390 cannot write down -- and will still be one at the
    next release. A caller catching this has an answer ("watch these
    addresses instead"), where a caller catching a parse failure has a
    bug report.

    A BTClibValueError, so code catching that keeps catching this: the
    refusal it most often stands in front of is
    `miniscript.from_script`'s, which is one.
    """


class InvalidContributionError(BTClibRuntimeError):
    """A party to an interactive protocol sent a value that does not check out.

    Which party, and which of its contributions: `signer` is the index
    in the list the caller passed, None for the aggregator -- who has no
    index, having no key -- and `contrib` names what was wrong, one of
    "pubkey", "pubnonce", "aggnonce", "aggothernonce", "psig" or
    "adaptor". That is the whole point of the class: a multi-round
    protocol that merely fails leaves every participant a suspect, and
    the answer a caller needs is who to hold accountable and to exclude
    from the next attempt.

    A BTClibRuntimeError and not a BTClibValueError, which is the other
    obvious base and the one BIP327 keeps separate: its reference
    implementation raises ValueError for an argument that breaks a
    precondition -- the caller's own mistake, a 33-byte tweak -- and
    this for a peer misbehaving, and the MuSig2 test vectors distinguish
    the two case by case. Sharing a base would put the two beyond
    telling apart by `except`, and would let every `except ValueError`
    in the library swallow an accusation.
    """

    def __init__(self, signer: int | None, contrib: str) -> None:
        self.signer = signer
        self.contrib = contrib
        super().__init__(signer, contrib)

    @override
    def __str__(self) -> str:
        who = "the aggregator" if self.signer is None else f"signer {self.signer}"
        return f"invalid {self.contrib} from {who}"


class BorromeanRingError(BTClibRuntimeError):
    """A borromean ring signature check failed, and where names it.

    `ring` is the index into `pubk_rings` and `position` the index
    within that ring: an e-value landing on zero, and the point at
    infinity its one-in-n neighbour lands a ring's nonce or its `r` on
    instead, each happen at one ring and one position, and
    `btclib.ecc.borromean.sign` and `assert_as_valid` already have both
    in hand at every one of their raises. Naming them is what tells a
    caller building on this primitive which key rejected the signature
    rather than only that the whole thing did.

    Both are None for the one failure with no ring of its own: the
    final `e0` not matching what every ring converges on is a property
    of the whole signature, not of any single ring in it.

    A BTClibRuntimeError and not `InvalidContributionError`: that class
    names a party to an interactive multi-round protocol -- MuSig2 --
    and which of its contributions was wrong, where a borromean ring
    signature is not interactive and has no parties to accuse, only
    positions in a signature that either close their ring or do not.
    A BTClibRuntimeError still, so code catching that keeps catching
    this, as `verify` already does.
    """

    def __init__(self, message: str, ring: int | None, position: int | None) -> None:
        self.ring = ring
        self.position = position
        super().__init__(message, ring, position)

    @override
    def __str__(self) -> str:
        if self.ring is None:
            return str(self.args[0])
        return f"{self.args[0]} (ring {self.ring}, position {self.position})"


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
