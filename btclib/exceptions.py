#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""Exception classes.

These exist only to tell an exception raised by btclib from one raised by
any other code: each derives from the built-in that says what kind of
failure it is, and adds nothing to it.

So a caller is usually better off catching the regular ValueError,
TypeError or RuntimeError, and does not lose anything by doing so.
"""


class BTClibValueError(ValueError):
    pass


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
        super().__init__(f"{message} (command {index}, stack depth {stack_depth})")


class NotAPrvKeyError(BTClibValueError):
    """The input is not in this private key format at all: try the next one.

    The library accepts a private key as a WIF, a BIP32 xprv, octets, or an
    int, and works out which by trying them in turn. That only reads well
    when a failed attempt says which kind of failure it was, and this is
    the kind that means "wrong format, keep going".

    A BTClibValueError, so code catching that keeps catching this.
    """


class InvalidPrvKeyError(BTClibValueError):
    """The format was recognised and the content is wrong: stop here.

    The counterpart of NotAPrvKeyError. A WIF whose version prefix says
    mainnet but whose payload is the wrong size is not something another
    format might accept: reporting it is more use than trying the input as
    a hex string and telling the caller it was not a private key.

    A BTClibValueError, so code catching that keeps catching this.
    """


class BTClibTypeError(TypeError):
    pass


class BTClibRuntimeError(RuntimeError):
    pass


class InvalidContributionError(BTClibRuntimeError):
    """A party to an interactive protocol sent a value that does not check out.

    Which party, and which of its contributions: `signer` is the index
    in the list the caller passed, None for the aggregator -- who has no
    index, having no key -- and `contrib` names what was wrong, one of
    "pubkey", "pubnonce", "aggnonce", "aggothernonce" or "psig". That is
    the whole point of the class: a multi-round protocol that merely
    fails leaves every participant a suspect, and the answer a caller
    needs is who to hold accountable and to exclude from the next
    attempt.

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
        who = "the aggregator" if signer is None else f"signer {signer}"
        super().__init__(f"invalid {contrib} from {who}")


class FetchError(BTClibRuntimeError):
    """A backend of btclib.fetch did not answer, or did not answer this.

    A RuntimeError and not a ValueError, which is the distinction worth
    keeping: nothing the caller passed is wrong. The node is down, the
    credentials are stale, the explorer sent html, the transaction is not
    in the index -- retrying later can work, and correcting the argument
    cannot.

    It covers the conversion of an answer too. A backend that replies
    with something which is not a transaction has failed, and reporting
    that as the BTClibValueError `Tx.parse` raised would name the parser
    rather than the host that has to be fixed.
    """


class RpcError(FetchError):
    """bitcoind answered with a JSON-RPC error object, and this is it.

    `code` is the node's, from `src/rpc/protocol.h`: -5 is
    RPC_INVALID_ADDRESS_OR_KEY, which is what `getrawtransaction` returns
    for a transaction it cannot find -- including every non-wallet
    transaction on a node running without `-txindex`. A caller that means
    to tell "no such transaction" from "the node is unreachable" needs
    the number, and parsing it back out of the message is what having a
    field avoids.

    A FetchError still, so code catching that keeps catching this.
    """

    def __init__(self, message: str, code: int) -> None:
        self.code = code
        super().__init__(f"{message} (rpc error code {code})")


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
    """
