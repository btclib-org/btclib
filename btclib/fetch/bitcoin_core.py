#!/usr/bin/env python3

# Copyright (C) The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.
"""A JSON-RPC client against Bitcoin Core, and the fetcher built on it.

`BitcoinCoreRpcClient` invokes any one rpc method a node has, with
positional or named parameters: one HTTP POST per call, basic
authentication, the result or an exception. Any method, and not only the
three `BitcoinCoreFetcher` asks for -- a caller with a node has every reason
to ask it something else, and refusing that would only mean they write
this class again. One method per call, though: a batch answers several at
once and needs an api for correlating the answers and for partly failing,
which is a question of its own and not this one.

**Not python-bitcoinrpc's `AuthServiceProxy`, and not a port of it.**
That class, and the copy of it Core's test framework maintains, carry the
LGPL-2.1 of their python-jsonrpc ancestry, where btclib is MIT: this is
an implementation of the protocol rather than a translation of theirs,
and shares no line with either. It is not API-compatible with them
either, and does not try to be -- `call("getblockcount")` against an
attribute lookup that builds a method name is a different interface, and
the explicit one is what makes an unknown method a value rather than a
typo that becomes a request.

**Migrating from `AuthServiceProxy`.** A migration and not a drop-in
replacement: four things change, and each of them is the difference
deliberately.

.. code-block:: python

    # a method is an argument, not an attribute: an unknown one is a
    # value that arrives at the node, not an AttributeError here
    rpc.getblock(block_id, 2)
    client.call("getblock", [block_id, 2])

    # and the named form is the other structure Core takes, which no
    # attribute lookup can express
    client.call("getblock", {"blockhash": block_id, "verbosity": 2})

    # credentials leave the url, which is what gets written into a
    # config file and printed in a traceback
    AuthServiceProxy(f"http://{user}:{password}@127.0.0.1:8332")
    BitcoinCoreRpcClient("http://127.0.0.1:8332", user=user, password=password)
    BitcoinCoreRpcClient.from_network("mainnet")  # or the node's cookie file

    # one wallet of a multi-wallet node, percent-encoded
    client.for_wallet("hot").call("getbalance")

`JSONRPCException` becomes three exceptions, because it covered three
things a caller acts on differently: `RpcError` when the node computed an
error, with its `code`; `HttpError` when the exchange failed, with its
`status`; `FetchError` when there was no answer to read at all. All three
are `FetchError`, so one `except FetchError` is the equivalent of the one
`except JSONRPCException`. What catching them apart buys is a policy on
the status -- a 503 from a full work queue is the case where the same
request works later, and a 401 is the case where it never will. It is not
a rule about which failures are transient: a refused connection and an
expired timeout arrive as a plain `FetchError` and can both clear on
their own.
Whether *this* call may be sent again is the caller's question and the
method's, and this module's docstring says why -- a timeout is not a
deadline.

``batch_`` is what a consumer loses: several calls in one request, which
is a named non-goal here because a batch needs an api for correlating the
answers and for partly failing. Core's maintained fork spells it `batch`.
A loop over `call` is the replacement, at one HTTP request each.

Notifications -- a request sent with no `id`, which a node does not answer
-- are a non-goal too, and no `AuthServiceProxy` consumer is giving one
up: both implementations count an `id` into every request they build, so
sending one at all means reaching past the public interface into
`_request`.

**One call, one HTTP request, and no retry.** A 503 from bitcoind means
its rpc work queue is full and the same request works once the queue
drains, so a retry is the obvious convenience -- and it is the caller's
to write, for two reasons. `call` carries any method, so this class
cannot know whether re-sending one is safe. And a timeout is not a
deadline: a node that stopped answering may still be executing the call,
so a client re-sending a wallet command of its own accord can execute it
twice. `HttpError.status` is what makes the caller's policy three lines
rather than a match on the text of a message.

**JSON-RPC 2.0, and 1.1 read back.** Core answers 1.1 by default and 2.0
to a request carrying the `"jsonrpc": "2.0"` marker, and the difference
is which layer reports a bitcoin error: under 1.1 an unknown transaction
comes back as HTTP 500 with the error object in the body, so a genuine
server fault and a routine "no such transaction" are the same status.
Under 2.0 an rpc error is HTTP 200 with an `error` member, and a non-2xx
means the HTTP exchange itself failed. Both are read here -- a node older
than v28 does not know the marker and replies 1.1 to it -- but only one
of them can be told apart from a proxy in the way.

**No credentials in the url.** A url with the userinfo part filled in --
the `<user>:<password>@` before the host -- puts a password in a string
that ends up in configuration files, tracebacks and logs. Such a url is
refused here; the password arrives as an argument, or, better, is never
seen at all -- `.cookie` is what bitcoind writes for exactly this,
rotated at every restart, readable by the user running the node and by
nobody else.
"""

from __future__ import annotations

import json
from base64 import b64encode
from collections.abc import Mapping, Sequence
from decimal import Decimal
from math import isfinite
from pathlib import Path
from secrets import token_hex
from typing import Any
from urllib.parse import quote, urlsplit

from btclib.alias import Octets
from btclib.exceptions import (
    BTClibTypeError,
    BTClibValueError,
    FetchError,
    HttpError,
    RpcError,
)
from btclib.fetch.fetcher import Fetcher, fetch_errors, tx_from_raw, tx_id_hex
from btclib.fetch.transport import (
    DEFAULT_MAX_BODY_SIZE,
    DEFAULT_TIMEOUT,
    HttpTransport,
    http_request,
    urlopen_transport,
)
from btclib.tx import Tx
from btclib.utils import bytes_from_octets, is_integer

__all__ = [
    "COOKIE_USER",
    "DEFAULT_DATADIR",
    "BitcoinCoreFetcher",
    "BitcoinCoreRpcClient",
    "cookie_auth",
]

# the rpc port and the datadir subdirectory of each network, from Core's
# `CreateBaseChainParams` in src/chainparamsbase.cpp. Mainnet's cookie is
# in the datadir itself, which is the empty subdirectory below. Core's
# chain names and not btclib's network registry, because what they index
# here is a port and a directory: a chain btclib knows and Core has no
# default port for is an explicit url, which is the constructor
_RPC_PORT = {
    "mainnet": 8332,
    "testnet": 18332,
    "testnet4": 48332,
    "signet": 38332,
    "regtest": 18443,
}
_DATADIR_SUBDIR = {
    "mainnet": "",
    "testnet": "testnet3",
    "testnet4": "testnet4",
    "signet": "signet",
    "regtest": "regtest",
}

# the username bitcoind writes into the cookie file, COOKIEAUTH_USER in
# src/rpc/request.cpp. The node ignores it -- cookie authentication
# compares the whole `user:password` line -- so it is documentation, and
# a cookie file whose first field is something else is still a valid one
COOKIE_USER = "__cookie__"

# `~/.bitcoin`, which is the datadir on Linux and on nothing else: macOS
# puts it under ~/Library/Application Support/Bitcoin and Windows under
# %APPDATA%\Bitcoin. Guessing per platform would put two branches here
# that no test on a third platform can reach, and a wrong guess fails
# exactly as an absent file does; `cookie_path` is how a caller says
# where it really is, and the unreadable-cookie error names the file it
# looked for, which is what tells a caller on either platform to pass one
DEFAULT_DATADIR = Path.home() / ".bitcoin"

# what a cookie file may weigh. bitcoind writes one line of some seventy
# octets, so a bound three orders of magnitude above that refuses nothing
# a node wrote; what it refuses is holding a log, a core dump or a disk
# image in memory whole because `cookie_path` pointed at one, only to
# report a missing colon afterwards
_MAX_COOKIE_SIZE = 4096

# how many random bytes make the `id` of a request this call's. Random
# per call rather than fixed or counted: the echo check exists to catch a
# reply that answers another request -- a caching proxy in the way -- and
# a value reused across calls cannot tell that reply from the right one.
# Random rather than a counter because a counter is shared mutable state,
# which is the one thing that would make a client unsafe to call from two
# threads. Prefixed on the way out, so a node's debug log says whose call
# it was
_RPC_ID_BYTES = 8

# how deep a parameter structure may nest. Both the encoder and the walk
# that checks a structure before it recurse, so a bound is what turns
# something too deep for either into a refusal that names the parameters
# rather than a RecursionError out of the standard library. Core's own
# methods nest a few levels -- the inputs of a psbt, the tree of a
# descriptor -- so this is not a limit a call arrives at
_MAX_PARAMS_DEPTH = 100

# what a reply that is a number or a hash may weigh: the json envelope
# around `result`, `error` and `id`, and a value of a few dozen octets.
# `getrawtransaction` is the one answer here that is not small, and it
# keeps the default of `call`
_MAX_SMALL_REPLY = 1024

# http and https, and nothing else, which is what a POST to an rpc
# endpoint can be. `http_request` refuses any other scheme again before
# it builds a request, that being the boundary where `urlopen` would
# otherwise read a `file:` url off the local disk; this one is about
# configuration, and refuses it where the caller who wrote it can still
# see the line
_SCHEMES = ("http", "https")


def _rpc_id() -> str:
    """Return the `id` of one request, distinct from every other."""
    return f"btclib-{token_hex(_RPC_ID_BYTES)}"


def _assert_valid_timeout(timeout: float, what: str) -> None:
    """Refuse a timeout that is not a number of seconds to wait.

    A bool is not a duration and `timeout=True` would be one second; a
    zero or a negative one makes the socket give up before it connects;
    an infinity or a nan is what `Infinity` in a json configuration
    decodes to. All four reach the socket layer and fail there, out of
    the standard library rather than through btclib's exception contract.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise BTClibTypeError(f"non-numeric {what}: {timeout!r}")
    if not isfinite(timeout) or timeout <= 0:
        raise BTClibValueError(f"{what} is not a positive number of seconds: {timeout}")


def _checked_url(url: str) -> str:
    """Return the endpoint url, having refused what is not one.

    Checked when the client is built and not at the first call, which is
    where `urlopen` would refuse most of it: a url is configuration, and
    configuration that cannot work is worth refusing while the caller who
    supplied it is still looking at the line.
    """
    split = urlsplit(url)
    if split.scheme not in _SCHEMES:
        err_msg = f"invalid rpc url scheme: '{split.scheme}' instead of http(s)"
        raise BTClibValueError(err_msg)
    if split.username is not None or split.password is not None:
        err_msg = "credentials in the rpc url:"
        err_msg += " pass user and password, or use the cookie file"
        raise BTClibValueError(err_msg)
    if not split.hostname:
        raise BTClibValueError(f"no host in the rpc url: {url}")
    if split.query or split.fragment:
        err_msg = f"query or fragment in the rpc url: {url}"
        err_msg += " -- an rpc endpoint is a path, and the call is the body"
        raise BTClibValueError(err_msg)
    try:
        # the port is parsed on access and not before, so this is what
        # refuses `http://node:https` here rather than at the first call
        _ = split.port
    except ValueError as e:
        raise BTClibValueError(f"invalid port in the rpc url: {url}") from e
    return url


def cookie_auth(cookie_path: Path) -> str:
    """Return the `user:password` bitcoind wrote in its cookie file.

    One line, `__cookie__:` and 32 random bytes in hex, rewritten at
    every start of the node. Read at each call rather than once at
    construction: a client built when the node was up and used an hour
    later would otherwise answer 401 for the rest of the process, the
    node having been restarted in between, and the cost of not doing so
    is one small local read against an HTTP round trip.

    One line, ascii, and a bounded read. A path that is not a cookie file
    is the ordinary mistake here, and a credential is the one value that
    must not appear in the error reporting it: what the three checks buy
    is that everything a wrong path produces -- a binary file, a log,
    something enormous -- arrives as a FetchError naming the file, rather
    than as a UnicodeDecodeError or as memory nobody agreed to.
    """
    try:
        with cookie_path.open("rb") as file:
            raw = file.read(_MAX_COOKIE_SIZE + 1)
    except OSError as e:
        raise FetchError(f"unreadable rpc cookie file {cookie_path}: {e}") from e
    if len(raw) > _MAX_COOKIE_SIZE:
        err_msg = f"oversized rpc cookie file {cookie_path}:"
        err_msg += f" more than the {_MAX_COOKIE_SIZE} bytes one can be"
        raise FetchError(err_msg)
    try:
        line = raw.decode("ascii").strip()
    except UnicodeDecodeError as e:
        raise FetchError(f"non-ascii rpc cookie file {cookie_path}: {e}") from e
    if "\n" in line or "\r" in line:
        raise FetchError(f"malformed rpc cookie file {cookie_path}: several lines")
    if ":" not in line:
        raise FetchError(f"malformed rpc cookie file {cookie_path}: no ':' in it")
    return line


def _params_member(params: Sequence[Any] | Mapping[str, Any] | None) -> Any:
    """Return what goes in the request as `params`, refusing what cannot.

    JSON-RPC has two parameter structures and Core takes both: an array,
    read positionally, and an object, read by name. Which of them a
    method wants is the method's business, so both go through unchanged
    -- Core's `args` convenience included, a named call carrying an array
    of leading positional values, which is one key of a caller's mapping
    and needs nothing here.

    A str, bytes or bytearray is a Sequence and is never a list of
    parameters: `call("getblock", block_id)` means one parameter, where
    json would have sent sixty-four of them. Refused rather than wrapped,
    since a caller who meant a sequence of one has `[block_id]` to say so
    and nothing tells the two intentions apart from here.
    """
    if params is None:
        return []
    if isinstance(params, Mapping):
        return dict(params)
    if isinstance(params, (str, bytes, bytearray)):
        err_msg = f"rpc params is a {type(params).__name__} and not a sequence"
        err_msg += " of parameters: pass [params] for a single positional one"
        raise BTClibTypeError(err_msg)
    if isinstance(params, Sequence):
        return list(params)
    err_msg = "rpc params is neither a sequence nor a mapping, but a"
    err_msg += f" {type(params).__name__}"
    raise BTClibTypeError(err_msg)


def _assert_json_params(
    value: Any, depth: int = 0, enclosing: tuple[int, ...] = ()
) -> None:
    """Refuse a parameter structure json cannot carry, before it is encoded.

    Walked rather than left to the encoder, because most of what goes
    wrong here is silent or unhelpful in it. A mapping keyed by anything
    but a string is *rewritten*: `{1: "a"}` encodes as `{"1": "a"}`, so a
    caller's value reaches the node changed rather than refused, and only
    the outermost mapping is a name a caller wrote by hand. A structure
    containing itself raises ValueError("Circular reference detected"),
    which is the same type a non-finite number raises and means something
    else entirely. One nested past the interpreter's stack raises
    RecursionError from inside the encoder. And a Decimal or a `bytes`
    reaches `default`, which cannot say where in the structure it was.

    `enclosing` carries the ids of the containers this value sits inside,
    which is what a cycle is: a container reached from within itself. No
    depth bound tells that from a structure that is merely deep, and no
    bound on a *reply* helps -- these are the caller's own objects.
    """
    if depth > _MAX_PARAMS_DEPTH:
        err_msg = f"rpc params nested deeper than the {_MAX_PARAMS_DEPTH} allowed"
        raise BTClibValueError(err_msg)
    if _json_scalar(value):
        return
    if isinstance(value, Mapping):
        _assert_no_cycle(value, enclosing)
        for name, item in value.items():
            if not isinstance(name, str):
                raise BTClibTypeError(f"non-string rpc parameter name: {name!r}")
            _assert_json_params(item, depth + 1, (*enclosing, id(value)))
        return
    if isinstance(value, Sequence):
        _assert_no_cycle(value, enclosing)
        for item in value:
            _assert_json_params(item, depth + 1, (*enclosing, id(value)))
        return
    raise BTClibTypeError(f"rpc parameter that is not a json value: {value!r}")


def _json_scalar(value: Any) -> bool:
    """Say whether a value is a json scalar, refusing three that look like one.

    A Decimal, a non-finite float and a `bytes` are each a value a caller
    has a reason to pass and json has no rendering for, so each is refused
    where what to pass instead can be named -- rather than reported as
    "not a json value" from the end of the walk, or, for the `bytes`,
    walked as the list of the ints of its octets.
    """
    if isinstance(value, Decimal):
        err_msg = "Decimal rpc parameter: json carries no exact decimal, so"
        err_msg += " pass what the method documents -- an int of satoshis,"
        err_msg += " or the string it accepts -- rather than a rounded float"
        raise BTClibTypeError(err_msg)
    if isinstance(value, float) and not isfinite(value):
        raise BTClibValueError(f"not a json number in the rpc params: {value}")
    if isinstance(value, (bytes, bytearray)):
        raise BTClibTypeError(f"rpc parameter that is not a json value: {value!r}")
    return value is None or isinstance(value, (bool, int, float, str))


def _assert_no_cycle(value: Any, enclosing: tuple[int, ...]) -> None:
    """Refuse a container reached from inside itself, by the ids it is in."""
    if id(value) in enclosing:
        raise BTClibValueError("rpc params contains itself, so it has no json")


def _refuse_param(value: Any) -> Any:
    """Refuse a parameter the walk before the encoder did not anticipate.

    The backstop, and every type it can be reached with today is one
    `_assert_json_params` refuses first. What keeps it here is that
    `json.dumps` calling this is the alternative to a TypeError from
    inside the encoder: an object that is a `Sequence` of json values and
    still has no json -- `range(3)` is one -- passes the walk and arrives
    here.
    """
    raise BTClibTypeError(f"rpc parameter that is not a json value: {value!r}")


def _refuse_constant(name: str) -> Any:
    """Refuse the three non-numbers Python's json decodes by default.

    `NaN`, `Infinity` and `-Infinity` are what Python writes and reads
    for floats json has no numbers for. A node does not send them; a
    proxy or a stub in the way can, and a nan arriving as an amount
    compares false against itself for the rest of its life.
    """
    raise FetchError(f"not a json number in the reply: {name}")


def _http_error(where: str, status: int) -> HttpError:
    """Turn a status that is itself the failure into the exception for it."""
    if status == 401:
        message = f"{where}: HTTP 401, the node refused the credentials"
        return HttpError(message, status)
    return HttpError(f"{where}: HTTP {status}", status)


def _id_error(where: str, request_id: str, reply: Mapping[str, Any]) -> FetchError:
    """Say that a reply answers some request other than this one."""
    err_msg = f"{where}: reply id {reply.get('id')!r}"
    err_msg += f" is not the {request_id!r} asked for"
    return FetchError(err_msg)


def _rpc_error(where: str, error: Any) -> FetchError:
    """Turn what the node put in `error` into the exception for it.

    An error object is a code that is an integer and a message that is a
    string; a caller acts on the first and reads the second, so neither is
    something to render whatever arrived. A missing message would become
    an empty one and a list would be formatted into the exception, both of
    which report the node as having said something it did not.
    """
    if not isinstance(error, Mapping):
        return FetchError(f"{where}: unreadable rpc error {error!r}")
    # Any, both of them: every value of a reply is whatever the backend
    # put there, which is what the two checks below are for
    code: Any = error.get("code")
    message: Any = error.get("message")
    if not is_integer(code) or not isinstance(message, str):
        return FetchError(f"{where}: unreadable rpc error {error!r}")
    return RpcError(f"{where}: {message}", code, error.get("data"))


def _unreadable(where: str, cause: Exception) -> FetchError:
    """Say what shape a body was, for the 200 where the status says nothing.

    Each shape gets its own sentence, being a different thing to go and
    look at: not utf-8, nested past the interpreter's stack, not json.
    Anything else -- a json integer longer than
    `sys.get_int_max_str_digits` allows, and whatever a later Python adds
    -- is the parser refusing the reply, which is what happened.

    Only for a 200. Under any other status the shape is not the answer:
    see `_reply_object`, which reaches this only after ruling that out.
    """
    if isinstance(cause, UnicodeDecodeError):
        return FetchError(f"{where}: a reply that is not utf-8 ({cause})")
    if isinstance(cause, RecursionError):
        return FetchError(f"{where}: a reply nested too deeply to parse")
    if isinstance(cause, json.JSONDecodeError):
        return FetchError(f"{where}: not json ({cause})")
    return FetchError(f"{where}: a reply the json parser refused ({cause})")


def _reply_object(where: str, status: int, payload: bytes) -> Mapping[str, Any]:
    """Return the json object a reply is, or say what arrived instead.

    One rule for every body that is not a json-rpc reply, whichever way it
    is not one: none of them can be a *correlated* answer, so none can be
    this call's rpc error, and on a non-200 what is left to report is the
    status -- the 401 with the empty body Core sends, or a 503 whose body
    is whatever stands in front of the node. Reporting the encoding of an
    error page would name the symptom and hide the cause.

    The status cannot be consulted before this, which is why the rule
    lives here and not at the top of `_result`: a 1.1 error object
    arriving with an HTTP 500 *is* a reply, and giving up on the status
    first would report every "no such transaction" from an old node as a
    server fault.
    """
    try:
        reply = json.loads(
            payload, parse_float=Decimal, parse_constant=_refuse_constant
        )
    except FetchError as e:
        # `_refuse_constant`, i.e. one of the three non-numbers Python
        # decodes by default. Its own sentence names which, so under a 200
        # it is re-raised as it stands -- `raise _unreadable(...) from e`
        # would hand back this very object and make the exception its own
        # `__cause__`, which anything walking that chain follows in a loop
        if status == 200:
            raise
        raise _http_error(where, status) from e
    except (ValueError, RecursionError) as e:
        # the rest of the ways a parse fails: JSONDecodeError and
        # UnicodeDecodeError are both ValueError, the bare ValueError of
        # the integer digit limit is a third, and json recurses
        if status != 200:
            raise _http_error(where, status) from e
        raise _unreadable(where, e) from e
    if not isinstance(reply, dict):
        # read, and still not a reply: an array, a string or a number is
        # no more a json-rpc answer than a page of html is, so a 503 whose
        # body is `[1, 2, 3]` is a 503
        if status != 200:
            raise _http_error(where, status)
        raise FetchError(f"{where}: not a json-rpc reply, but a {type(reply).__name__}")
    return reply


def _legacy_result(
    where: str, request_id: str, status: int, reply: Mapping[str, Any]
) -> Any:
    """Return the `result` of a reply carrying no version marker.

    Core's legacy JSON-RPC 1.1: what a node answers to a request without
    the 2.0 marker, and what v27 and older answer to every request.
    `result` and `error` are both present, one of them null, and an rpc
    error arrives with an HTTP 500 -- so the error is read before the
    status, or every "no such transaction" from an old node would be
    reported as a server fault.

    Before the status, but not before the id. A 500 from something in the
    way, carrying an error object of its own or another call's, is a
    failure of the HTTP exchange and not this call's rpc error.
    """
    ours = reply.get("id") == request_id
    error = reply.get("error")
    if ours and error is not None:
        raise _rpc_error(where, error)
    if status != 200:
        raise _http_error(where, status)
    if not ours:
        raise _id_error(where, request_id, reply)
    if "result" not in reply:
        raise FetchError(f"{where}: a reply with neither result nor error")
    return reply["result"]


def _v2_result(
    where: str, request_id: str, status: int, reply: Mapping[str, Any]
) -> Any:
    """Return the `result` of a JSON-RPC 2.0 reply.

    The status is read first, and that is the whole gain of asking for
    2.0: a non-200 is a failure of the HTTP exchange and never an rpc
    error, Core answering 200 with an `error` member for those. So a 401
    from the node, a 403 from something in front of it and a 503 from a
    full work queue cannot be reported as anything the node computed,
    however json-shaped the body beside them is.

    Then exactly one of `result` and `error`, which is 2.0's own rule and
    what tells a 2.0 reply from a 1.1 one wearing the marker. Which member
    is *present*, and not which is non-null: `"error": null` beside a
    result is the 1.1 shape, and a reply that is 1.1 under a 2.0 marker is
    one whose errors this function would look for in the wrong place.
    """
    if status != 200:
        raise _http_error(where, status)
    if reply.get("id") != request_id:
        raise _id_error(where, request_id, reply)
    has_result = "result" in reply
    has_error = "error" in reply
    if has_result == has_error:
        both = "both result and error" if has_result else "neither result nor error"
        raise FetchError(f"{where}: a 2.0 reply with {both}")
    if has_error:
        raise _rpc_error(where, reply["error"])
    return reply["result"]


class BitcoinCoreRpcClient:
    """One Bitcoin Core JSON-RPC endpoint, and the credentials to reach it.

    Not a dataclass, and that is about the password: a generated
    `__repr__` prints every field, so the credential would appear in any
    traceback that renders the client, and in any log line that prints
    it.

    Credentials or a cookie path, and not both: each of the two says who
    is calling, so a client given both would have to rank them, and a
    caller who passed both has a mistaken idea of which one is in use.
    `from_network` is the constructor that fills in a cookie path, along
    with the port, from Core's own defaults.

    **Concurrent calls are supported while the configuration is not
    mutated.** `call` writes nothing on the client, opens its own
    connection and takes its request id from no shared counter, so one
    client serves any number of threads. What is not promised is a client
    whose url, credentials or transport are reassigned while a call is in
    flight, or a caller's transport that is not itself thread-safe --
    that one is the transport's own contract.

    **Basic authentication is cleartext over plain HTTP**, that being
    what Core's rpc speaks. On loopback, which is what `from_network`
    builds, the cleartext is between one process and the node beside it.
    For a node anywhere else it is on the wire, and rpc credentials
    authorise every wallet command that node has: an `https` url, or a
    tunnel, is what keeps them off it.

    Nothing here asks the node which chain it is on. The url and the
    cookie path say where to ask; `BitcoinCoreFetcher`'s `network` says what
    the answers are labelled with, and holding the two together is the
    caller's -- `getblockchaininfo` through `call` is how it is checked.
    """

    def __init__(
        self,
        url: str,
        *,
        user: str | None = None,
        password: str | None = None,
        cookie_path: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> None:
        self.url = _checked_url(url)
        if (user is None) != (password is None):
            raise BTClibValueError("rpc user and password go together, or neither")
        if user is not None and cookie_path is not None:
            err_msg = "both rpc credentials and a cookie path:"
            err_msg += " either of them says who is calling, so pass one"
            raise BTClibValueError(err_msg)
        if user is None and cookie_path is None:
            err_msg = "no rpc credentials: pass user and password, or the"
            err_msg += " path of the cookie file the node writes"
            raise BTClibValueError(err_msg)
        _assert_valid_timeout(timeout, "rpc timeout")
        self.user = user
        self._password = password
        self.cookie_path = None if cookie_path is None else Path(cookie_path)
        self.timeout = timeout
        self.transport = transport

    @classmethod
    def from_network(
        cls,
        network: str = "mainnet",
        *,
        user: str | None = None,
        password: str | None = None,
        cookie_path: Path | str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
        transport: HttpTransport = urlopen_transport,
    ) -> BitcoinCoreRpcClient:
        """Return a client for the local node of one of Core's networks.

        The convenience of not writing out a loopback url, a port and a
        datadir: all three come from Core's own tables, and everything
        else is the constructor's. The five names are Core's chain names,
        because what they index here is a port and a directory -- a chain
        btclib knows and Core has no default port for is an explicit url
        with a `cookie_path`, which is the constructor.

        Nor is this the chain the answers get labelled with. That is
        `BitcoinCoreFetcher`'s `network`, and nothing here verifies that the
        node agrees with either of them.
        """
        if network not in _RPC_PORT:
            raise BTClibValueError(f"unknown network: {network}")
        if user is None and cookie_path is None:
            cookie_path = DEFAULT_DATADIR / _DATADIR_SUBDIR[network] / ".cookie"
        return cls(
            f"http://127.0.0.1:{_RPC_PORT[network]}",
            user=user,
            password=password,
            cookie_path=cookie_path,
            timeout=timeout,
            transport=transport,
        )

    def for_wallet(self, wallet_name: str) -> BitcoinCoreRpcClient:
        """Return a client for this node's `/wallet/<name>` endpoint.

        Which is how a node with several wallets loaded is told which one
        a wallet command is about. The name is percent-encoded, a wallet
        being a directory and free to be called anything a filesystem
        accepts: a space, a `#` or a `/` written into the path unencoded
        addresses a different endpoint, or none.

        The credentials, the timeout and the transport are this client's,
        the endpoint being the only difference -- so a caller working on
        several wallets builds one client and derives the rest.
        """
        url = f"{self.url.rstrip('/')}/wallet/{quote(wallet_name, safe='')}"
        return BitcoinCoreRpcClient(
            url,
            user=self.user,
            password=self._password,
            cookie_path=self.cookie_path,
            timeout=self.timeout,
            transport=self.transport,
        )

    def auth_header(self) -> str:
        """Return the Basic credential, from the arguments or the cookie.

        RFC 7617 leaves the charset of the credential unspecified and
        Core compares the decoded bytes, so utf-8 is a choice that only
        matters for a password with a non-ascii character in it -- where
        it is the choice that matches what a shell and a config file
        would have written.
        """
        if self.cookie_path is not None:
            credential = cookie_auth(self.cookie_path)
        else:
            credential = f"{self.user}:{self._password}"
        return "Basic " + b64encode(credential.encode()).decode("ascii")

    def call(
        self,
        method: str,
        params: Sequence[Any] | Mapping[str, Any] | None = None,
        *,
        request_timeout: float | None = None,
        max_body_size: int = DEFAULT_MAX_BODY_SIZE,
    ) -> Any:
        """Invoke one rpc method, returning its `result`.

        `params` is one value, shaped as json-rpc shapes it: a sequence
        for the positional form, a mapping for the named one. The
        client's own controls are keyword-only for that reason --
        `timeout` is a parameter of several Core methods, and a signature
        mixing the two would have to decide which of them owns the name.

        Amounts do not travel as binary floating point in either
        direction: a number in the reply decodes as a Decimal, and a
        Decimal parameter is refused rather than rounded through `float`.
        `NaN` and `Infinity` are refused both ways, being what Python
        writes for floats json has no numbers for.

        `request_timeout` is this call's, defaulting to the client's.
        What it is for is the handful of methods that legitimately run
        long -- `rescanblockchain`, `scantxoutset`, `dumptxoutset` -- for
        which the alternative is a second client whose wider timeout
        applies to everything.

        `max_body_size` is what the reply may weigh, and it defaults to
        the widest answer a fetcher asks for -- a raw transaction, as hex
        inside a json envelope. A caller invoking something whose reply is
        a number tightens it; one invoking `getblock` on a large block
        widens it, this being their node and their memory.

        There is no retry: one call is one HTTP request, whatever comes
        back. `HttpError.status` is what a caller's own policy reads --
        503 from a full work queue is worth another attempt, 401 never is
        -- and the reason the policy is theirs is in this module's
        docstring: any method may be carried here, and a timeout does not
        say the node stopped executing one.
        """
        request_id = _rpc_id()
        timeout = self.timeout if request_timeout is None else request_timeout
        _assert_valid_timeout(timeout, "rpc request_timeout")
        params_member = _params_member(params)
        _assert_json_params(params_member)
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params_member,
        }
        try:
            body = json.dumps(request, allow_nan=False, default=_refuse_param).encode()
        except ValueError as e:
            # an int of more digits than `sys.get_int_max_str_digits`
            # allows, which is the mirror of the limit a *reply* holding
            # one runs into: json has the number and this interpreter will
            # not write it. The walk above refuses the types json has no
            # rendering for, and this is a value of a type it does, so the
            # encoder is where it surfaces
            raise BTClibValueError(f"rpc params json cannot carry: {e}") from e
        status, payload = http_request(
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": self.auth_header(),
            },
            timeout=timeout,
            max_body_size=max_body_size,
            transport=self.transport,
        )
        return self._result(method, request_id, status, payload)

    def _result(self, method: str, request_id: str, status: int, payload: bytes) -> Any:
        where = f"{method} at {self.url}"
        reply = _reply_object(where, status, payload)
        if "jsonrpc" not in reply:
            # the member and not its value: `"jsonrpc": null` is a reply
            # that names no protocol, which is not the same thing as a
            # 1.1 reply, and it is the member's absence that means 1.1
            return _legacy_result(where, request_id, status, reply)
        marker = reply["jsonrpc"]
        if marker != "2.0":
            err_msg = f"{where}: json-rpc version {marker!r}, neither 2.0"
            err_msg += " nor the legacy reply that carries no version at all"
            raise FetchError(err_msg)
        return _v2_result(where, request_id, status, reply)


class BitcoinCoreFetcher(Fetcher):
    """The three questions, answered by a node over its rpc.

    The client is a constructor argument rather than a set of connection
    arguments repeated here: one class owns the endpoint and the
    credentials, this one owns the mapping onto btclib types, and a
    caller who already has a client does not build a second.

    `network` is btclib's chain label and belongs to this class and not
    to the connection: it is what the outputs of a fetched transaction
    are labelled with, so that `ScriptPubKey.address` renders an address
    of the right chain. The client knows a url and no chain, and nothing
    here asks the node which one it serves -- a client pointed at a
    testnet node under a fetcher labelling mainnet is a caller's mistake
    to avoid, and `getblockchaininfo` through `call` is how it is
    checked.
    """

    def __init__(self, client: BitcoinCoreRpcClient, network: str = "mainnet") -> None:
        super().__init__(network)
        self.client = client

    def get_tx(self, tx_id: Octets) -> Tx:
        """Return the transaction with this id.

        `getrawtransaction` with no verbosity, i.e. the serialization
        rather than the node's json rendering of it: the bytes are what
        `Tx.parse` recomputes the id from, so a transaction that arrived
        wrong announces itself, and a rendering that btclib and Core
        disagree about cannot come between them.

        A node answers for a transaction in its mempool, one of its
        wallet's, and -- only with `-txindex` -- any other. Without the
        index the error is rpc code -5, and its message says so.
        """
        hex_ = tx_id_hex(tx_id)
        raw = self.client.call("getrawtransaction", [hex_])
        return tx_from_raw(raw, hex_, self.network)

    def get_block_count(self) -> int:
        """Return the height of the node's best chain tip."""
        with fetch_errors("getblockcount"):
            reply = self.client.call("getblockcount", max_body_size=_MAX_SMALL_REPLY)
            return int(reply)

    def get_best_block_id(self) -> bytes:
        """Return the hash of the node's best chain tip, display order."""
        with fetch_errors("getbestblockhash"):
            reply = self.client.call("getbestblockhash", max_body_size=_MAX_SMALL_REPLY)
            return bytes_from_octets(reply, 32)
