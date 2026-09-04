# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""BIP380 KEY expressions: what a descriptor names a public key with.

The bottom of the descriptor package, and the half of BIP380's grammar
that says nothing about scripts: a KEY expression is a public key, an
extended key with a derivation path, or BIP390's ``musig()`` aggregate of
either, optionally behind the ``[fingerprint/path]`` key origin a signer
needs. `KeyExpression` is what one parses to and `sec` is what it derives.

A module of its own because two modules above it read the same grammar.
`descriptors` reads it inside ``pk()``, ``multi()``, ``tr()`` and the rest;
`miniscript` reads it inside ``pk_k()``, ``pk_h()``, ``multi()`` and
``multi_a()`` -- BIP379's "Key expressions are specified in BIP380", the
same production and not a second dialect of it. Both import this one and
this one imports neither, which is the direction of the layering.

Three text helpers come with it, for the same reason: `_expression`,
`_split_arguments` and `_split_function` are what write a function out and
read one back, and both halves of the grammar are written in functions.

BIP380: https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki
BIP390: https://github.com/bitcoin/bips/blob/master/bip-0390.mediawiki
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from typing_extensions import override

from btclib import b58
from btclib.bip32.bip32 import (
    BIP328_CHAIN_CODE,
    BIP32KeyData,
    derive_,
    xpub_from_xprv,
)
from btclib.bip32.der_path import (
    _HARDENED_OFFSET,
    _HARDENING,
    hardenings_from_der_path,
    indexes_from_der_path,
    str_from_der_path,
    str_from_index_int,
)
from btclib.bip32.key_origin import BIP32KeyOrigin
from btclib.curves import secp256k1
from btclib.curves.sec_point import bytes_from_point
from btclib.ecc.musig2 import key_agg, key_sort
from btclib.exceptions import BTClibValueError
from btclib.network import network_from_name
from btclib.to_pub_key import point_from_pub_key, pub_keyinfo_from_key
from btclib.utils import bytes_from_octets

__all__ = ["KeyExpression", "PrvKeys"]

_FINGERPRINT = re.compile(r"[0-9a-fA-F]{8}")
_HEX = re.compile(r"[0-9a-fA-F]*")
# what `_split_arguments` stops at, compiled once here rather than
# handed to `re.finditer` as a pattern string per call: the cache that
# would answer for it is a dict lookup on that string, which a function
# called once per branch of a tr() tree makes for nothing
_DELIMITERS = re.compile(r"[(){},]")

# what `parse` hands back beside the descriptor, and what expansion takes
# when a hardened step needs it: the extended private key each extended
# key was read from, filed under the neutered spelling the descriptor
# keeps. Public identity to private material, which is how Bitcoin Core's
# `FlatSigningProvider` is keyed too -- by the key id there, by the xpub
# here, an extended key being what a descriptor derives from
PrvKeys = Mapping[str, str]


@dataclass(frozen=True)
class KeyExpression:
    """A BIP380 KEY expression: an origin, a key, a derivation path.

    One of three things is the key. Either `pub_key` is the one the
    descriptor fixes, in SEC bytes; or `xkey` is the extended key that
    `der_path` and `wildcard` derive from; or `participants` are the KEY
    expressions BIP390's ``musig()`` aggregates, `der_path` and `wildcard`
    then deriving from the aggregate key as BIP328 prescribes. An x-only
    key is held as its even-y SEC form, which is what BIP340 says those 32
    bytes mean, so that everything downstream sees one representation of a
    public key.

    `origin` never changes the script. It says which master key and which
    path the key came from, which is what a hardware signer needs and
    what BIP174 carries in a PSBT.

    `xkey` is public whatever the descriptor spelled: `parse` neuters an
    xprv and hands the private material back to its caller, so no part of
    a parsed descriptor holds a key that signs. What that costs is a
    hardened step, which an xpub cannot take -- `sec` takes the keys back
    as a parameter for it, the way Bitcoin Core's expansion takes a
    `SigningProvider`.
    """

    origin: BIP32KeyOrigin | None = None
    pub_key: bytes | None = None
    xkey: str = ""
    der_path: tuple[int, ...] = ()
    # the final `/*` step, as the offset its hardening adds to the index:
    # None where the descriptor has no wildcard, 0 for `/*`, 2**31 for
    # `/*h`. One field rather than a flag and a bool, because "hardened"
    # is only meaningful when there is a wildcard to harden
    wildcard: int | None = None
    x_only: bool = False
    # BIP390's ``musig()``: the participants whose keys aggregate to this
    # one, in the order the descriptor writes them. `KeySort` is applied
    # at aggregation and not here, so what is kept is the text's order and
    # what is computed does not depend on it
    participants: tuple[KeyExpression, ...] = ()
    # the symbol every hardened step of this expression is written with:
    # BIP380 gives "h" and "'" one meaning and two spellings, and the two
    # are different strings with different checksums, so a descriptor
    # handed back in the other one is not the descriptor that was read.
    # One symbol for the whole expression, origin included, which is
    # Bitcoin Core's single `m_apostrophe` per key: a path spelled both
    # ways -- BIP380's own valid `[deadbeef/0'/0h/0']` -- is read and
    # written back in the symbol its last hardened step used
    hardening: str = _HARDENING

    @property
    def is_ranged(self) -> bool:
        """Answer whether the key has a wildcard to derive at an index.

        A ``musig()`` is ranged where its own path has one and where a
        participant has one: BIP390 forbids both at once, so whichever it
        is, the index is read in one place.
        """
        return self.wildcard is not None or any(
            key.is_ranged for key in self.participants
        )

    @property
    def is_aggregate(self) -> bool:
        """Answer whether the key is the aggregate of BIP390 participants."""
        return bool(self.participants)

    @property
    def is_compressed(self) -> bool:
        """Return False for an uncompressed SEC public key, True otherwise.

        An extended key is compressed by construction: BIP32 has no
        uncompressed serialization.
        """
        return self.pub_key is None or len(self.pub_key) == 33

    def sec(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> bytes:
        """Return the SEC public key bytes, derived at `index` if ranged.

        `prv_keys` is what `parse` handed back, and is needed for a
        hardened step and for nothing else: an unhardened path derives
        from the xpub the descriptor holds. A key it does not name is
        left as it is, so a mapping covering some of a multisig's keys
        answers for those and no more.

        A ``musig()`` answers with the key its participants aggregate to,
        derived along its own path where it has one: BIP328's synthetic
        xpub is that key at depth zero with the fixed chain code an
        aggregate has instead of one of its own, and `derive_` is then what
        refuses a hardened step -- there being no aggregate private key to
        take one with. The index derives the participants or the aggregate
        and never both, BIP390 allowing a wildcard on one side only.
        """
        if self.participants:
            aggregate = self.aggregate(index, network, prv_keys)
            musig_path = list(self.der_path)
            if self.wildcard is not None:
                musig_path.append(self.wildcard + index)
            if not musig_path:
                return aggregate
            synthetic = BIP32KeyData(
                version=network_from_name(network).bip32_pub,
                depth=0,
                parent_fingerprint=b"\x00" * 4,
                index=0,
                chain_code=BIP328_CHAIN_CODE,
                key=aggregate,
            )
            return pub_keyinfo_from_key(derive_(synthetic, musig_path), network)[0]
        if self.pub_key is not None:
            return self.pub_key
        der_path = list(self.der_path)
        if self.wildcard is not None:
            der_path.append(self.wildcard + index)
        xkey = prv_keys.get(self.xkey, self.xkey) if prv_keys else self.xkey
        # `derive_` and not `derive`: the Base58Check text would be decoded
        # straight back by `pub_keyinfo_from_key` on this same line, a
        # `BIP32KeyData` being in the `PubKey` union already, the text
        # spelling being the dearer of the two per key at an index (issue
        # 886). The union `derive_` takes is `derive`'s, so the xkey a
        # descriptor holds as a string
        # still goes in as it is
        return pub_keyinfo_from_key(derive_(xkey, der_path), network)[0]

    def participant_keys(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> list[bytes]:
        """Return the participant keys in the order they are aggregated in.

        Which is `KeySort`'s order and not the descriptor's: BIP390 sorts
        after all derivation and before aggregation, so that the order the
        keys were written in does not change the key -- a set of keys is
        what MuSig2 is about, and a descriptor that was not backed up does
        not need the order guessed as well. BIP373 stores the participants
        of a psbt in aggregation order too, which is what makes this the
        list that goes into `PSBT_IN_MUSIG2_PARTICIPANT_PUBKEYS`.
        """
        derived = [key.sec(index, network, prv_keys) for key in self.participants]
        return key_sort(derived)

    def aggregate(
        self,
        index: int = 0,
        network: str = "mainnet",
        prv_keys: PrvKeys | None = None,
    ) -> bytes:
        """Return the key BIP390's participants aggregate to, derived.

        `KeyAgg` over the sorted participants, and nothing more: the
        ``/NUM/.../*`` path of the expression derives *from* this key, and
        `sec` is what walks it. The two are separate because BIP373 keys
        its MuSig2 psbt fields by the aggregate key itself even where what
        the script holds is a child of it -- an aggregate key is what the
        participants make, and a derivation of it is a key the same group
        answers for.
        """
        return bytes_from_point(
            key_agg(self.participant_keys(index, network, prv_keys)).Q, secp256k1
        )

    @override
    def __str__(self) -> str:
        """Return the KEY expression, in the spelling it was read in.

        Public whatever was read: an xprv is the xpub `parse` neutered it
        to, and a WIF is the hex of the public key it was reduced to.
        Bitcoin Core writes the same, `ToString` having only the public
        key to write and `ToPrivateString` taking the private material
        back from the caller.

        An x-only key is written as the 32 bytes a ``tr()`` holds, which
        is the spelling it was read in and the only one allowed there.

        A ``musig()`` writes its participants in the order they were read,
        which is not the order they aggregate in: `KeySort` is applied when
        the key is computed, so the text keeps what the descriptor said.
        """
        if self.participants:
            text = _expression("musig", *(str(key) for key in self.participants))
            for index in self.der_path:
                text += "/" + str_from_index_int(index, self.hardening)
            if self.wildcard is not None:
                text += "/*"
            return text
        text = ""
        if self.origin is not None:
            path = str_from_der_path(
                self.origin.der_path, self.origin.master_fingerprint, self.hardening
            )
            text = f"[{path}]"
        if self.pub_key is not None:
            return text + (self.pub_key[1:] if self.x_only else self.pub_key).hex()
        text += self.xkey
        for index in self.der_path:
            text += "/" + str_from_index_int(index, self.hardening)
        if self.wildcard is not None:
            text += "/*" + (self.hardening if self.wildcard else "")
        return text


def _expression(name: str, *args: str) -> str:
    """Return a descriptor function written out: its name and its arguments."""
    return f"{name}({','.join(args)})"


def _offered_signature(
    signatures: Mapping[bytes, bytes], sec: bytes, *, x_only: bool
) -> bytes | None:
    """Return the signature offered for a public key, None where none is.

    A taproot key answers to either of its two spellings: the 32 x-only
    bytes the script holds, and the 33-byte even-y SEC form a
    KeyExpression keeps it as. Neither is the more correct one, a caller
    has whichever its signer handed back, and 32 bytes cannot be taken
    for 33.
    """
    if sec in signatures:
        return signatures[sec]
    if x_only and sec[1:] in signatures:
        return signatures[sec[1:]]
    return None


def _split_arguments(arguments: str) -> list[str]:
    """Split a comma-separated argument list, at nesting depth zero.

    Parentheses and braces only: they are what nests and what can hold a
    comma of its own, a nested SCRIPT expression and a tr() branch. The
    key origin brackets are deliberately not counted, so that a bracket
    written wrong reaches the key expression parser, which can say which
    of the two ways it is wrong.
    """
    depth = 0
    start = 0
    result = []
    # the loop is over the delimiters and not over the string: every
    # other character decides nothing, and `re` skips them in C. What
    # makes that worth writing is the recursion above -- `_parse_tree`
    # splits a branch and splits each of its branches again, so a
    # character deep in a tr() tree is walked once per level above it
    for match in _DELIMITERS.finditer(arguments):
        char = match[0]
        if char in "({":
            depth += 1
        elif char in ")}":
            depth -= 1
            if depth < 0:
                raise BTClibValueError(f"unbalanced brackets: {arguments}")
        elif depth == 0:  # a comma, the only other character matched
            result.append(arguments[start : match.start()])
            start = match.end()
    if depth:
        raise BTClibValueError(f"unbalanced brackets: {arguments}")
    result.append(arguments[start:])
    return result


def _split_function(expression: str) -> tuple[str, str]:
    """Return the function name and the argument string it encloses."""
    open_bracket = expression.find("(")
    if open_bracket < 1 or not expression.endswith(")"):
        raise BTClibValueError(f"not a descriptor expression: {expression}")
    return expression[:open_bracket], expression[open_bracket + 1 : -1]


def _der_path(path: str) -> list[int]:
    """Return the indexes of a `/`-separated derivation path.

    `bip380_enforced` is the whole of the difference from what a BIP32
    path may spell: an uppercase "H", a "+1", a leading "m" and the
    spaces of "0 h" are all read elsewhere in btclib and none of them is
    a step BIP380 allows. It also refuses 2**31 and above written
    unhardened, there being no such BIP32 index.
    """
    return indexes_from_der_path(path, bip380_enforced=True) if path else []


def _hardening(path: str) -> str:
    """Return the symbol the last hardened step of a path was written with.

    Empty where the path hardens nothing, so that a caller choosing
    between two paths can tell "no opinion" from "an apostrophe". The
    last and not the first, which is Bitcoin Core's rule by construction:
    its parser assigns the bool per hardened element, so the one it ends
    on is the one that is written back.
    """
    if not path:
        return ""
    symbols = [s for s in hardenings_from_der_path(path, bip380_enforced=True) if s]
    return symbols[-1] if symbols else ""


def _key_origin(description: str) -> tuple[BIP32KeyOrigin, str]:
    """Return the key origin of a `[fingerprint/path]` prefix, and its symbol.

    The symbol is the origin's alone, and the caller picks between it and
    the key path's: `BIP32KeyOrigin` does not carry it, an origin being a
    fingerprint and a path whichever way the path was spelled -- two
    origins that differ in nothing else are the same origin, and equality
    and `serialize` both have to keep saying so.
    """
    fingerprint, _, path = description.partition("/")
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise BTClibValueError(f"invalid key origin fingerprint: {fingerprint}")
    return BIP32KeyOrigin(fingerprint, _der_path(path)), _hardening(path)


def _pub_key_from_hex(key: str, *, x_only: bool) -> tuple[bytes, bool]:
    """Return the SEC bytes of a hex key, and whether it was x-only."""
    length = len(key)
    if length == 64:
        if not x_only:
            # "inside tr()" would not be true of every position that
            # refuses one: a musig() participant is inside a tr() and is
            # aggregated as a point, so it needs the byte an x-only key drops
            err_msg = "x-only public keys are allowed in a taproot key expression only"
            raise BTClibValueError(err_msg)
        # the even-y lift of BIP340, which is what an x-only key means
        pub_key = b"\x02" + bytes_from_octets(key)
    elif length in {66, 130}:
        prefix = key[:2]
        if (length == 66 and prefix not in {"02", "03"}) or (
            length == 130 and prefix != "04"
        ):
            # 06 and 07 are the hybrid encoding, which nothing in bitcoin
            # produces and Bitcoin Core refuses in a descriptor too
            raise BTClibValueError(f"invalid public key prefix: 0x{prefix}")
        pub_key = bytes_from_octets(key)
    else:
        raise BTClibValueError(f"invalid public key length: {length} characters")
    # a key expression is parsed in order to be used, and a point off the
    # curve has no script to derive: refuse it here, where the error can
    # still say it was the key
    point_from_pub_key(pub_key)
    return pub_key, length == 64


def _is_extended_key(key: str) -> bool:
    try:
        BIP32KeyData.b58decode(key)
    # ValueError, not Exception: the question is whether these characters
    # are an extended key, and characters that are not are False
    except ValueError:
        return False
    return True


def _neutered(xkey: str, prv_keys: dict[str, str]) -> str:
    """Return the public spelling of an extended key, filing the private one.

    The one place a descriptor's private material is separated from the
    descriptor, and the reason `KeyExpression.xkey` can be said to be
    public: an xprv is answered with its xpub, and the xprv goes to the
    caller's mapping under that xpub. An xpub is answered with itself and
    files nothing.

    Filed under the public spelling, so that what indexes the mapping is
    not itself a secret -- which is how Bitcoin Core keys the
    `FlatSigningProvider` its own parser fills, by the id of the public
    key rather than by anything that signs.
    """
    if not BIP32KeyData.b58decode(xkey).is_private:
        return xkey
    xpub = xpub_from_xprv(xkey)
    prv_keys[xpub] = xkey
    return xpub


def _origin_and_rest(expression: str) -> tuple[BIP32KeyOrigin | None, str, str]:
    """Split the `[fingerprint/path]` prefix off a KEY expression."""
    if not expression.startswith("["):
        if "]" in expression:
            raise BTClibValueError("']' without the '[' that opens a key origin")
        return None, "", expression
    end = expression.find("]")
    if end < 0:
        raise BTClibValueError("missing ']' in the key origin")
    origin, hardening = _key_origin(expression[1:end])
    return origin, hardening, expression[end + 1 :]


def _assert_musig_allowed(*, musig_allowed: bool) -> None:
    """Refuse a ``musig()`` anywhere BIP390 does not put one.

    Which is everywhere but a ``tr()`` and a ``rawtr()``: their internal
    or output key, and the keys of the ``pk()``, ``multi_a()`` and
    ``sortedmulti_a()`` leaves of a script tree. A participant is one of
    the places it is refused, which is BIP390's "cannot be nested within
    another musig()", and the message names both -- Bitcoin Core's own,
    and the same sentence answers a nested one and a ``wpkh(musig())``.

    BIP390 names ``sp()`` as a third position; btclib does not read
    ``sp()`` at all, so there is nothing here to allow it in.
    """
    if not musig_allowed:
        raise BTClibValueError("musig() is only allowed in tr() and rawtr()")


def _assert_key_characters(rest: str) -> None:
    """Refuse what a KEY expression cannot hold once the origin is off."""
    if "]" in rest:
        raise BTClibValueError("more than one ']' in a single key expression")
    if "<" in rest:
        err_msg = "multipath key expression: use multipath_descriptors first"
        raise BTClibValueError(err_msg)
    if "(" in rest:
        # a function where a key belongs. BIP390's musig() is the one that
        # is a key expression, and reaching here means it was written
        # behind a key origin, which is not where it may be nested
        if rest.startswith("musig("):
            raise BTClibValueError("musig() cannot be nested inside a key origin")
        raise BTClibValueError("not a key expression")


def _split_wildcard(steps: list[str]) -> tuple[list[str], int | None, str]:
    """Split the final `/*` step off a path: its offset, and its symbol."""
    if steps and steps[-1] in {"*", "*'", "*h"}:
        offset = 0 if steps[-1] == "*" else _HARDENED_OFFSET
        return steps[:-1], offset, steps[-1][1:]
    return steps, None, ""


def _fixed_pub_key(key: str, *, x_only: bool) -> tuple[bytes, bool]:
    """Return the SEC bytes of a hex or WIF key, and whether x-only.

    A hex key is x-only when it was written in 32 bytes, and a WIF when it
    sits where only an x-only key is written: it has no spelling of its
    own to echo, so what is written back is the spelling the position
    takes. Bitcoin Core makes the same distinction with one bool per key
    -- `false` for a hex key it read whole, `ctx == ParseScriptContext::
    P2TR` for a private one -- which is what makes its ``tr(WIF)`` and
    ``rawtr(WIF)`` vectors come back in 32 bytes and not 33.
    """
    if _HEX.fullmatch(key):
        return _pub_key_from_hex(key, x_only=x_only)
    # what is left is a WIF, which is b58's object and not to_pub_key's
    # (issue #1188); prv_key_data_from_wif answers both for it and for
    # characters that are no key expression at all
    try:
        return b58.prv_key_data_from_wif(key).pub.sec, x_only
    except (TypeError, ValueError) as e:
        raise BTClibValueError("invalid key expression") from e


def _musig_der_path(suffix: str) -> tuple[tuple[int, ...], int | None]:
    """Return the path and wildcard a ``musig()`` derives the aggregate by.

    Every one of BIP390's rules about it is a refusal here: no hardened
    step and no hardened wildcard, an aggregate key having no private half
    to take either with, which is BIP328's own restriction.
    """
    if not suffix:
        return (), None
    if not suffix.startswith("/"):
        raise BTClibValueError(f"not a musig() derivation path: {suffix}")
    steps, wildcard, wildcard_hardening = _split_wildcard(suffix[1:].split("/"))
    if wildcard_hardening:
        raise BTClibValueError("musig() cannot have a hardened wildcard")
    der_path = _der_path("/".join(steps))
    if any(index >= _HARDENED_OFFSET for index in der_path):
        raise BTClibValueError("musig() cannot have hardened derivation steps")
    return tuple(der_path), wildcard


def _parse_musig(expression: str, prv_keys: dict[str, str]) -> KeyExpression:
    """Return the KeyExpression of a BIP390 ``musig()`` expression.

    The participants are KEY expressions read as any other key in a
    ``tr()`` is, except that none of them may be x-only: MuSig2
    aggregation is over points, so it needs the evenness byte an x-only
    spelling drops -- which is Bitcoin Core's rule too, its own parse
    context allowing 32-byte keys under ``tr()`` and not under
    ``musig()``.

    Derivation on the aggregate key costs three further conditions, all
    BIP390's: every participant an extended key, none of them ranged, and
    no hardened step. The first two are what make one aggregate key per
    index well defined -- with both sides ranged there would be two
    indexes and one wildcard to read them from.
    """
    close = expression.rfind(")")
    inner = expression[len("musig(") : close]
    arguments = _split_arguments(inner)
    if arguments == [""]:
        raise BTClibValueError("musig() takes at least one key")
    try:
        participants = tuple(
            _parse_key(
                key,
                prv_keys,
                x_only=False,
                compressed=True,
                musig_allowed=False,
            )
            for key in arguments
        )
    # which of several participants was wrong is half the answer, and the
    # inner message names neither the function nor the position. Bitcoin
    # Core prefixes its own the same way, "musig(): ..."
    except BTClibValueError as e:
        raise BTClibValueError(f"musig(): {e}") from e
    der_path, wildcard = _musig_der_path(expression[close + 1 :])
    if der_path or wildcard is not None:
        if any(not key.xkey for key in participants):
            err_msg = "musig() derivation requires every participant to be extended"
            raise BTClibValueError(err_msg)
        if any(key.is_ranged for key in participants):
            err_msg = "musig() cannot have a ranged participant and derivation too"
            raise BTClibValueError(err_msg)
    return KeyExpression(
        participants=participants, der_path=der_path, wildcard=wildcard
    )


def _parse_key(
    expression: str,
    prv_keys: dict[str, str],
    *,
    x_only: bool,
    compressed: bool,
    musig_allowed: bool,
) -> KeyExpression:
    """Return the KeyExpression of a BIP380 KEY expression.

    Never echo the key in an error message: a KEY expression is a WIF or
    an xprv as often as it is a public key, and an error message ends up
    in logs and in bug reports.

    The hardening symbol is the last one the expression used, read in the
    order it is written: the origin's path, then the key's, then the
    wildcard. A fixed key hardens nothing and keeps the default, there
    being no step of it to write.

    A ``musig()`` is read before the key origin and not after it, which is
    Bitcoin Core's order and where BIP390's "cannot be nested" comes from:
    the expression is a musig one or it is not, so an origin in front of it
    is not a musig expression with an origin -- it is a key that is no key.
    """
    if expression.startswith("musig("):
        _assert_musig_allowed(musig_allowed=musig_allowed)
        return _parse_musig(expression, prv_keys)
    origin, origin_hardening, rest = _origin_and_rest(expression)
    _assert_key_characters(rest)
    key, separator, path = rest.partition("/")
    if _is_extended_key(key):
        steps, wildcard, wildcard_hardening = _split_wildcard(
            path.split("/") if separator else []
        )
        der_path = "/".join(steps)
        hardening = origin_hardening
        for symbol in (_hardening(der_path), wildcard_hardening):
            hardening = symbol or hardening
        return KeyExpression(
            origin=origin,
            xkey=_neutered(key, prv_keys),
            der_path=tuple(_der_path(der_path)),
            wildcard=wildcard,
            hardening=hardening or _HARDENING,
        )
    if separator:
        raise BTClibValueError("derivation path after a key that cannot derive")
    pub_key, was_x_only = _fixed_pub_key(key, x_only=x_only)
    key_expression = KeyExpression(
        origin=origin,
        pub_key=pub_key,
        x_only=was_x_only,
        hardening=origin_hardening or _HARDENING,
    )
    if compressed and not key_expression.is_compressed:
        raise BTClibValueError("uncompressed public keys are not allowed here")
    return key_expression
