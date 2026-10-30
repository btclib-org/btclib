# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Witness dataclass; the class docstring has the contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from typing_extensions import override

from btclib import var_int
from btclib.alias import BinaryData, Octets
from btclib.consensus import MAX_WITNESS_STACK_ITEMS
from btclib.exceptions import BTClibTypeError, BTClibValueError
from btclib.utils import (
    assert_no_trailing,
    bytes_from_octets,
    bytesio_from_binarydata,
    fields_from_json_object,
    is_octets,
    list_from_json_array,
)

__all__ = [
    "Witness",
]

# the width of the number after each var_int prefix
_PREFIX_WIDTH = {0xFD: 2, 0xFE: 4, 0xFF: 8}


def _read_size(data: bytes, pos: int) -> tuple[int, int]:
    """Return the var_int at pos of a checked serialization, and its end."""
    size = data[pos]
    if size < 0xFD:
        return size, pos + 1
    width = _PREFIX_WIDTH[size]
    end = pos + 1 + width
    return int.from_bytes(data[pos + 1 : end], byteorder="little"), end


def _size_prefix(size: int) -> bytes:
    """Return var_int.serialize(size), the common one-octet case first."""
    return bytes((size,)) if size < 0xFD else var_int.serialize(size)


# frozen, and held as bytes, which makes a Witness immutable all the way
# down: neither replacing the stack of a witness held by someone else
# (issue #140) nor mutating one in place through a shared default (issue
# #139) is expressible, and the generated __hash__ works.
#
# Held as its serialization, a parsed witness keeps no object per element.
# parse asks the stream for read() alone: a caller's BytesIO may hand out
# what it reads without holding it, as btclib-node's mempool reader does,
# and then neither getbuffer() nor an absolute seek finds the bytes.
#
# The serialization is canonical, var_int refusing every other encoding of
# a length, so two witnesses have one serialization exactly when they have
# one stack: the generated __eq__ and __hash__ compare it.
#
# `stack` is cached in `_stack`, which is not a field, and the field it is
# derived from cannot change under it. The constructor fills the cache with
# the elements it was handed, and parse leaves it empty. It is a property
# and not a functools.cached_property, which mypy would let a caller assign
# to.
@dataclass(frozen=True)
class Witness:
    """The witness stack of one transaction input, per BIP141.

    A Witness holds its serialization. `stack` is the tuple of its byte
    strings, bottom of the stack first; for a parsed Witness, it is read
    from the serialization on first access and cached. A non-segwit input
    has an empty one.
    Immutable throughout, so a Witness can be shared and hashed; the
    script interpreter pops a list copy of its own.
    """

    _serialized: bytes

    def __init__(
        self, stack: Sequence[Octets] | None = None, *, check_validity: bool = True
    ) -> None:
        # every Octets is itself a Sequence, so passing one instead of a
        # list of stack elements would zip through its bytes and treat
        # each as its own element (issue #1405)
        if is_octets(stack):
            raise BTClibTypeError(f"invalid stack type: {type(stack).__name__}")
        # https://docs.python.org/3/tutorial/controlflow.html#default-argument-values
        if not stack:
            # the empty witness of a legacy input, without the general loop
            object.__setattr__(self, "_serialized", b"\x00")
            object.__setattr__(self, "_stack", ())
            if check_validity:
                self.assert_valid()
            return
        elements = tuple(bytes_from_octets(element) for element in stack)
        parts = [_size_prefix(len(elements))]
        for element in elements:
            parts += (_size_prefix(len(element)), element)
        object.__setattr__(self, "_serialized", b"".join(parts))
        object.__setattr__(self, "_stack", elements)

        if check_validity:
            self.assert_valid()

    @property
    def stack(self) -> tuple[bytes, ...]:
        """The stack elements, bottom first.

        A parsed Witness reads them from its bytes on first access.
        """
        stack: tuple[bytes, ...] | None = self.__dict__.get("_stack")
        if stack is None:
            data = self._serialized
            n, pos = _read_size(data, 0)
            elements = []
            for _ in range(n):
                size, pos = _read_size(data, pos)
                elements.append(data[pos : pos + size])
                pos += size
            stack = tuple(elements)
            object.__setattr__(self, "_stack", stack)
        return stack

    def __len__(self) -> int:
        return _read_size(self._serialized, 0)[0]

    @override
    def __repr__(self) -> str:
        return f"{type(self).__name__}(stack={self.stack!r})"

    def assert_valid(self) -> None:
        """Refuse a serialization that does not read as bytes.

        Any elements are a valid witness -- what they must mean is the
        spending script's business. The constructor and parse always
        store bytes; the coercion is for a Witness built any other way.
        """
        bytes(self._serialized)

    def to_dict(self, *, check_validity: bool = True) -> dict[str, list[str]]:
        """Return the witness as a dict of hex strings, for json.

        from_dict reads the same shape back, and the round trip is
        exact, hex being a spelling of the bytes and nothing less.
        """
        if check_validity:
            self.assert_valid()

        return {"stack": [v.hex() for v in self.stack]}

    @classmethod
    def from_dict(
        cls: type[Witness],
        dict_: Mapping[str, Sequence[Octets]],
        *,
        check_validity: bool = True,
    ) -> Witness:
        """Build a Witness from the dict shape to_dict writes.

        The stack is asked for as an array rather than left to the
        constructor, which reads `stack or []`: a `None` there is an
        empty witness, so a schema mistake was a witness of no elements
        instead of an error.
        """
        dict_ = fields_from_json_object(dict_, "witness")
        stack = list_from_json_array(dict_["stack"], "witness stack")
        return cls(stack, check_validity=check_validity)

    def _serialized_size(self) -> int:
        """Return what serialize writes, without writing it."""
        return len(self._serialized)

    def serialize(self, *, check_validity: bool = True) -> bytes:
        """Return the serialization of the Witness."""
        if check_validity:
            self.assert_valid()

        return self._serialized

    @classmethod
    def parse(
        cls: type[Witness], data: BinaryData, *, check_validity: bool = True
    ) -> Witness:
        """Return a Witness by parsing binary data.

        Octets are one whole witness and a stream is the caller's:
        btclib/utils.py states the rule both halves of this contract read.
        The stream case is what a transaction is parsed with -- one witness
        per input, out of the stream the transaction is read from -- and the
        octet case is what a PSBT_IN_FINAL_SCRIPTWITNESS value is.
        """
        stream = bytesio_from_binarydata(data)
        # bounded by the block that would have to carry the stack rather
        # than by var_int's own MAX_SIZE, which answers whether a
        # CompactSize is sane and not whether anything could hold this
        # many: an element costs a witness octet at least, so a count
        # above MAX_WITNESS_STACK_ITEMS is one no transaction was ever
        # serialized with (issue #569). Not MAX_STACK_SIZE, which is the
        # interpreter's -- a stack of a million elements is unspendable
        # and parses, here as it does for Core, and refusing it here would
        # be issue #123 again
        n = var_int.parse(stream, MAX_WITNESS_STACK_ITEMS)
        serialized = bytearray(_size_prefix(n))
        read = stream.read
        for _ in range(n):
            # a length under 0xfd is one octet and canonical; any other is
            # var_int's to read, with its refusals, so what is kept of it
            # is the canonical encoding read
            prefix = read(1)
            if prefix and prefix[0] < 0xFD:
                size = prefix[0]
            else:
                if prefix:
                    prefix += read(_PREFIX_WIDTH[prefix[0]])
                size = var_int.parse(prefix)
            serialized += prefix
            if size:
                element = read(size)
                if len(element) != size:
                    raise BTClibValueError("not enough binary data")
                serialized += element
        assert_no_trailing(data, stream, "witness")

        witness = cls.__new__(cls)
        object.__setattr__(witness, "_serialized", bytes(serialized))
        if check_validity:
            witness.assert_valid()
        return witness
