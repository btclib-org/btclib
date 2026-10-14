# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.
"""A four-byte field that is not an int is a type error in every preimage.

The sequence, the vout of the outpoint, the version and the lock time are
written as four unsigned bytes, and each preimage reads them from a
transaction that need not have been judged whole (`check_validity=False`).
"""

from collections.abc import Callable

import pytest

from btclib.exceptions import BTClibTypeError
from btclib.script import Witness, sig_hash
from btclib.tx import OutPoint, Tx, TxIn, TxOut

_NOT_AN_INT = [1.5, 1.0, "1", b"\x01", None, True, False]
_P2TR = TxOut(1000, bytes([0x51, 0x20]) + bytes(32))
_P2WPKH = bytes([0x00, 0x14]) + bytes(20)


def _tx(field: str, value: object) -> Tx:
    vout = 0
    sequence = 0xFFFFFFFE
    version = 2
    lock_time = 0
    if field == "vout":
        vout = value  # type: ignore[assignment]
    elif field == "sequence":
        sequence = value  # type: ignore[assignment]
    elif field == "version":
        version = value  # type: ignore[assignment]
    else:
        lock_time = value  # type: ignore[assignment]
    out_point = OutPoint(b"\x01" * 32, vout, check_validity=False)
    return Tx(
        version,
        lock_time,
        [TxIn(out_point, b"", sequence, Witness([b"\x00" * 64]), check_validity=False)],
        [TxOut(1000, _P2WPKH)],
        check_validity=False,
    )


_PREIMAGES: dict[str, Callable[[Tx], bytes]] = {
    "legacy": lambda tx: sig_hash.legacy(b"", tx, 0, sig_hash.ALL),
    "segwit_v0": lambda tx: sig_hash.segwit_v0(b"", tx, 0, sig_hash.ALL, 1000),
    "taproot": lambda tx: sig_hash.from_tx([_P2TR], tx, 0, sig_hash.DEFAULT),
}


@pytest.mark.parametrize("preimage", _PREIMAGES)
@pytest.mark.parametrize(
    "field, name",
    [
        ("sequence", "sequence"),
        ("vout", "vout"),
        ("version", "version"),
        ("lock_time", "lock time"),
    ],
)
@pytest.mark.parametrize("value", _NOT_AN_INT)
def test_a_four_byte_field_that_is_not_an_int_is_a_type_error(
    preimage: str, field: str, name: str, value: object
) -> None:
    """Each value is refused as a type, a bool included.

    A bool is an int to Python and not to `is_integer`.
    """
    tx = _tx(field, value)
    with pytest.raises(BTClibTypeError, match=f"invalid {name} type: "):
        _PREIMAGES[preimage](tx)


@pytest.mark.parametrize("preimage", _PREIMAGES)
def test_the_transaction_without_the_spoiled_field_is_hashed(preimage: str) -> None:
    """The control: each test above spoils one field of this transaction."""
    assert len(_PREIMAGES[preimage](_tx("vout", 0))) == 32
