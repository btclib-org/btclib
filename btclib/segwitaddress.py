# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# Copyright (C) 2019-2020 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.


"""SegWit address implementation.

Some of these functions were originally from
https://github.com/sipa/bech32/tree/master/ref/python,
with the following modifications:

* splitted the original segwit_addr.py file in bech32.py and segwitaddr.py
* type annotated python3
* avoided returning None or (None, None), throwing ValueError instead
* detailed error messages and exteded safety checks
* check that Bech32 addresses are not longer than 90 characters
  (as this is not enforced by bech32.encode anymore)
"""


from typing import Tuple, Iterable, List, Union

from . import bech32
from . import script
from .utils import Octets, h160, sha256
from .wifaddress import p2sh_address

WitnessProgram = Union[List[int], bytes]

_NETWORKS = ['mainnet', 'testnet', 'regtest']
_P2W_PREFIXES = ['bc', 'tb', 'bcrt']


def _convertbits(data: Iterable[int], frombits: int,
                 tobits: int, pad: bool = True) -> List[int]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("failure")
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("failure")

    return ret


def check_witness(witvers: int, witprog: WitnessProgram):
    l = len(witprog)
    if witvers == 0:
        if l != 20 and l != 32:
            raise ValueError(f"witness program length ({l}) is not 20 or 32")
    elif witvers > 16 or witvers < 0:
        msg = f"witness version ({witvers}) not in [0, 16]"
        raise ValueError(msg)
    else:
        if l < 2 or l > 40:
            raise ValueError(f"witness program length ({l}) not in [2, 40]")


def scriptpubkey(witvers: int, witprog: WitnessProgram) -> bytes:
    """Construct a SegWit scriptPubKey for a given witness.
    
    The scriptPubKey is the witness version
    (OP_0 for version 0, OP_1 for version 1, etc.)
    followed by the canonical push of the witness program
    (i.e. program lenght + program).

    E.g. for P2WPKH the program is a 20-byte keyhash,
    the scriptPubkey is 0x0014{20-byte key-hash};
    for P2SKH the program is a 32-byte script-hash,
    the scriptPubkey is 0x0020{32-byte keyhash}
    """

    check_witness(witvers, witprog)
    return script.serialize([witvers, bytes(witprog)])


def decode(address: Union[str, bytes],
           network: str = 'mainnet') -> Tuple[str, int, List[int]]:
    """Decode a SegWit address."""

    if isinstance(address, str):
        address = address.strip()

    # the following check was originally in bech32.decode2
    # but it does not pertain there
    if len(address) > 90:
        raise ValueError(f"Bech32 address length ({len(address)}) > 90")

    hrp, data = bech32.decode(address)

    # check that it is a SegWit address
    i = _P2W_PREFIXES.index(hrp)

    # check that it is a SegWit address for the given network
    if _NETWORKS[i] != network:
        msg = f"{address} is a SegWit address for "
        msg += f"a network other than {network}"
        raise ValueError(msg)

    if len(data) == 0:
        raise ValueError(f"Bech32 address with empty data")

    witvers = data[0]
    witprog = _convertbits(data[1:], 5, 8, False)
    check_witness(witvers, witprog)
    
    return hrp, witvers, witprog


def encode(wver: int, wprog: WitnessProgram, network: str = 'mainnet') -> bytes:
    """Encode a SegWit address."""
    hrp = _P2W_PREFIXES[_NETWORKS.index(network)]
    check_witness(wver, wprog)
    ret = bech32.encode(hrp, [wver] + _convertbits(wprog, 8, 5))
    return ret


def _p2wpkh_address(pubkey: Octets, native: bool, network: str) -> bytes:
    """Return the p2wpkh address as native SegWit or legacy p2sh-wrapped."""

    if isinstance(pubkey, str):  # hex string
        pubkey = pubkey.strip()
        pubkey = bytes.fromhex(pubkey)
    if pubkey[0] not in (2, 3):
        raise ValueError(f"Uncompressed pubkey {pubkey}")

    witvers = 0
    witprog = h160(pubkey)

    if native:
        return encode(witvers, witprog, network)
    script_pubkey = scriptpubkey(witvers, witprog)
    return p2sh_address(script_pubkey, network)


def p2wpkh_address(pubkey: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wpkh native SegWit address."""
    return _p2wpkh_address(pubkey, True, network)


def p2wpkh_p2sh_address(pubkey: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wpkh-p2sh (legacy) address."""
    return _p2wpkh_address(pubkey, False, network)


def h160_from_p2wpkh_address(address = Union[str, bytes],
                             network: str = 'mainnet') -> bytes:

    if isinstance(address, str):
        address = address.strip()

    hrp, witver, witprog = decode(address, network)

    # check that it is a p2wpkh address
    if len(witprog) != 20 and witver == 0:
        msg = f"Witness program length ({len(witprog)}) is not "
        msg += "20: not a V0 p2wpkh address"
        raise ValueError(msg)

    return bytes(witprog)


def _p2wsh_address(witness_script: Octets, native: bool, network: str) -> bytes:
    """Return the address as native SegWit Bech32 or legacy p2sh-wrapped."""

    witvers = 0
    witprog = sha256(witness_script)
    if native:
        return encode(witvers, witprog, network)
    script_pubkey = scriptpubkey(witvers, witprog)
    return p2sh_address(script_pubkey, network)


def p2wsh_address(witness_script: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wsh native SegWit address."""
    return _p2wsh_address(witness_script, True, network)


def p2wsh_p2sh_address(witness_script: Octets, network: str = 'mainnet') -> bytes:
    """Return the p2wsh-p2sh (legacy) address."""
    return _p2wsh_address(witness_script, False, network)


def sha256_from_p2wsh_address(address = Union[str, bytes],
                              network: str = 'mainnet') -> bytes:

    if isinstance(address, str):
        address = address.strip()

    hrp, witver, witprog = decode(address, network)

    # check that it is a p2wsh address
    if len(witprog) != 32 and witver == 0:
        msg = f"Witness program length ({len(witprog)}) is not "
        msg += "32: not a V0 p2wsh address"
        raise ValueError(msg)

    return bytes(witprog)
