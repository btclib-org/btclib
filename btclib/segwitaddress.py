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

Most of the functions here are originally from
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
from .curve import Point
from .utils import h160_from_pubkey, Octets, sha256
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
            raise ValueError(f"{l}-bytes witness program: must be 20 or 32")
    elif witvers > 16 or witvers < 0:
        msg = f"witness version ({witvers}) not in [0, 16]"
        raise ValueError(msg)
    else:
        if l < 2 or l > 40:
            raise ValueError(f"{l}-bytes witness program: must be in [2,40]")


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


def decode(addr: str, network: str = 'mainnet') -> Tuple[int, List[int]]:
    """Decode a segwit address."""

    # the following check was originally in bech32.decode2
    # but it does not pertain there
    if len(addr) > 90:
        raise ValueError(f"Bech32 address length ({len(addr)}) > 90")

    hrp, data = bech32.decode(addr)

    # also verify that the network is known
    if _NETWORKS[_P2W_PREFIXES.index(hrp)] != network:
        raise ValueError(f"HPR ({hrp}) / network ({network}) mismatch")

    if len(data) == 0:
        raise ValueError(f"Bech32 address with empty data")

    witvers = data[0]
    witprog = _convertbits(data[1:], 5, 8, False)
    check_witness(witvers, witprog)
    
    return witvers, witprog


def encode(wver: int, wprog: WitnessProgram, network: str = 'mainnet') -> str:
    """Encode a segwit address."""
    hrp = _P2W_PREFIXES[_NETWORKS.index(network)]
    check_witness(wver, wprog)
    ret = bech32.encode(hrp, [wver] + _convertbits(wprog, 8, 5))
    return ret


def p2wpkh_p2sh_address(Q: Point, network: str = 'mainnet') -> bytes:
    """Return SegWit p2wpkh nested in p2sh address."""

    witvers = 0
    witprog = h160_from_pubkey(Q, True)
    script_pubkey = scriptpubkey(witvers, witprog)
    return p2sh_address(script_pubkey, network)


def p2wpkh_address(Q: Point, network: str = 'mainnet') -> str:
    """Return native SegWit Bech32 p2wpkh address."""

    witvers = 0
    witprog = h160_from_pubkey(Q, True)
    return encode(witvers, witprog, network)



def p2wsh_p2sh_address(witness_script: Octets, network: str = 'mainnet') -> bytes:
    """Return SegWit p2wsh nested in p2sh address."""

    witvers = 0
    witprog = sha256(witness_script)
    script_pubkey = scriptpubkey(witvers, witprog)
    return p2sh_address(script_pubkey, network)


def p2wsh_address(witness_script: Octets, network: str = 'mainnet') -> str:
    """Return native SegWit Bech32 p2wsh address."""

    witvers = 0
    witprog = sha256(witness_script)
    return encode(witvers, witprog, network)
