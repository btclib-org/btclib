#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Bitcoin address-based compact signature for messages.

For message signatures, Bitcoin wallets use an address-based scheme with a
compact 65 bytes custom signature encoding. Such a signature proves the control
of the private key corresponding to a given address and, consequently, of the
associated bitcoins (if any).
The signature goes along with the address: at verification time public key
recovery is used, i.e. given a message, the public key that would have created
that signature is found and compared with the provided address.

Note that in the Bitcoin protocol this compact 65 bytes signature encoding is
only used for messages: for transactions Bitcoin uses DER encoding instead,
resulting in 71 bytes signatures on average.

This scheme being address-based, at signing time it must rely on a wallet
infrastructure to access the private key corresponding to the provided address.
For a given message and address, the ECDSA signature of
"\x18Bitcoin Signed Message:\n" + chr(len(msg)) + msg is calculated
(0x18 is just the length of the prefix text); this prefix manipulation avoids
the plain signature of a possibly deceiving message.
Finally, the resulting 64 bytes (r, s) signature is base64-encoded as
[1 byte][r][s], where the first byte is used to convey
information in the verification process about which of the
recovered public keys will have to be used and
if the corresponding address is compressed or not.

Base64-encoding uses 10 digits, 26 lowercase characters,
26 uppercase characters, '+' (plus sign), and '/' (forward slash);
equal sign '=' is used as 65th character pad,
a complement in the final process of encoding a message.

https://bitcoin.stackexchange.com/questions/10759/how-does-the-signature-verification-feature-in-bitcoin-qt-work-without-a-public
https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long
https://bitcoin.stackexchange.com/questions/34135/what-is-the-strmessagemagic-good-for
https://bitcoin.stackexchange.com/questions/36838/why-does-the-standard-bitcoin-message-signature-include-a-message-prefix
https://bitcoin.stackexchange.com/questions/68844/explicit-message-length-in-bitcoin-signed-message
https://github.com/bitcoinjs/bitcoinjs-lib/blob/1079bf95c1095f7fb018f6e4757277d83b7b9d07/src/message.js#L13
https://bitcointalk.org/index.php?topic=6428.msg536734#msg536734
https://bitcointalk.org/index.php?topic=6428.msg550155#msg550155
https://github.com/bitcoin/bitcoin/pull/524
https://www.reddit.com/r/Bitcoin/comments/bgcgs2/can_bitcoin_core_0171_sign_message_from_segwit/
https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki
"""

import base64
from hashlib import sha256 as hf
from typing import Tuple

from .curve import mult
from .curves import secp256k1 as ec
from .wifaddress import address_from_pubkey, h160_from_pubkey, _h160_from_address
from . import dsa

def _bitcoin_msg(msg: str) -> bytes:
    # Electrum does strip leading and trailing spaces; bitcoin core does not
    #msg = msg.strip()
    message = "\x18Bitcoin Signed Message:\n" + chr(len(msg)) + msg
    return hf(message.encode()).digest()

def sign(prvkey: int, msg: str, compressed: bool) -> Tuple[str, str]:

    pubkey = mult(ec, prvkey)
    address = address_from_pubkey(pubkey, compressed, b'\x00')

    bitcoin_msg = _bitcoin_msg(msg)
    sig = dsa.sign(ec, hf, bitcoin_msg, prvkey)

    pubkeys = dsa.pubkey_recovery(ec, hf, bitcoin_msg, sig)
    sig = sig[0].to_bytes(32, 'big') + sig[1].to_bytes(32, 'big')
    for i in range(len(pubkeys)):
        if pubkeys[i] == pubkey:
            nV = 27 + i
            if compressed:
                nV += 4
            return address, base64.b64encode(bytes([nV]) + sig)

    # the following line should never be executed
    raise ValueError("Public key could not be recovered")

def verify(address: bytes, sig: bytes, msg: str) -> bool:
    """Verify Bitcoin compact signature for a given address/message pair."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(address, sig, msg)
    except Exception:
        return False


def _verify(address: bytes, sig: bytes, msg: str) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    # verify it is a valid address
    h160 = _h160_from_address(address)

    sig = base64.b64decode(sig)
    if len(sig) != 65:
        raise ValueError(f"Wrong encoding length: {len(sig)} instead of 65")

    nV = int.from_bytes(sig[0:1], 'big')
    #if nV < 27 or nV > 34: return False
    # i selects which key is recovered
    i = (nV - 27) & 3
    compressed = (nV - 27) & 4 != 0

    r = int.from_bytes(sig[1:33], 'big')
    s = int.from_bytes(sig[33:], 'big')
    sig = r, s
    bitcoin_msg = _bitcoin_msg(msg)
    pubkeys = dsa.pubkey_recovery(ec, hf, bitcoin_msg, sig)
    
    #add1 = address_from_pubkey(pubkeys[0], compressed, b'\x00')
    #add2 = address_from_pubkey(pubkeys[1], compressed, b'\x00')

    return h160 == h160_from_pubkey(pubkeys[i], compressed)
