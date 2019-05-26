#!/usr/bin/env python3

# Copyright (C) 2019 The btclib developers
#
# This file is part of btclib. It is subject to the license terms in the
# LICENSE file found in the top-level directory of this distribution.
#
# No part of btclib including this file, may be copied, modified, propagated,
# or distributed except according to the terms contained in the LICENSE file.

""" Bitcoin (P2PKH) address-based compact signature for messages.

For message signatures, Bitcoin wallets use a P2PKH address-based scheme
with a compact 65 bytes custom signature encoding.
As it is the case for all digital signature scheme, this scheme actually
works with keys, not addresses: it uses a P2PKH address to uniquely
identify a private/public keypair.
This signature proves the control of the private key corresponding to
a given address and, consequently, of the associated bitcoins (if any).
The signature goes along with its address: at verification time
public key recovery is used, i.e. given a message, the public key
that would have created that signature is found and compared with
the provided address.

Note that in the Bitcoin protocol this compact 65 bytes signature
encoding is only used for messages: for transactions Bitcoin uses DER
encoding instead, resulting in 71 bytes signatures on average.

At signing time a wallet infrastructure is required
to access the private key corresponding to the
provided address. For a given message and address, the ECDSA signature
of the hash of "Bitcoin Signed Message" *magic* prefix followed by
the message is calculated; this prefix
manipulation avoids the plain signature of a possibly deceiving message.
The resulting 64 bytes (r, s) signature is serialized as
[1 byte][r][s], where the first byte is a recovery flag used
during the verification process to discriminate among the recovered
public keys and to manage address compression.
Explicitly, the recovery flag value is:

    27 + (IF compressed THEN 4 ELSE 0) + key_id

where:

- 27 identify a P2PKH address (Electrum also supports Segwit P2WPKH-P2SH
  and P2WPKH, but not according to the BIP137 specifications;
  anyway this module and bitcoin core do not support them yet)
- compressed indicates if the address is the hash of the compressed
  public key representation (Segwit is always compressed)
- key_id is the index in the [0, 3] range identifying which of the
  recovered public keys is the one associated to the address;
  it is stored in the least significant 2 bits of the header

+-----------+--------+--------------------+
| rec. flag | key_id |    address type    |
+===========+========+====================+
|     27    |    0   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     28    |    1   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     29    |    2   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     30    |    3   | P2PKH uncompressed |
+-----------+--------+--------------------+
|     31    |    0   | P2PKH compressed   |
+-----------+--------+--------------------+
|     32    |    1   | P2PKH compressed   |
+-----------+--------+--------------------+
|     33    |    2   | P2PKH compressed   |
+-----------+--------+--------------------+
|     34    |    3   | P2PKH compressed   |
+-----------+--------+--------------------+
|     35    |    0   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     36    |    1   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     37    |    2   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     38    |    3   | P2WPKH-P2SH        |
+-----------+--------+--------------------+
|     39    |    0   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     40    |    1   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     41    |    2   | P2WPKH (bech32)    |
+-----------+--------+--------------------+
|     42    |    3   | P2WPKH (bech32)    |
+-----------+--------+--------------------+

Finally, the serialized signature can be base64-encoded to transport it
across channels that are designed to deal with textual data.
Base64-encoding uses 10 digits, 26 lowercase characters, 26 uppercase
characters, '+' (plus sign), and '/' (forward slash); equal sign '=' is
used as 65th character pad, a complement in the final process of
message encoding.

Warning: one should never sign a vague statement that could be reused
out of the context it was intended for. E.g. always include at least

- your name (nickname, customer id, email, etc.)
- date and time
- who the message is intended for (name, business name, email, etc.)
- specific purpose of the message

https://bitcoin.stackexchange.com/questions/10759/how-does-the-signature-verification-feature-in-bitcoin-qt-work-without-a-public

https://bitcoin.stackexchange.com/questions/12554/why-the-signature-is-always-65-13232-bytes-long

https://bitcoin.stackexchange.com/questions/34135/what-is-the-strmessagemagic-good-for

https://bitcoin.stackexchange.com/questions/36838/why-does-the-standard-bitcoin-message-signature-include-a-message-prefix

https://bitcoin.stackexchange.com/questions/68844/explicit-message-length-in-bitcoin-signed-message

https://github.com/bitcoinjs/bitcoinjs-lib/blob/1079bf95c1095f7fb018f6e4757277d83b7b9d07/src/message.js#L13

https://bitcointalk.org/index.php?topic=6428

https://bitcointalk.org/index.php?topic=6430

https://crypto.stackexchange.com/questions/18105/how-does-recovering-the-public-key-from-an-ecdsa-signature-work/18106?newreg=670c5855241d4340af0cbbc960fd2dc3

https://github.com/bitcoin/bitcoin/pull/524

https://www.reddit.com/r/Bitcoin/comments/bgcgs2/can_bitcoin_core_0171_sign_message_from_segwit/

https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki

https://github.com/brianddk/bips/blob/legacysignverify/bip-0xyz.mediawiki

"""

import base64
from hashlib import sha256 as hf
from typing import Tuple, Union

from .base58 import _str_to_bytes
from .curve import mult
from .curves import secp256k1 as ec
from .wifaddress import address_from_pubkey, h160_from_pubkey, _h160_from_address
from . import dsa

# TODO: support msg as bytes
# TODO: add testnet / regtest / litecoin signature
# TODO: add small wallet (address <-> private key) infrastructure
# TODO:                           then also add sign(address, msg)
# TODO: decouple serialization from address-based signature
# TODO: add test vectors from P. Todd's library
# TODO: report Electrum bug

def _magic_hash(msg: str) -> bytes:
    # Electrum does strip leading and trailing spaces;
    # bitcoin core does not
    # msg = msg.strip()
    m = hf()
    prefix = b'\x18Bitcoin Signed Message:\n'
    m.update(prefix)
    message = chr(len(msg)) + msg
    m.update(message.encode())
    return m.digest()

def sign(msg: str, prvkey: int, compressed: bool) -> Tuple[str, str]:
    """Generate message signature for a given P2PKH address."""

    pubkey = mult(ec, prvkey)
    address = address_from_pubkey(pubkey, compressed, b'\x00')

    magic_msg = _magic_hash(msg)
    sig = dsa.sign(ec, hf, magic_msg, prvkey)

    pubkeys = dsa.pubkey_recovery(ec, hf, magic_msg, sig)
    sig = sig[0].to_bytes(32, 'big') + sig[1].to_bytes(32, 'big')
    for i in range(len(pubkeys)):
        if pubkeys[i] == pubkey:
            rf = 27 + i
            if compressed:
                rf += 4
            return address, base64.b64encode(bytes([rf]) + sig)

    # the following line should never be executed
    raise ValueError("Public key not recovered")

def verify(msg: str, addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    """Verify message signature for a given P2PKH address."""

    # try/except wrapper for the Errors raised by _verify
    try:
        return _verify(msg, addr, sig)
    except Exception:
        return False


def _verify(msg: str, addr: Union[str, bytes], sig: Union[str, bytes]) -> bool:
    # Private function for test/dev purposes
    # It raises Errors, while verify should always return True or False

    sig = base64.b64decode(sig)
    if len(sig) != 65:
        raise ValueError(f"Wrong encoding length: {len(sig)} instead of 65")

    r = int.from_bytes(sig[1:33], 'big')
    s = int.from_bytes(sig[33:], 'big')
    magic_msg = _magic_hash(msg)
    pubkeys = dsa.pubkey_recovery(ec, hf, magic_msg, (r, s))

    # almost any sig/msg pair recovers (a pubkey and) an addr:
    # signature is valid only if the provided addr is matched
    addr = _str_to_bytes(addr)
    rf = int.from_bytes(sig[0:1], 'big')
    if rf < 27 or rf > 42:
        raise ValueError(f"Unknown recovery flag: {rf}")
    elif rf > 38 or addr.startswith(b'bc1'):
        raise ValueError("P2WPKH bech32 address not supported yet")
    elif rf > 34 or addr.startswith(b'3'):
        raise ValueError("P2WPKH-P2SH address not supported yet")
    else:
        # verify that input addr is a valid P2PKH addr
        h160 = _h160_from_address(addr)
        # i selects which key is recovered
        i = (rf - 27) & 3
        if rf < 31:
            return h160 == h160_from_pubkey(pubkeys[i], False)
        else:
            return h160 == h160_from_pubkey(pubkeys[i], True)
