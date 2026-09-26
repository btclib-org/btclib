A guide by task
===============

The rest of this documentation is the API reference: it answers "what
does this function take". This page answers the question before it,
"which function do I call", and it is arranged by what you want to do
rather than by which module the code lives in.

Every example below is executed by btclib's own test suite, in
``tests/docs_examples_test.py``. What follows a ``>>>`` prompt is what
the library answered, not what somebody expected it to answer, and an
example that stops being true fails a test rather than sitting here
misleading.

.. contents:: On this page
   :local:
   :depth: 1

What btclib does, and what it will not do for you
-------------------------------------------------

btclib is a library about the *cryptography and the encodings* of
bitcoin. Everything on this page happens in your process, offline. In
particular btclib does **not**:

- talk to the network. There is no node, no RPC client, no block
  explorer, no broadcasting. The last example on this page produces a
  fully signed transaction as hex; putting it on the chain is somebody
  else's job (``bitcoin-cli sendrawtransaction``, for instance)
- keep a wallet. Nothing is stored between runs, no key is written to
  disk, no address is remembered as "yours", nothing tracks which of
  your outputs are unspent. When an example below needs the output being
  spent, the example supplies it
- choose coins, estimate a fee, or pick a change amount. A fee is the
  difference between what the inputs are worth and what the outputs are
  worth, and that arithmetic is yours: btclib builds a transaction
  that pays a thousand-bitcoin fee without objection
- protect your secrets from the machine they are on. Read the
  `limitations section of SECURITY.md <security_link.html>`_ before you
  use it with a key that holds value: private keys live in ordinary,
  immutable python objects that are never zeroized, and — the least
  obvious limitation — **not every operation reaches the constant-time
  C library**. With the bindings installed, what you pass decides
  whether a given call does. A curve other than secp256k1 takes the
  pure python path whatever the call; on secp256k1 an operation may
  carry a further condition of its own, and that section gives them.
  The hash function is one of those conditions rather than a second
  absolute: where an operation has one, ``sha256`` itself is what
  counts and ``functools.partial(sha256)`` is not it; where an
  operation has none, hashing with something else leaves the call
  delegated. The pure python path is double-and-add and makes no
  attempt to be constant-time

.. warning::

   Every private key and WIF on this page is either a **published test
   vector**, copied from BIP143 or BIP340 so that you can check btclib's
   answer against the specification itself, or a scalar as small as 1.
   They are known to the whole world. Never send bitcoin to an address derived
   from any of them, and never reuse one for anything real.

Installing
~~~~~~~~~~

.. code-block:: shell

   python -m pip install --upgrade "btclib[secp256k1]"

btclib requires python 3.11 or later. The ``secp256k1`` extra pulls in
``btclib-secp256k1``, and it is the recommended install: it needs one of
that package's wheels or a C toolchain to build it. Plain ``pip install
btclib`` works and installs no C at all — btclib then answers on its own
Python arithmetic, tens of times more slowly and not in constant time,
which ``SECURITY.md`` publishes.

secp256k1 arithmetic is delegated to those bindings, and the delegation
can be turned off. Setting ``BTCLIB_ECC_NO_LIBSECP256K1`` to a
non-empty value in the environment, before btclib is imported, makes
*off* the state the process starts in:

.. code-block:: shell

   BTCLIB_ECC_NO_LIBSECP256K1=1 python your_script.py

:func:`btclib.curves.set_libsecp256k1_serving
<btclib.curves.curve.set_libsecp256k1_serving>` changes it from inside a
running process — including back on, so the variable sets the initial
state rather than locking one — and
:func:`btclib.curves.is_libsecp256k1_serving
<btclib.curves.curve.is_libsecp256k1_serving>` reads the answer back.
Both are one state and not two: what they report is whether the next
call goes to libsecp256k1 or to the Python arithmetic, which is the only
difference a caller can act on.

The Python arithmetic is a second implementation and not a fallback of
convenience: it is slower — tens of times, and ``SECURITY.md`` publishes
that it is not constant-time — and it is what a project must run when it
has to check libsecp256k1 with something that is not libsecp256k1.

.. doctest is the reason the version is asserted loosely: the value
   moves with every release, and pinning it here would make this page
   fail on the release commit rather than on a real defect

>>> import btclib
>>> btclib.__version__.startswith("20")
True

Which type to pass
------------------

Most of the public API takes "anything convertible" rather than one
type, so the rules of the conversion are worth learning first.
There are four aliases, all in :mod:`btclib.alias`, and one rule matters
more than the rest.

**A ``str`` is hexadecimal, not text.** Anywhere the signature says
``Octets`` — a message to sign, a script, a hash — a ``str`` is parsed
with ``bytes.fromhex``. Passing text where hex is expected fails:

>>> from btclib.ecc import dsa
>>> dsa.sign("hello world", 1)
Traceback (most recent call last):
btclib_ecc.exceptions.BTClibEccValueError: invalid hex string: non-hexadecimal number found in fromhex() arg at position 0

Pass ``bytes`` when you mean text, and let the hex spelling be for
things that are bytes:

>>> sig = dsa.sign(b"hello world", 1)
>>> type(sig).__name__
'Sig'

The four aliases:

``Octets = bytes | str | bytearray | memoryview``
    Bytes, or their hex spelling. Blanks inside the hex string are
    allowed, so ``"02 cc71eb30..."`` is fine. Use
    ``btclib.utils.bytes_from_octets`` to normalize one yourself. The
    mutable buffers are here because every consumer takes one: a
    ``memoryview`` sliced out of a larger field is octets like any
    other. That coercion copies it, so writing to a buffer after
    passing it does not reach what btclib built from it.

``String = bytes | str | bytearray | memoryview``
    The same types, read the other way round: here a ``str`` is *text*,
    and this is what addresses, WIFs and extended keys are. The alias a
    function names tells you which reading applies.

``Integer = Octets | int``
    An ``int``, or an ``Octets`` scalar: what a private key is spelled as.
    Neither spelling carries a network or a compressed-public-key flag,
    so everything downstream is told mainnet and compressed, or is told
    otherwise by an argument.

    The two spellings that do carry both are read where they are defined
    (issue #1188). A WIF is ``b58``'s own object,
    ``b58.prv_key_data_from_wif`` reading it and ``b58.wif_from_prv_key``
    building it; an extended key is ``btclib_wallet.bip32``'s, and
    ``btclib_wallet.bip32.prv_keyinfo_from_xprv`` answers the same
    ``(scalar, network, compressed)`` triple from an ``xprv``.
    An address builder takes neither spelling: it takes the public key,
    which ``b58.prv_key_data_from_wif(wif).pub`` and
    ``btclib_wallet.bip32.pub_keyinfo_from_xkey(xkey)`` are the two ways
    to reach.

    **The arithmetic layer reads it with** ``curves.scalar_from_prv_key``,
    and a second name for the same union of types would be nothing a type
    checker could tell apart (issue #1188). It does not take an extended
    key: ``dsa.sign(msg, xprv)`` does not work; pass
    ``btclib_wallet.bip32.prv_keyinfo_from_xprv(xprv)[0]``. ``ecc.bms``
    is narrower still: message signing wants the network and the
    compression too, so it takes the ``btclib.key.PrvKeyData`` a WIF and
    a scalar both resolve to — ``b58.prv_key_data_from_wif(wif)`` for the
    one, ``btclib.key.PrvKeyData(q)`` for the other.

``btclib.key.PubKeyData``
    A public key parsed once and carried: the SEC octets, compressed or
    not, and the network they are read on. It is what ``b58.p2pkh``,
    ``b58.p2wpkh_p2sh``, ``b32.p2wpkh`` and the ``ScriptPubKey``
    constructors take, and a caller says which half of a key pair it
    holds rather than leaving the size and the format to decide
    (issue #1188). ``btclib.key.PrvKeyData(q).pub`` derives it from a
    scalar, ``b58.prv_key_data_from_wif(wif).pub`` from a WIF, and
    ``btclib_wallet.bip32.pub_keyinfo_from_xkey(xkey)`` answers the pair
    a ``PubKeyData`` is built from for an extended key.

>>> from btclib import b58
>>> from btclib.key import PrvKeyData
>>> wif = b58.wif_from_prv_key(1)
>>> wif
'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
>>> b58.p2pkh(b58.prv_key_data_from_wif(wif).pub)
'1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
>>> b58.p2pkh(PrvKeyData(1).pub)
'1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
>>> b58.wif_from_prv_key(1, compressed=False)
'5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'
>>> b58.p2pkh(PrvKeyData(1, compressed=False).pub)
'1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'

The same scalar, two addresses: ``compressed`` is what decides which
public key it derives, and the address follows from that. A WIF carries
that flag, which is why ``prv_key_data_from_wif`` answers it.

Four address flavours
---------------------

Which address a key becomes is a decision separate from the key itself:
one public key has a p2pkh, a p2wpkh-p2sh, a p2wpkh and a p2tr address,
and the address function is what picks. BIP44, BIP49, BIP84 and BIP86
tie the purpose of a derivation path to one of them, and that convention
is ``btclib_wallet.bip44``'s; here the key is given directly.

>>> from btclib import b32
>>> from btclib.script import taproot
>>> pub = PrvKeyData(1).pub
>>> for name, address in [
...     ("p2pkh", lambda k: b58.p2pkh(k)),
...     ("p2wpkh-p2sh", lambda k: b58.p2wpkh_p2sh(k)),
...     ("p2wpkh", lambda k: b32.p2wpkh(k)),
...     ("p2tr", lambda k: b32.p2tr(taproot.output_pubkey(k)[0])),
... ]:
...     print(name, address(pub))
p2pkh 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
p2wpkh-p2sh 3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
p2wpkh bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
p2tr bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9

The taproot one is the odd one out and deliberately so: a BIP86 address
is not the hash of the key but the key *tweaked* by a commitment to an
empty script tree, which ``taproot.output_pubkey`` computes. It returns
the 32-byte x-only output key and the parity bit that spending it needs.

Addresses and the scripts behind them
-------------------------------------

An address is a script in disguise. :class:`btclib.script.script_pub_key.ScriptPubKey`
is the thing itself, and it converts both ways:

>>> from btclib.script.script_pub_key import ScriptPubKey
>>> script_pub_key = ScriptPubKey.from_address(
...     "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu"
... )
>>> script_pub_key.script.hex()
'00146507b03ecb290510ee3a730585f83136b6b466f2'
>>> script_pub_key.type
'p2wpkh'
>>> script_pub_key.asm
['OP_0', '6507B03ECB290510EE3A730585F83136B6B466F2']
>>> script_pub_key.address
'bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu'

The network is carried by the object, so a testnet address decodes to a
testnet script and encodes back to the same address.

Reading a raw transaction
-------------------------

:class:`btclib.tx.tx.Tx` parses the wire format, hex or bytes. The one
below is BIP143's worked example, unsigned:

>>> from btclib.tx import Tx
>>> raw = (
...     "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4"
...     "e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b30"
...     "9fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9"
...     "148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976"
...     "a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000"
... )
>>> tx = Tx.parse(raw)
>>> tx.version
1
>>> tx.lock_time
17
>>> len(tx.vin), len(tx.vout)
(2, 2)

The identifier is a property, and it is reversed on the way out because
that is how bitcoin displays a hash:

>>> tx.id.hex()
'3335ffae0df20c5407e8de12b49405c8e912371f00fe4132bfaf95ad49c40243'
>>> tx.size, tx.vsize, tx.weight
(160, 160, 640)

Watch the parentheses here. ``id``, ``hash``, ``size``, ``vsize``,
``weight`` and ``vwitness`` are properties; ``is_segwit`` and
``is_coinbase`` are methods and need calling. Forgetting the call gives
you a bound method, which is truthy, which is the sort of bug that
passes review:

>>> tx.is_segwit
False

An input names the output it spends. The transaction id inside
``OutPoint`` is stored in wire order, so it reads back reversed from
what a block explorer shows:

>>> tx.vin[0].prev_out.tx_id.hex()
'9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff'
>>> tx.vin[0].prev_out.vout
0
>>> hex(tx.vin[0].sequence)
'0xffffffee'

An output is an amount in satoshi and a script, and the script knows its
own address:

>>> tx.vout[0].value
112340000
>>> tx.vout[0].script_pub_key.type
'p2pkh'
>>> tx.vout[0].script_pub_key.address
'1Cu32FVupVCgHkMMRJdYJugxwo2Aprgk7H'
>>> tx.vout[1].script_pub_key.address
'16TZ8J6Q5iZKBWizWzFAYnrsaox5Z5aBRV'

Serialization is exact — what went in comes back out:

>>> tx.serialize(include_witness=True).hex() == raw
True

``to_dict`` gives the shape ``bitcoin-cli decoderawtransaction`` gives,
which is handy for eyeballing:

>>> sorted(tx.to_dict())
['hash', 'locktime', 'size', 'txid', 'version', 'vin', 'vout', 'vsize', 'weight']

Building a transaction
----------------------

A transaction is four fields, and btclib does not hide any of them.
Amounts are integers in satoshi throughout: there is no float anywhere
in the library, on purpose.

>>> from btclib.tx import OutPoint, TxIn, TxOut
>>> funding = OutPoint(
...     bytes.fromhex(
...         "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef"
...     ),
...     1,
... )
>>> tx_in = TxIn(funding, b"", 0xFFFFFFFF)
>>> tx_out = TxOut.from_address(599000000, "bc1qr583w2swedy2acd7rung055k8t3n7udp7vyzyg")
>>> unsigned = Tx(1, 0, [tx_in], [tx_out])
>>> unsigned.serialize(include_witness=True).hex()
'0100000001ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff01c003b423000000001600141d0f172a0ecb48aee1be1f2687d2963ae33f71a100000000'

There is no fee field. The fee is what the inputs are worth minus what
the outputs are worth, and btclib cannot compute the first half — the
value of an input lives in the *previous* transaction, which is not in
this one. You have to supply it:

>>> prevout = TxOut.from_address(600000000, "bc1qr583w2swedy2acd7rung055k8t3n7udp7vyzyg")
>>> prevout.value - unsigned.vout[0].value
1000000

The hash that gets signed
-------------------------

A signature does not sign the transaction; it signs a hash derived from
it, and *which* hash depends on the script type of the output being
spent, on the sighash flags, and — for segwit — on the amount. Getting
this wrong is the classic way to produce a signature that verifies
against nothing.

:func:`btclib.script.sig_hash.from_tx` is the function to call: give it
the outputs being spent, the transaction, which input, and the hash
type, and it dispatches to the legacy, segwit v0 or taproot rule for
you.

>>> from btclib.script import sig_hash
>>> sig_hash.from_tx([prevout], unsigned, 0, 0x01).hex()
'8feec313e988999f1db646742b8a287269d10706cd086f8cda79aa491cc843af'

Check that it agrees with the specification. BIP143 publishes both the
transaction and the hash for its native-p2wpkh example, so btclib's
answer has something to be right about:

>>> from btclib.script.script_pub_key import ScriptPubKey
>>> bip143_prevouts = [
...     TxOut(
...         625000000,
...         ScriptPubKey(
...             "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac"
...         ),
...     ),
...     TxOut(600000000, ScriptPubKey("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")),
... ]
>>> sig_hash.from_tx(bip143_prevouts, tx, 1, 0x01).hex()
'c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'

That is BIP143's published ``sigHash``. The hash type ``0x01`` is
``SIGHASH_ALL``; ``btclib.script.sig_hash`` names the others
(``NONE``, ``SINGLE``, ``ANYONECANPAY``).

Signing, and checking the result without a node
-----------------------------------------------

The private key below is BIP143's, published in the specification.

>>> prv_key = "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9"
>>> from btclib.curves import scalar_from_prv_key
>>> key = PrvKeyData(scalar_from_prv_key(prv_key))
>>> pub_key = key.pub.sec
>>> pub_key.hex()
'025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'
>>> b32.p2wpkh(key.pub)
'bc1qr583w2swedy2acd7rung055k8t3n7udp7vyzyg'

Sign the hash from the previous section. Note ``sign_``, with the
trailing underscore: throughout btclib that suffix means "the caller has
already reduced the input with the hash function". ``dsa.sign`` would
hash its argument again, which is not what you want here — the sighash
*is* the message.

>>> from btclib.ecc import dsa
>>> msg_hash = sig_hash.from_tx([prevout], unsigned, 0, 0x01)
>>> sig = dsa.sign_(msg_hash, prv_key)
>>> sig.serialize().hex()
'304402207b7dffe084afa0d951726827d8469628e646349e9e6e1d60b76aa91d4a459ff2022003c3fd5ed4795126862efa7bc194d03c76af29741eb36c47659ac39506f2de10'

The nonce is RFC-6979 deterministic, the ``s`` value is the canonical
low one and the ``r`` is ground low as Bitcoin Core grinds it — 70 bytes
of DER rather than 71 — so this signature is the same on every machine
and every run. btclib never invents randomness for an ECDSA signature.

A segwit v0 input is spent with a witness, not with a script_sig: the
DER signature with the hash type appended, then the public key.

>>> from btclib.script.witness import Witness
>>> signed = Tx(1, 0, [TxIn(funding, b"", 0xFFFFFFFF)], [tx_out])
>>> signed.vin[0].script_witness = Witness([sig.serialize() + b"\x01", pub_key])
>>> signed.is_segwit
True
>>> signed.serialize(include_witness=True).hex()
'01000000000101ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff01c003b423000000001600141d0f172a0ecb48aee1be1f2687d2963ae33f71a10247304402207b7dffe084afa0d951726827d8469628e646349e9e6e1d60b76aa91d4a459ff2022003c3fd5ed4795126862efa7bc194d03c76af29741eb36c47659ac39506f2de100121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635700000000'

Now the two identifiers differ, which is what segwit bought: the witness
is not covered by the txid.

>>> signed.id.hex()
'4ebbcec1c2b21740e5e4ffe6aaffe485f6285e7afcbce3130cf34cee05d653c7'
>>> signed.hash.hex()
'3f0a8a5f75909c79c075e7f62333ad7ae2cf05112283225a67202fa6deec4a19'
>>> signed.id == unsigned.id
True
>>> signed.size, signed.vsize, signed.weight
(191, 110, 437)

Finally, do not take your own word for it. btclib ships a script
interpreter, so the transaction can be verified against the outputs it
spends before it goes anywhere near a node:
:func:`btclib.script.engine.verify_transaction` raises on a bad one and
returns ``None`` on a good one.

>>> from btclib.script.engine import verify_transaction
>>> verify_transaction([prevout], signed)

Change one satoshi of the output and the signature no longer covers it.
``TxOut`` is a frozen dataclass, so tampering means building another one
rather than assigning to a field — which is the library saying that an
output you have already signed over is not yours to edit:

>>> tampered = Tx(1, 0, [TxIn(funding, b"", 0xFFFFFFFF)], [TxOut.from_address(
...     599000001, "bc1qr583w2swedy2acd7rung055k8t3n7udp7vyzyg"
... )])
>>> tampered.vin[0].script_witness = signed.vin[0].script_witness
>>> verify_transaction([prevout], tampered)
Traceback (most recent call last):
btclib.exceptions.BTClibValueError: false top stack element

Signatures on their own
-----------------------

The two schemes live in :mod:`btclib.ecc.dsa` (ECDSA, what pre-taproot
bitcoin uses) and :mod:`btclib.ecc.ssa` (BIP340 Schnorr, what taproot
uses). Both come in two spellings, and the difference is the trailing
underscore: ``sign`` hashes its argument for you, ``sign_`` takes the
hash.

ECDSA
~~~~~

>>> from btclib.ecc import dsa
>>> sig = dsa.sign(b"Satoshi Nakamoto", prv_key)
>>> sig.serialize().hex()
'304402204729dbf89f9288d56d32d1aea04db19df37c45c0a02863602f9ad98e7e506ce4022017489be41857144bf5782e964632d254b6b13ea22ce84837f775540784341f43'
>>> dsa.verify(b"Satoshi Nakamoto", pub_key, sig)
True
>>> dsa.verify(b"satoshi nakamoto", pub_key, sig)
False

Verification returns a bool and never raises, which is what you want in
a loop over untrusted input; ``dsa.assert_as_valid`` is the spelling
that raises with a reason, for when you want to know why.

A verifier that has the signature but not the public key can recover it,
which is what makes the 65-byte message signature below shorter than a
key plus a signature. Recovery answers up to four candidate keys, so the
signer has to say which one is theirs: ``dsa.sign_recoverable`` is
``dsa.sign`` with that number beside it — the ``key_id``
``dsa.recover_pub_key`` takes. It costs nothing to ask for: the two bits
are computed by any signer and thrown away by ``sign``.

>>> sig, key_id = dsa.sign_recoverable(b"Satoshi Nakamoto", prv_key)
>>> key_id
1
>>> from btclib.curves import bytes_from_point
>>> recovered = dsa.recover_pub_key(key_id, b"Satoshi Nakamoto", sig)
>>> bytes_from_point(recovered) == pub_key
True

BIP340 Schnorr
~~~~~~~~~~~~~~~

BIP340 keys are x-only: 32 bytes, with the y coordinate implied even.
``gen_keys`` returns the scalar and that x coordinate.

>>> from btclib.ecc import ssa
>>> q, x_Q = ssa.gen_keys(
...     "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF"
... )
>>> x_Q.to_bytes(32, "big").hex().upper()
'DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'

Unlike ECDSA, a BIP340 nonce mixes in auxiliary randomness, so
``ssa.sign`` is **not** deterministic unless you supply the ``aux``
argument. Supplying it is what makes the example below reproducible, and
it is exactly what BIP340's test vector 1 does:

>>> aux = "0000000000000000000000000000000000000000000000000000000000000001"
>>> msg = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89"
>>> sig = ssa.sign_(msg, "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", aux)
>>> sig.serialize().hex().upper()
'6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A'
>>> ssa.verify_(msg, x_Q, sig)
True

That is BIP340's published signature for vector 1. In production leave
``aux`` alone and let ``secrets`` fill it: the randomness is a defence
against fault attacks, and the signature is valid either way.

Signing a message with an address
---------------------------------

:mod:`btclib.ecc.bms` is the "sign this text with the key behind this
address" scheme that wallets expose. It prefixes the message with the
magic string ``"Bitcoin Signed Message:\n"``, signs the hash with ECDSA,
and serializes the result as 65 fixed bytes — a recovery flag, then
``r``, then ``s`` — base64-encoded. The public key is not transmitted:
verification recovers it from the signature and checks that it hashes to
the address.

The message is ``Octets``, so text has to be ``bytes``. It is signed
byte for byte, with no trimming of your own.

>>> from btclib.ecc import bms
>>> wif = b58.wif_from_prv_key(prv_key)
>>> address = b58.p2pkh(b58.prv_key_data_from_wif(wif).pub)
>>> address
'13eeg4y5wYGxNTxBEuWLPFauoMJQLxdoip'
>>> signature = bms.sign(
...     b"paid invoice 42 on 2026-01-01", b58.prv_key_data_from_wif(wif)
... )
>>> signature.b64encode()
'IPn1BZ4xi86uCS5NrSrX+2g+RSsHgm94QX5+krikMl4Fd25te6nrF53iI9amQ5XtAcM4fMggHPybYOxufoR8MVA='
>>> bms.verify(b"paid invoice 42 on 2026-01-01", address, signature)
True
>>> bms.verify(b"paid invoice 43 on 2026-01-01", address, signature)
False

The recovery flag encodes both which of the recovered public keys is the
right one and what kind of address it is; ``31`` to ``34`` mean a
compressed p2pkh key, which Electrum also accepts for p2wpkh and
p2wpkh-p2sh.

>>> signature.rf
32

The whole point of the scheme is proving control of an address, so sign
something that cannot be replayed out of context: a date, a
counterparty, and what the statement is for. The module docstring of
:mod:`btclib.ecc.bms` says the same at more length, and it is worth
reading before you use this for anything that matters.

Where to go next
----------------

- the `README <readme_link.html>`_ lists every feature, and
  `ARCHITECTURE <architecture_link.html>`_ is the fastest way to guess
  where something lives
- `SECURITY.md <security_link.html>`_ has the limitations in full; read
  it before trusting any of this with value
- the API reference under :doc:`PYTHON PACKAGE <modules>` documents
  every module. The docstrings carry the reasoning, not just the
  signatures
- the test suite is the second half of the documentation. ``tests/``
  mirrors ``src/btclib/`` and reproduces the published vectors of the BIPs,
  of RFC 6979 and of Bitcoin Core, so if you want to know exactly what
  btclib promises about something, the test for it is where it is
  written down
