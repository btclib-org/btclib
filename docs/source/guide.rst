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
  C library**. secp256k1 signing and generator multiplication are
  delegated to the libsecp256k1 bindings; another curve, another hash
  function, a nonce of your own, or a message that is not 32 bytes takes
  the pure python path instead, which is double-and-add and makes no
  attempt to be constant-time

.. warning::

   Every private key, WIF and mnemonic on this page is a **published
   test vector**, copied from BIP39, BIP143 or BIP340 so that you can
   check btclib's answer against the specification itself. They are
   known to the whole world. Never send bitcoin to an address derived
   from any of them, and never reuse one for anything real.

Installing
~~~~~~~~~~

.. code-block:: shell

   python -m pip install --upgrade "btclib[secp256k1]"

btclib requires python 3.10 or later. The ``secp256k1`` extra pulls in
``btclib_secp256k1``, and it is the recommended install: it needs one of
that package's wheels or a C toolchain to build it. Plain ``pip install
btclib`` works and installs no C at all — btclib then answers on its own
Python arithmetic, tens of times more slowly and not in constant time,
which ``SECURITY.md`` publishes.

secp256k1 arithmetic is delegated to those bindings, and the delegation
can be turned off. Setting ``BTCLIB_NO_LIBSECP256K1`` to a non-empty
value in the environment, before btclib is imported, makes *off* the
state the process starts in:

.. code-block:: shell

   BTCLIB_NO_LIBSECP256K1=1 python your_script.py

:func:`btclib.curves.set_libsecp256k1_serving` changes it from inside a
running process — including back on, so the variable sets the initial
state rather than locking one — and
:func:`btclib.curves.is_libsecp256k1_serving` reads the answer back.
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
btclib.exceptions.BTClibValueError: invalid hex string: non-hexadecimal number found in fromhex() arg at position 0

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
    other, and is not copied on its way in.

``String = bytes | str | bytearray | memoryview``
    The same types, read the other way round: here a ``str`` is *text*,
    and this is what addresses, WIFs and extended keys are. The alias a
    function names tells you which reading applies.

``PrvKey``
    An ``int``, an ``Octets`` scalar, a WIF, a BIP32 ``xprv``, or a
    ``BIP32KeyData``. **Prefer the WIF or the extended key.** They carry
    the network and the compressed-public-key flag with them, so
    ``b58.p2pkh(wif)`` knows which address to build; a bare integer
    carries neither and everything downstream has to assume mainnet and
    compressed.

    **This is the bitcoin layer's type, not** ``ecc``\ **'s.** The
    signature schemes take a scalar — an ``int``, its ``n_size`` octets,
    or their hex — because a WIF and an extended key are ``b58``'s and
    ``bip32``'s objects, and converting one is a call you make. So
    ``b58.p2pkh(wif)`` works and ``dsa.sign(msg, wif)`` does not; pass
    ``prv_keyinfo_from_prv_key(wif)[0]``. ``ecc.bms`` is the exception,
    message signing being bitcoin: it still takes the lot.

``Key``
    A public key in any of its spellings — SEC bytes compressed or not,
    an ``(x, y)`` tuple, an ``xpub`` — and also anything that is a
    ``PrvKey``, from which the public key is computed. Convert once with
    ``btclib.to_pub_key.pub_keyinfo_from_key`` if you are about to use
    it repeatedly.

>>> from btclib import b58
>>> wif = b58.wif_from_prv_key(1)
>>> wif
'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn'
>>> b58.p2pkh(wif)
'1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
>>> b58.p2pkh(1)
'1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'
>>> b58.wif_from_prv_key(1, compressed=False)
'5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf'
>>> b58.p2pkh(b58.wif_from_prv_key(1, compressed=False))
'1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm'

The same scalar, three addresses: the WIF is what remembers whether the
public key was compressed, and the address follows from that.

A mnemonic, and the seed underneath it
--------------------------------------

A BIP39 mnemonic is a human-transcribable encoding of some entropy,
with a checksum so that a typo is caught. :mod:`btclib.mnemonic.bip39`
is the whole of it.

To make a fresh one, pass nothing and the operating system's ``secrets``
module supplies the entropy:

>>> from btclib.mnemonic import bip39
>>> words = bip39.mnemonic_from_entropy()
>>> len(words.split())
12

That one is genuinely random, so this page cannot show you its value.
The rest of this section uses BIP39's own first test vector — sixteen
zero bytes — which is why you may recognize it:

>>> mnemonic = bip39.mnemonic_from_entropy(bytes.fromhex("00" * 16))
>>> mnemonic
'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'

Note the ``bytes.fromhex``. ``mnemonic_from_entropy`` takes ``Entropy``,
where a ``str`` is a *binary* ``0``/``1`` string rather than hex, so the
hex spelling has to be decoded first:

>>> bip39.entropy_from_mnemonic(mnemonic)
'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

128 bits, and they round-trip. More entropy means more words: 128 bits
gives 12, 256 bits gives 24.

>>> len(bip39.mnemonic_from_entropy(bytes.fromhex("00" * 32)).split())
24

The checksum is what catches a backup written down wrong, and it is
checked on the way back in:

>>> bip39.entropy_from_mnemonic(mnemonic.replace("about", "abandon"))
Traceback (most recent call last):
btclib.exceptions.BTClibValueError: invalid checksum: 0000; expected: 0011

From mnemonic to seed is PBKDF2 with 2048 iterations, salted with the
string ``"mnemonic"`` and the passphrase:

>>> seed = bip39.seed_from_mnemonic(mnemonic, "TREZOR")
>>> seed.hex()
'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'

That is byte for byte BIP39's published seed for this mnemonic and this
passphrase, which is the point of using a vector.

The passphrase is not a password on the mnemonic: it is an input to the
derivation, so every passphrase yields a different, equally valid
wallet, and there is nothing anywhere that can tell you a passphrase was
wrong.

>>> bip39.seed_from_mnemonic(mnemonic, "").hex()[:32]
'5eb00bbddcf069084889a8ab91555681'
>>> bip39.seed_from_mnemonic(mnemonic, "TREZOR") == seed
True

The root extended private key is the seed run through BIP32, and
``mxprv_from_mnemonic`` does both steps:

>>> rootxprv = bip39.mxprv_from_mnemonic(mnemonic, "TREZOR")
>>> rootxprv
'xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF'

btclib does not store that anywhere. It is a string in your process, and
what happens to it next is entirely yours.

One backup behind many wallets
------------------------------

A second wallet means a second seed, and a second seed means a second
paper backup — which is the part of this that goes wrong. BIP85 removes
the second backup rather than the second wallet: a fully hardened path
off one root key derives the *entropy* another wallet is seeded from, so
what you keep is still one root key. :mod:`btclib.bip85` is that
derivation and the formats the BIP defines on top of it.

The examples here use a key of the BIP's own rather than the
``rootxprv`` above, so the values below are the ones the specification
publishes:

>>> from btclib import bip85
>>> master = "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
>>> bip85.mnemonic_from_root_key(master)
'girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose'

That is a BIP39 mnemonic like any other: type it into any wallet that
reads one. What it is not is random — it is a function of the root key
and the path, so it comes back the same forever, and the index is how
you ask for the next one:

>>> bip85.mnemonic_from_root_key(master, index=1).split()[:3]
['mystery', 'car', 'occur']

The length and the language are path levels too, not formatting:
another word count is another wallet, and so is another language.

>>> len(bip85.mnemonic_from_root_key(master, 24).split())
24
>>> bip85.mnemonic_from_root_key(master, 12, "it").split()[:2]
['smilzo', 'opinione']

A wallet that does not read BIP39 takes one of the other formats: the
WIF is what Bitcoin Core imports as an ``hdseed``, taking the leading
256 bits as a private key, and the xprv is a BIP32 root of its own,
taking all 512 as a chain code and a key.

>>> bip85.wif_from_root_key(master)
'Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'
>>> bip85.xprv_from_root_key(master)[:14]
'xprv9s21ZrQH14'

Not everything derived this way is a wallet. A password is a slice of
the same entropy in base64 or base85, and dice rolls are drawn from a
SHAKE256 stream seeded with it — useful where a die is what a wallet
asks you for, and reproducible where a real die is not:

>>> bip85.base64_password_from_root_key(master, 21)
'dKLoepugzdVJvdL56ogNV'
>>> bip85.rolls_from_root_key(master, 10)
[1, 0, 0, 2, 0, 1, 5, 5, 2, 4]

For a path no function here formats, ``entropy_from_der_path`` is the
derivation itself and the truncation is yours:

>>> bip85.entropy_from_der_path(master, "m/83696968h/0h/0h").hex()[:32]
'efecfbccffea313214232d29e71563d9'

RSA is where the BIP stops rather than btclib: it says a key generator
should read BIP85's own SHAKE256 stream and says nothing about how the
primes are found, so ``rsa_drng_from_root_key`` hands back that stream
and the key belongs to whatever library reads it.

What this costs is worth stating plainly. Every wallet derived here
hangs off the one root key: back it up and you have backed up all of
them; lose it and they go together, none of them being re-derivable
from anything else. A passphrase on the BIP39 mnemonic underneath the
root key is what changes the answer, because it changes the root key
itself.

An account, its xpub, and the addresses under it
------------------------------------------------

:mod:`btclib.bip32.bip32` derives keys along a path. ``derive`` takes an
extended key and a path and hands back another extended key, as a
string:

>>> from btclib import bip32
>>> account = bip32.derive(rootxprv, "m/84h/0h/0h")
>>> xpub = bip32.xpub_from_xprv(account)
>>> xpub
'xpub6Crgkie5Rb7wDabkf4Uf6A2qnuERMA3p2QrnmHNQDrsXTaGvz9zugU38Apne8WqrcbSjdLwbhtfHrzWjNCJPVAkkNoQhMfzhBm8rKMA8KxH'

Paths are case-, blank- and slash-insensitive, and hardening may be
written ``h``, ``H`` or ``'``. The apostrophe is the one from the
specifications and the one that needs escaping in a shell, so ``h`` is
usually the easier spelling:

>>> bip32.derive(rootxprv, "m/84'/0'/0'") == account
True
>>> bip32.derive(rootxprv, [0x80000054, 0x80000000, 0x80000000]) == account
True

The account **xpub** is the useful object: it derives every receiving
and change address of that account and cannot produce a single private
key. That is what you copy onto the machine that watches the balance.

``derive_from_account`` is the two remaining levels, and it refuses the
mistakes that make this dangerous — it insists the account key be
hardened, that the branch be ``0`` (receive) or ``1`` (change), and that
the index be sane:

>>> bip32.derive_from_account(xpub, 0, 0)
'xpub6FoBDgKSsn7RYSaiPAFqm476huu2RpAd2XswekGkmvNDRXvvvuqwSLXg1gvaSby83KTLrFNzXCp1gH4V2JJzMJryGNv7gE2Uk4kd8JXmvEF'
>>> bip32.derive_from_account(xpub, 2, 0)
Traceback (most recent call last):
btclib.exceptions.BTClibValueError: invalid branch number: 2 not in (0, 1)

The four address flavours
~~~~~~~~~~~~~~~~~~~~~~~~~

Which address a key becomes is a separate decision from where the key
came from, and BIP44/49/84/86 are the convention that ties a purpose
number to a script type. btclib does not enforce the tie — you pick the
path, then you pick the address function — but following it is what lets
another wallet find your coins from the same mnemonic.

>>> from btclib import b32, b58
>>> from btclib.script import taproot
>>> for purpose, address in [
...     (44, lambda k: b58.p2pkh(k)),
...     (49, lambda k: b58.p2wpkh_p2sh(k)),
...     (84, lambda k: b32.p2wpkh(k)),
...     (86, lambda k: b32.p2tr(taproot.output_pubkey(k)[0])),
... ]:
...     acct = bip32.xpub_from_xprv(bip32.derive(rootxprv, f"m/{purpose}h/0h/0h"))
...     print(purpose, address(bip32.derive_from_account(acct, 0, 0)))
44 1PEha8dk5Me5J1rZWpgqSt5F4BroTBLS5y
49 3Aho3kS7vgVWKTpRHjcqBoPXiCujiSuTaZ
84 bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu
86 bc1p3ryfth56dp058avv97ppn065ctsk263puvwp4rcka3wpg6cudp9qd3jsuu

The taproot one is the odd one out and deliberately so: a BIP86 address
is not the hash of the key but the key *tweaked* by a commitment to an
empty script tree, which ``taproot.output_pubkey`` computes. It returns
the 32-byte x-only output key and the parity bit that spending it needs.

SLIP-132 version bytes
~~~~~~~~~~~~~~~~~~~~~~

Some wallets label an account key by script type, spelling it ``ypub``
or ``zpub`` instead of ``xpub``. That is SLIP-132, and it changes four
version bytes and nothing else. :mod:`btclib.slip132` takes the
**root** key and does the derivation itself, because the version and the
path have to agree:

>>> from btclib import slip132
>>> bip32.xpub_from_xprv(slip132.p2wpkh_xkey(rootxprv))
'zpub6rXDN3yuixCtvAyzKn3uWLDr8qXKEQ2orduEL5AAysdHZmuPVUL2vbMQDEhp8L9hRsgM8J8idDNPdZjrob8R5e7x7UoYXVdfjDG96TLa7La'
>>> bip32.xpub_from_xprv(slip132.p2wpkh_p2sh_xkey(rootxprv))
'ypub6XRZqAj8R959SPF3UeP8gLsosvY7dskBv68N1rtd6pBwRwvAYJob7XS2VdxawoSdBdNEi32eQatwPBm412BZyfig481iqZKgseAZbdQdmMK'

Hand it something that is not a root key and it says so rather than
guessing:

>>> slip132.p2wpkh_xkey(xpub)
Traceback (most recent call last):
btclib.exceptions.BTClibValueError: not a root key: depth 3, parent fingerprint 0xa40176dc

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
>>> from btclib.to_pub_key import pub_keyinfo_from_prv_key
>>> pub_key = pub_keyinfo_from_prv_key(prv_key)[0]
>>> pub_key.hex()
'025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357'
>>> b32.p2wpkh(prv_key)
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
>>> address = b58.p2pkh(wif)
>>> address
'13eeg4y5wYGxNTxBEuWLPFauoMJQLxdoip'
>>> signature = bms.sign(b"paid invoice 42 on 2026-01-01", wif)
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

Partially signed transactions
-----------------------------

A PSBT (BIP174) is the container that lets an unsigned transaction, the
data needed to sign it, and the signatures themselves travel between
programs that do not trust each other — a watch-only wallet, a hardware
signer, a coordinator. BIP174 describes the work as *roles*, and
:mod:`btclib.psbt.psbt` gives you the data structure for each of them,
not a wallet that plays them.

**Creator.** From an unsigned transaction:

>>> from btclib.psbt import Psbt
>>> psbt = Psbt.from_tx(unsigned)
>>> psbt.b64encode()
'cHNidP8BAFIBAAAAAe9R4bgEzInRgtJ5ZVw6qJ6BWxswn+KH2bK1XVe5DsaKAQAAAAD/////AcADtCMAAAAAFgAUHQ8XKg7LSK7hvh8mh9KWOuM/caEAAAAAAAAA'
>>> len(psbt.inputs), len(psbt.outputs)
(1, 1)

**Updater.** A signer cannot compute a segwit sighash without the amount
being spent, and the amount is not in the transaction, so the updater
puts it in:

>>> psbt.inputs[0].witness_utxo = prevout
>>> psbt.inputs[0].witness_utxo.value
600000000

**Signer.** btclib does not sign a PSBT for you — it has no idea which
keys are yours. What it hands you is the message: ``ecdsa_sig_hash``
reads the utxo and the scripts off the psbt, which is where a psbt keeps
them, and returns the hash the input signs. The signature then goes in
the slot BIP174 defines for it, keyed by public key, with the hash type
appended:

>>> from btclib.psbt import ecdsa_sig_hash
>>> msg_hash = ecdsa_sig_hash(psbt, 0)
>>> der = dsa.sign_(msg_hash, prv_key).serialize()
>>> psbt.inputs[0].partial_sigs = {pub_key: der + b"\x01"}
>>> psbt.assert_signable()

The hash type is the one the input asks for, ``SIGHASH_ALL`` when it
asks for none, and a keyword argument when the signer chooses.
``sig_hash.from_tx`` above cannot serve here: it reads the redeem script
out of an input's script_sig and the witness script off its witness
stack, and an unsigned transaction has neither — in a psbt they are
fields. A taproot input signs ``taproot_sig_hash`` instead, its
signature being schnorr and travelling in the taproot fields rather than
in ``partial_sigs``.

A PSBT survives base64 round-tripping, which is how it moves between
programs:

>>> Psbt.b64decode(psbt.b64encode()) == psbt
True

**Version 2 (BIP370).** In version 2 the unsigned transaction stops
being a field: the transaction version, each input's outpoint and
sequence, and each output's amount and script live in the psbt itself,
which is what lets a *Constructor* add inputs and outputs after the psbt
exists. btclib holds every psbt that way and computes the transaction
from it, so the two versions differ only in how they are written, and
converting is a method each way:

>>> v2 = psbt.to_v2()
>>> v2.version, v2.tx_version, v2.lock_time
(2, 1, 0)
>>> v2.inputs[0].previous_tx_id == psbt.tx.vin[0].prev_out.tx_id
True
>>> v2.tx == psbt.tx
True
>>> v2.to_v0() == psbt
True

``psbt.tx`` is computed from the fields at every access, so writing into
it writes into a copy: to change what is being built, set the field —
``psbt.inputs[0].sequence``, ``psbt.outputs[0].amount``.

A version 2 psbt says what may still be changed, in
``PSBT_GLOBAL_TX_MODIFIABLE``, and btclib honours it: ``sort_inputs``,
``sort_outputs`` and ``join`` refuse to reorder or add on a side
the flags do not allow, since every signature already made commits to
the order it saw:

>>> v2.tx_modifiable = 0
>>> v2.sort_inputs()
Traceback (most recent call last):
btclib.exceptions.BTClibValueError: the inputs are not modifiable

The lock time of a version 2 psbt is computed too, from the lock times
its inputs require and the fallback for when none does — and a psbt
whose inputs require both a block height and a timestamp has no lock
time at all, one ``nLockTime`` being one number of one kind. That is a
psbt btclib refuses rather than resolves.

**Finalizer and Extractor.** ``finalize`` turns the partial
signatures into a final script_sig or witness and ``extract_tx`` pulls
out the network transaction. Be aware of the shape they handle: they
build what BIP174's own vectors need, which are p2sh and p2wsh
multisig, and they do not know that a bare p2wpkh input wants its
signature in the witness rather than in the script_sig. For a
single-key segwit input, build the witness yourself as the previous
section does — two stack items, signature then public key — and use
``verify_transaction`` to check the result.

**A psbt too large to hold.** Everything above reads the whole psbt into
memory first, which for a psbt whose inputs each carry the previous
transaction they spend is all of them at once. ``PsbtView`` reads the same
psbt out of a seekable stream — a file as much as a ``BytesIO`` — and
keeps no map at all: it learns where each one begins and reads one when
it is asked for it.

>>> from io import BytesIO
>>> from btclib.psbt import PsbtView
>>> view = PsbtView(BytesIO(psbt.serialize()))
>>> view.input_count, view.output_count
(1, 1)
>>> view.input(0).witness_utxo.value
600000000
>>> view.ecdsa_sig_hash(0) == msg_hash
True

It is a reader: the stream is never written, so a signer assembles its own
answer out of the maps the view hands it, one ``PsbtIn`` per input signed.

>>> from btclib.psbt import PsbtIn
>>> psbt_in = view.input(0)
>>> psbt_in.partial_sigs = {pub_key: der + b"\x01"}
>>> answer = PsbtIn.parse(psbt_in.serialize())
>>> answer.partial_sigs == psbt.inputs[0].partial_sigs
True

What it holds between calls is in the module docstring of
:mod:`btclib.psbt.psbt_view`, and so is the one rule using it imposes:
the stream must not change while the view is alive. A view answers from
the bytes that were there when it read them, and an amount or a script
that changes between two reads is a sighash committing to a transaction
the signer was never shown — so a psbt on removable or untrusted storage
is copied into memory you control before it is viewed.

Where to go next
----------------

- the `README <readme_link.html>`_ lists every feature, and its module
  layout table is the fastest way to guess where something lives
- `SECURITY.md <security_link.html>`_ has the limitations in full; read
  it before trusting any of this with value
- the API reference under :doc:`PYTHON PACKAGE <modules>` documents
  every module. The docstrings carry the reasoning, not just the
  signatures
- the test suite is the second half of the documentation. ``tests/``
  mirrors ``btclib/`` and reproduces the published vectors of the BIPs,
  of RFC 6979 and of Bitcoin Core, so if you want to know exactly what
  btclib promises about something, the test for it is where it is
  written down
