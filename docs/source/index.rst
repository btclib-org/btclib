btclib
======

btclib is a python3 type annotated library intended for teaching and
demonstration of the elliptic curve cryptography used in bitcoin.

It does not have external requirements or dependencies;
to install (and upgrade) it:

```shell
python3 -m pip install --upgrade btclib
```

Originally developed for the
[_Bitcoin and Blockchain Technology Course_](https://www.ametrano.net/bbt/)
at Milano Bicocca and Politecnico di Milano, its algorithms are not intended
for production environments: they could be broken using side-channel attacks;
moreover, they are often refactored without care for backward compatibility.

The library includes:

- modulo algebra functions (gcd, inverse, legendre symbol, square root)
- octets / integer / point conversion functions
- elliptic curve class
  - fast algebra implemented using Jacobian coordinates
  - double scalar multiplication (Straus's algorithm, also known as
    Shamir's trick)
  - multi scalar multiplication (Bos-coster's algorithm)
  - point simmetry solution: odd/even, low/high, and quadratic residue
  - available curves: SEC 1 v1 and v2, NIST, Brainpool, and
    low cardinality test curves
- DSA signature and DER encoding
- Schnorr signature (according to
  [bip-schnorr](https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki)
  bitcoin standardization)
  - batch validation
  - threshold signature (see test-suite)
  - MuSig multi-signature (see test-suite)
- Borromean ring signature
- [RFC 6979](https://tools.ietf.org/html/rfc6979:) to make signature
  schemes deterministic
- Sign-to-contract commitment
- Diffie-Hellman
- Pedersen Committment
- Base58 encoding, addresses, WIFs
- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  hierarchical deterministic wallets
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
  mnemonic code for generating deterministic keys
- [Electrum](https://electrum.org/#home) standard for mnemonic code

A very extensive test suite reproduces results from major official sources and [covers 100%](https://coveralls.io/github/dginst/btclib) of the library code base.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Contents:
---------
.. toctree::
   :maxdepth: 2

   btclib.rst
