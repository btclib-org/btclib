# Release notes

All notable changes to this project will be documented in this file.
Release names follow [Calendar Versioning](https://calver.org/):
full year, short month, short day (YYYY-MM-DD)

## current master branch

Major changes includes:

- the usage of DER (de)serialization is advocated through
dsa.(de)serialize, similarly to ssa.(de)serialize
and btcmsg.(de)serialize; therefore, the corresponding
der.py functions have been renamed with leading underscore
- introduced Sig and SigTuple for DSA, BTCMSG, and SSA

## v2020.4.7

This is a major release that complete the far-reaching refactoring
initiated with v2020.3.20; it requires python>=3.8 as we use TypedDict.

Chances are this release might break most projects using btclib,
but the changes were long overdue and should be stable in time.
Functions and modules have been renamed to better reflect
the library design; anyway, because of the clearer logic,
it should not be hard to find the new versions.
The module alias.py might be a good entry point
to familiarize with the new design.

Most notably the library is now able to accept
any representation of private keys as input,
with all the WIF/BIP32/bytes/integer conversion
auto-magically being taken care of.
The same apply to public key BIP32/SEC-bytes/tuple conversion.
As usual, whenever bytes are accepted, hex-string or
text string are accepted too, as appropriate.

Moreover, major changes include:

- updated the Schnorr implementation to BIP340 proposed standard
- refactored BIP32 for increased derivation efficiency
- improved documentation
- extended functional test case coverage (as usual tests cover 100% of the code base)
- removed all mypy warnings (but one)
