# Security policy

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/btclib/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to _security at btclib dot org_ is
equally welcome.

Much of what btclib does is delegated to
[btclib_libsecp256k1](https://github.com/btclib-org/btclib_libsecp256k1/security/advisories/new)
and, through it, to
[libsecp256k1](https://github.com/bitcoin-core/secp256k1/security/advisories/new)
itself: a vulnerability in the elliptic curve arithmetic, in signing, or
in verification is likely to belong to one of those. Report it wherever
you found it, though — routing it is the maintainers' job, not yours.
