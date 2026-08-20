btclib.p2p package
==================

Submodules
----------

btclib.p2p.limits module
------------------------

.. automodule:: btclib.p2p.limits
   :members:
   :show-inheritance:

btclib.p2p.magic module
-----------------------

.. `magic_from_chain` and `magic_from_signet_challenge` are re-exported by
   this module and by the package below, and belong to neither: they are
   `bitcoin-core-rpc`'s, and autodoc resolves both names to those same two
   functions. Documented once, under the package, which is where a caller
   reaches them -- without this each is rendered twice, at two
   cross-reference targets, and -W fails the build on the duplicate.
   `btclib.fetch.bitcoin_core` carries the same stanza for the same reason.

.. automodule:: btclib.p2p.magic
   :members:
   :exclude-members: magic_from_chain, magic_from_signet_challenge
   :show-inheritance:

btclib.p2p.message module
-------------------------

.. automodule:: btclib.p2p.message
   :members:
   :show-inheritance:

Module contents
---------------

.. automodule:: btclib.p2p
   :members:
   :show-inheritance:
