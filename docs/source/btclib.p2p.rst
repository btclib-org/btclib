btclib.p2p package
==================

Submodules
----------

btclib.p2p.address module
-------------------------

.. automodule:: btclib.p2p.address
   :members:
   :show-inheritance:

btclib.p2p.data module
----------------------

.. automodule:: btclib.p2p.data
   :members:
   :show-inheritance:

btclib.p2p.handshake module
---------------------------

.. automodule:: btclib.p2p.handshake
   :members:
   :show-inheritance:

btclib.p2p.inventory module
---------------------------

.. automodule:: btclib.p2p.inventory
   :members:
   :show-inheritance:

btclib.p2p.keepalive module
---------------------------

.. automodule:: btclib.p2p.keepalive
   :members:
   :show-inheritance:

btclib.p2p.limits module
------------------------

.. automodule:: btclib.p2p.limits
   :members:
   :show-inheritance:

btclib.p2p.magic module
-----------------------

.. All three names are published by the package below as well, so autodoc
   documents each of them twice -- at `btclib.p2p.magic_from_chain` and at
   `btclib.p2p.magic.magic_from_chain`, two cross-reference targets for
   one function. Documented once, under the package, which is where
   `__all__` publishes them and where a caller reaches them.
   `btclib.fetch.bitcoin_core` carries the same stanza for the same
   reason. -W does not fail on this -- the two targets are distinct, so
   nothing is a duplicate description -- which is why the exclusion has to
   be written rather than waited for.

.. automodule:: btclib.p2p.magic
   :members:
   :exclude-members: magic_from_chain, magic_from_network,
       magic_from_signet_challenge
   :show-inheritance:

btclib.p2p.message module
-------------------------

.. automodule:: btclib.p2p.message
   :members:
   :show-inheritance:

btclib.p2p.payload module
-------------------------

.. automodule:: btclib.p2p.payload
   :members:
   :show-inheritance:

Module contents
---------------

.. automodule:: btclib.p2p
   :members:
   :show-inheritance:
