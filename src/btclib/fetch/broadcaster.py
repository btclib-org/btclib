# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The interface a chain backend answers to announce a transaction.

Kept apart from `Fetcher`: broadcasting is a write and not every backend
that answers `Fetcher`'s questions can perform one --
`BitcoinCoreRestFetcher`, over Core's read-only `-rest` interface, is
exactly that backend, `bitcoin-core-rpc`'s `BitcoinCoreRestClient`
declaring no method that writes. An ABC method here would force a choice
between a `NotImplementedError` on a class that never promised the
capability and a signature every backend has to carry whether or not it
can honour it; a `Protocol` lets `BitcoinCoreFetcher` and `EsploraFetcher`
satisfy `Broadcaster` structurally, with nothing to say about
`BitcoinCoreRestFetcher` at all.

Not `runtime_checkable`. The contract below -- the txid check, the single
request -- is not what `isinstance(x, Broadcaster)` would verify, only
whether something named `broadcast` exists; marking the protocol checkable
would invite exactly that shortcut in place of reading the contract.
"""

from __future__ import annotations

from typing import Protocol

from btclib.tx import Tx

__all__ = ["Broadcaster"]


class Broadcaster(Protocol):
    """A backend able to announce a signed transaction to the network.

    One method and one contract, binding on every implementation of it:

    - the txid is computed from `tx` before the request is sent, and a
      success naming any other txid is refused as a `FetchError` -- the
      backend answered for a transaction that is not the one it was
      asked to broadcast;
    - one request, no retry. After a timeout there is no way to tell a
      transaction that never reached the backend from one that did and
      whose acknowledgement was merely lost in transit, so retrying could
      announce the same signed spend twice for no information gained;
      whether to try again, and how, is the caller's decision, made with
      whatever else it can ask the backend -- this is
      `bitcoin-core-rpc`'s own one-call contract, carried across;
    - a refusal keeps its reason. Whatever the backend answered --
      Core's `RpcError` code and message, an explorer's error body -- it
      reaches the caller through `client_errors`, text intact and not
      reshaped into a code common to every backend, because the two
      refuse for different reasons and a caller acts on the one it got.
    """

    def broadcast(self, tx: Tx) -> bytes:
        """Announce `tx`, and return the txid the backend confirmed."""
        ...
