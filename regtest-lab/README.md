# Bitcoin Core - regtest lab session

Please install and run Bitcoin Core for your platform, following the instructions provided in
[windows.md](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows.md),
[linux.md](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/linux.md), or
[mac-os.md](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/mac-os.md).

In general any command line must starts with `bitcoin-cli -regtest [...]` to use the regtest daemon process. In the GUI console environment `bitcoin-cli -regtest` is already assumed and just `[...]` must be typed. 

* connect to one peculiar node of the network  
  ```
  $ bitcoin-cli -regtest addnode “ipaddress-to-be-comunicated-in-class” “add”
  ```
* generate 101 blocks  
  ```
  $ bitcoin-cli -regtest generate 101
  ```
* generate a _legacy_ (non _p2sh-segwit_ or _bech32_) address with the label "used to sign", then use it to sign the message _"Hello, World!"_ with the corresponding private key, finally verify the signature
  ```
  $ bitcoin-cli -regtest getnewaddress "used to sign" legacy
  mzQv9qxgPEdqdm6efXeBJ1ehB199EKC1xy
  
  $ bitcoin-cli -regtest signmessage "mzQv9qxgPEdqdm6efXeBJ1ehB199EKC1xy" "Hello, World!"
  H9Keh3kKLKsGYaXL9oaO+4kwyeDbR0rtftquIyzcv3HeHB2sK2dC2DKYdmOmSYJL7CXPUAlBqR6FxOj7qubYXIM=
  
  $ bitcoin-cli -regtest verifymessage "mzQv9qxgPEdqdm6efXeBJ1ehB199EKC1xy" "H9Keh3kKLKsGYaXL9oaO+4kwyeDbR0rtftquIyzcv3HeHB2sK2dC2DKYdmOmSYJL7CXPUAlBqR6FxOj7qubYXIM=" "Hello, World!"
  true
  ```
* send 0.1 regtest-bitcoins to bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd and inspect the transaction
  ```
  $ bitcoin-cli -regtest sendtoaddress bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd 0.1
  dc5f23588ec02b78481b6bc95fb881ecfd1fabc92e09958ae934bf5130655858
  
  $ bitcoin-cli -regtest gettransaction dc5f23588ec02b78481b6bc95fb881ecfd1fabc92e09958ae934bf5130655858
  {
    "amount": 0.00000000,
    "fee": -0.00003700,
    "confirmations": 1,
    "blockhash": "3f306f189ef845ce0bd41feb6c00b33f11ef98448a2e72fe645ad8505e032fba",
    "blockindex": 1,
    "blocktime": 1541987015,
    "txid": "dc5f23588ec02b78481b6bc95fb881ecfd1fabc92e09958ae934bf5130655858",
    "walletconflicts": [
    ],
    "time": 1541986988,
    "timereceived": 1541986988,
    "bip125-replaceable": "no",
    "details": [
      {
        "address": "bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd",
        "category": "send",
        "amount": -0.10000000,
        "label": "",
        "vout": 0,
        "fee": -0.00003700,
        "abandoned": false
      },
      {
        "address": "bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd",
        "category": "receive",
        "amount": 0.10000000,
        "label": "",
        "vout": 0
      }
    ],
    "hex": "02000000016ccf4ffa7eba319e3bb077c41ee05d622aa27d32110ede5907df612c323448590000000048473044022051dac1e8f4f2ab5e63d5968df23cdf40f9648a168383dd7fe17c1fd89e041a3a022035f8cbdc99a40bc92ef5e4ab6738f2212a001107bf488ffebeee0048118a9d4f01fdffffff028096980000000000160014192aea3e0146509ee76cf5be705329b26d1407140c546a9400000000160014b734587009ecbfd597e24a4c0e28e5cb063dce8bfe000000"
  }
  ```
* stop the daemon (and the GUI) with the command
  ```
  bitcoin-cli -regtest stop
  ```

For a [full command list](https://bitcoincore.org/en/doc/0.17.0/):
  ```
  bitcoin-cli help
  ```

For help about a peculiar command (e.g. [generate](https://bitcoincore.org/en/doc/0.17.0/rpc/generating/generate/)):
  ```
  bitcoin-cli generate
  ```

To go beyond this short lab class, please see <https://github.com/dginst/Learning-Bitcoin-from-the-Command-Line>
