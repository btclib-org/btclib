# Bitcoin Core - regtest lab session

## Install Bitcoin Core

Please install and run Bitcoin Core for your platform, following the instructions provided in
[windows.md](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows.md),
[linux.md](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/linux.md), or
[mac-os.md](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/mac-os.md).

## The `bitcoin-cli` Command Line Tool

In general any command line must starts with `bitcoin-cli -regtest [...]` to use the _regtest_ daemon process. In the GUI console environment `bitcoin-cli -regtest` is already assumed and can be skipped, typing only the `[...]` part.

* connect to one peculiar node of the network  
  ```
  $ bitcoin-cli -regtest addnode “ipaddress-to-be-comunicated-in-class” “add”
  ```
* generate 101 blocks  
  ```
  $ bitcoin-cli -regtest generate 101
  ```

## Digital Signature Using `bitcoin-cli`

* generate a _legacy_ (non _p2sh-segwit_ or _bech32_) address, optionally labelled with "used to sign", then use it to sign the message _"Hello, World"_ with the corresponding private key, finally verify the signature
  ```
  $ bitcoin-cli -regtest getnewaddress "used to sign" legacy
  mqmgZrj7SiyhzRAuDyoFZLwgfUxFVTZVKh

  $ bitcoin-cli -regtest signmessage "mqmgZrj7SiyhzRAuDyoFZLwgfUxFVTZVKh" "Hello, World"
  INQtUSJsBFe6NIt499uuugBoBypU+bhoWzgU9hp+ZZ6eJiRFU+Ins5erSXI7YqBpeth8NtJAuu/MOOLrJFoFl2I=

  $ bitcoin-cli -regtest verifymessage "mqmgZrj7SiyhzRAuDyoFZLwgfUxFVTZVKh" "INQtUSJsBFe6NIt499uuugBoBypU+bhoWzgU9hp+ZZ6eJiRFU+Ins5erSXI7YqBpeth8NtJAuu/MOOLrJFoFl2I=" "Hello, World"
  true
  ```

## A Simple Bitcoin Transaction

* send 99.0 regtest-bitcoins to bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd and inspect the transaction
  ```
  $ bitcoin-cli -regtest sendtoaddress bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd 99
  66637dc2f33f6917e6e952506037a3cf18f6875e0d883bbb1c3c1d332324d925
  
  $ bitcoin-cli -regtest gettransaction 66637dc2f33f6917e6e952506037a3cf18f6875e0d883bbb1c3c1d332324d925
  {
  "amount": -99.00000000,
  "fee": -0.00005960,
  "confirmations": 1,
  "blockhash": "253b88209ef763acda745b2b70559447dd256f977d50c9b0657751b716125498",
  "blockindex": 1,
  "blocktime": 1541987830,
  "txid": "66637dc2f33f6917e6e952506037a3cf18f6875e0d883bbb1c3c1d332324d925",
  "walletconflicts": [
  ],
  "time": 1541987780,
  "timereceived": 1541987780,
  "bip125-replaceable": "no",
  "details": [
    {
      "address": "bcrt1qry4w50spgegfaemv7kl8q5efkfk3gpc5zvxnrd",
      "category": "send",
      "amount": -99.00000000,
      "vout": 0,
      "fee": -0.00005960,
      "abandoned": false
    }
  ],
  "hex": "0200000002660172d960544e2b0d0a95da6fd8fc12f1511267c86fa30e68416823e3d2f153000000004847304402205ee1882e32eb20615624fb907a33b6711761cae1192f23dfd8b13d662352e50502206fd249e1b1bed074db304a89d65bd34742c16534e30cc81332e32f0a2961002501fdffffff70f35359b2ec08531bf2e94bee6462a61299fefaa7a1ec2b04c4aa11286f8659000000004847304402206a1d0c5794c33cf8be9fe48962d99d0435e85a2bd215921e3e77b23c63ef8df60220513e64431dae450bf7f3d42639fed2ede7eaf9213f87d8307221778399ebda7a01fdffffff020003164e02000000160014192aea3e0146509ee76cf5be705329b26d140714b8c9f50500000000160014eeae5616d5c5fed6b1bdaf8eae235e8b3c34c8a466000000"
  }
  ```
* stop the daemon (and the GUI) with the command
  ```
  bitcoin-cli -regtest stop
  ```

## Further Material

For a [full command list](https://bitcoincore.org/en/doc/0.17.0/):
  ```
  bitcoin-cli help
  ```

For help about a peculiar command (e.g. [generate](https://bitcoincore.org/en/doc/0.17.0/rpc/generating/generate/)):
  ```
  bitcoin-cli generate
  ```

To go beyond this short lab class, please see <https://github.com/dginst/Learning-Bitcoin-from-the-Command-Line>
