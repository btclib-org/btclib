- open terminal
- download Bitcoin Core
  ```
  curl -O https://bitcoin.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-osx64.tar.gz
  ```
- extract the archive
  ```
  tar -zxf bitcoin-0.17.0.1-osx64.tar.gz
  ```
- move executables into your default path to make bitcoin daemon running and stopping easily:
  ```
  sudo mkdir -p /usr/local/bin
  sudo cp bitcoin-0.17.0.1/bin/bitcoin* /usr/local/bin/.
  ```
- clean up the temporary directory
  ```
  rm -rf bitcoin-0.17.0.1*
  ```
- run Bitcoin Core in regtest mode
  ```
  bitcoind -regtest -daemon
  ```
- to connect to one node of the network  
   ```
   bitcoin-cli -regtest addnode “ipaddress-to-be-comunicated-in-class” “add”
   ```
- to generate 101 blocks  
   ```
   bitcoin-cli -regtest generate 101
   ```
- to stop the daemon:
  ```
  bitcoin-cli -regtest stop
  ```
- in general any command line must starts with `bitcoin-cli -regtest [...]` to use the regtest process

For a [full command list](https://bitcoincore.org/en/doc/0.17.0/):
   ```
   bitcoin-cli -regtest help
   ```

For help about a peculiar command (e.g. [generate](https://bitcoincore.org/en/doc/0.17.0/rpc/generating/generate/)):
   ```
   bitcoin-cli -regtest generate
   ```
