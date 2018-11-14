# Bitcoin Core Setup (Mac-OS)

1. open terminal
2. download Bitcoin Core
  ```
  curl -O https://bitcoin.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-osx64.tar.gz
  ```
3. extract the archive
  ```
  tar -zxf bitcoin-0.17.0.1-osx64.tar.gz
  ```
4. move executables into your default path to make bitcoin daemon running and stopping easily:
  ```
  sudo mkdir -p /usr/local/bin
  sudo cp bitcoin-0.17.0/bin/bitcoin* /usr/local/bin/.
  ```
5. clean up the temporary directory
  ```
  rm -rf bitcoin-0.17.0*
  ```
6. start the Bitcoin Core daemon in regtest mode:
  ```
  bitcoind -regtest -daemon
  ```

You are now ready to start the regtest lab session.

Whenever you want *to start with a fresh new regtest network, remember to clear the regtest data folder* in the bitcoin working folder:
```
cd /Users/your_username/Library/Application Support/Bitcoin
rm -rf regtest
```
