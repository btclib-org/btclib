- Download Bitcoin core directly from the terminal by typing:

  ```
  curl -O https://bitcoin.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-osx64.tar.gz
  ```

- Extract bitcoin daemon and its support binaries from the archive you just downloaded by running this command in Terminal:

  ```
  tar -zxf bitcoin-0.17.0.1-osx64.tar.gz
  ```

- Move the executables into your default path to make bitcoin daemon running and stopping easily:

  ```
  sudo mkdir -p /usr/local/bin
  sudo cp bitcoin-0.17.0.1/bin/bitcoin* /usr/local/bin/.
  ```

- Clean up the directory you have been working in typing:

  ```
  rm -rf bitcoin-0.17.0.1*
  ```

- Now you should be able to run your full node in any terminal window ( regtest mode is now your interest ) simply:

  ```
  bitcoind -regtest -daemon
  ```

- To stop the daemon type:

  ```
  bitcoin-cli -regtest stop
  ```

- For any detail look at the guide here [Mac-os-guide](https://bitcoin.org/en/full-node#mac-os-x-instructions)

- You can find a full bitcoin-cli command list here: [Command List](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_calls_list)

