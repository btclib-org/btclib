- Open Linux terminal

- SETUP variables ( for an easy installation )

  ```
  $ export BITCOIN=bitcoin-core-0.17.0
  $ export BITCOINPLAIN=`echo $BITCOIN | sed 's/bitcoin-core/bitcoin/'`
  ```

- DOWNLOAD relevant files (REMARK: every time you see user1 like in the code below replace it with your personal username !!! )

  ```
  $ wget https://bitcoin.org/bin/$BITCOIN/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -O ~user1/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz
  ```

- Install bitcoin core

  ```
  $ /bin/tar xzf ~user1/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -C ~user1
  $ sudo /usr/bin/install -m 0755 -o root -g root -t /usr/local/bin ~user1/$BITCOINPLAIN/bin/*
  $ /bin/rm -rf ~user1/$BITCOINPLAIN/
  ```

- Create the directory

  ```
  $ /bin/mkdir ~user1/.bitcoin
  ```

  Now your bitcoin files are in .bitcoin directory

- Start the daemon in your terminal easily ( now you are interested in regtest mode ) by typing:

  ```
  $ bitcoind -regtest -daemon
  ```

- To stop the daemon type:

  ```
  $ bitcoin-cli -regtest stop
  ```

- Another types of Linux-based installation are available here [Linux-guide](https://bitcoin.org/en/full-node#linux-instructions)

- You can find a full bitcoin-cli command list here: [Command List](https://en.bitcoin.it/wiki/Original_Bitcoin_client/API_calls_list)

