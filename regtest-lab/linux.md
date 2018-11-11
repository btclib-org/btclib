# Bitcoin Core Setup (Linux)

1. open terminal
2. export convenience variables (for an easy installation)
  ```
  $ export BITCOIN=bitcoin-core-0.17.0
  $ export BITCOINPLAIN=`echo $BITCOIN | sed 's/bitcoin-core/bitcoin/'`
  ```
3. download relevant files (every time you see _username_ in the code below, please replace it with your personal username)
  ```
  $ wget https://bitcoin.org/bin/$BITCOIN/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -O ~username/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz
  ```
4. install Bitcoin Core
  ```
  $ /bin/tar xzf ~username/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -C ~username
  $ sudo /usr/bin/install -m 0755 -o root -g root -t /usr/local/bin ~username/$BITCOINPLAIN/bin/*
  $ /bin/rm -rf ~username/$BITCOINPLAIN/
  ```
5. create the bitcoin working directory
  ```
  $ /bin/mkdir ~username/.bitcoin
  ```
6. start the Bitcoin Core daemon in regtest mode:
  ```
  $ bitcoind -regtest -daemon
  ```
