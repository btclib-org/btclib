* open terminal
* setup variables (for an easy installation)
  ```
  $ export BITCOIN=bitcoin-core-0.17.0
  $ export BITCOINPLAIN=`echo $BITCOIN | sed 's/bitcoin-core/bitcoin/'`
  ```
* download relevant files (every time you see _user1_ in the code below, please replace it with your personal username !!!)
  ```
  $ wget https://bitcoin.org/bin/$BITCOIN/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -O ~user1/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz
  ```
* install Bitcoin Core
  ```
  $ /bin/tar xzf ~user1/$BITCOINPLAIN-x86_64-linux-gnu.tar.gz -C ~user1
  $ sudo /usr/bin/install -m 0755 -o root -g root -t /usr/local/bin ~user1/$BITCOINPLAIN/bin/*
  $ /bin/rm -rf ~user1/$BITCOINPLAIN/
  ```
* create the bitcoin working directory
  ```
  $ /bin/mkdir ~user1/.bitcoin
  ```
  Now your bitcoin files are in the .bitcoin directory
- start the daemon in regtest mode:
  ```
  $ bitcoind -regtest -daemon
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
