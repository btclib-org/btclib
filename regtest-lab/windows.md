# Bitcoin Core Setup (Windows)

1. Download the portable version (zip) of Bitcoin Core:  
   <https://bitcoincore.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-win32.zip>
2. unzip it in your favorite location; in the following `c:\your\bitcoinfolder` is where the `bin`, `include`, `lib`, and `share` folders are located
3. add the `c:\your\bitcoinfolder\bin folder` (the one including the `bitcoinqt`, `bitcoind`, and `bitcoin-cli` executables) to your %PATH% environment variable, so that whenever you will call the bitcoin executables, Windows will know where to find them even if you are not in the `c:\your\bitcoinfolder\bin` folder. You can do this permanently, or for each command prompt window 
    ```
    > ECHO %PATH%
    > SET PATH=%PATH%;c:\your\bitcoinfolder\bin
    > ECHO %PATH%
    ```
4. open a command prompt window (with the `c:\your\bitcoinfolder\bin` augmented PATH) and start the Bitcoin Core GUI+deamon in regtest mode:
   ```
   > bitcoinqt -regtest -addresstype=bech32 -walletrbf=1 -server -rpcallowip=127.0.0.1
   ```
5. in the GUI open the console (Help | Debug Window | Console) type
   ```
   getblockcount
   ```
6. to really experiment beyond easy commands, the genuine command line `bitcoin-cli` is a better experience than using the GUI console. `bitcoin-cli` can be used along with the GUI just opening another command prompt window (with the `c:\your\bitcoinfolder\bin` augmented PATH) and using it, e.g.:
    ```
    > bitcoin-cli -regtest getblockcount
    ```

You should now be ready to start the regtest lab session.

Whenever you want *to start with a fresh new regtest network, remember to clear the regtest data folder* that has been created in the `%APPDATA%\Bitcoin\regtest` folder:
```
> rmdir %APPDATA%\Bitcoin\regtest /s /q
```

For convenience the
[windows-regtest-18444-start.bat](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows-regtest-18444-start.bat)
and
[windows-regtest-18444-reset.bat](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows-regtest-18444-reset.bat)
batch files are provided to respectively launch and reset the regtest network, without tweaking with the %PATH% environment variable: just put the batch files in `c:\your\bitcoinfolder`.

One can start multiple nodes, as separate instances of the bitcoin GUI+deamon, on the same machine: each node must use a different p2p port and data folder to avoid conflicts. For convenience the
[windows-regtest-18555-start.bat](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows-regtest-18555-start.bat)
and
[windows-regtest-18555-reset.bat](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows-regtest-18555-reset.bat)
batch files are provided to respectively launch and reset Alice's node,
while
[windows-regtest-18666-start.bat](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows-regtest-18666-start.bat)
and
[windows-regtest-18666-reset.bat](https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/windows-regtest-18666-reset.bat)
batch files are provided to launch and reset Bob's node. Every node (server 18444, Alice 18555, and Bob 18666) has its own wallet and can interact with the other nodes generating blocks which are broadcasted to the network and sending/receiving regtest-bitcoins.

