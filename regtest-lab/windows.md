# Bitcoin Core Session (Windows)

1. Download the portable version (zip) of Bitcoin Core:  
   <https://bitcoincore.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-win32.zip>
2. unzip in your favorite location; in the following c:\your\bitcoinfolder is where the bin, include, lib, and share folders are located

Bitcoin Coire GUI is nice for a quick and easy start:

3. download (save as) the file regtest.bat in c:\your\bitcoinfolder folder:  
   <https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/regtest.bat>
4. launch Bitcoin Core daemon+GUI double-clicking the regtest.bat file
5. open the console: Help | Debug Window | Console
6. to connect to one node of the network  
   ```
   addnode “ipaddress-to-be-comunicated-in-class” “add”
   ```
6. to generate 101 blocks  
   ```
   generate 101
   ```
7. to stop the GUI just close the process

To really experiment beyond easy commands, a genuine command line experience is better than the GUI. The command line can be used along with the GUI: just skip ponts 3 and 4, start from point 5 below. Else, it can be used as alternative to the GUI, but in this case the Bitcoin Core daemon must be explicitly launched (points 3 e 4 below)

3. open a command prompt and
    - move into the c:\your\bitcoinfolder\bin folder (where bitcoin-cli.exe is located)
    ```
    cd c:\your\bitcoinfolder\bin
    ```
    - alternatively, add c:\your\bitcoinfolder\bin to your %PATH% environment variable (so that whenever you will call the `bitcoin-cli` executable, Windows will know where to find it even if you are not in the c:\your\bitcoinfolder\bin folder)
    ```
    SET PATH=%PATH%;c:\your\bitcoinfolder\bin
    ```
4. create your (blockchain) data folder and launch the Bitcoin Core daemon
   ```
   if not exist "c:\your\bitcoinfolder\bitcoin-data" mkdir "c:\your\bitcoinfolder\bitcoin-data"
   bitcoind -datadir="c:\your\bitcoinfolder\bitcoin-data" -addresstype=bech32 -walletrbf=1 -regtest -server
   ```
5. to connect to one peculiar node of the network  
   ```
   bitcoin-cli -regtest addnode “ipaddress-to-be-comunicated-in-class” “add”
   ```
6. to generate 101 blocks  
   ```
   bitcoin-cli -regtest generate 101
   ```
7. to stop the daemon
  ```
  bitcoin-cli -regtest stop
  ```

In general any command line must starts with `bitcoin-cli -regtest [...]` to use the regtest process. In the GUI environment `bitcoin-cli -regtest` is already assumed and just `[...]` must be typed. For a [full command list](https://bitcoincore.org/en/doc/0.17.0/):
   ```
   bitcoin-cli -regtest help
   ```

For help about a peculiar command (e.g. [generate](https://bitcoincore.org/en/doc/0.17.0/rpc/generating/generate/)):
   ```
   bitcoin-cli -regtest generate
   ```
