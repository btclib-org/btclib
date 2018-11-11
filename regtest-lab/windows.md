# Bitcoin Core Setup (Windows)

1. Download the portable version (zip) of Bitcoin Core:  
   <https://bitcoincore.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-win32.zip>
2. unzip in your favorite location; in the following c:\your\bitcoinfolder is where the bin, include, lib, and share folders are located

Bitcoin Coire GUI is nice for a quick and easy start:

3. download (save as) the file regtest.bat in c:\your\bitcoinfolder folder:  
   <https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/regtest.bat>
4. launch Bitcoin Core daemon+GUI double-clicking the regtest.bat file
5. open the console: Help | Debug Window | Console

To really experiment beyond easy commands, the genuine command line _bitcoin-cli_ is a better experience than the GUI. _bitcoin-cli_ can be used along with the GUI: just jump to point 5 below, skipping points 3 and 4; else, it can be used as alternative to the GUI, but in this case the Bitcoin Core daemon must be explicitly launched (points 3 e 4 below)

3. create your (blockchain) data folder
   ```
   > if not exist "c:\your\bitcoinfolder\bitcoin-data" mkdir "c:\your\bitcoinfolder\bitcoin-data"
   ```
4. start the Bitcoin Core daemon in regtest mode:
   ```
   > c:\your\bitcoinfolder\bin\bitcoind -datadir="c:\your\bitcoinfolder\bitcoin-data" -addresstype=bech32 -walletrbf=1 -regtest -server
   ```
5. open a command prompt and
    - move into the c:\your\bitcoinfolder\bin folder (where bitcoin-cli.exe is located)
    ```
    > cd c:\your\bitcoinfolder\bin
    ```
    - alternatively, better add c:\your\bitcoinfolder\bin to your %PATH% environment variable (so that whenever you will call the `bitcoin-cli` executable, Windows will know where to find it even if you are not in the c:\your\bitcoinfolder\bin folder)
    ```
    > SET PATH=%PATH%;c:\your\bitcoinfolder\bin
    ```

You are now ready to start the regtest lab session.

Whenever you want *to start with a fresh new regtest network, remember to clear the regtest data folder* in the c:\your\bitcoinfolder folder:
```
> cd c:\your\bitcoinfolder
> rmdir regtest /s
```
