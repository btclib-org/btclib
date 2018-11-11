# Bitcoin Core Session (Windows)

1. Download the portable version (zip) of Bitcoin Core: <https://bitcoincore.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-win32.zip>
2. unzip in your favorite location
3. download (save as) the following bat in the unzip folder, at the same level of the bin folder: <https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/regtest.bat>
4. Launch bitcoin core double-clicking the bat file
5. open the console: Help | Debug Window | Console
6. to connect to one node of the network, type `addnode “ipaddress-to-be-comunicated-in-class” “add”`
7. to generate 101 blocks, type `generate 101`

alternatively:
5. open a command prompt in the bin folder (where bitcoin-cli.exe is located)
6. type `bitcoin-cli -regtest addnode “ipaddress-to-be-comunicated-in-class” “add”`
7. type `bitcoin-cli -regtest generate 101`
