# Bitcoin Core Session (Windows)

1. Download the portable version (zip) of Bitcoin Core:  
   <https://bitcoincore.org/bin/bitcoin-core-0.17.0.1/bitcoin-0.17.0.1-win32.zip>
2. unzip in your favorite location
3. download (save as) the file regtest.bat in the unzip folder, at the same level of the bin folder:  
   <https://github.com/dginst/BitcoinBlockchainTechnology/blob/master/regtest-lab/regtest.bat>

Bitcoin Coire GUI is nice for a quick and easy start:

4. Launch Bitcoin Core GUI double-clicking the bat file; then open the console: Help | Debug Window | Console
6. to connect to one node of the network, type  
   `addnode “ipaddress-to-be-comunicated-in-class” “add”`
7. to generate 101 blocks, type  
   `generate 101`
8. in general any command line that starts with `bitcoin-cli -regtest [...]` must be typed in the console as `[...]`, as the leading `bitcoin-cli -regtest` is already assumed in the UX environment

Anyway, the GUI is limited: to really experiment beyond easy commands, a genuine command line experience is better:

5. open a command prompt in the bin folder (where bitcoin-cli.exe is located) or add that folder to your %PATH% environment variable
6. to connect to one node of the network, type  
   `bitcoin-cli -regtest addnode “ipaddress-to-be-comunicated-in-class” “add”`
7. to generate 101 blocks, type  
   `bitcoin-cli -regtest generate 101`
8. in general any command line must starts with `bitcoin-cli -regtest [...]` to use the regtest process
