if not exist "..\bitcoin-data" mkdir "..\bitcoin-data"
"bin\bitcoin-qt.exe" -datadir="..\bitcoin-data" -addresstype=bech32 -walletrbf=1 -regtest -server
