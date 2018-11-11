if not exist "..\bitcoin-data" mkdir "..\bitcoin-data"
"bin\bitcoin-qt.exe" -testnet -datadir="..\bitcoin-data" -addresstype=bech32 -walletrbf=1 -server -rpcallowip=127.0.0.1