if not exist "..\bitcoin-data" mkdir "..\bitcoin-data"
if not exist "..\bitcoin-data\_Alice" mkdir "..\bitcoin-data\_Alice"
"bin\bitcoin-qt.exe" -regtest -datadir="..\bitcoin-data\_Alice" -addresstype=bech32 -walletrbf=1 -port=18555 -addnode=localhost:18444
