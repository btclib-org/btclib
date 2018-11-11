start cmd /k cd bin
bin\bitcoin-qt.exe -regtest -addresstype=bech32 -walletrbf=1 -server -rpcallowip=127.0.0.1
