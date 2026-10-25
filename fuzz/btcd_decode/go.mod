module github.com/btclib-org/btclib/fuzz/btcd_decode

go 1.26.10

toolchain go1.27.1

require (
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.2
)

require (
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)
