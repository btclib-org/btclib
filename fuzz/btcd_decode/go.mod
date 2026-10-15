module github.com/btclib-org/btclib/fuzz/btcd_decode

go 1.25.0

toolchain go1.27.1

require (
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.1
)

require (
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
