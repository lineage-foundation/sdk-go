# Lineage Go SDK

Go SDK for the Lineage `/v1` REST API: a keyless read `Client` and a key-holding `Wallet` that signs transactions locally.

## Installation

```bash
go get github.com/lineage-foundation/sdk-go
```

## Configuration

```go
sdkgo.Config{
	Mempool: "https://mempool.lineage.to", // required
	Storage: "https://storage.lineage.to", // required
	Valence: "https://valence.lineage.to", // optional, needed for two-way payments
	APIKey:  "",                           // optional, sent as x-api-key
}
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"

	sdkgo "github.com/lineage-foundation/sdk-go"
	"github.com/lineage-foundation/sdk-go/crypto"
)

func main() {
	ctx := context.Background()

	w := sdkgo.NewWallet(sdkgo.Config{
		Mempool: "https://mempool.lineage.to",
		Storage: "https://storage.lineage.to",
	})

	// Generate a fresh BIP39 mnemonic; persist masterKeyEncrypted and reopen
	// later with w.FromMasterKey(masterKeyEncrypted, passphrase).
	masterKeyEncrypted, err := w.InitNew("a secure passphrase")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("master key:", masterKeyEncrypted)

	kp, err := w.GetNewKeypair(nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("address:", kp.Address)

	balance, err := w.FetchBalance(ctx, []string{kp.Address})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("balance: %+v\n", balance)

	// Send 100 Token assets, sourcing inputs from kp and returning change to kp.
	resp, err := w.MakeTokenPayment(ctx, "recipient-address", 100, []crypto.EncryptedKeypair{kp}, kp, 0)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("payment: %+v\n", resp)
}
```

`Wallet` embeds `*Client`, so every read method (`Supply`, `Balances`, `TransactionStatus`, `LatestBlock`, `BlockByNum`, `BlockchainEntry`, `SerializeTransactions`, `DeserializeTransactions`, ...) is available directly on a `Wallet` too. Use a bare `sdkgo.NewClient(cfg)` for read-only use cases that never sign anything.

## Two-way (DRUID) payments

A two-way payment is an atomic swap between two parties, brokered through [Valence](https://github.com/lineage-foundation/valence), a plaintext message-relay service that exchanges trade offers/acceptances but never sees keys or signs anything.

```go
half, err := walletA.Make2WayPayment(ctx, bAddress,
	sdkgo.NewItemAsset(50, "default_genesis_hash", nil), // A sends 50 items
	sdkgo.NewTokenAsset(100),                             // A wants 100 tokens back
	[]crypto.EncryptedKeypair{aItemKeypair}, aReceiveKeypair)
// persist half (keyed by half.Druid) until it settles

// ...on B's side, out of band:
pending, _, err := walletB.FetchPending2WayPayment(ctx, nil, []crypto.EncryptedKeypair{bKeypair})
offer := pending[half.Druid]
err = walletB.Accept2WayPayment(ctx, offer, []crypto.EncryptedKeypair{bKeypair})

// ...back on A's side, a later poll settles it:
_, settled, err := walletA.FetchPending2WayPayment(ctx, []sdkgo.PendingHalf{half}, []crypto.EncryptedKeypair{aReceiveKeypair})
// settled now contains half.Druid; A holds the tokens, B holds the item.
```

Two-way trades interoperate across all the SDKs and settle atomically through the mempool's DRUID pool, so either party can be on any SDK.

See `twoway_e2e_test.go` (build-tagged `e2e`) for a complete two-wallet live example.

## Wire compatibility

Keys and signatures are byte-for-byte compatible across every Lineage SDK — a wallet (mnemonic) created in one derives the same addresses and produces the same signatures in all of them. sdk-js is the reference implementation; BIP39/BIP32 derivation, SHA3-256 addresses, ed25519 signing, and the `/v1` transaction serialization (field order is load-bearing — you sign exactly what you submit) all match it exactly. This is enforced by golden test vectors in `internal/testvectors/*.json`, generated from sdk-js's own crypto primitives (see `internal/vectorgen/README.md`); this SDK never depends on sdk-js at build or run time.

## Testing

```bash
go test ./...                        # unit tests (fast, no network)
go test -tags=integration ./...      # + wire-compat integration test against a live node, needs LINEAGE_TEST_HOST
go test -tags=e2e ./...              # + two-way live e2e, needs LINEAGE_E2E_WRITE=1 to write
go vet ./...
```

## Lineage SDKs

- [JavaScript / TypeScript](https://github.com/lineage-foundation/sdk-js)
- [Python](https://github.com/lineage-foundation/sdk-python)
- [Go](https://github.com/lineage-foundation/sdk-go)
- [Rust](https://github.com/lineage-foundation/sdk-rust)
- [PHP](https://github.com/lineage-foundation/sdk-php)
- [Laravel](https://github.com/lineage-foundation/sdk-laravel)

## License

MIT — see [LICENSE](LICENSE).
