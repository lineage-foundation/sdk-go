//go:build e2e

package sdkgo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// Hosts for the live testnet this e2e drives. Unlike integration_test.go
// (pointed at an arbitrary LINEAGE_TEST_HOST), the two-way swap needs a
// mempool, storage, valence, *and* faucet all backed by the same chain
// state, so these are fixed to the shared Lineage testnet deployment.
const (
	e2eMempoolHost        = "https://mempool.lineage.to"
	e2eStorageHost        = "https://storage.lineage.to"
	e2eValenceHost        = "https://valence.lineage.to"
	e2eMinerHost          = "https://miner.lineage.to"
	e2eDefaultGenesisHash = "default_genesis_hash"
)

func e2eConfig() Config {
	return Config{Mempool: e2eMempoolHost, Storage: e2eStorageHost, Valence: e2eValenceHost}
}

// step runs fn, printing an "ok"/"ERR" line for name, and fails the test
// immediately on error (each later step depends on the wallets/offers
// earlier steps produced).
func step(t *testing.T, name string, fn func() error) {
	t.Helper()
	if err := fn(); err != nil {
		t.Fatalf("  ERR  %-40s %v", name, err)
	}
	t.Logf("  ok   %-40s", name)
}

// fundFromMiner asks the testnet miner's faucet to pay amount Token assets
// to address. This hits the miner's own `POST /v1/payments` faucet route,
// not the general `/v1` API surface this SDK otherwise wraps, so it's a raw
// HTTP call local to this harness rather than a Client/Wallet method.
func fundFromMiner(ctx context.Context, address string, amount int64) error {
	reqBody, err := json.Marshal(struct {
		Kind       string `json:"kind"`
		Address    string `json:"address"`
		Amount     int64  `json:"amount"`
		Passphrase string `json:"passphrase"`
	}{Kind: "address", Address: address, Amount: amount, Passphrase: ""})
	if err != nil {
		return fmt.Errorf("marshal faucet request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e2eMinerHost+"/v1/payments", bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("build faucet request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("faucet request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("faucet POST /v1/payments: status %d", resp.StatusCode)
	}
	return nil
}

// pollBalance polls addr's balance (via w) every 5s, up to 24 tries (~2
// minutes), until want reports satisfied against the resulting
// FetchBalanceResponse.
func pollBalance(ctx context.Context, w *Wallet, addr string, want func(FetchBalanceResponse) bool) (FetchBalanceResponse, error) {
	var last FetchBalanceResponse
	for i := 0; i < 24; i++ {
		r, err := w.FetchBalance(ctx, []string{addr})
		if err != nil {
			return last, err
		}
		last = r
		if want(r) {
			return r, nil
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return last, fmt.Errorf("poll timeout: last balance total=%+v", last.Total)
}

// TestTwoWaySwap_Live drives a full two-wallet, two-way (DRUID) atomic swap
// against the live Lineage testnet: wallet A mints an item and offers it in
// exchange for tokens from wallet B; B accepts; A settles. Both wallets'
// final balances are polled to confirm the swap landed atomically (A ends
// up with the tokens, B ends up with the item).
//
// This funds fresh wallets from the testnet miner faucet and submits real
// transactions, so it only runs with LINEAGE_E2E_WRITE=1 set; it is skipped
// otherwise (including under plain `go test ./...`, which doesn't even
// compile this file, since it's gated by the `e2e` build tag).
//
// Run with:
//
//	LINEAGE_E2E_WRITE=1 go test -tags=e2e -run TestTwoWaySwap_Live -v ./... -timeout 10m
func TestTwoWaySwap_Live(t *testing.T) {
	if os.Getenv("LINEAGE_E2E_WRITE") != "1" {
		t.Skip("set LINEAGE_E2E_WRITE=1 to run the live two-wallet 2-way swap")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	const (
		itemAmount  = 50   // items A mints and offers
		tokenAmount = 100  // tokens B pays and A receives
		fundTokensA = 1000 // just enough for A to exist as a funded address
		fundTokensB = 1000 // must cover tokenAmount
	)

	walletA := NewWallet(e2eConfig())
	walletB := NewWallet(e2eConfig())
	var aKP, bKP crypto.EncryptedKeypair

	t.Log("== wallet A: create, fund, mint item ==")
	step(t, "A: InitNew", func() error {
		_, err := walletA.InitNew("e2e-wallet-a-pass")
		return err
	})
	step(t, "A: GetNewKeypair", func() error {
		var err error
		aKP, err = walletA.GetNewKeypair(nil)
		return err
	})
	step(t, "A: fund from miner", func() error {
		return fundFromMiner(ctx, aKP.Address, fundTokensA)
	})
	step(t, "A: poll funded", func() error {
		_, err := pollBalance(ctx, walletA, aKP.Address, func(r FetchBalanceResponse) bool { return r.Total.Tokens > 0 })
		return err
	})
	step(t, "A: CreateItems", func() error {
		_, err := walletA.CreateItems(ctx, aKP, true, itemAmount, nil)
		return err
	})
	step(t, "A: poll item minted", func() error {
		_, err := pollBalance(ctx, walletA, aKP.Address, func(r FetchBalanceResponse) bool {
			return r.Total.Items[e2eDefaultGenesisHash] >= itemAmount
		})
		return err
	})

	t.Log("== wallet B: create, fund with tokens ==")
	step(t, "B: InitNew", func() error {
		_, err := walletB.InitNew("e2e-wallet-b-pass")
		return err
	})
	step(t, "B: GetNewKeypair", func() error {
		var err error
		bKP, err = walletB.GetNewKeypair(nil)
		return err
	})
	step(t, "B: fund from miner", func() error {
		return fundFromMiner(ctx, bKP.Address, fundTokensB)
	})
	step(t, "B: poll funded", func() error {
		_, err := pollBalance(ctx, walletB, bKP.Address, func(r FetchBalanceResponse) bool { return r.Total.Tokens >= tokenAmount })
		return err
	})

	t.Log("== A: Make2WayPayment (offer item, want tokens) ==")
	var half PendingHalf
	step(t, "A: Make2WayPayment", func() error {
		var err error
		half, err = walletA.Make2WayPayment(
			ctx,
			bKP.Address,
			NewItemAsset(itemAmount, e2eDefaultGenesisHash, nil), // sendingAsset: A's item
			NewTokenAsset(tokenAmount),                           // receivingAsset: tokens A wants
			[]crypto.EncryptedKeypair{aKP},
			aKP,
		)
		return err
	})

	t.Log("== B: FetchPending2WayPayment sees the offer, then Accept2WayPayment ==")
	var offer Pending2WTxDetails
	step(t, "B: FetchPending2WayPayment (sees offer)", func() error {
		pending, _, err := walletB.FetchPending2WayPayment(ctx, nil, []crypto.EncryptedKeypair{bKP})
		if err != nil {
			return err
		}
		d, ok := pending[half.Druid]
		if !ok {
			return fmt.Errorf("B did not see A's offer for druid %s (pending=%+v)", half.Druid, pending)
		}
		offer = d
		return nil
	})
	step(t, "B: Accept2WayPayment", func() error {
		return walletB.Accept2WayPayment(ctx, offer, []crypto.EncryptedKeypair{bKP})
	})

	t.Log("== A: FetchPending2WayPayment second pass settles the swap ==")
	step(t, "A: FetchPending2WayPayment (settle)", func() error {
		pending, settled, err := walletA.FetchPending2WayPayment(ctx, []PendingHalf{half}, []crypto.EncryptedKeypair{aKP})
		if err != nil {
			return err
		}
		for _, d := range settled {
			if d == half.Druid {
				return nil
			}
		}
		return fmt.Errorf("druid %s was not settled (settled=%v, pending=%+v)", half.Druid, settled, pending)
	})

	t.Log("== poll final balances: A should hold the tokens, B should hold the item ==")
	var finalA, finalB FetchBalanceResponse
	step(t, "A: poll tokens landed", func() error {
		var err error
		finalA, err = pollBalance(ctx, walletA, aKP.Address, func(r FetchBalanceResponse) bool { return r.Total.Tokens >= tokenAmount })
		return err
	})
	step(t, "B: poll item landed", func() error {
		var err error
		finalB, err = pollBalance(ctx, walletB, bKP.Address, func(r FetchBalanceResponse) bool {
			return r.Total.Items[e2eDefaultGenesisHash] >= itemAmount
		})
		return err
	})

	t.Logf("FINAL A tokens=%d items=%v", finalA.Total.Tokens, finalA.Total.Items)
	t.Logf("FINAL B tokens=%d items=%v", finalB.Total.Tokens, finalB.Total.Items)

	if finalA.Total.Tokens < tokenAmount {
		t.Errorf("A: expected >= %d tokens after the swap, got %d", tokenAmount, finalA.Total.Tokens)
	}
	if finalB.Total.Items[e2eDefaultGenesisHash] < itemAmount {
		t.Errorf("B: expected >= %d items after the swap, got %d", itemAmount, finalB.Total.Items[e2eDefaultGenesisHash])
	}
}
