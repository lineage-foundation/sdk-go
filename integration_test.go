//go:build integration

package sdkgo

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// TestSerializeDeserialize_WireCompat is a wire-compatibility check against a
// live node: it builds the same payment transaction as
// TestMakeTokenPayment_MatchesVector (from payment.json's fixed
// balance/keypair scenario), POSTs it to `POST /v1/transactions:serialize`,
// then feeds the resulting hex back to `POST /v1/transactions:deserialize`,
// and asserts the round trip returns an equivalent CreateTransaction.
//
// Requires a live node: set LINEAGE_TEST_HOST to a mempool-capable node's
// base URL (e.g. http://localhost:3000) to run this test. It is skipped
// otherwise.
//
// Run with: go test -tags=integration ./...
func TestSerializeDeserialize_WireCompat(t *testing.T) {
	host := os.Getenv("LINEAGE_TEST_HOST")
	if host == "" {
		t.Skip("set LINEAGE_TEST_HOST to run")
	}

	var v struct {
		FetchBalanceResponse FetchBalanceResponse `json:"fetchBalanceResponse"`
		PaymentAddress       string               `json:"paymentAddress"`
		PaymentAsset         Asset                `json:"paymentAsset"`
		ExcessAddress        string               `json:"excessAddress"`
		Locktime             int                  `json:"locktime"`
		SenderAddress        string               `json:"senderAddress"`
		SenderPublicKey      string               `json:"senderPublicKey"`
	}
	loadVector(t, "payment.json", &v)

	_, _, senderSecretKeyHex, _ := findDerivationEntry(t, v.SenderPublicKey, v.SenderAddress)

	senderKp := crypto.Keypair{
		PublicKey: mustHexDecode(t, v.SenderPublicKey),
		SecretKey: mustHexDecode(t, senderSecretKeyHex),
	}
	keyPairs := map[string]crypto.Keypair{v.SenderAddress: senderKp}

	tx, err := CreatePaymentTx(v.PaymentAddress, v.PaymentAsset, v.ExcessAddress, v.FetchBalanceResponse, keyPairs, v.Locktime)
	if err != nil {
		t.Fatalf("CreatePaymentTx: %v", err)
	}

	c := NewClient(Config{Mempool: host, Storage: host})
	ctx := context.Background()

	serResp, err := c.SerializeTransactions(ctx, []CreateTransaction{tx})
	if err != nil {
		t.Fatalf("SerializeTransactions: %v", err)
	}
	if len(serResp.Transactions) != 1 {
		t.Fatalf("SerializeTransactions: got %d transactions, want 1", len(serResp.Transactions))
	}
	txHex := serResp.Transactions[0].TxnHex
	if txHex == "" {
		t.Fatal("SerializeTransactions: empty txn_hex in response")
	}

	deResp, err := c.DeserializeTransactions(ctx, []string{txHex})
	if err != nil {
		t.Fatalf("DeserializeTransactions: %v", err)
	}
	if len(deResp.Transactions) != 1 {
		t.Fatalf("DeserializeTransactions: got %d transactions, want 1", len(deResp.Transactions))
	}

	got := deResp.Transactions[0]
	if !reflect.DeepEqual(got, tx) {
		t.Fatalf("round-tripped transaction differs from the original:\n got:  %+v\n want: %+v", got, tx)
	}
}
