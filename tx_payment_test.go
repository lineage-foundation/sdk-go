package sdkgo

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// TestCreatePaymentTx is the load-bearing test for Task 8: CreatePaymentTx
// must replicate sdk-js's createPaymentTx byte-for-byte, given the same
// balance/keypairs/payment parameters captured in payment.json.
func TestCreatePaymentTx(t *testing.T) {
	var v struct {
		FetchBalanceResponse FetchBalanceResponse `json:"fetchBalanceResponse"`
		PaymentAddress       string               `json:"paymentAddress"`
		PaymentAsset         Asset                `json:"paymentAsset"`
		ExcessAddress        string               `json:"excessAddress"`
		Locktime             int                  `json:"locktime"`
		SenderAddress        string               `json:"senderAddress"`
		SenderPublicKey      string               `json:"senderPublicKey"`
		CreateTxPayload      struct {
			CreateTx json.RawMessage `json:"createTx"`
		} `json:"createTxPayload"`
	}
	loadVector(t, "payment.json", &v)

	var derivation struct {
		Depths []struct {
			PublicKey string `json:"publicKey"`
			SecretKey string `json:"secretKey"`
			Address   string `json:"address"`
		} `json:"depths"`
	}
	loadVector(t, "derivation.json", &derivation)

	var senderSecretKeyHex string
	for _, d := range derivation.Depths {
		if d.PublicKey == v.SenderPublicKey && d.Address == v.SenderAddress {
			senderSecretKeyHex = d.SecretKey
			break
		}
	}
	if senderSecretKeyHex == "" {
		t.Fatalf("no derivation.json entry matches senderPublicKey/senderAddress from payment.json")
	}

	keyPairs := map[string]crypto.Keypair{
		v.SenderAddress: {
			PublicKey: mustHexDecode(t, v.SenderPublicKey),
			SecretKey: mustHexDecode(t, senderSecretKeyHex),
		},
	}

	tx, err := CreatePaymentTx(v.PaymentAddress, v.PaymentAsset, v.ExcessAddress, v.FetchBalanceResponse, keyPairs, v.Locktime)
	if err != nil {
		t.Fatalf("CreatePaymentTx: %v", err)
	}

	got, err := json.Marshal(tx)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	var wantBuf bytes.Buffer
	if err := json.Compact(&wantBuf, v.CreateTxPayload.CreateTx); err != nil {
		t.Fatalf("compact want: %v", err)
	}
	want := wantBuf.Bytes()

	if !bytes.Equal(got, want) {
		i := 0
		for i < len(got) && i < len(want) && got[i] == want[i] {
			i++
		}
		t.Fatalf("createTx mismatch at byte offset %d:\n got:  %s\n want: %s", i, got, want)
	}
}
