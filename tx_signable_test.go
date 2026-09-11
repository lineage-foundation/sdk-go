package sdkgo

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

func loadVector(t *testing.T, file string, v interface{}) {
	t.Helper()
	b, err := os.ReadFile("internal/testvectors/" + file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func mustHexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSignableHashAndSig is the load-bearing test for Task 7: the transaction
// signable hash and signature must match sdk-js and the server byte-for-byte.
func TestSignableHashAndSig(t *testing.T) {
	var v struct {
		OutPoint       OutPoint `json:"outPoint"`
		TxOuts         []TxOut  `json:"txOuts"`
		SignableHash   string   `json:"signableHash"`
		SignatureHex   string   `json:"signatureHex"`
		AssetTokenHash string   `json:"assetTokenHash"`
		AssetItemHash  string   `json:"assetItemHash"`
	}
	loadVector(t, "signable.json", &v)

	var signing struct {
		Seed32 string `json:"seed32"`
	}
	loadVector(t, "signing.json", &signing)

	if got := ConstructTxInOutSignableHash(&v.OutPoint, v.TxOuts); got != v.SignableHash {
		t.Fatalf("hash: got %s want %s", got, v.SignableHash)
	}

	kp := crypto.KeypairFromSeed(mustHexDecode(t, signing.Seed32))
	if got := ConstructSignature(v.SignableHash, kp.SecretKey); got != v.SignatureHex {
		t.Fatalf("sig: got %s want %s", got, v.SignatureHex)
	}

	if got := ConstructItemAssetSignableHash(NewTokenAsset(1000)); got != v.AssetTokenHash {
		t.Fatalf("token asset hash: got %s want %s", got, v.AssetTokenHash)
	}
}
