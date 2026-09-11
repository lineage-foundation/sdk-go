package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func load(t *testing.T, file string, v interface{}) {
	b, err := os.ReadFile("../internal/testvectors/" + file)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

func TestSignMessage(t *testing.T) {
	var v struct {
		Seed32       string
		PublicKey    string
		Message      string
		SignatureHex string
	}
	load(t, "signing.json", &v)
	seed, _ := hex.DecodeString(v.Seed32)
	kp := KeypairFromSeed(seed)
	if hex.EncodeToString(kp.PublicKey) != v.PublicKey {
		t.Fatalf("pub key mismatch: got %s want %s", hex.EncodeToString(kp.PublicKey), v.PublicKey)
	}
	sig := Sign([]byte(v.Message), kp.SecretKey)
	if hex.EncodeToString(sig) != v.SignatureHex {
		t.Fatalf("sig mismatch: got %s want %s", hex.EncodeToString(sig), v.SignatureHex)
	}
	if !Verify([]byte(v.Message), sig, kp.PublicKey) {
		t.Fatal("verify failed")
	}
}
