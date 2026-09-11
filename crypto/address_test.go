package crypto

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestConstructAddress(t *testing.T) {
	b, _ := os.ReadFile("../internal/testvectors/derivation.json")
	var v struct {
		Depths []struct {
			PublicKey string
			Address   string
		}
	}
	json.Unmarshal(b, &v)
	for _, d := range v.Depths {
		pub, _ := hex.DecodeString(d.PublicKey)
		if got := ConstructAddress(pub); got != d.Address {
			t.Fatalf("addr: got %s want %s", got, d.Address)
		}
	}
}
