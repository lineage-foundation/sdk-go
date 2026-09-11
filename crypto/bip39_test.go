package crypto

import (
	"encoding/hex"
	"testing"
)

func TestDerivation(t *testing.T) {
	var v struct {
		Mnemonic   string
		Passphrase string
		Xprivkey   string
		Depths     []struct {
			Depth     uint32
			ChildXprv string
			EdSeed32  string
			PublicKey string
			SecretKey string
			Address   string
		}
	}
	load(t, "derivation.json", &v)

	seed := MnemonicToSeed(v.Mnemonic, v.Passphrase)
	master := NewMasterKey(seed)
	if master.Xprv() != v.Xprivkey {
		t.Fatalf("master xprv: got %s want %s", master.Xprv(), v.Xprivkey)
	}

	for _, d := range v.Depths {
		child := master.DeriveHardened(d.Depth)
		if child.Xprv() != d.ChildXprv {
			t.Fatalf("child xprv d=%d: got %s want %s", d.Depth, child.Xprv(), d.ChildXprv)
		}
		edSeed := []byte(child.Xprv())[:32]
		if hex.EncodeToString(edSeed) != d.EdSeed32 {
			t.Fatalf("edSeed d=%d: got %s want %s", d.Depth, hex.EncodeToString(edSeed), d.EdSeed32)
		}
		kp := KeypairFromSeed(edSeed)
		if hex.EncodeToString(kp.PublicKey) != d.PublicKey {
			t.Fatalf("pub d=%d: got %s want %s", d.Depth, hex.EncodeToString(kp.PublicKey), d.PublicKey)
		}
		if hex.EncodeToString(kp.SecretKey) != d.SecretKey {
			t.Fatalf("sec d=%d: got %s want %s", d.Depth, hex.EncodeToString(kp.SecretKey), d.SecretKey)
		}
		if ConstructAddress(kp.PublicKey) != d.Address {
			t.Fatalf("addr d=%d: got %s want %s", d.Depth, ConstructAddress(kp.PublicKey), d.Address)
		}

		// DeriveKeypair convenience wrapper must match too.
		kp2 := DeriveKeypair(v.Mnemonic, v.Passphrase, d.Depth)
		if hex.EncodeToString(kp2.PublicKey) != d.PublicKey {
			t.Fatalf("DeriveKeypair pub d=%d: got %s want %s", d.Depth, hex.EncodeToString(kp2.PublicKey), d.PublicKey)
		}
	}
}
