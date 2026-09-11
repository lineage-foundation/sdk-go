package crypto

import (
	"encoding/hex"
	"testing"
)

func TestKeystoreInterop(t *testing.T) {
	var v struct {
		Passphrase string
		Plaintext  struct {
			PublicKey string `json:"publicKey"`
			SecretKey string `json:"secretKey"`
			Address   string `json:"address"`
			Version   *int   `json:"version"`
		}
		Encrypted EncryptedKeypair
	}
	load(t, "keystore.json", &v)

	key := PassphraseKey(v.Passphrase)
	kp, err := DecryptKeypair(v.Encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(kp.PublicKey) != v.Plaintext.PublicKey {
		t.Fatalf("pub key mismatch: got %s want %s", hex.EncodeToString(kp.PublicKey), v.Plaintext.PublicKey)
	}
	if hex.EncodeToString(kp.SecretKey) != v.Plaintext.SecretKey {
		t.Fatalf("secret key mismatch: got %s want %s", hex.EncodeToString(kp.SecretKey), v.Plaintext.SecretKey)
	}
}

func TestKeystoreRoundTrip(t *testing.T) {
	kp := Keypair{
		PublicKey: make([]byte, 32),
		SecretKey: make([]byte, 64),
	}
	for i := range kp.PublicKey {
		kp.PublicKey[i] = byte(i)
	}
	for i := range kp.SecretKey {
		kp.SecretKey[i] = byte(i + 1)
	}

	key := PassphraseKey("round-trip-passphrase")
	nonce := "abcdefghijklmnopqrstuvwx" // 24 ASCII bytes
	address := "deadbeef"

	enc := EncryptKeypair(kp, address, nonce, key)
	if enc.Address != address {
		t.Fatalf("address mismatch: got %s want %s", enc.Address, address)
	}
	if enc.Nonce != nonce {
		t.Fatalf("nonce mismatch: got %s want %s", enc.Nonce, nonce)
	}

	dec, err := DecryptKeypair(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(dec.PublicKey) != hex.EncodeToString(kp.PublicKey) {
		t.Fatalf("round-trip pub key mismatch: got %x want %x", dec.PublicKey, kp.PublicKey)
	}
	if hex.EncodeToString(dec.SecretKey) != hex.EncodeToString(kp.SecretKey) {
		t.Fatalf("round-trip secret key mismatch: got %x want %x", dec.SecretKey, kp.SecretKey)
	}
}
