package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/sha3"
)

// EncryptedKeypair is the on-disk/wire representation of a passphrase-encrypted
// keypair, matching the sdk-js keystore record shape.
type EncryptedKeypair struct {
	Address string `json:"address"`
	Nonce   string `json:"nonce"`
	Version *int   `json:"version"`
	Save    string `json:"save"`
}

// PassphraseKey derives the 32-byte secretbox key from a passphrase:
// utf8(hex(sha3_256(passphrase))[0:32]) — i.e. the ASCII bytes of the first
// 32 hex characters of the digest, NOT the raw digest bytes.
func PassphraseKey(passphrase string) [32]byte {
	h := sha3.Sum256([]byte(passphrase))
	hexStr := hex.EncodeToString(h[:]) // 64 chars
	var k [32]byte
	copy(k[:], []byte(hexStr[:32]))
	return k
}

// EncryptKeypair seals PublicKey(32)||SecretKey(64) with nacl secretbox
// (XSalsa20-Poly1305) under the given key and nonce. The nonce must be the
// first 24 ASCII characters of a v4 UUID string, matching sdk-js.
func EncryptKeypair(kp Keypair, address, nonce string, key [32]byte) EncryptedKeypair {
	var n [24]byte
	copy(n[:], []byte(nonce))
	plain := append(append([]byte(nil), kp.PublicKey...), kp.SecretKey...)
	sealed := secretbox.Seal(nil, plain, &n, &key)
	return EncryptedKeypair{
		Address: address,
		Nonce:   nonce,
		Save:    base64.StdEncoding.EncodeToString(sealed),
	}
}

// DecryptKeypair opens a keystore record produced by EncryptKeypair (or by
// sdk-js) and recovers the Keypair.
func DecryptKeypair(e EncryptedKeypair, key [32]byte) (Keypair, error) {
	var n [24]byte
	copy(n[:], []byte(e.Nonce))
	raw, err := base64.StdEncoding.DecodeString(e.Save)
	if err != nil {
		return Keypair{}, err
	}
	plain, ok := secretbox.Open(nil, raw, &n, &key)
	if !ok {
		return Keypair{}, errors.New("keystore: decrypt failed")
	}
	if len(plain) != 96 {
		return Keypair{}, errors.New("keystore: unexpected plaintext length")
	}
	return Keypair{
		PublicKey: plain[:32],
		SecretKey: plain[32:],
	}, nil
}
