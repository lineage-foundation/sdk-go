package crypto

import "crypto/ed25519"

type Keypair struct {
	PublicKey []byte
	SecretKey []byte
}

// KeypairFromSeed creates a keypair from a 32-byte seed.
// SecretKey is 64 bytes: seed(32) || publicKey(32), matching nacl's layout.
func KeypairFromSeed(seed32 []byte) Keypair {
	priv := ed25519.NewKeyFromSeed(seed32)
	return Keypair{
		PublicKey: append([]byte(nil), priv[32:]...),
		SecretKey: priv,
	}
}

// Sign produces a 64-byte detached signature for the given message.
func Sign(message, secretKey64 []byte) []byte {
	return ed25519.Sign(ed25519.PrivateKey(secretKey64), message)
}

// Verify checks the validity of a signature against the message and public key.
func Verify(message, sig, publicKey []byte) bool {
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, sig)
}
