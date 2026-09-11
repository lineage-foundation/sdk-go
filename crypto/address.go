package crypto

import (
	"encoding/hex"

	"golang.org/x/crypto/sha3"
)

// ConstructAddress returns hex(sha3_256(pubKey)); matches sdk-js constructVersionDefaultAddress.
func ConstructAddress(pubKey []byte) string {
	h := sha3.Sum256(pubKey)
	return hex.EncodeToString(h[:])
}
