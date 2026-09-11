package crypto

import (
	"crypto/sha256"

	"github.com/mr-tron/base58"
)

// Base58CheckEncode appends a 4-byte double-SHA256 checksum to payload and
// returns the Base58 encoding of the result.
func Base58CheckEncode(payload []byte) string {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	out := make([]byte, 0, len(payload)+4)
	out = append(out, payload...)
	out = append(out, second[:4]...)
	return base58.Encode(out)
}
