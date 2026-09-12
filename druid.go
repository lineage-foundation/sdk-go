package sdkgo

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// GenerateDRUID produces a new DRUID (DDE receipt unique identifier) used to
// correlate the two halves of a two-way trade: "DRUID0x" followed by the
// first 32 hex characters of hex(sha3_256(uuid)), where uuid is a random
// UUIDv4 with its dashes stripped. This matches sdk-js's generateDRUID
// byte-for-byte (the DRUID is a hash of the UUID text, not the UUID's raw
// bytes), except that this SDK draws its randomness from crypto/rand rather
// than a userspace UUID library.
func GenerateDRUID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic(fmt.Sprintf("sdkgo: read random bytes for DRUID: %v", err))
	}
	// Stamp the UUIDv4 version/variant bits (RFC 4122), matching the shape
	// of the uuidv4() library sdk-js draws its randomness from.
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80

	uuidHex := hex.EncodeToString(raw[:])
	h := sha3.Sum256([]byte(uuidHex))
	return "DRUID0x" + hex.EncodeToString(h[:])[:32]
}
