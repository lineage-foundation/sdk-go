package sdkgo

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// ConstructTxInOutSignableHash builds the signable hash for a transaction
// input: hex(sha3_256(concat(json.Marshal(txOut) for each output) +
// json.Marshal(prevOut))). prevOut may be nil, in which case it contributes
// the literal bytes "null" to the preimage. This must stay byte-identical to
// sdk-js's construct_tx_in_out_signable_hash, since both the client and the
// server hash the same JSON-encoded preimage.
func ConstructTxInOutSignableHash(prevOut *OutPoint, txOuts []TxOut) string {
	var b strings.Builder
	for _, o := range txOuts {
		j, _ := json.Marshal(o)
		b.Write(j)
	}
	j, _ := json.Marshal(prevOut) // prevOut may be nil -> "null"
	b.Write(j)
	h := sha3.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:])
}

// ConstructSignature signs the UTF-8 bytes of the signable hash's hex string
// (not the raw digest bytes) and returns the resulting signature as hex.
func ConstructSignature(signableHashHex string, secretKey []byte) string {
	sig := crypto.Sign([]byte(signableHashHex), secretKey)
	return hex.EncodeToString(sig)
}

// ConstructItemAssetSignableHash returns hex(sha3_256("Token:"+amount)) for a
// Token asset, or hex(sha3_256("Item:"+amount)) for an Item asset, with the
// amount formatted as a decimal integer.
func ConstructItemAssetSignableHash(a Asset) string {
	prefix := "Token"
	if a.Kind == AssetKindItem {
		prefix = "Item"
	}
	s := fmt.Sprintf("%s:%d", prefix, a.Amount)
	h := sha3.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
