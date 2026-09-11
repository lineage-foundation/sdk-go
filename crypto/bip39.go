package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/text/unicode/norm"
)

// mainnetXprvVersion is bitcore's mainnet BIP32 private version bytes (0x0488ADE4).
const mainnetXprvVersion uint32 = 0x0488ADE4

// MnemonicToSeed derives the 64-byte BIP39 seed:
// PBKDF2(HMAC-SHA512, NFKD(mnemonic), "mnemonic"+NFKD(passphrase), 2048, 64).
func MnemonicToSeed(mnemonic, passphrase string) []byte {
	m := norm.NFKD.String(mnemonic)
	p := "mnemonic" + norm.NFKD.String(passphrase)
	return pbkdf2.Key([]byte(m), []byte(p), 2048, 64, sha512.New)
}

// ExtKey is a BIP32 extended private key.
type ExtKey struct {
	version   uint32
	depth     uint8
	parentFP  [4]byte
	childNum  uint32
	chainCode [32]byte
	key       [32]byte
}

// NewMasterKey builds the BIP32 master key from a 64-byte seed using the
// "Bitcoin seed" HMAC key, with bitcore's mainnet private version.
func NewMasterKey(seed64 []byte) *ExtKey {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed64)
	I := mac.Sum(nil)

	k := &ExtKey{version: mainnetXprvVersion, depth: 0, childNum: 0}
	copy(k.key[:], I[:32])
	copy(k.chainCode[:], I[32:])
	return k
}

// compressedPubKey returns the 33-byte compressed secp256k1 public key for the
// extended key's private key.
func (k *ExtKey) compressedPubKey() []byte {
	priv := secp256k1.PrivKeyFromBytes(k.key[:])
	return priv.PubKey().SerializeCompressed()
}

// DeriveHardened performs BIP32 CKDpriv with a hardened index (index|0x80000000).
func (k *ExtKey) DeriveHardened(index uint32) *ExtKey {
	i := index | 0x80000000

	data := make([]byte, 0, 1+32+4)
	data = append(data, 0x00)
	data = append(data, k.key[:]...)
	var ser [4]byte
	binary.BigEndian.PutUint32(ser[:], i)
	data = append(data, ser[:]...)

	mac := hmac.New(sha512.New, k.chainCode[:])
	mac.Write(data)
	I := mac.Sum(nil)

	// childKey = (I[:32] + parentKey) mod n
	var il, pk secp256k1.ModNScalar
	il.SetByteSlice(I[:32])
	pk.SetByteSlice(k.key[:])
	il.Add(&pk)
	childKeyBytes := il.Bytes()

	child := &ExtKey{
		version:  k.version,
		depth:    k.depth + 1,
		childNum: i,
	}
	copy(child.key[:], childKeyBytes[:])
	copy(child.chainCode[:], I[32:])

	// parentFingerprint = HASH160(parentCompressedPubKey)[:4]
	fp := hash160(k.compressedPubKey())
	copy(child.parentFP[:], fp[:4])

	return child
}

// Xprv serializes the extended private key as a bitcore mainnet Base58Check string.
func (k *ExtKey) Xprv() string {
	payload := make([]byte, 0, 78)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], k.version)
	payload = append(payload, ver[:]...)
	payload = append(payload, k.depth)
	payload = append(payload, k.parentFP[:]...)
	var cn [4]byte
	binary.BigEndian.PutUint32(cn[:], k.childNum)
	payload = append(payload, cn[:]...)
	payload = append(payload, k.chainCode[:]...)
	payload = append(payload, 0x00)
	payload = append(payload, k.key[:]...)
	return Base58CheckEncode(payload)
}

// DeriveKeypair derives the ed25519 keypair for the given hardened depth.
// The ed25519 seed is the first 32 bytes of the ASCII xprv string (non-standard,
// matching sdk-js).
func DeriveKeypair(mnemonic, passphrase string, depth uint32) Keypair {
	m := NewMasterKey(MnemonicToSeed(mnemonic, passphrase))
	edSeed := []byte(m.DeriveHardened(depth).Xprv())[:32]
	return KeypairFromSeed(edSeed)
}

func hash160(b []byte) []byte {
	s := sha256.Sum256(b)
	r := ripemd160.New()
	r.Write(s[:])
	return r.Sum(nil)
}
