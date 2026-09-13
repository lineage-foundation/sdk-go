package sdkgo

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// NetworkVersion is the current Lineage two-way network version, matching
// sdk-js's NETWORK_VERSION. Every CreateTransaction built by this SDK is
// stamped with this version.
const NetworkVersion = 2

// ConstructTxInOutSignableHash builds the signable hash for a transaction
// input: hex(sha3_256(concat(json.Marshal(txOut) for each output) +
// json.Marshal(prevOut))). prevOut may be nil, in which case it contributes
// the literal bytes "null" to the preimage. This must stay byte-identical to
// sdk-js's construct_tx_in_out_signable_hash, since both the client and the
// server hash the same JSON-encoded preimage.
//
// TxOut.Value is an Asset, whose MarshalJSON errors for an unset/unrecognized
// Kind; every constructor in this package (NewTokenAsset/NewItemAsset) always
// sets one, so that error is not reachable through normal use. It's still a
// caller bug if it ever happens, and silently hashing a truncated/empty
// preimage would produce a signature over the wrong bytes with no
// indication, so a marshal failure here panics instead of being swallowed.
func ConstructTxInOutSignableHash(prevOut *OutPoint, txOuts []TxOut) string {
	var b strings.Builder
	for _, o := range txOuts {
		j, err := json.Marshal(o)
		if err != nil {
			panic(fmt.Sprintf("sdkgo: marshal TxOut for signable hash: %v", err))
		}
		b.Write(j)
	}
	j, err := json.Marshal(prevOut) // prevOut may be nil -> "null"
	if err != nil {
		panic(fmt.Sprintf("sdkgo: marshal OutPoint for signable hash: %v", err))
	}
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

// assetsCompatible reports whether two assets can be combined/compared: both
// must be the same kind, and Item assets must additionally share a genesis
// hash. Matches sdk-js's assetsAreCompatible.
func assetsCompatible(a, b Asset) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == AssetKindItem {
		return a.GenesisHash == b.GenesisHash
	}
	return true
}

// hasEnoughFunds reports whether the balance total can possibly cover
// paymentAsset, matching the up-front check in sdk-js's getInputsForTx.
func hasEnoughFunds(paymentAsset Asset, balance FetchBalanceResponse) bool {
	if paymentAsset.Kind == AssetKindToken {
		return paymentAsset.Amount <= balance.Total.Tokens
	}
	return paymentAsset.Amount <= balance.Total.Items[paymentAsset.GenesisHash]
}

// addressVersionForKeypair determines the address_version to record for an
// input's script signature: nil for the current/default address derivation
// (hex(sha3_256(publicKey))), matching sdk-js's getAddressVersion for the
// two-argument (publicKey, address) form. This SDK does not implement the
// deprecated/temporary address schemes, so any address that doesn't match
// the default derivation is reported as an error.
func addressVersionForKeypair(publicKey []byte, address string) (*int, error) {
	if crypto.ConstructAddress(publicKey) == address {
		return nil, nil
	}
	return nil, fmt.Errorf("sdkgo: address %q does not match the default derivation for its public key (old/temp address versions are not supported)", address)
}

// addressListOrder returns the addresses of balance.AddressList in the order
// input-gathering should walk them: the JSON address_list object's original
// key order when balance was decoded from JSON (see
// FetchBalanceResponse.addressOrder), matching sdk-js's
// Object.entries(fetchBalanceResponse.address_list) byte-for-byte; falling
// back to address-sorted order for a FetchBalanceResponse built by hand.
func addressListOrder(balance FetchBalanceResponse) []string {
	if len(balance.addressOrder) > 0 {
		addresses := make([]string, 0, len(balance.addressOrder))
		seen := make(map[string]bool, len(balance.addressOrder))
		for _, address := range balance.addressOrder {
			if _, ok := balance.AddressList[address]; ok && !seen[address] {
				addresses = append(addresses, address)
				seen[address] = true
			}
		}
		return addresses
	}

	addresses := make([]string, 0, len(balance.AddressList))
	for address := range balance.AddressList {
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	return addresses
}

// getInputsForTx selects unspent outputs from balance to cover paymentAsset,
// walking addresses in addressListOrder(balance). It returns the selected
// inputs (with placeholder-free signatures to be filled in by
// CreatePaymentTx once outputs are known) and the total asset amount
// gathered. Matches sdk-js's getInputsForTx.
func getInputsForTx(paymentAsset Asset, balance FetchBalanceResponse, keyPairs map[string]crypto.Keypair) ([]CreateTxIn, Asset, error) {
	if !hasEnoughFunds(paymentAsset, balance) {
		return nil, Asset{}, fmt.Errorf("sdkgo: insufficient funds")
	}

	total := Asset{Kind: paymentAsset.Kind, GenesisHash: paymentAsset.GenesisHash, Metadata: paymentAsset.Metadata}

	addresses := addressListOrder(balance)

	var inputs []CreateTxIn
	for _, address := range addresses {
		kp, ok := keyPairs[address]
		if !ok {
			return nil, Asset{}, fmt.Errorf("sdkgo: no keypair for address %q", address)
		}
		addrVersion, err := addressVersionForKeypair(kp.PublicKey, address)
		if err != nil {
			return nil, Asset{}, err
		}
		for _, entry := range balance.AddressList[address] {
			if total.Amount >= paymentAsset.Amount {
				continue
			}
			if !assetsCompatible(paymentAsset, entry.Value) {
				continue
			}

			outPoint := entry.OutPoint
			inputs = append(inputs, CreateTxIn{
				PreviousOut: &outPoint,
				ScriptSignature: ScriptSig{
					Pay2PkH: &Pay2PkH{
						PublicKey:      hex.EncodeToString(kp.PublicKey),
						AddressVersion: addrVersion,
					},
				},
			})

			total.Amount += entry.Value.Amount
		}
	}

	return inputs, total, nil
}

// addressForOutPoint finds the address in balance.AddressList that owns the
// out-point identified by tHash, matching sdk-js's
// getAddressFromFetchBalanceResponse.
func addressForOutPoint(balance FetchBalanceResponse, tHash string) (string, error) {
	addresses := addressListOrder(balance)

	for _, address := range addresses {
		for _, entry := range balance.AddressList[address] {
			if entry.OutPoint.THash == tHash {
				return address, nil
			}
		}
	}
	return "", fmt.Errorf("sdkgo: no address in balance owns out-point %q", tHash)
}

// CreatePaymentTx builds a payment transaction sending paymentAsset to
// paymentAddress, sourcing inputs from balance and sending any change to
// excessAddress. It replicates sdk-js's createPaymentTx (getInputsForTx +
// createTx + updateSignatures) byte-for-byte: inputs are selected from
// balance in address-sorted order, outputs are [payment, change] (change
// omitted when there's no excess), and every input is (re)signed over the
// signable hash of its previous-out plus the full output set.
func CreatePaymentTx(paymentAddress string, paymentAsset Asset, excessAddress string, balance FetchBalanceResponse, keyPairs map[string]crypto.Keypair, locktime int) (CreateTransaction, error) {
	return createTxWithDruidInfo(paymentAddress, paymentAsset, excessAddress, balance, keyPairs, locktime, nil)
}

// Create2WTxHalf builds one half of a two-way (DRUID) trade: an ordinary
// P2PKH transaction that pays counterExpectation.asset to
// counterExpectation.to (plus any excess back to excessAddress), carrying
// thisExpectation as this party's half of the DRUID trade metadata.
//
// It replicates sdk-js's create2WTxHalf byte-for-byte: input selection and
// output/signature construction are exactly CreatePaymentTx's (driven by
// counterExpectation.asset/to), and druid_info is attached as
// { druid, participants: 2, expectations: [thisExpectation] } — unsigned,
// and never folded into any signable preimage. Each input is signed exactly
// as in the 1-way path, over ConstructTxInOutSignableHash(input.previous_out,
// outputs).
func Create2WTxHalf(druid string, thisExpectation, counterExpectation DruidExpectation, balance FetchBalanceResponse, keyPairs map[string]crypto.Keypair, excessAddress string, locktime int) (CreateTransaction, error) {
	druidInfo := &DruidInfo{
		Druid:        druid,
		Participants: 2,
		Expectations: []DruidExpectation{thisExpectation},
	}
	return createTxWithDruidInfo(counterExpectation.To, counterExpectation.Asset, excessAddress, balance, keyPairs, locktime, druidInfo)
}

// createTxWithDruidInfo is the shared core of CreatePaymentTx and
// Create2WTxHalf: gather inputs for paymentAsset, build [payment, change]
// outputs, sign every input over the full output set, and stamp druidInfo
// (nil for an ordinary 1-way payment) onto the result.
func createTxWithDruidInfo(paymentAddress string, paymentAsset Asset, excessAddress string, balance FetchBalanceResponse, keyPairs map[string]crypto.Keypair, locktime int, druidInfo *DruidInfo) (CreateTransaction, error) {
	inputs, totalGathered, err := getInputsForTx(paymentAsset, balance, keyPairs)
	if err != nil {
		return CreateTransaction{}, err
	}
	if len(inputs) == 0 {
		return CreateTransaction{}, fmt.Errorf("sdkgo: no inputs available to cover payment")
	}

	outputs := []TxOut{{
		Value:           paymentAsset,
		Locktime:        locktime,
		ScriptPublicKey: paymentAddress,
	}}

	if totalGathered.Amount > paymentAsset.Amount {
		excess := paymentAsset
		excess.Amount = totalGathered.Amount - paymentAsset.Amount
		outputs = append(outputs, TxOut{
			Value:           excess,
			Locktime:        0,
			ScriptPublicKey: excessAddress,
		})
	}

	tx := CreateTransaction{
		Inputs:    inputs,
		Outputs:   outputs,
		Version:   NetworkVersion,
		DruidInfo: druidInfo,
	}

	// updateSignatures: re-sign each input now that the full output set is known.
	for i := range tx.Inputs {
		in := &tx.Inputs[i]
		address, err := addressForOutPoint(balance, in.PreviousOut.THash)
		if err != nil {
			return CreateTransaction{}, err
		}
		kp, ok := keyPairs[address]
		if !ok {
			return CreateTransaction{}, fmt.Errorf("sdkgo: no keypair for address %q", address)
		}

		signableData := ConstructTxInOutSignableHash(in.PreviousOut, tx.Outputs)
		signature := ConstructSignature(signableData, kp.SecretKey)

		in.ScriptSignature.Pay2PkH.SignableData = signableData
		in.ScriptSignature.Pay2PkH.Signature = signature
	}

	return tx, nil
}

// ConstructTxInsAddress derives the "from" address used to correlate the two
// halves of a DRUID trade from a transaction's inputs:
// hex(sha3_256(joined per-input P2PKH script strings)). It replicates
// sdk-js's constructTxInsAddress / getFormattedScriptString byte-for-byte,
// including sdk-js's exact P2PKH stack layout (Bytes/Signature/PubKey/Op
// entries), even though this SDK does not otherwise construct or evaluate
// scripts.
func ConstructTxInsAddress(inputs []CreateTxIn) string {
	parts := make([]string, len(inputs))
	for i, in := range inputs {
		parts[i] = txInAddressPart(in)
	}
	joined := strings.Join(parts, "-")
	h := sha3.Sum256([]byte(joined))
	return hex.EncodeToString(h[:])
}

// txInAddressPart formats a single input as sdk-js's constructTxInsAddress
// does: "{n}-{t_hash}-{p2pkh script string}" (or "null-{...}" when
// previous_out is absent).
func txInAddressPart(in CreateTxIn) string {
	sig := in.ScriptSignature.Pay2PkH

	hashOp := "OP_HASH256"
	if sig.AddressVersion != nil && *sig.AddressVersion != 1 {
		hashOp = "OP_HASH256_TEMP"
	}

	pubKeyBytes, err := hex.DecodeString(sig.PublicKey)
	if err != nil {
		panic(fmt.Sprintf("sdkgo: decode public key for tx-ins address: %v", err))
	}
	address := crypto.ConstructAddress(pubKeyBytes)

	script := strings.Join([]string{
		"Bytes:" + sig.SignableData,
		"Signature:" + sig.Signature,
		"PubKey:" + sig.PublicKey,
		"Op:OP_DUP",
		"Op:" + hashOp,
		"Bytes:" + address,
		"Op:OP_EQUALVERIFY",
		"Op:OP_CHECKSIG",
	}, "-")

	if in.PreviousOut == nil {
		return "null-" + script
	}
	return fmt.Sprintf("%d-%s-%s", in.PreviousOut.N, in.PreviousOut.THash, script)
}
