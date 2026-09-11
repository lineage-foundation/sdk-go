package sdkgo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// mnemonicBits is the BIP39 entropy size used by InitNew: 128 bits of entropy
// yields a 12-word mnemonic, matching bitcore-mnemonic's default (and sdk-js's
// generateSeed) word count.
const mnemonicBits = 128

// bip39Passphrase is the BIP39 passphrase this SDK always derives with. Every
// seed-to-master-key call site in sdk-js's key-generation flows (mgmtClient's
// initNew/fromSeed, via generateMasterKey) passes no BIP39 passphrase, so this
// SDK fixes it to "" too; the wallet's own passphrase only ever encrypts the
// keystore (master key and keypairs) at rest.
const bip39Passphrase = ""

// Wallet is a keyed client for the Lineage /v1 API: it embeds the keyless
// *Client (read operations) and adds the consumer-signing operations backed
// by an in-memory BIP39 mnemonic and passphrase-derived keystore key.
//
// A Wallet is unusable for signing operations until one of InitNew, FromSeed,
// or FromMasterKey has been called.
type Wallet struct {
	*Client

	// mnemonic is the BIP39 mnemonic phrase every keypair is derived from
	// (crypto.DeriveKeypair(mnemonic, bip39Passphrase, depth)). Empty until
	// the wallet has been initialized.
	mnemonic string
	// encKey is the secretbox key (crypto.PassphraseKey(passphrase)) used to
	// seal/open the master key and individual keypairs at rest.
	encKey [32]byte
}

// NewWallet builds an uninitialized Wallet from the given Config. Call
// InitNew, FromSeed, or FromMasterKey before using any signing operation.
func NewWallet(cfg Config) *Wallet {
	return &Wallet{Client: NewClient(cfg)}
}

// MasterKeyEncrypted is the on-disk/wire representation of a Wallet's
// passphrase-encrypted master key, matching the shape of sdk-js's
// IMasterKeyEncrypted (a nonce plus a sealed payload). InitNew and FromSeed
// return this JSON-encoded so the consumer can persist it; FromMasterKey
// consumes that same JSON back.
//
// Unlike sdk-js, which seals the BIP32 extended private key (xprivkey)
// string, this SDK seals the BIP39 mnemonic phrase itself: every keypair
// this SDK derives comes from crypto.DeriveKeypair(mnemonic, "", depth), so
// the mnemonic — not a decoded xprv object — is this SDK's reconstructable
// master-key state.
type MasterKeyEncrypted struct {
	Nonce string `json:"nonce"`
	Save  string `json:"save"`
}

// InitNew generates a fresh BIP39 mnemonic, derives the passphrase keystore
// key from passphrase, and returns the JSON-encoded MasterKeyEncrypted for
// the consumer to persist (e.g. alongside FromMasterKey on next launch).
// Mirrors sdk-js's Wallet.initNew / mgmtClient.initNew.
func (w *Wallet) InitNew(passphrase string) (masterKeyEncrypted string, err error) {
	entropy, err := bip39.NewEntropy(mnemonicBits)
	if err != nil {
		return "", fmt.Errorf("sdkgo: generate entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("sdkgo: generate mnemonic: %w", err)
	}
	return w.initFromMnemonic(mnemonic, passphrase)
}

// FromSeed initializes the wallet from a caller-supplied BIP39 mnemonic
// phrase and returns the JSON-encoded MasterKeyEncrypted for the consumer to
// persist. Mirrors sdk-js's Wallet.fromSeed / mgmtClient.fromSeed.
func (w *Wallet) FromSeed(mnemonic, passphrase string) (masterKeyEncrypted string, err error) {
	return w.initFromMnemonic(mnemonic, passphrase)
}

// FromMasterKey initializes the wallet from a MasterKeyEncrypted JSON string
// previously returned by InitNew or FromSeed, decrypting it with passphrase.
// Mirrors sdk-js's Wallet.fromMasterKey / mgmtClient.fromMasterKey.
func (w *Wallet) FromMasterKey(masterKeyEncrypted, passphrase string) error {
	var enc MasterKeyEncrypted
	if err := json.Unmarshal([]byte(masterKeyEncrypted), &enc); err != nil {
		return fmt.Errorf("sdkgo: parse master key: %w", err)
	}
	key := crypto.PassphraseKey(passphrase)
	mnemonic, err := openMnemonic(enc, key)
	if err != nil {
		return err
	}
	w.mnemonic = mnemonic
	w.encKey = key
	return nil
}

// initFromMnemonic is the shared implementation of InitNew and FromSeed: it
// sets the wallet's derivation/encryption state and seals the mnemonic under
// the passphrase-derived key.
func (w *Wallet) initFromMnemonic(mnemonic, passphrase string) (string, error) {
	key := crypto.PassphraseKey(passphrase)
	enc, err := sealMnemonic(mnemonic, key)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(enc)
	if err != nil {
		return "", fmt.Errorf("sdkgo: marshal master key: %w", err)
	}
	w.mnemonic = mnemonic
	w.encKey = key
	return string(out), nil
}

// sealMnemonic seals the mnemonic under key with nacl secretbox, using a
// fresh v4-UUID-derived nonce, matching sdk-js's encryptMasterKey.
func sealMnemonic(mnemonic string, key [32]byte) (MasterKeyEncrypted, error) {
	nonceStr, err := newNonce()
	if err != nil {
		return MasterKeyEncrypted{}, err
	}
	var n [24]byte
	copy(n[:], []byte(nonceStr))
	sealed := secretbox.Seal(nil, []byte(mnemonic), &n, &key)
	return MasterKeyEncrypted{Nonce: nonceStr, Save: base64.StdEncoding.EncodeToString(sealed)}, nil
}

// openMnemonic opens a MasterKeyEncrypted sealed by sealMnemonic, recovering
// the mnemonic phrase.
func openMnemonic(enc MasterKeyEncrypted, key [32]byte) (string, error) {
	var n [24]byte
	copy(n[:], []byte(enc.Nonce))
	raw, err := base64.StdEncoding.DecodeString(enc.Save)
	if err != nil {
		return "", fmt.Errorf("sdkgo: decode master key: %w", err)
	}
	plain, ok := secretbox.Open(nil, raw, &n, &key)
	if !ok {
		return "", errors.New("sdkgo: master key decrypt failed")
	}
	return string(plain), nil
}

// newNonce returns a fresh 24-ASCII-character nonce: the first 24 characters
// of a random v4 UUID string, matching sdk-js's
// truncateByBytesUTF8(uuidv4(), 24) (used for both keypair and master-key
// encryption nonces).
func newNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("sdkgo: generate nonce: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	return uuidStr[:24], nil
}

// GetNewKeypair derives and encrypts the next unused keypair: starting at
// depth len(existing), it derives keypairs at increasing depths until it
// finds one whose address isn't already present in existing, matching
// sdk-js's generateNewKeypairAndAddress.
func (w *Wallet) GetNewKeypair(existing []string) (crypto.EncryptedKeypair, error) {
	if w.mnemonic == "" {
		return crypto.EncryptedKeypair{}, errors.New("sdkgo: wallet not initialized")
	}

	taken := make(map[string]bool, len(existing))
	for _, a := range existing {
		taken[a] = true
	}

	counter := uint32(len(existing))
	kp := crypto.DeriveKeypair(w.mnemonic, bip39Passphrase, counter)
	addr := crypto.ConstructAddress(kp.PublicKey)
	for taken[addr] {
		counter++
		kp = crypto.DeriveKeypair(w.mnemonic, bip39Passphrase, counter)
		addr = crypto.ConstructAddress(kp.PublicKey)
	}

	nonce, err := newNonce()
	if err != nil {
		return crypto.EncryptedKeypair{}, err
	}
	return crypto.EncryptKeypair(kp, addr, nonce, w.encKey), nil
}

// FetchBalance returns UTXO balances for the given addresses. Delegates to
// the embedded Client's QueryBalances. Mirrors sdk-js's Wallet.fetchBalance.
func (w *Wallet) FetchBalance(ctx context.Context, addrs []string) (FetchBalanceResponse, error) {
	return w.QueryBalances(ctx, addrs)
}

// CreateItems creates item assets against addr's address: it signs the
// item-asset signable hash with addr's decrypted secret key and submits
// `POST /v1/items`. defaultGenesisHash selects between the well-known
// default item DRS transaction hash (true) and a freshly assigned one
// (false). Mirrors sdk-js's Wallet.createItems / createItemPayload.
func (w *Wallet) CreateItems(ctx context.Context, addr crypto.EncryptedKeypair, defaultGenesisHash bool, amount int, metadata *string) (CreateItemResponse, error) {
	kp, err := crypto.DecryptKeypair(addr, w.encKey)
	if err != nil {
		return CreateItemResponse{}, fmt.Errorf("sdkgo: decrypt keypair: %w", err)
	}

	genesisHashSpec := GenesisHashSpecCreate
	if defaultGenesisHash {
		genesisHashSpec = GenesisHashSpecDefault
	}

	// The genesis hash isn't part of the item-asset signable hash (it isn't
	// known until the server assigns/resolves it), matching item.mgmt.ts's
	// createItemPayload.
	asset := NewItemAsset(int64(amount), "", metadata)
	signableHash := ConstructItemAssetSignableHash(asset)
	signature := ConstructSignature(signableHash, kp.SecretKey)

	scriptPublicKey := crypto.ConstructAddress(kp.PublicKey)
	publicKeyHex := hex.EncodeToString(kp.PublicKey)

	req := CreateItemRequest{
		ItemAmount:      int64(amount),
		GenesisHashSpec: genesisHashSpec,
		Metadata:        metadata,
		ScriptPublicKey: &scriptPublicKey,
		PublicKey:       &publicKeyHex,
		Signature:       &signature,
	}

	var out CreateItemResponse
	err = w.doJSON(ctx, http.MethodPost, w.mempool, "/v1/items", req, &out)
	return out, err
}

// createTxSubmission is the wire shape of a single transaction inside a
// `POST /v1/transactions` request body: a CreateTransaction with an explicit
// (always-null) fees field appended, matching sdk-js's `{...tx, fees: null}`
// spread in Wallet.makePayment. fees isn't part of the signed transaction —
// it's a separate, nullable field required by the DTO.
type createTxSubmission struct {
	Inputs    []CreateTxIn `json:"inputs"`
	Outputs   []TxOut      `json:"outputs"`
	Version   int          `json:"version"`
	DruidInfo *DruidInfo   `json:"druid_info"`
	Fees      []TxOut      `json:"fees"`
}

// createTransactionsSubmission is the top-level `POST /v1/transactions`
// request body: a plain array of transactions (not the map-keyed shape of
// CreateTransactionsRequest, which describes a different request shape).
type createTransactionsSubmission struct {
	Transactions []createTxSubmission `json:"transactions"`
}

// MakeTokenPayment sends amount Token assets to paymentAddress, sourcing
// inputs from allKeypairs's addresses and sending change to excessKeypair's
// address. Mirrors sdk-js's Wallet.makeTokenPayment.
func (w *Wallet) MakeTokenPayment(ctx context.Context, paymentAddress string, amount int64, allKeypairs []crypto.EncryptedKeypair, excessKeypair crypto.EncryptedKeypair, locktime int) (CreateTransactionsResponse, error) {
	return w.makePayment(ctx, paymentAddress, NewTokenAsset(amount), allKeypairs, excessKeypair, locktime)
}

// MakeItemPayment sends amount Item assets (of the given genesisHash) to
// paymentAddress, sourcing inputs from allKeypairs's addresses and sending
// change to excessKeypair's address. Mirrors sdk-js's Wallet.makeItemPayment.
func (w *Wallet) MakeItemPayment(ctx context.Context, paymentAddress string, amount int64, genesisHash string, allKeypairs []crypto.EncryptedKeypair, excessKeypair crypto.EncryptedKeypair, metadata *string, locktime int) (CreateTransactionsResponse, error) {
	return w.makePayment(ctx, paymentAddress, NewItemAsset(amount, genesisHash, metadata), allKeypairs, excessKeypair, locktime)
}

// makePayment is the shared implementation behind MakeTokenPayment and
// MakeItemPayment: decrypt allKeypairs, fetch their combined balance, build
// the payment transaction via CreatePaymentTx, and submit it via
// `POST /v1/transactions`. Mirrors sdk-js's private Wallet.makePayment.
func (w *Wallet) makePayment(ctx context.Context, paymentAddress string, asset Asset, allKeypairs []crypto.EncryptedKeypair, excessKeypair crypto.EncryptedKeypair, locktime int) (CreateTransactionsResponse, error) {
	if len(allKeypairs) == 0 {
		return CreateTransactionsResponse{}, errors.New("sdkgo: no keypairs provided")
	}

	addresses := make([]string, 0, len(allKeypairs))
	keyPairs := make(map[string]crypto.Keypair, len(allKeypairs))
	for _, enc := range allKeypairs {
		kp, err := crypto.DecryptKeypair(enc, w.encKey)
		if err != nil {
			return CreateTransactionsResponse{}, fmt.Errorf("sdkgo: decrypt keypair for %q: %w", enc.Address, err)
		}
		addresses = append(addresses, enc.Address)
		keyPairs[enc.Address] = kp
	}

	balance, err := w.FetchBalance(ctx, addresses)
	if err != nil {
		return CreateTransactionsResponse{}, fmt.Errorf("sdkgo: fetch balance: %w", err)
	}

	tx, err := CreatePaymentTx(paymentAddress, asset, excessKeypair.Address, balance, keyPairs, locktime)
	if err != nil {
		return CreateTransactionsResponse{}, err
	}

	body := createTransactionsSubmission{
		Transactions: []createTxSubmission{{
			Inputs:    tx.Inputs,
			Outputs:   tx.Outputs,
			Version:   tx.Version,
			DruidInfo: tx.DruidInfo,
			Fees:      nil,
		}},
	}

	var out CreateTransactionsResponse
	err = w.doJSON(ctx, http.MethodPost, w.mempool, "/v1/transactions", body, &out)
	return out, err
}

// SignMessage signs message's raw bytes (nacl detached, i.e. ed25519) with
// each of keypairs' decrypted secret keys, returning a map of hex public key
// to hex signature. Mirrors sdk-js's mgmtClient.signMessage.
func (w *Wallet) SignMessage(keypairs []crypto.EncryptedKeypair, message []byte) (map[string]string, error) {
	if len(keypairs) == 0 {
		return nil, errors.New("sdkgo: no keypairs provided")
	}

	signatures := make(map[string]string, len(keypairs))
	for _, enc := range keypairs {
		kp, err := crypto.DecryptKeypair(enc, w.encKey)
		if err != nil {
			return nil, fmt.Errorf("sdkgo: decrypt keypair for %q: %w", enc.Address, err)
		}
		sig := crypto.Sign(message, kp.SecretKey)
		signatures[hex.EncodeToString(kp.PublicKey)] = hex.EncodeToString(sig)
	}
	return signatures, nil
}

// VerifyMessage verifies that signatures (keyed by hex public key, as
// returned by SignMessage) contains a valid nacl-detached signature of
// message's raw bytes for every one of keypairs. Mirrors sdk-js's
// mgmtClient.verifyMessage.
func (w *Wallet) VerifyMessage(message []byte, signatures map[string]string, keypairs []crypto.EncryptedKeypair) (bool, error) {
	if len(keypairs) == 0 || len(signatures) != len(keypairs) {
		return false, errors.New("sdkgo: invalid inputs")
	}

	for _, enc := range keypairs {
		kp, err := crypto.DecryptKeypair(enc, w.encKey)
		if err != nil {
			return false, fmt.Errorf("sdkgo: decrypt keypair for %q: %w", enc.Address, err)
		}
		sigHex, ok := signatures[hex.EncodeToString(kp.PublicKey)]
		if !ok {
			return false, fmt.Errorf("sdkgo: no signature for public key %s", hex.EncodeToString(kp.PublicKey))
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil {
			return false, fmt.Errorf("sdkgo: decode signature: %w", err)
		}
		if !crypto.Verify(message, sig, kp.PublicKey) {
			return false, nil
		}
	}
	return true, nil
}
