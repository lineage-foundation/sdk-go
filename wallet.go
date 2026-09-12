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

// submissionDruidInfo is the wire shape of druid_info inside a
// `POST /v1/transactions` submission: unlike DruidInfo (used for the
// as-constructed transaction, which omits genesis_hash entirely),
// GenesisHash here has no omitempty, so a nil value still serializes as an
// explicit "genesis_hash":null. This matches sdk-js's
// `{ ...tx.druid_info, genesis_hash: null }` spread in make2WayPayment's
// mempool submissions, which the server requires.
type submissionDruidInfo struct {
	Druid        string             `json:"druid"`
	Participants int                `json:"participants"`
	Expectations []DruidExpectation `json:"expectations"`
	GenesisHash  *string            `json:"genesis_hash"`
}

// createTxSubmission is the wire shape of a single transaction inside a
// `POST /v1/transactions` request body: a CreateTransaction with an explicit
// (always-null) fees field appended, matching sdk-js's `{...tx, fees: null}`
// spread in Wallet.makePayment. fees isn't part of the signed transaction —
// it's a separate, nullable field required by the DTO.
type createTxSubmission struct {
	Inputs    []CreateTxIn         `json:"inputs"`
	Outputs   []TxOut              `json:"outputs"`
	Version   int                  `json:"version"`
	DruidInfo *submissionDruidInfo `json:"druid_info"`
	Fees      []TxOut              `json:"fees"`
}

// createTransactionsSubmission is the top-level `POST /v1/transactions`
// request body: a plain array of transactions.
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
			DruidInfo: druidInfoForSubmission(tx.DruidInfo),
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

/* -------------------------------------------------------------------------- */
/*                               2-Way payment                                */
/* -------------------------------------------------------------------------- */

// valenceClient builds a ValenceClient against this wallet's configured
// valence host, reusing the wallet's own *http.Client.
func (w *Wallet) valenceClient() *ValenceClient {
	return newValenceClient(w.valence, w.httpClient)
}

// encryptTransaction seals tx under key with nacl secretbox, using a fresh
// nonce, matching sdk-js's mgmtClient.encryptTransaction. The DRUID is
// carried alongside in cleartext (as sdk-js does) so a caller can index
// stored halves by druid without decrypting them.
func encryptTransaction(tx CreateTransaction, key [32]byte) (EncryptedTransaction, error) {
	plain, err := json.Marshal(tx)
	if err != nil {
		return EncryptedTransaction{}, fmt.Errorf("sdkgo: marshal transaction: %w", err)
	}
	nonceStr, err := newNonce()
	if err != nil {
		return EncryptedTransaction{}, err
	}
	var n [24]byte
	copy(n[:], []byte(nonceStr))
	sealed := secretbox.Seal(nil, plain, &n, &key)

	var druid string
	if tx.DruidInfo != nil {
		druid = tx.DruidInfo.Druid
	}
	return EncryptedTransaction{
		Druid: druid,
		Nonce: nonceStr,
		Save:  base64.StdEncoding.EncodeToString(sealed),
	}, nil
}

// decryptTransaction opens an EncryptedTransaction produced by
// encryptTransaction (or by sdk-js's encryptTransaction), recovering the
// CreateTransaction.
func decryptTransaction(enc EncryptedTransaction, key [32]byte) (CreateTransaction, error) {
	var n [24]byte
	copy(n[:], []byte(enc.Nonce))
	raw, err := base64.StdEncoding.DecodeString(enc.Save)
	if err != nil {
		return CreateTransaction{}, fmt.Errorf("sdkgo: decode encrypted transaction: %w", err)
	}
	plain, ok := secretbox.Open(nil, raw, &n, &key)
	if !ok {
		return CreateTransaction{}, errors.New("sdkgo: transaction decrypt failed")
	}
	var tx CreateTransaction
	if err := json.Unmarshal(plain, &tx); err != nil {
		return CreateTransaction{}, fmt.Errorf("sdkgo: unmarshal decrypted transaction: %w", err)
	}
	return tx, nil
}

// decryptKeypairsMap decrypts every one of keypairs under w.encKey, returning
// both the plain address list (in keypairs' order) and an address-to-Keypair
// map, mirroring sdk-js's keyMgmt.getAllAddressesAndKeypairMap.
func (w *Wallet) decryptKeypairsMap(keypairs []crypto.EncryptedKeypair) ([]string, map[string]crypto.Keypair, error) {
	addresses := make([]string, 0, len(keypairs))
	keyPairs := make(map[string]crypto.Keypair, len(keypairs))
	for _, enc := range keypairs {
		kp, err := crypto.DecryptKeypair(enc, w.encKey)
		if err != nil {
			return nil, nil, fmt.Errorf("sdkgo: decrypt keypair for %q: %w", enc.Address, err)
		}
		addresses = append(addresses, enc.Address)
		keyPairs[enc.Address] = kp
	}
	return addresses, keyPairs, nil
}

// druidInfoForSubmission converts info to its submission wire shape with
// GenesisHash forced to an explicit null: the genesis hash isn't part of a
// two-way half's signed preimage, and `/v1/transactions` requires it
// explicit-null on submission, matching sdk-js's
// `{ ...tx.druid_info, genesis_hash: null }` spread in make2WayPayment's
// mempool submissions.
func druidInfoForSubmission(info *DruidInfo) *submissionDruidInfo {
	if info == nil {
		return nil
	}
	return &submissionDruidInfo{
		Druid:        info.Druid,
		Participants: info.Participants,
		Expectations: info.Expectations,
		GenesisHash:  nil,
	}
}

// submitTwoWayHalf POSTs tx to host's `/v1/transactions`, with fees and
// druid_info.genesis_hash explicitly null, matching sdk-js's two-way-payment
// mempool submissions in make2WayPayment/handle2WTxResponse/
// fetchPending2WayPayment.
func (w *Wallet) submitTwoWayHalf(ctx context.Context, host string, tx CreateTransaction) (CreateTransactionsResponse, error) {
	body := createTransactionsSubmission{
		Transactions: []createTxSubmission{{
			Inputs:    tx.Inputs,
			Outputs:   tx.Outputs,
			Version:   tx.Version,
			DruidInfo: druidInfoForSubmission(tx.DruidInfo),
			Fees:      nil,
		}},
	}
	var out CreateTransactionsResponse
	err := w.doJSON(ctx, http.MethodPost, host, "/v1/transactions", body, &out)
	return out, err
}

// Make2WayPayment offers a two-way (DRUID) trade to paymentAddress: this
// wallet will pay sendingAsset to paymentAddress in exchange for
// receivingAsset delivered to receiveKeypair's address. It builds this
// party's transaction half (sourcing inputs from allKeypairs's addresses,
// change back to receiveKeypair's address), posts the plaintext offer to
// valence (addressed to paymentAddress's mailbox, signed by receiveKeypair),
// and returns a PendingHalf — this party's half, sealed at rest under the
// wallet's passphrase key — for the caller to persist until
// FetchPending2WayPayment reports it settled. Mirrors sdk-js's
// Wallet.make2WayPayment.
func (w *Wallet) Make2WayPayment(ctx context.Context, paymentAddress string, sendingAsset, receivingAsset Asset, allKeypairs []crypto.EncryptedKeypair, receiveKeypair crypto.EncryptedKeypair) (PendingHalf, error) {
	if len(allKeypairs) == 0 {
		return PendingHalf{}, errors.New("sdkgo: no keypairs provided")
	}

	senderKP, err := crypto.DecryptKeypair(receiveKeypair, w.encKey)
	if err != nil {
		return PendingHalf{}, fmt.Errorf("sdkgo: decrypt receive keypair: %w", err)
	}

	addresses, keyPairs, err := w.decryptKeypairsMap(allKeypairs)
	if err != nil {
		return PendingHalf{}, err
	}

	balance, err := w.FetchBalance(ctx, addresses)
	if err != nil {
		return PendingHalf{}, fmt.Errorf("sdkgo: fetch balance: %w", err)
	}

	druid := GenerateDRUID()

	// senderExpectation: what this (sending) party expects to receive.
	// receiverExpectation: what the counterparty (payee) is owed by this half.
	senderExpectation := DruidExpectation{From: "", To: receiveKeypair.Address, Asset: receivingAsset}
	receiverExpectation := DruidExpectation{From: "", To: paymentAddress, Asset: sendingAsset}

	myHalf, err := Create2WTxHalf(druid, senderExpectation, receiverExpectation, balance, keyPairs, receiveKeypair.Address, 0)
	if err != nil {
		return PendingHalf{}, err
	}

	// Now that this half's inputs are known, fill in the "from" the
	// counterparty will use to correlate their acceptance transaction.
	receiverExpectation.From = ConstructTxInsAddress(myHalf.Inputs)

	encHalf, err := encryptTransaction(myHalf, w.encKey)
	if err != nil {
		return PendingHalf{}, err
	}

	details := Pending2WTxDetails{
		Druid:               druid,
		SenderExpectation:   senderExpectation,
		ReceiverExpectation: receiverExpectation,
		Status:              Pending2WTxStatusPending,
		MempoolHost:         w.mempool,
	}

	if err := w.valenceClient().Post(ctx, paymentAddress, senderKP, details); err != nil {
		return PendingHalf{}, fmt.Errorf("sdkgo: post offer to valence: %w", err)
	}

	return PendingHalf{
		Druid:               druid,
		EncryptedHalf:       encHalf,
		SenderExpectation:   senderExpectation,
		ReceiverExpectation: receiverExpectation,
	}, nil
}

// FetchPending2WayPayment polls this wallet's own mailboxes — one per
// address in allKeypairs, deduplicated — and does both of this wallet's
// possible roles in a two-way (DRUID) trade against whatever it finds
// there:
//
//  1. Acceptor discovery: an offer Make2WayPayment posts is addressed to
//     whichever of the counterparty's own addresses it was handed as
//     paymentAddress, so it lands in one of *our* mailboxes here. Any
//     mailbox entry whose druid isn't in stored — this wallet never
//     initiated it — is surfaced as-is in the returned pending map for the
//     caller to inspect and Accept2WayPayment/Reject2WayPayment.
//  2. Initiator settlement: an offer this wallet made shows up back in its
//     own mailbox once the counterparty accepts (handle2WTxResponse posts
//     the "accepted" status to senderExpectation.To, one of our own
//     addresses). For any such entry — druid present in stored, status
//     accepted — the stored half is decrypted, its druid_info expectation
//     is replaced with the counterparty-filled senderExpectation now on the
//     mailbox entry, the resulting transaction is submitted to this
//     wallet's own mempool, and the settled mailbox entry is deleted.
//
// allKeypairs supplies both which addresses' mailboxes to poll and the
// secret keys needed to authenticate each one's GET/DELETE requests.
//
// The returned pending map holds every still-outstanding (non-settled)
// mailbox entry found across those mailboxes, keyed by druid — this
// includes newly-discovered incoming offers, and any of our own stored
// offers that are still pending or were rejected; settled holds the druids
// that were just submitted and removed from valence. Mirrors sdk-js's
// Wallet.fetchPending2WayPayment (the "accepted" branch, generalized across
// every one of the wallet's own addresses rather than a single caller-
// supplied keypair; sdk-js's own "rejected" handling is folded into that
// same branch as a pre-existing quirk of the reference implementation, so
// this SDK instead simply leaves rejected entries in pending for the caller
// to act on).
//
// A failure against one mailbox, or one mailbox entry, never discards
// progress already made against the others: pending and settled are
// accumulated across every mailbox regardless of errors elsewhere, and are
// always returned alongside err (rather than as nil, nil) so a caller can
// still learn about work that has already been committed on-chain — in
// particular, a settled druid whose valence entry has already been deleted
// would otherwise become unrecoverable. Every error encountered is joined
// (via errors.Join) into the returned err.
func (w *Wallet) FetchPending2WayPayment(ctx context.Context, stored []PendingHalf, allKeypairs []crypto.EncryptedKeypair) (pending map[string]Pending2WTxDetails, settled []string, err error) {
	addresses, keyPairs, err := w.decryptKeypairsMap(allKeypairs)
	if err != nil {
		return nil, nil, err
	}

	storedByDruid := make(map[string]PendingHalf, len(stored))
	for _, half := range stored {
		storedByDruid[half.Druid] = half
	}

	pending = map[string]Pending2WTxDetails{}
	vc := w.valenceClient()

	var errs []error
	seenMailbox := make(map[string]bool, len(addresses))
	for _, mailboxAddress := range addresses {
		if seenMailbox[mailboxAddress] {
			continue
		}
		seenMailbox[mailboxAddress] = true

		kp := keyPairs[mailboxAddress]

		entries, err := vc.Get(ctx, mailboxAddress, kp)
		if err != nil {
			// This mailbox is unreachable; skip it and keep polling the
			// rest rather than aborting discovery/settlement entirely.
			errs = append(errs, fmt.Errorf("sdkgo: fetch valence mailbox %q: %w", mailboxAddress, err))
			continue
		}

		for druid, details := range entries {
			half, ok := storedByDruid[druid]
			if !ok || details.Status != Pending2WTxStatusAccepted {
				// Either an incoming offer (or status update) this wallet
				// never initiated, or one of our own offers that isn't
				// settled yet — surface both as pending.
				pending[druid] = details
				continue
			}

			tx, err := decryptTransaction(half.EncryptedHalf, w.encKey)
			if err != nil {
				errs = append(errs, fmt.Errorf("sdkgo: decrypt stored half for druid %q: %w", druid, err))
				continue
			}
			if tx.DruidInfo == nil || len(tx.DruidInfo.Expectations) == 0 {
				errs = append(errs, fmt.Errorf("sdkgo: stored half for druid %q has no DRUID expectations", druid))
				continue
			}
			// The counterparty has now filled in senderExpectation.from;
			// replace our stored (incomplete) expectation with theirs.
			tx.DruidInfo.Expectations[0] = details.SenderExpectation

			if _, err := w.submitTwoWayHalf(ctx, w.mempool, tx); err != nil {
				errs = append(errs, fmt.Errorf("sdkgo: submit settled half for druid %q: %w", druid, err))
				continue
			}

			if err := vc.Delete(ctx, druid, mailboxAddress, kp); err != nil {
				// The half is already submitted on-chain even though the
				// valence entry couldn't be cleaned up — this is
				// committed progress and must still be reported settled.
				errs = append(errs, fmt.Errorf("sdkgo: delete settled valence entry for druid %q: %w", druid, err))
				settled = append(settled, druid)
				continue
			}
			settled = append(settled, druid)
		}
	}

	return pending, settled, errors.Join(errs...)
}

// handle2WTxResponse is the shared implementation behind Accept2WayPayment
// and Reject2WayPayment: it stamps details with status, and — only when
// accepting — builds this party's matching transaction half (paying
// details.SenderExpectation's asset to its address, embedding
// details.ReceiverExpectation as this party's own druid_info expectation;
// sdk-js's accept2WayPayment role-swap relative to Make2WayPayment) and
// submits it to details.MempoolHost, before posting the updated status back
// to valence (addressed to details.SenderExpectation.To's mailbox, signed by
// this party's own — details.ReceiverExpectation.To — keypair). Mirrors
// sdk-js's private Wallet.handle2WTxResponse.
func (w *Wallet) handle2WTxResponse(ctx context.Context, details Pending2WTxDetails, status Pending2WTxStatus, allKeypairs []crypto.EncryptedKeypair) error {
	addresses, keyPairs, err := w.decryptKeypairsMap(allKeypairs)
	if err != nil {
		return err
	}

	receiverKP, ok := keyPairs[details.ReceiverExpectation.To]
	if !ok {
		return fmt.Errorf("sdkgo: no keypair for receiver address %q", details.ReceiverExpectation.To)
	}

	details.Status = status

	if status == Pending2WTxStatusAccepted {
		balance, err := w.FetchBalance(ctx, addresses)
		if err != nil {
			return fmt.Errorf("sdkgo: fetch balance: %w", err)
		}

		myHalf, err := Create2WTxHalf(details.Druid, details.ReceiverExpectation, details.SenderExpectation, balance, keyPairs, details.ReceiverExpectation.To, 0)
		if err != nil {
			return err
		}

		details.SenderExpectation.From = ConstructTxInsAddress(myHalf.Inputs)

		if _, err := w.submitTwoWayHalf(ctx, details.MempoolHost, myHalf); err != nil {
			return fmt.Errorf("sdkgo: submit accepted half: %w", err)
		}
	}

	if err := w.valenceClient().Post(ctx, details.SenderExpectation.To, receiverKP, details); err != nil {
		return fmt.Errorf("sdkgo: post %s status to valence: %w", status, err)
	}
	return nil
}

// Accept2WayPayment accepts a pending two-way trade offer described by
// details: it pays details.SenderExpectation's asset to the offering party,
// embeds this party's own details.ReceiverExpectation as its half of the
// DRUID trade, submits the resulting transaction to details.MempoolHost, and
// posts the accepted status (with senderExpectation.from now filled in)
// back to valence. allKeypairs must include the keypair for
// details.ReceiverExpectation.To (this party's own address in the offer).
// Mirrors sdk-js's Wallet.accept2WayPayment.
func (w *Wallet) Accept2WayPayment(ctx context.Context, details Pending2WTxDetails, allKeypairs []crypto.EncryptedKeypair) error {
	return w.handle2WTxResponse(ctx, details, Pending2WTxStatusAccepted, allKeypairs)
}

// Reject2WayPayment declines a pending two-way trade offer described by
// details: no transaction is built or submitted, but the rejected status is
// posted back to valence so the offering party's FetchPending2WayPayment can
// observe it. allKeypairs must include the keypair for
// details.ReceiverExpectation.To (this party's own address in the offer).
// Mirrors sdk-js's Wallet.reject2WayPayment.
func (w *Wallet) Reject2WayPayment(ctx context.Context, details Pending2WTxDetails, allKeypairs []crypto.EncryptedKeypair) error {
	return w.handle2WTxResponse(ctx, details, Pending2WTxStatusRejected, allKeypairs)
}
