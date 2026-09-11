package sdkgo

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// TestCreateItems_MatchesVector is the load-bearing test for Task 10's item
// path: CreateItems must POST /v1/items with a body byte-identical to the
// real sdk-js wire body.
//
// item.json's "payload" field is captured from sdk-js's internal
// createItemPayload() return value, which includes a legacy "version": null
// field. sdk-js's actual POST /v1/items request omits that field (its
// request interface only carries item_amount, script_public_key, public_key,
// signature, genesis_hash_spec and metadata), so payload as captured is not
// itself the wire body — it's one field short of it being usable directly.
// wantBody below is therefore item.json's raw payload bytes (not
// re-marshaled through any Go struct) with the "version" field mechanically
// struck out, compared against the actual bytes CreateItems sends, read off
// the httptest server. That keeps this an independent (vector-vs-observed)
// check rather than a Go-vs-Go one, while the byte-exact signature — the
// load-bearing part of the payload — is asserted unchanged.
func TestCreateItems_MatchesVector(t *testing.T) {
	var v struct {
		SecretKey              string          `json:"secretKey"`
		PublicKey              string          `json:"publicKey"`
		Amount                 int64           `json:"amount"`
		DefaultGenesisHashSpec bool            `json:"defaultGenesisHashSpec"`
		Metadata               *string         `json:"metadata"`
		Payload                json.RawMessage `json:"payload"`
	}
	loadVector(t, "item.json", &v)

	var payload struct {
		ScriptPublicKey string `json:"script_public_key"`
	}
	if err := json.Unmarshal(v.Payload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}

	var compact bytes.Buffer
	if err := json.Compact(&compact, v.Payload); err != nil {
		t.Fatalf("compact payload: %v", err)
	}
	const versionField = `"version":null,`
	compacted := compact.String()
	if strings.Count(compacted, versionField) != 1 {
		t.Fatalf("item.json payload: expected exactly one %q, got %s", versionField, compacted)
	}
	wantBody := strings.Replace(compacted, versionField, "", 1)

	const respBody = `{"asset":{"kind":"item","amount":250},"to_address":"9b759300eb5de255eb7e27881a963ad9be3cc7ca3961cb8199f21100535a2908","tx_hash":"deadbeef"}`
	srv := serverExpect(t, http.MethodPost, "/v1/items", "", wantBody, http.StatusOK, respBody)
	defer srv.Close()

	w := &Wallet{Client: NewClient(Config{Mempool: srv.URL, Storage: srv.URL}), encKey: crypto.PassphraseKey("item-test-pass")}

	kp := crypto.Keypair{
		PublicKey: mustHexDecode(t, v.PublicKey),
		SecretKey: mustHexDecode(t, v.SecretKey),
	}
	address := crypto.ConstructAddress(kp.PublicKey)
	if address != payload.ScriptPublicKey {
		t.Fatalf("sanity: derived address %s != vector script_public_key %s", address, payload.ScriptPublicKey)
	}
	encKp := crypto.EncryptKeypair(kp, address, "abcdefghijklmnopqrstuvwx", w.encKey)

	got, err := w.CreateItems(context.Background(), encKp, v.DefaultGenesisHashSpec, int(v.Amount), v.Metadata)
	if err != nil {
		t.Fatalf("CreateItems: %v", err)
	}
	if got.ToAddress != payload.ScriptPublicKey {
		t.Fatalf("CreateItems response: got ToAddress %s want %s", got.ToAddress, payload.ScriptPublicKey)
	}
}

// TestMakeTokenPayment_MatchesVector is the load-bearing test for Task 10's
// payment path: MakeTokenPayment must POST /v1/transactions with a body
// byte-identical to `{"transactions":[{...payment.json's createTx,"fees":null}]}`.
func TestMakeTokenPayment_MatchesVector(t *testing.T) {
	var v struct {
		FetchBalanceResponse FetchBalanceResponse `json:"fetchBalanceResponse"`
		PaymentAddress       string               `json:"paymentAddress"`
		PaymentAsset         Asset                `json:"paymentAsset"`
		ExcessAddress        string               `json:"excessAddress"`
		Locktime             int                  `json:"locktime"`
		SenderAddress        string               `json:"senderAddress"`
		SenderPublicKey      string               `json:"senderPublicKey"`
		CreateTxPayload      struct {
			CreateTx json.RawMessage `json:"createTx"`
		} `json:"createTxPayload"`
	}
	loadVector(t, "payment.json", &v)

	_, _, senderSecretKeyHex, _ := findDerivationEntry(t, v.SenderPublicKey, v.SenderAddress)

	var compact bytes.Buffer
	if err := json.Compact(&compact, v.CreateTxPayload.CreateTx); err != nil {
		t.Fatalf("compact createTx: %v", err)
	}
	txBytes := compact.Bytes()
	if txBytes[len(txBytes)-1] != '}' {
		t.Fatalf("createTx: expected to end with '}': %s", txBytes)
	}
	txBytes = txBytes[:len(txBytes)-1] // drop trailing '}'
	wantBody := `{"transactions":[` + string(txBytes) + `,"fees":null}]}`

	balanceRespBody, err := json.Marshal(struct {
		Balance FetchBalanceResponse `json:"balance"`
	}{Balance: v.FetchBalanceResponse})
	if err != nil {
		t.Fatalf("marshal balance response: %v", err)
	}
	const transactionsRespBody = `{"transactions":{}}`

	// MakeTokenPayment first fetches the balance (POST /v1/balances/query)
	// before submitting the payment (POST /v1/transactions), so the fake
	// server must dispatch on path.
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/balances/query":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write(balanceRespBody)
		case "/v1/transactions":
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if got := string(b); got != wantBody {
				i := 0
				for i < len(got) && i < len(wantBody) && got[i] == wantBody[i] {
					i++
				}
				t.Errorf("POST /v1/transactions body mismatch at byte offset %d:\n got:  %s\n want: %s", i, got, wantBody)
			}
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(transactionsRespBody))
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	w := &Wallet{Client: NewClient(Config{Mempool: srv.URL, Storage: srv.URL}), encKey: crypto.PassphraseKey("payment-test-pass")}

	senderKp := crypto.Keypair{
		PublicKey: mustHexDecode(t, v.SenderPublicKey),
		SecretKey: mustHexDecode(t, senderSecretKeyHex),
	}
	senderEnc := crypto.EncryptKeypair(senderKp, v.SenderAddress, "abcdefghijklmnopqrstuvwx", w.encKey)

	if v.PaymentAsset.Kind != AssetKindToken {
		t.Fatalf("payment.json paymentAsset is not a Token asset: %+v", v.PaymentAsset)
	}

	_, err = w.MakeTokenPayment(context.Background(), v.PaymentAddress, v.PaymentAsset.Amount, []crypto.EncryptedKeypair{senderEnc}, senderEnc, v.Locktime)
	if err != nil {
		t.Fatalf("MakeTokenPayment: %v", err)
	}
}

// findDerivationEntry returns the mnemonic/publicKey/secretKey/address of the
// derivation.json depth whose public key and address match wantPublicKey and
// wantAddress.
func findDerivationEntry(t *testing.T, wantPublicKey, wantAddress string) (mnemonic, publicKeyHex, secretKeyHex, address string) {
	t.Helper()
	var v struct {
		Mnemonic string `json:"mnemonic"`
		Depths   []struct {
			PublicKey string `json:"publicKey"`
			SecretKey string `json:"secretKey"`
			Address   string `json:"address"`
		} `json:"depths"`
	}
	loadVector(t, "derivation.json", &v)
	for _, d := range v.Depths {
		if d.PublicKey == wantPublicKey && d.Address == wantAddress {
			return v.Mnemonic, d.PublicKey, d.SecretKey, d.Address
		}
	}
	t.Fatalf("no derivation.json entry matches publicKey=%s address=%s", wantPublicKey, wantAddress)
	return "", "", "", ""
}

// TestFromSeedAndGetNewKeypair_MatchesDerivationVector is the load-bearing
// test for Task 10's keypair-derivation path: FromSeed + GetNewKeypair must
// derive the same depth-0/1/2 addresses as derivation.json, in order,
// skipping addresses already passed in `existing`.
func TestFromSeedAndGetNewKeypair_MatchesDerivationVector(t *testing.T) {
	var v struct {
		Mnemonic string `json:"mnemonic"`
		Depths   []struct {
			PublicKey string `json:"publicKey"`
			Address   string `json:"address"`
		} `json:"depths"`
	}
	loadVector(t, "derivation.json", &v)
	if len(v.Depths) < 3 {
		t.Fatalf("derivation.json: need at least 3 depths, got %d", len(v.Depths))
	}

	w := NewWallet(Config{Mempool: "http://unused.invalid", Storage: "http://unused.invalid"})
	masterKeyEncrypted, err := w.FromSeed(v.Mnemonic, "wallet-test-pass")
	if err != nil {
		t.Fatalf("FromSeed: %v", err)
	}
	if masterKeyEncrypted == "" {
		t.Fatal("FromSeed: expected a non-empty encrypted master key")
	}

	var existing []string
	for i, d := range v.Depths {
		got, err := w.GetNewKeypair(existing)
		if err != nil {
			t.Fatalf("GetNewKeypair depth %d: %v", i, err)
		}
		if got.Address != d.Address {
			t.Fatalf("GetNewKeypair depth %d: got address %s want %s", i, got.Address, d.Address)
		}
		kp, err := crypto.DecryptKeypair(got, w.encKey)
		if err != nil {
			t.Fatalf("decrypt derived keypair depth %d: %v", i, err)
		}
		if hex.EncodeToString(kp.PublicKey) != d.PublicKey {
			t.Fatalf("GetNewKeypair depth %d: got public key %s want %s", i, hex.EncodeToString(kp.PublicKey), d.PublicKey)
		}
		existing = append(existing, got.Address)
	}

	// A second Wallet reconstructed purely from the persisted encrypted
	// master key must derive the exact same addresses.
	w2 := NewWallet(Config{Mempool: "http://unused.invalid", Storage: "http://unused.invalid"})
	if err := w2.FromMasterKey(masterKeyEncrypted, "wallet-test-pass"); err != nil {
		t.Fatalf("FromMasterKey: %v", err)
	}
	got, err := w2.GetNewKeypair(nil)
	if err != nil {
		t.Fatalf("GetNewKeypair (from master key): %v", err)
	}
	if got.Address != v.Depths[0].Address {
		t.Fatalf("GetNewKeypair (from master key): got address %s want %s", got.Address, v.Depths[0].Address)
	}
}

// TestInitNew_RoundTrips exercises InitNew end-to-end: the returned encrypted
// master key must decrypt (via FromMasterKey) back to a wallet that derives
// the exact same first keypair as the original.
func TestInitNew_RoundTrips(t *testing.T) {
	w := NewWallet(Config{Mempool: "http://unused.invalid", Storage: "http://unused.invalid"})
	masterKeyEncrypted, err := w.InitNew("init-new-pass")
	if err != nil {
		t.Fatalf("InitNew: %v", err)
	}

	want, err := w.GetNewKeypair(nil)
	if err != nil {
		t.Fatalf("GetNewKeypair: %v", err)
	}

	w2 := NewWallet(Config{Mempool: "http://unused.invalid", Storage: "http://unused.invalid"})
	if err := w2.FromMasterKey(masterKeyEncrypted, "init-new-pass"); err != nil {
		t.Fatalf("FromMasterKey: %v", err)
	}
	got, err := w2.GetNewKeypair(nil)
	if err != nil {
		t.Fatalf("GetNewKeypair (round-tripped): %v", err)
	}
	if got.Address != want.Address {
		t.Fatalf("round-tripped wallet derived a different address: got %s want %s", got.Address, want.Address)
	}

	// Wrong passphrase must fail to decrypt.
	w3 := NewWallet(Config{Mempool: "http://unused.invalid", Storage: "http://unused.invalid"})
	if err := w3.FromMasterKey(masterKeyEncrypted, "wrong-pass"); err == nil {
		t.Fatal("FromMasterKey: expected an error for the wrong passphrase")
	}
}

// TestSignMessage_MatchesVector is the load-bearing test for Task 10's
// message-signing path: SignMessage must produce signing.json's
// byte-for-byte ed25519-detached signature.
func TestSignMessage_MatchesVector(t *testing.T) {
	var v struct {
		PublicKey    string `json:"publicKey"`
		SecretKey    string `json:"secretKey"`
		Address      string `json:"address"`
		Message      string `json:"message"`
		SignatureHex string `json:"signatureHex"`
	}
	loadVector(t, "signing.json", &v)

	w := &Wallet{Client: NewClient(Config{}), encKey: crypto.PassphraseKey("sign-test-pass")}
	kp := crypto.Keypair{
		PublicKey: mustHexDecode(t, v.PublicKey),
		SecretKey: mustHexDecode(t, v.SecretKey),
	}
	enc := crypto.EncryptKeypair(kp, v.Address, "abcdefghijklmnopqrstuvwx", w.encKey)

	signatures, err := w.SignMessage([]crypto.EncryptedKeypair{enc}, []byte(v.Message))
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}
	got, ok := signatures[v.PublicKey]
	if !ok {
		t.Fatalf("SignMessage: no signature for public key %s: %+v", v.PublicKey, signatures)
	}
	if got != v.SignatureHex {
		t.Fatalf("SignMessage: got %s want %s", got, v.SignatureHex)
	}

	ok, err = w.VerifyMessage([]byte(v.Message), signatures, []crypto.EncryptedKeypair{enc})
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if !ok {
		t.Fatal("VerifyMessage: expected true")
	}

	// Tampering with the message must fail verification.
	ok, err = w.VerifyMessage([]byte(v.Message+"!"), signatures, []crypto.EncryptedKeypair{enc})
	if err != nil {
		t.Fatalf("VerifyMessage (tampered): %v", err)
	}
	if ok {
		t.Fatal("VerifyMessage (tampered): expected false")
	}
}
