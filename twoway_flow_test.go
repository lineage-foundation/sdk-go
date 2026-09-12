package sdkgo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// twoWayFixture loads the shared druid/keypair/balance fixtures out of
// twoway.json, common to every two-way flow test in this file.
type twoWayFixture struct {
	Druid   string
	Ours    []crypto.EncryptedKeypair
	OursKP  []crypto.Keypair
	CP      crypto.EncryptedKeypair // counterparty
	CPKP    crypto.Keypair
	Balance FetchBalanceResponse
	// SenderExpectation/ReceiverExpectation as they appear in the
	// create2WTxHalf vector's input: the offer a sender (holding all "ours"
	// keypairs) makes to the counterparty.
	SenderExpectation   DruidExpectation
	ReceiverExpectation DruidExpectation
	EncKey              [32]byte
}

func loadTwoWayFixture(t *testing.T) twoWayFixture {
	t.Helper()
	var v struct {
		Druid         string `json:"druid"`
		FixedKeypairs struct {
			Ours []struct {
				Address   string `json:"address"`
				PublicKey string `json:"public_key"`
				SecretKey string `json:"secret_key"`
			} `json:"ours"`
			Counterparty struct {
				Address   string `json:"address"`
				PublicKey string `json:"public_key"`
				SecretKey string `json:"secret_key"`
			} `json:"counterparty"`
		} `json:"fixedKeypairs"`
		Create2WTxHalf struct {
			Input struct {
				FetchBalanceResponse FetchBalanceResponse `json:"fetchBalanceResponse"`
				SenderExpectation    DruidExpectation     `json:"senderExpectation"`
				ReceiverExpectation  DruidExpectation     `json:"receiverExpectation"`
			} `json:"input"`
		} `json:"create2WTxHalf"`
	}
	loadVector(t, "twoway.json", &v)

	encKey := crypto.PassphraseKey("twoway-flow-test-pass")

	f := twoWayFixture{
		Druid:               v.Druid,
		Balance:             v.Create2WTxHalf.Input.FetchBalanceResponse,
		SenderExpectation:   v.Create2WTxHalf.Input.SenderExpectation,
		ReceiverExpectation: v.Create2WTxHalf.Input.ReceiverExpectation,
		EncKey:              encKey,
	}
	for i, o := range v.FixedKeypairs.Ours {
		kp := crypto.Keypair{PublicKey: mustHexDecode(t, o.PublicKey), SecretKey: mustHexDecode(t, o.SecretKey)}
		f.OursKP = append(f.OursKP, kp)
		f.Ours = append(f.Ours, crypto.EncryptKeypair(kp, o.Address, "abcdefghijklmnopqrstuvw"+string(rune('0'+i)), encKey))
	}
	f.CPKP = crypto.Keypair{
		PublicKey: mustHexDecode(t, v.FixedKeypairs.Counterparty.PublicKey),
		SecretKey: mustHexDecode(t, v.FixedKeypairs.Counterparty.SecretKey),
	}
	f.CP = crypto.EncryptKeypair(f.CPKP, v.FixedKeypairs.Counterparty.Address, "abcdefghijklmnopqrstuvwz", encKey)
	return f
}

// newBalanceMempoolServer returns an httptest.Server that answers
// POST /v1/balances/query with balance and records every
// POST /v1/transactions body (raw JSON) into *submitted.
func newBalanceMempoolServer(t *testing.T, balance FetchBalanceResponse, submitted *[][]byte) *httptest.Server {
	t.Helper()
	balanceBody, err := json.Marshal(struct {
		Balance FetchBalanceResponse `json:"balance"`
	}{Balance: balance})
	if err != nil {
		t.Fatalf("marshal balance: %v", err)
	}
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/balances/query":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write(balanceBody)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/transactions":
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read /v1/transactions body: %v", err)
			}
			*submitted = append(*submitted, b)
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(`{"transactions":{}}`))
		default:
			t.Fatalf("unexpected mempool request: %s %s", r.Method, r.URL.Path)
		}
	}))
}

// statefulValenceServer is an in-memory httptest-backed valence mailbox
// mock: it serves GET/POST/DELETE /messages against a shared map, and
// records every POST body and every deleted id for assertions.
type statefulValenceServer struct {
	mu     sync.Mutex
	store  map[string]Pending2WTxDetails
	posted []struct {
		address string
		body    map[string]any
	}
	deleted []string
	srv     *httptest.Server
}

func newStatefulValenceServer(t *testing.T) *statefulValenceServer {
	t.Helper()
	s := &statefulValenceServer{store: map[string]Pending2WTxDetails{}}
	s.srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/messages":
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read valence POST body: %v", err)
			}
			var body struct {
				ID   string             `json:"id"`
				Data Pending2WTxDetails `json:"data"`
			}
			if err := json.Unmarshal(b, &body); err != nil {
				t.Fatalf("unmarshal valence POST body: %v", err)
			}
			var raw map[string]any
			_ = json.Unmarshal(b, &raw)
			s.posted = append(s.posted, struct {
				address string
				body    map[string]any
			}{address: r.Header.Get("address"), body: raw})
			s.store[body.ID] = body.Data
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(`{"id":"` + body.ID + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/messages":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(rw).Encode(s.store)
		case r.Method == http.MethodDelete:
			id := r.URL.Path[len("/messages/"):]
			s.deleted = append(s.deleted, id)
			delete(s.store, id)
			rw.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected valence request: %s %s", r.Method, r.URL.Path)
		}
	}))
	return s
}

func (s *statefulValenceServer) setStatus(t *testing.T, druid string, status Pending2WTxStatus, senderExpectation DruidExpectation) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.store[druid]
	if !ok {
		t.Fatalf("statefulValenceServer: no stored entry for druid %s", druid)
	}
	d.Status = status
	d.SenderExpectation = senderExpectation
	s.store[druid] = d
}

func (s *statefulValenceServer) close() { s.srv.Close() }

// TestMake2WayPayment_PostsPlaintextOfferAndReturnsPendingHalf is the
// load-bearing test for Make2WayPayment: it must build the DRUID offer
// (per the already-verified Create2WTxHalf/ConstructTxInsAddress path),
// POST the *plaintext* offer to valence (addressed to the counterparty,
// signed by the receive keypair), and return a PendingHalf carrying the
// locally-encrypted transaction half for the caller to persist.
func TestMake2WayPayment_PostsPlaintextOfferAndReturnsPendingHalf(t *testing.T) {
	f := loadTwoWayFixture(t)

	var submitted [][]byte
	mempoolSrv := newBalanceMempoolServer(t, f.Balance, &submitted)
	defer mempoolSrv.Close()

	valenceSrv := newStatefulValenceServer(t)
	defer valenceSrv.close()

	w := &Wallet{Client: NewClient(Config{Mempool: mempoolSrv.URL, Valence: valenceSrv.srv.URL}), encKey: f.EncKey}

	paymentAddress := f.ReceiverExpectation.To // counterparty address, per the vector's roles
	sendingAsset := f.ReceiverExpectation.Asset
	receivingAsset := f.SenderExpectation.Asset
	receiveKeypair := f.Ours[0] // whose address == f.SenderExpectation.To

	half, err := w.Make2WayPayment(context.Background(), paymentAddress, sendingAsset, receivingAsset, f.Ours, receiveKeypair)
	if err != nil {
		t.Fatalf("Make2WayPayment: %v", err)
	}

	if half.Druid == "" {
		t.Fatal("Make2WayPayment: expected a non-empty druid")
	}
	if half.SenderExpectation.To != receiveKeypair.Address {
		t.Errorf("half.SenderExpectation.To: got %s want %s", half.SenderExpectation.To, receiveKeypair.Address)
	}
	if half.ReceiverExpectation.To != paymentAddress {
		t.Errorf("half.ReceiverExpectation.To: got %s want %s", half.ReceiverExpectation.To, paymentAddress)
	}
	if half.ReceiverExpectation.From == "" {
		t.Error("half.ReceiverExpectation.From: expected constructTxInsAddress to have filled this in")
	}
	if half.EncryptedHalf.Save == "" || half.EncryptedHalf.Nonce == "" {
		t.Errorf("half.EncryptedHalf: expected a sealed transaction, got %+v", half.EncryptedHalf)
	}
	if half.EncryptedHalf.Druid != half.Druid {
		t.Errorf("half.EncryptedHalf.Druid: got %s want %s", half.EncryptedHalf.Druid, half.Druid)
	}

	// The stored half must decrypt back to a transaction that pays sendingAsset.
	tx, err := decryptTransaction(half.EncryptedHalf, f.EncKey)
	if err != nil {
		t.Fatalf("decryptTransaction: %v", err)
	}
	if len(tx.Outputs) == 0 || tx.Outputs[0].ScriptPublicKey != paymentAddress {
		t.Errorf("decrypted half outputs: got %+v, want first output to %s", tx.Outputs, paymentAddress)
	}

	if len(valenceSrv.posted) != 1 {
		t.Fatalf("expected exactly one valence POST, got %d", len(valenceSrv.posted))
	}
	posted := valenceSrv.posted[0]
	if posted.address != paymentAddress {
		t.Errorf("valence POST address header: got %s want %s", posted.address, paymentAddress)
	}
	if posted.body["id"] != half.Druid {
		t.Errorf("valence POST body id: got %v want %s", posted.body["id"], half.Druid)
	}
	data, ok := posted.body["data"].(map[string]any)
	if !ok {
		t.Fatalf("valence POST body data: not an object: %v", posted.body["data"])
	}
	if data["status"] != "pending" {
		t.Errorf("valence POST body data.status: got %v want pending", data["status"])
	}
	if data["mempoolHost"] != mempoolSrv.URL {
		t.Errorf("valence POST body data.mempoolHost: got %v want %s", data["mempoolHost"], mempoolSrv.URL)
	}
	// Plaintext: the asset must be readable directly off the wire body, not
	// an encrypted blob.
	senderExp, ok := data["senderExpectation"].(map[string]any)
	if !ok {
		t.Fatalf("valence POST body data.senderExpectation: not an object: %v", data["senderExpectation"])
	}
	assetField, ok := senderExp["asset"].(map[string]any)
	if !ok {
		t.Fatalf("valence POST body data.senderExpectation.asset: not an object: %v", senderExp["asset"])
	}
	if _, ok := assetField["Item"]; !ok {
		t.Errorf("valence POST body data.senderExpectation.asset: expected a plaintext Item asset, got %v", assetField)
	}
}

// accepterBalance returns a FetchBalanceResponse giving address a spendable
// Item UTXO of amount, at the given genesis hash — what the accepting party
// (the counterparty in the offer, who owes the sender's requested asset)
// needs on hand to build its matching half. This is a fixture separate from
// twoWayFixture.Balance, which only funds the "ours" (sending) addresses.
func accepterBalance(address, genesisHash string, amount int64) FetchBalanceResponse {
	return FetchBalanceResponse{
		Total: BalanceTotal{Items: map[string]int64{genesisHash: amount}},
		AddressList: map[string][]BalanceEntry{
			address: {{
				OutPoint: OutPoint{THash: "accepter-utxo", N: 0},
				Value:    NewItemAsset(amount, genesisHash, nil),
			}},
		},
	}
}

// TestAccept2WayPayment_SubmitsMatchingHalfAndPostsAcceptance is the
// load-bearing test for Accept2WayPayment: it must build the receiver's
// matching transaction half (role-swapped per sdk-js's accept2WayPayment),
// submit it to details.MempoolHost's /v1/transactions with
// druid_info.genesis_hash:null and fees:null, and post the accepted status
// back to valence with senderExpectation.from filled in.
func TestAccept2WayPayment_SubmitsMatchingHalfAndPostsAcceptance(t *testing.T) {
	f := loadTwoWayFixture(t)

	details := Pending2WTxDetails{
		Druid:               f.Druid,
		SenderExpectation:   f.SenderExpectation,
		ReceiverExpectation: f.ReceiverExpectation,
		Status:              Pending2WTxStatusPending,
	}

	// The accepting party is the counterparty in the offer (they're the one
	// who owes details.SenderExpectation's asset); details.ReceiverExpectation.To
	// is their own address.
	balance := accepterBalance(details.ReceiverExpectation.To, details.SenderExpectation.Asset.GenesisHash, details.SenderExpectation.Asset.Amount)
	var submitted [][]byte
	mempoolSrv := newBalanceMempoolServer(t, balance, &submitted)
	defer mempoolSrv.Close()
	details.MempoolHost = mempoolSrv.URL

	valenceSrv := newStatefulValenceServer(t)
	defer valenceSrv.close()

	// Config.Mempool feeds Wallet.FetchBalance (this wallet's own balance
	// lookup); details.MempoolHost (also mempoolSrv here) is where the
	// resulting half is actually submitted, per the sender's original choice.
	w := &Wallet{Client: NewClient(Config{Mempool: mempoolSrv.URL, Valence: valenceSrv.srv.URL}), encKey: f.EncKey}

	// The acceptor only needs the keypair for its own address
	// (details.ReceiverExpectation.To, the counterparty here); include the
	// full keypair set, as a caller normally would.
	allKeypairs := append([]crypto.EncryptedKeypair{f.CP}, f.Ours...)
	if err := w.Accept2WayPayment(context.Background(), details, allKeypairs); err != nil {
		t.Fatalf("Accept2WayPayment: %v", err)
	}

	if len(submitted) != 1 {
		t.Fatalf("expected exactly one /v1/transactions submission, got %d", len(submitted))
	}
	var sub struct {
		Transactions []struct {
			DruidInfo *struct {
				Druid        string             `json:"druid"`
				Expectations []DruidExpectation `json:"expectations"`
				GenesisHash  *string            `json:"genesis_hash"`
			} `json:"druid_info"`
			Fees json.RawMessage `json:"fees"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(submitted[0], &sub); err != nil {
		t.Fatalf("unmarshal submitted body: %v", err)
	}
	if len(sub.Transactions) != 1 {
		t.Fatalf("submitted body: expected 1 transaction, got %d", len(sub.Transactions))
	}
	tx := sub.Transactions[0]
	if string(tx.Fees) != "null" {
		t.Errorf("submitted tx fees: got %s want null", tx.Fees)
	}
	if tx.DruidInfo == nil {
		t.Fatal("submitted tx: expected druid_info to be set")
	}
	if tx.DruidInfo.GenesisHash != nil {
		t.Errorf("submitted tx druid_info.genesis_hash: got %v want null", *tx.DruidInfo.GenesisHash)
	}
	if tx.DruidInfo.Druid != f.Druid {
		t.Errorf("submitted tx druid_info.druid: got %s want %s", tx.DruidInfo.Druid, f.Druid)
	}
	if len(tx.DruidInfo.Expectations) != 1 || tx.DruidInfo.Expectations[0].To != f.ReceiverExpectation.To {
		t.Errorf("submitted tx druid_info.expectations: got %+v, want [%+v]", tx.DruidInfo.Expectations, f.ReceiverExpectation)
	}

	// Valence must have received the accepted status with senderExpectation.from filled.
	if len(valenceSrv.posted) != 1 {
		t.Fatalf("expected exactly one valence POST, got %d", len(valenceSrv.posted))
	}
	posted := valenceSrv.posted[0]
	if posted.address != f.SenderExpectation.To {
		t.Errorf("valence POST address header: got %s want %s", posted.address, f.SenderExpectation.To)
	}
	data := posted.body["data"].(map[string]any)
	if data["status"] != "accepted" {
		t.Errorf("valence POST body data.status: got %v want accepted", data["status"])
	}
	senderExp := data["senderExpectation"].(map[string]any)
	if senderExp["from"] == "" || senderExp["from"] == nil {
		t.Error("valence POST body data.senderExpectation.from: expected non-empty")
	}
}

// TestReject2WayPayment_PostsRejectedWithoutSubmitting asserts
// Reject2WayPayment never submits a transaction, only updates valence.
func TestReject2WayPayment_PostsRejectedWithoutSubmitting(t *testing.T) {
	f := loadTwoWayFixture(t)

	details := Pending2WTxDetails{
		Druid:               f.Druid,
		SenderExpectation:   f.SenderExpectation,
		ReceiverExpectation: f.ReceiverExpectation,
		Status:              Pending2WTxStatusPending,
	}

	balance := accepterBalance(details.ReceiverExpectation.To, details.SenderExpectation.Asset.GenesisHash, details.SenderExpectation.Asset.Amount)
	var submitted [][]byte
	mempoolSrv := newBalanceMempoolServer(t, balance, &submitted)
	defer mempoolSrv.Close()
	details.MempoolHost = mempoolSrv.URL

	valenceSrv := newStatefulValenceServer(t)
	defer valenceSrv.close()

	w := &Wallet{Client: NewClient(Config{Mempool: mempoolSrv.URL, Valence: valenceSrv.srv.URL}), encKey: f.EncKey}

	allKeypairs := append([]crypto.EncryptedKeypair{f.CP}, f.Ours...)
	if err := w.Reject2WayPayment(context.Background(), details, allKeypairs); err != nil {
		t.Fatalf("Reject2WayPayment: %v", err)
	}

	if len(submitted) != 0 {
		t.Fatalf("Reject2WayPayment must not submit a transaction, got %d submissions", len(submitted))
	}
	if len(valenceSrv.posted) != 1 {
		t.Fatalf("expected exactly one valence POST, got %d", len(valenceSrv.posted))
	}
	data := valenceSrv.posted[0].body["data"].(map[string]any)
	if data["status"] != "rejected" {
		t.Errorf("valence POST body data.status: got %v want rejected", data["status"])
	}
}

// TestFetchPending2WayPayment_DiscoversIncomingOfferForAcceptor is the
// load-bearing test for the acceptor role: a wallet that never called
// Make2WayPayment (so it has no stored halves at all) must still see an
// offer that landed in one of its own addresses' mailboxes, surfaced in the
// returned pending map so the caller can Accept2WayPayment/
// Reject2WayPayment it. This is the exact scenario that failed against a
// live testnet: FetchPending2WayPayment only ever derived mailboxes from
// stored, so an acceptor with an empty stored slice polled nothing and the
// offer was never discovered.
func TestFetchPending2WayPayment_DiscoversIncomingOfferForAcceptor(t *testing.T) {
	f := loadTwoWayFixture(t)

	valenceSrv := newStatefulValenceServer(t)
	defer valenceSrv.close()

	// Simulate the initiator having already posted an offer into the
	// acceptor's mailbox (f.CP.Address == f.ReceiverExpectation.To, the
	// paymentAddress Make2WayPayment would have used), out of band.
	offer := Pending2WTxDetails{
		Druid:               f.Druid,
		SenderExpectation:   f.SenderExpectation,
		ReceiverExpectation: f.ReceiverExpectation,
		Status:              Pending2WTxStatusPending,
		MempoolHost:         "https://mempool.lineage.to",
	}
	valenceSrv.store[f.Druid] = offer

	// The acceptor wallet: no stored halves (it never initiated anything),
	// and only holds its own keypair — not the initiator's.
	w := &Wallet{Client: NewClient(Config{Valence: valenceSrv.srv.URL}), encKey: f.EncKey}

	pending, settled, err := w.FetchPending2WayPayment(context.Background(), nil, []crypto.EncryptedKeypair{f.CP})
	if err != nil {
		t.Fatalf("FetchPending2WayPayment: %v", err)
	}

	if len(settled) != 0 {
		t.Errorf("settled: got %v, want none (this wallet never initiated the offer)", settled)
	}
	got, ok := pending[f.Druid]
	if !ok {
		t.Fatalf("pending: expected druid %s to be discovered, got %v", f.Druid, pending)
	}
	if got.Status != Pending2WTxStatusPending {
		t.Errorf("pending[druid].Status: got %s want %s", got.Status, Pending2WTxStatusPending)
	}
	if got.SenderExpectation.To != f.SenderExpectation.To {
		t.Errorf("pending[druid].SenderExpectation.To: got %s want %s", got.SenderExpectation.To, f.SenderExpectation.To)
	}
}

// TestFetchPending2WayPayment_SettlesAcceptedStoredHalf is the load-bearing
// test for the make -> (counterparty accepts, out of band) -> fetch
// second-pass settlement path: FetchPending2WayPayment must recognize a
// stored half whose valence entry flipped to "accepted", decrypt it, fill in
// the counterparty-supplied senderExpectation.from, submit it to this
// wallet's own mempool, and delete the settled valence entry.
func TestFetchPending2WayPayment_SettlesAcceptedStoredHalf(t *testing.T) {
	f := loadTwoWayFixture(t)

	var submitted [][]byte
	mempoolSrv := newBalanceMempoolServer(t, f.Balance, &submitted)
	defer mempoolSrv.Close()

	valenceSrv := newStatefulValenceServer(t)
	defer valenceSrv.close()

	w := &Wallet{Client: NewClient(Config{Mempool: mempoolSrv.URL, Valence: valenceSrv.srv.URL}), encKey: f.EncKey}

	paymentAddress := f.ReceiverExpectation.To
	sendingAsset := f.ReceiverExpectation.Asset
	receivingAsset := f.SenderExpectation.Asset
	receiveKeypair := f.Ours[0]

	half, err := w.Make2WayPayment(context.Background(), paymentAddress, sendingAsset, receivingAsset, f.Ours, receiveKeypair)
	if err != nil {
		t.Fatalf("Make2WayPayment: %v", err)
	}
	submitted = nil // discount balance-only traffic from Make2WayPayment; no /v1/transactions calls expected from it anyway

	// Simulate the counterparty accepting out of band: valence's entry for
	// this druid flips to "accepted", carrying the counterparty-filled
	// senderExpectation.from.
	filledSenderExpectation := half.SenderExpectation
	filledSenderExpectation.From = "counterparty-supplied-tx-ins-address"
	valenceSrv.setStatus(t, half.Druid, Pending2WTxStatusAccepted, filledSenderExpectation)

	pending, settled, err := w.FetchPending2WayPayment(context.Background(), []PendingHalf{half}, f.Ours)
	if err != nil {
		t.Fatalf("FetchPending2WayPayment: %v", err)
	}

	if len(settled) != 1 || settled[0] != half.Druid {
		t.Errorf("settled: got %v want [%s]", settled, half.Druid)
	}
	if _, ok := pending[half.Druid]; ok {
		t.Errorf("pending: settled druid %s should not still be pending: %+v", half.Druid, pending[half.Druid])
	}

	if len(submitted) != 1 {
		t.Fatalf("expected exactly one /v1/transactions submission from the settle pass, got %d", len(submitted))
	}
	var sub struct {
		Transactions []struct {
			DruidInfo *struct {
				Expectations []DruidExpectation `json:"expectations"`
				GenesisHash  *string            `json:"genesis_hash"`
			} `json:"druid_info"`
			Fees json.RawMessage `json:"fees"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(submitted[0], &sub); err != nil {
		t.Fatalf("unmarshal submitted body: %v", err)
	}
	if len(sub.Transactions) != 1 {
		t.Fatalf("submitted body: expected 1 transaction, got %d", len(sub.Transactions))
	}
	tx := sub.Transactions[0]
	if string(tx.Fees) != "null" {
		t.Errorf("submitted tx fees: got %s want null", tx.Fees)
	}
	if tx.DruidInfo == nil || tx.DruidInfo.GenesisHash != nil {
		t.Errorf("submitted tx druid_info.genesis_hash: expected null, got %+v", tx.DruidInfo)
	}
	if len(tx.DruidInfo.Expectations) != 1 || tx.DruidInfo.Expectations[0].From != "counterparty-supplied-tx-ins-address" {
		t.Errorf("submitted tx druid_info.expectations: got %+v, want from=counterparty-supplied-tx-ins-address", tx.DruidInfo.Expectations)
	}

	if len(valenceSrv.deleted) != 1 || valenceSrv.deleted[0] != half.Druid {
		t.Errorf("valence deleted: got %v want [%s]", valenceSrv.deleted, half.Druid)
	}
}
