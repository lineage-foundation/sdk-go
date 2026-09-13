package sdkgo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// loadValenceFixture loads twoway.json's valenceAuth vector and the matching
// fixed keypair (by address) to sign with.
func loadValenceFixture(t *testing.T) (address, publicKeyHex, signatureHex string, kp crypto.Keypair) {
	t.Helper()
	var v struct {
		ValenceAuth struct {
			Address   string `json:"address"`
			PublicKey string `json:"public_key"`
			Signature string `json:"signature"`
		} `json:"valenceAuth"`
		FixedKeypairs struct {
			Ours []struct {
				Address   string `json:"address"`
				PublicKey string `json:"public_key"`
				SecretKey string `json:"secret_key"`
			} `json:"ours"`
		} `json:"fixedKeypairs"`
	}
	loadVector(t, "twoway.json", &v)

	for _, o := range v.FixedKeypairs.Ours {
		if o.Address == v.ValenceAuth.Address {
			return v.ValenceAuth.Address, v.ValenceAuth.PublicKey, v.ValenceAuth.Signature, crypto.Keypair{
				PublicKey: mustHexDecode(t, o.PublicKey),
				SecretKey: mustHexDecode(t, o.SecretKey),
			}
		}
	}
	t.Fatalf("twoway.json: no fixedKeypairs.ours entry matches valenceAuth.address %s", v.ValenceAuth.Address)
	return "", "", "", crypto.Keypair{}
}

// TestValenceAuthHeaders_MatchesVector is the load-bearing test for the
// valence client's request signing: the address/public_key/signature headers
// a POST /messages request carries must match twoway.json's valenceAuth
// vector byte-for-byte for the fixed address+keypair, proving the signature
// is computed over the raw (unhashed) UTF-8 bytes of the address string.
func TestValenceAuthHeaders_MatchesVector(t *testing.T) {
	wantAddress, wantPublicKey, wantSignature, kp := loadValenceFixture(t)

	var gotAddress, gotPublicKey, gotSignature, gotContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAddress = r.Header.Get("address")
		gotPublicKey = r.Header.Get("public_key")
		gotSignature = r.Header.Get("signature")
		gotContentType = r.Header.Get("Content-Type")
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"id":"DRUID0xtest"}`))
	}))
	defer srv.Close()

	vc := newValenceClient(srv.URL, srv.Client())
	details := Pending2WTxDetails{
		Druid:               "DRUID0xtest",
		SenderExpectation:   DruidExpectation{Asset: NewTokenAsset(1)},
		ReceiverExpectation: DruidExpectation{Asset: NewTokenAsset(1)},
		Status:              Pending2WTxStatusPending,
		MempoolHost:         "http://mempool.invalid",
	}
	if err := vc.Post(context.Background(), wantAddress, kp, details); err != nil {
		t.Fatalf("Post: %v", err)
	}

	if gotAddress != wantAddress {
		t.Errorf("address header: got %q want %q", gotAddress, wantAddress)
	}
	if gotPublicKey != wantPublicKey {
		t.Errorf("public_key header: got %q want %q", gotPublicKey, wantPublicKey)
	}
	if gotSignature != wantSignature {
		t.Errorf("signature header: got %q want %q", gotSignature, wantSignature)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type header: got %q want application/json", gotContentType)
	}
}

// TestValencePost_BodyShape asserts the POST /messages request body is the
// plaintext offer, shaped exactly like sdk-js's IRequestValenceSetBody:
// {"id": <druid>, "data": <Pending2WTxDetails>} with no encryption applied.
func TestValencePost_BodyShape(t *testing.T) {
	_, _, _, kp := loadValenceFixture(t)

	details := Pending2WTxDetails{
		Druid: "DRUID0xabc123",
		SenderExpectation: DruidExpectation{
			From: "", To: "receiver-addr", Asset: NewTokenAsset(50),
		},
		ReceiverExpectation: DruidExpectation{
			From: "", To: "sender-addr", Asset: NewTokenAsset(100),
		},
		Status:      Pending2WTxStatusPending,
		MempoolHost: "http://mempool.example",
	}

	var gotMethod, gotPath string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		gotBody = b
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(`{"id":"DRUID0xabc123"}`))
	}))
	defer srv.Close()

	vc := newValenceClient(srv.URL, srv.Client())
	if err := vc.Post(context.Background(), "receiver-addr", kp, details); err != nil {
		t.Fatalf("Post: %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method: got %s want POST", gotMethod)
	}
	if gotPath != "/messages" {
		t.Errorf("path: got %s want /messages", gotPath)
	}

	wantDataJSON, err := json.Marshal(details)
	if err != nil {
		t.Fatalf("marshal want data: %v", err)
	}
	var wantBody struct {
		ID   string          `json:"id"`
		Data json.RawMessage `json:"data"`
	}
	wantBody.ID = details.Druid
	wantBody.Data = wantDataJSON

	var got struct {
		ID   string          `json:"id"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(gotBody, &got); err != nil {
		t.Fatalf("unmarshal got body: %v", err)
	}
	if got.ID != wantBody.ID {
		t.Errorf("body id: got %s want %s", got.ID, wantBody.ID)
	}
	if !jsonEqual(t, got.Data, wantBody.Data) {
		t.Errorf("body data: got %s want %s", got.Data, wantBody.Data)
	}
}

// TestValenceGet_ReturnsFlatMap asserts GET /messages decodes the mailbox
// response as a flat map keyed by druid (the value being the stored
// Pending2WTxDetails payload directly, not wrapped), and sends the
// address/public_key/signature auth headers.
func TestValenceGet_ReturnsFlatMap(t *testing.T) {
	wantAddress, wantPublicKey, _, kp := loadValenceFixture(t)

	const respBody = `{
		"DRUID0xone": {"druid":"DRUID0xone","senderExpectation":{"from":"","to":"a","asset":{"Token":1}},"receiverExpectation":{"from":"","to":"b","asset":{"Token":2}},"status":"pending","mempoolHost":"http://x"}
	}`

	var gotAddress, gotPublicKey, gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAddress = r.Header.Get("address")
		gotPublicKey = r.Header.Get("public_key")
		gotMethod = r.Method
		gotPath = r.URL.Path
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte(respBody))
	}))
	defer srv.Close()

	vc := newValenceClient(srv.URL, srv.Client())
	got, err := vc.Get(context.Background(), wantAddress, kp)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method: got %s want GET", gotMethod)
	}
	if gotPath != "/messages" {
		t.Errorf("path: got %s want /messages", gotPath)
	}
	if gotAddress != wantAddress {
		t.Errorf("address header: got %q want %q", gotAddress, wantAddress)
	}
	if gotPublicKey != wantPublicKey {
		t.Errorf("public_key header: got %q want %q", gotPublicKey, wantPublicKey)
	}

	entry, ok := got["DRUID0xone"]
	if !ok {
		t.Fatalf("Get result missing DRUID0xone: %+v", got)
	}
	if entry.Status != Pending2WTxStatusPending {
		t.Errorf("entry status: got %q want pending", entry.Status)
	}
	if entry.ReceiverExpectation.To != "b" {
		t.Errorf("entry receiverExpectation.to: got %q want b", entry.ReceiverExpectation.To)
	}
}

// TestValenceDelete_HitsScopedPath asserts DELETE /messages/{druid} is sent
// with the auth headers, scoped to the given druid.
func TestValenceDelete_HitsScopedPath(t *testing.T) {
	wantAddress, _, _, kp := loadValenceFixture(t)

	var gotMethod, gotPath, gotAddress string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAddress = r.Header.Get("address")
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	vc := newValenceClient(srv.URL, srv.Client())
	if err := vc.Delete(context.Background(), "DRUID0xdeleteme", wantAddress, kp); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method: got %s want DELETE", gotMethod)
	}
	if gotPath != "/messages/DRUID0xdeleteme" {
		t.Errorf("path: got %s want /messages/DRUID0xdeleteme", gotPath)
	}
	if gotAddress != wantAddress {
		t.Errorf("address header: got %q want %q", gotAddress, wantAddress)
	}
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	aj, _ := json.Marshal(av)
	bj, _ := json.Marshal(bv)
	return string(aj) == string(bj)
}
