package sdkgo

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// serverExpect spins up an httptest.Server that asserts the request's method,
// path (including query string), and — when wantAPIKey is non-empty — the
// x-api-key header, then replies with the given status and body.
func serverExpect(t *testing.T, wantMethod, wantPath, wantAPIKey string, wantBody string, status int, respBody string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != wantMethod {
			t.Errorf("method: got %s want %s", r.Method, wantMethod)
		}
		if got := r.URL.RequestURI(); got != wantPath {
			t.Errorf("path: got %s want %s", got, wantPath)
		}
		if wantAPIKey != "" {
			if got := r.Header.Get("x-api-key"); got != wantAPIKey {
				t.Errorf("x-api-key: got %q want %q", got, wantAPIKey)
			}
		} else if got := r.Header.Get("x-api-key"); got != "" {
			t.Errorf("x-api-key: unexpectedly set to %q", got)
		}
		if wantBody != "" {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("read body: %v", err)
			}
			if got := string(b); got != wantBody {
				t.Errorf("body: got %s want %s", got, wantBody)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type: got %q want application/json", got)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	}))
}

func TestQueryBalances_Success(t *testing.T) {
	const respBody = `{"balance":{"total":{"tokens":100,"items":{}},"address_list":{"addr1":[{"out_point":{"t_hash":"abc","n":0},"value":{"Token":100}}]}}}`
	srv := serverExpect(t, http.MethodPost, "/v1/balances/query", "test-key", `{"addresses":["addr1"]}`, http.StatusOK, respBody)
	defer srv.Close()

	c := NewClient(Config{Mempool: srv.URL, Storage: srv.URL, APIKey: "test-key"})
	got, err := c.QueryBalances(context.Background(), []string{"addr1"})
	if err != nil {
		t.Fatalf("QueryBalances: %v", err)
	}
	if got.Total.Tokens != 100 {
		t.Fatalf("Total.Tokens: got %d want 100", got.Total.Tokens)
	}
	entries := got.AddressList["addr1"]
	if len(entries) != 1 || entries[0].OutPoint.THash != "abc" || entries[0].Value.Amount != 100 {
		t.Fatalf("AddressList[addr1]: got %+v", entries)
	}
}

func TestQueryBalances_NoAPIKey(t *testing.T) {
	const respBody = `{"balance":{"total":{"tokens":0,"items":{}},"address_list":{}}}`
	srv := serverExpect(t, http.MethodPost, "/v1/balances/query", "", `{"addresses":["addr1"]}`, http.StatusOK, respBody)
	defer srv.Close()

	c := NewClient(Config{Mempool: srv.URL, Storage: srv.URL})
	if _, err := c.QueryBalances(context.Background(), []string{"addr1"}); err != nil {
		t.Fatalf("QueryBalances: %v", err)
	}
}

func TestQueryBalances_APIError(t *testing.T) {
	const problem = `{"type":"about:blank","title":"Bad Request","status":400,"detail":"addresses must not be empty","code":"invalid_request"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(problem))
	}))
	defer srv.Close()

	c := NewClient(Config{Mempool: srv.URL, Storage: srv.URL})
	_, err := c.QueryBalances(context.Background(), []string{})
	if err == nil {
		t.Fatal("QueryBalances: expected error")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("QueryBalances: expected *APIError, got %T: %v", err, err)
	}
	if apiErr.Status != 400 || apiErr.Title != "Bad Request" || apiErr.Detail != "addresses must not be empty" || apiErr.Code != "invalid_request" {
		t.Fatalf("APIError: got %+v", apiErr)
	}
	if got, want := apiErr.Error(), "addresses must not be empty"; got != want {
		t.Fatalf("Error(): got %q want %q", got, want)
	}
}

func TestBalances_GetsMempoolHost(t *testing.T) {
	const respBody = `{"balance":{"total":{"tokens":5,"items":{}},"address_list":{}}}`
	mempool := serverExpect(t, http.MethodGet, "/v1/balances?address=addr1&address=addr2", "", "", http.StatusOK, respBody)
	defer mempool.Close()
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to storage host: %s %s", r.Method, r.URL)
	}))
	defer storage.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: storage.URL})
	got, err := c.Balances(context.Background(), []string{"addr1", "addr2"})
	if err != nil {
		t.Fatalf("Balances: %v", err)
	}
	if got.Total.Tokens != 5 {
		t.Fatalf("Total.Tokens: got %d want 5", got.Total.Tokens)
	}
}

func TestSupply_UsesMempoolHost(t *testing.T) {
	mempool := serverExpect(t, http.MethodGet, "/v1/supply", "", "", http.StatusOK, `{"total":100000000,"issued":42}`)
	defer mempool.Close()
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to storage host: %s %s", r.Method, r.URL)
	}))
	defer storage.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: storage.URL})
	got, err := c.Supply(context.Background())
	if err != nil {
		t.Fatalf("Supply: %v", err)
	}
	if got.Total != 100000000 || got.Issued != 42 {
		t.Fatalf("Supply: got %+v", got)
	}
}

func TestTransactionStatus(t *testing.T) {
	const respBody = `{"deadbeef":{"status":"Confirmed","timestamp":1700000000,"additional_info":"in block 5"}}`
	mempool := serverExpect(t, http.MethodGet, "/v1/transactions/status?hash=deadbeef", "", "", http.StatusOK, respBody)
	defer mempool.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: mempool.URL})
	got, err := c.TransactionStatus(context.Background(), []string{"deadbeef"})
	if err != nil {
		t.Fatalf("TransactionStatus: %v", err)
	}
	st, ok := got["deadbeef"]
	if !ok || st.Status != TxStatusConfirmed || st.Timestamp != 1700000000 || st.AdditionalInfo != "in block 5" {
		t.Fatalf("TransactionStatus: got %+v", got)
	}
}

func TestQueryTransactionStatus(t *testing.T) {
	const respBody = `{"deadbeef":{"status":"Pending","timestamp":1700000000,"additional_info":""}}`
	mempool := serverExpect(t, http.MethodPost, "/v1/transactions/status:query", "", `{"hashes":["deadbeef"]}`, http.StatusOK, respBody)
	defer mempool.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: mempool.URL})
	got, err := c.QueryTransactionStatus(context.Background(), []string{"deadbeef"})
	if err != nil {
		t.Fatalf("QueryTransactionStatus: %v", err)
	}
	if got["deadbeef"].Status != TxStatusPending {
		t.Fatalf("QueryTransactionStatus: got %+v", got)
	}
}

func TestLatestBlock_UsesStorageHost(t *testing.T) {
	const respBody = `{"block":{"header":{"b_num":5}},"difficulty_target":{"compact":"0x1d00ffff","target":"00000000ffff0000000000000000000000000000000000000000000000000000"}}`
	storage := serverExpect(t, http.MethodGet, "/v1/blocks/latest", "", "", http.StatusOK, respBody)
	defer storage.Close()
	mempool := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to mempool host: %s %s", r.Method, r.URL)
	}))
	defer mempool.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: storage.URL})
	got, err := c.LatestBlock(context.Background())
	if err != nil {
		t.Fatalf("LatestBlock: %v", err)
	}
	if got.DifficultyTarget == nil || got.DifficultyTarget.Compact != "0x1d00ffff" {
		t.Fatalf("LatestBlock: got %+v", got)
	}
}

func TestBlockByNum_UsesStorageHost(t *testing.T) {
	const respBody = `{"key":"blk-5","item_meta":{"type":"block","block_num":5,"tx_len":2},"data":{"b_num":5}}`
	storage := serverExpect(t, http.MethodGet, "/v1/blocks/5", "", "", http.StatusOK, respBody)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	got, err := c.BlockByNum(context.Background(), 5)
	if err != nil {
		t.Fatalf("BlockByNum: %v", err)
	}
	if got.Key != "blk-5" || got.ItemMeta.Type != BlockchainItemMetaBlock || got.ItemMeta.BlockNum != 5 || got.ItemMeta.TxLen != 2 {
		t.Fatalf("BlockByNum: got %+v", got)
	}
}

func TestBlocks_UsesStorageHost(t *testing.T) {
	const respBody = `[{"key":"blk-1","item_meta":{"type":"block","block_num":1,"tx_len":0},"data":{}},{"key":"blk-2","item_meta":{"type":"block","block_num":2,"tx_len":1},"data":{}}]`
	storage := serverExpect(t, http.MethodGet, "/v1/blocks?num=1&num=2", "", "", http.StatusOK, respBody)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	got, err := c.Blocks(context.Background(), []uint64{1, 2})
	if err != nil {
		t.Fatalf("Blocks: %v", err)
	}
	if len(got) != 2 || got[0].Key != "blk-1" || got[1].Key != "blk-2" {
		t.Fatalf("Blocks: got %+v", got)
	}
}

func TestBlockchainEntry_UsesStorageHost(t *testing.T) {
	const respBody = `{"key":"some-key","item_meta":{"type":"tx","block_num":3,"tx_num":1},"data":{"foo":"bar"}}`
	storage := serverExpect(t, http.MethodGet, "/v1/blockchain-entries/some-key", "", "", http.StatusOK, respBody)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	got, err := c.BlockchainEntry(context.Background(), "some-key")
	if err != nil {
		t.Fatalf("BlockchainEntry: %v", err)
	}
	if got.Key != "some-key" || got.ItemMeta.Type != BlockchainItemMetaTx || got.ItemMeta.TxNum != 1 {
		t.Fatalf("BlockchainEntry: got %+v", got)
	}
}

func TestQueryBlockchainEntries_UsesStorageHost(t *testing.T) {
	const respBody = `[{"key":"k1","item_meta":{"type":"tx","block_num":3,"tx_num":1},"data":{}}]`
	storage := serverExpect(t, http.MethodPost, "/v1/blockchain-entries/query", "", `{"keys":["k1","k2"]}`, http.StatusOK, respBody)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	got, err := c.QueryBlockchainEntries(context.Background(), []string{"k1", "k2"})
	if err != nil {
		t.Fatalf("QueryBlockchainEntries: %v", err)
	}
	if len(got) != 1 || got[0].Key != "k1" {
		t.Fatalf("QueryBlockchainEntries: got %+v", got)
	}
}

func TestSerializeTransactions_UsesMempoolHost(t *testing.T) {
	tx := CreateTransaction{
		Inputs:  []CreateTxIn{{PreviousOut: &OutPoint{THash: "abc", N: 0}, ScriptSignature: ScriptSig{Pay2PkH: &Pay2PkH{PublicKey: "pub"}}}},
		Outputs: []TxOut{{Value: NewTokenAsset(100), ScriptPublicKey: "addr1"}},
		Version: NetworkVersion,
	}
	wantBody, err := json.Marshal(SerializeTransactionsRequest{Transactions: []CreateTransaction{tx}})
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	const respBody = `{"transactions":[{"txn_hash_hex":"deadbeef","txn_hex":"0102"}]}`
	mempool := serverExpect(t, http.MethodPost, "/v1/transactions:serialize", "", string(wantBody), http.StatusOK, respBody)
	defer mempool.Close()
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to storage host: %s %s", r.Method, r.URL)
	}))
	defer storage.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: storage.URL})
	got, err := c.SerializeTransactions(context.Background(), []CreateTransaction{tx})
	if err != nil {
		t.Fatalf("SerializeTransactions: %v", err)
	}
	if len(got.Transactions) != 1 || got.Transactions[0].TxnHex != "0102" || got.Transactions[0].TxnHashHex != "deadbeef" {
		t.Fatalf("SerializeTransactions: got %+v", got)
	}
}

func TestDeserializeTransactions_UsesMempoolHost(t *testing.T) {
	const respBody = `{"transactions":[{"inputs":[],"outputs":[],"version":2,"druid_info":null}]}`
	mempool := serverExpect(t, http.MethodPost, "/v1/transactions:deserialize", "", `{"transactions":["0102"]}`, http.StatusOK, respBody)
	defer mempool.Close()
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request to storage host: %s %s", r.Method, r.URL)
	}))
	defer storage.Close()

	c := NewClient(Config{Mempool: mempool.URL, Storage: storage.URL})
	got, err := c.DeserializeTransactions(context.Background(), []string{"0102"})
	if err != nil {
		t.Fatalf("DeserializeTransactions: %v", err)
	}
	if len(got.Transactions) != 1 || got.Transactions[0].Version != 2 {
		t.Fatalf("DeserializeTransactions: got %+v", got)
	}
}

func TestNewClient_DefaultsHTTPClient(t *testing.T) {
	c := NewClient(Config{Mempool: "http://example.invalid", Storage: "http://example.invalid"})
	if c.httpClient == nil {
		t.Fatal("NewClient: httpClient should default to a non-nil *http.Client")
	}
}

func TestNewClient_UsesProvidedHTTPClient(t *testing.T) {
	custom := &http.Client{}
	c := NewClient(Config{Mempool: "http://example.invalid", Storage: "http://example.invalid", HTTPClient: custom})
	if c.httpClient != custom {
		t.Fatal("NewClient: should reuse the provided *http.Client")
	}
}
