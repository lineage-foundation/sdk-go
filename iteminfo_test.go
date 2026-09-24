package sdkgo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// itemInfoBody is a representative GET /v1/items/{genesis_hash} 200 payload,
// matching the resolver wire contract verbatim.
const itemInfoBody = `{"genesis_hash":"gh1","metadata":"ticket #1","total_amount":1000,"created":{"block_num":42,"tx_hash":"gh1"},"creator_address":"addr_creator"}`

// itemServer spins up a storage host serving GET /v1/items/{hash}: it counts
// every request in hits, and replies with status/body. A request to any other
// path fails the test.
func itemServer(t *testing.T, hits *atomic.Int64, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/items/") {
			t.Fatalf("unexpected path: %s %s", r.Method, r.URL)
		}
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s want GET", r.Method)
		}
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestGetItemInfo_Success(t *testing.T) {
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusOK, itemInfoBody)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	got, err := c.GetItemInfo(context.Background(), "gh1")
	if err != nil {
		t.Fatalf("GetItemInfo: %v", err)
	}
	if got.GenesisHash != "gh1" || got.Metadata == nil || *got.Metadata != "ticket #1" {
		t.Fatalf("GetItemInfo: got %+v", got)
	}
	if got.TotalAmount != 1000 || got.Created.BlockNum != 42 || got.Created.TxHash != "gh1" {
		t.Fatalf("GetItemInfo created/amount: got %+v", got)
	}
	if got.CreatorAddress == nil || *got.CreatorAddress != "addr_creator" {
		t.Fatalf("GetItemInfo creator: got %+v", got)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("resolver hits: got %d want 1", n)
	}
}

func TestGetItemInfo_CachesSuccess(t *testing.T) {
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusOK, itemInfoBody)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	if _, err := c.GetItemInfo(context.Background(), "gh1"); err != nil {
		t.Fatalf("GetItemInfo (first): %v", err)
	}
	if _, err := c.GetItemInfo(context.Background(), "gh1"); err != nil {
		t.Fatalf("GetItemInfo (second): %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("resolver hits: got %d want 1 (second call must be cached)", n)
	}
}

func TestGetItemInfo_NotFoundErrorsAndIsNotCached(t *testing.T) {
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusNotFound, `{"type":"about:blank","title":"Not Found","status":404}`)
	defer storage.Close()

	c := NewClient(Config{Mempool: storage.URL, Storage: storage.URL})
	if _, err := c.GetItemInfo(context.Background(), "gh1"); err == nil {
		t.Fatal("GetItemInfo: expected error for 404")
	}
	// Failure must not be cached: a second call hits the network again.
	if _, err := c.GetItemInfo(context.Background(), "gh1"); err == nil {
		t.Fatal("GetItemInfo: expected error for 404 (second)")
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("resolver hits: got %d want 2 (404 must not be cached)", n)
	}
}

func TestGetItemInfo_NoStorageHost(t *testing.T) {
	c := NewClient(Config{Mempool: "http://example.invalid"})
	if _, err := c.GetItemInfo(context.Background(), "gh1"); err == nil {
		t.Fatal("GetItemInfo: expected error when storage host is unconfigured")
	}
}

// balanceServer serves POST /v1/balances/query on the mempool host, returning
// a fixed balance body. It also fails the test on any unexpected request.
func balanceServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/balances/query" {
			t.Fatalf("unexpected mempool request: %s %s", r.Method, r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
}

// itemUTXO renders one item-asset balance entry with the given inline metadata
// (metaJSON is a raw JSON value: `null` or a quoted string).
func itemUTXO(tHash, genesisHash, metaJSON string) string {
	return fmt.Sprintf(
		`{"out_point":{"t_hash":%q,"n":0},"value":{"Item":{"amount":5,"genesis_hash":%q,"metadata":%s}}}`,
		tHash, genesisHash, metaJSON,
	)
}

func balanceBody(addrEntries string) string {
	return `{"balance":{"total":{"tokens":0,"items":{"gh1":5}},"address_list":{` + addrEntries + `}}}`
}

// newTestWallet builds an initialized Wallet pointed at the given hosts.
func newTestWallet(t *testing.T, mempool, storage string) *Wallet {
	t.Helper()
	w := NewWallet(Config{Mempool: mempool, Storage: storage})
	if _, err := w.InitNew("test"); err != nil {
		t.Fatalf("InitNew: %v", err)
	}
	return w
}

func TestFetchBalance_EnrichesItemMetadata(t *testing.T) {
	mempool := balanceServer(t, balanceBody(`"addr1":[`+itemUTXO("t0", "gh1", "null")+`]`))
	defer mempool.Close()
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusOK, itemInfoBody)
	defer storage.Close()

	w := newTestWallet(t, mempool.URL, storage.URL)
	bal, err := w.FetchBalance(context.Background(), []string{"addr1"})
	if err != nil {
		t.Fatalf("FetchBalance: %v", err)
	}
	entry := bal.AddressList["addr1"][0]
	if entry.Value.Metadata == nil || *entry.Value.Metadata != "ticket #1" {
		t.Fatalf("enriched metadata: got %v", entry.Value.Metadata)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("resolver hits: got %d want 1", n)
	}
}

func TestFetchBalance_NoStorageHostSkipsEnrichment(t *testing.T) {
	mempool := balanceServer(t, balanceBody(`"addr1":[`+itemUTXO("t0", "gh1", `"inline meta"`)+`]`))
	defer mempool.Close()

	// No storage server at all: if enrichment tried to resolve, there would
	// be nothing listening and the request would fail/hang.
	w := newTestWallet(t, mempool.URL, "")
	bal, err := w.FetchBalance(context.Background(), []string{"addr1"})
	if err != nil {
		t.Fatalf("FetchBalance: %v", err)
	}
	entry := bal.AddressList["addr1"][0]
	if entry.Value.Metadata == nil || *entry.Value.Metadata != "inline meta" {
		t.Fatalf("metadata: got %v want unchanged inline value", entry.Value.Metadata)
	}
}

func TestFetchBalance_DedupsAndCachesAcrossListings(t *testing.T) {
	// Two addresses, same genesis hash -> exactly one resolver call.
	body := balanceBody(`"addr1":[` + itemUTXO("t0", "gh1", "null") + `],"addr2":[` + itemUTXO("t1", "gh1", "null") + `]`)
	mempool := balanceServer(t, body)
	defer mempool.Close()
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusOK, itemInfoBody)
	defer storage.Close()

	w := newTestWallet(t, mempool.URL, storage.URL)

	bal, err := w.FetchBalance(context.Background(), []string{"addr1", "addr2"})
	if err != nil {
		t.Fatalf("FetchBalance: %v", err)
	}
	if m := bal.AddressList["addr2"][0].Value.Metadata; m == nil || *m != "ticket #1" {
		t.Fatalf("addr2 metadata: got %v", m)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("resolver hits after first listing: got %d want 1 (dedup)", n)
	}

	// A repeat listing must issue no further resolver calls (cache hit).
	if _, err := w.FetchBalance(context.Background(), []string{"addr1", "addr2"}); err != nil {
		t.Fatalf("FetchBalance (repeat): %v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Fatalf("resolver hits after repeat listing: got %d want 1 (cache)", n)
	}
}

func TestFetchBalance_GracefulDegradeOnResolverError(t *testing.T) {
	mempool := balanceServer(t, balanceBody(`"addr1":[`+itemUTXO("t0", "gh1", "null")+`]`))
	defer mempool.Close()
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusInternalServerError, `{"type":"about:blank","title":"boom","status":500}`)
	defer storage.Close()

	w := newTestWallet(t, mempool.URL, storage.URL)
	bal, err := w.FetchBalance(context.Background(), []string{"addr1"})
	if err != nil {
		t.Fatalf("FetchBalance must still succeed on resolver error: %v", err)
	}
	if m := bal.AddressList["addr1"][0].Value.Metadata; m != nil {
		t.Fatalf("metadata: got %v want nil (graceful degrade)", m)
	}
}

func TestFetchBalance_ResolveMissDoesNotClobberInlineMetadata(t *testing.T) {
	// Item arrives WITH inline metadata; resolver fails -> keep the inline value.
	mempool := balanceServer(t, balanceBody(`"addr1":[`+itemUTXO("t0", "gh1", `"inline meta"`)+`]`))
	defer mempool.Close()
	var hits atomic.Int64
	storage := itemServer(t, &hits, http.StatusInternalServerError, `{"type":"about:blank","title":"boom","status":500}`)
	defer storage.Close()

	w := newTestWallet(t, mempool.URL, storage.URL)
	bal, err := w.FetchBalance(context.Background(), []string{"addr1"})
	if err != nil {
		t.Fatalf("FetchBalance: %v", err)
	}
	if m := bal.AddressList["addr1"][0].Value.Metadata; m == nil || *m != "inline meta" {
		t.Fatalf("inline metadata must be preserved on resolve miss: got %v", m)
	}
}

func TestFetchBalance_OptOutIssuesNoResolverCalls(t *testing.T) {
	mempool := balanceServer(t, balanceBody(`"addr1":[`+itemUTXO("t0", "gh1", "null")+`]`))
	defer mempool.Close()
	// This storage server fails the test if it is ever hit.
	storage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("opt-out issued a resolver call: %s %s", r.Method, r.URL)
	}))
	defer storage.Close()

	w := newTestWallet(t, mempool.URL, storage.URL)
	bal, err := w.FetchBalance(context.Background(), []string{"addr1"}, WithoutEnrichment())
	if err != nil {
		t.Fatalf("FetchBalance: %v", err)
	}
	if m := bal.AddressList["addr1"][0].Value.Metadata; m != nil {
		t.Fatalf("opt-out must leave items unmodified: got %v", m)
	}
}
