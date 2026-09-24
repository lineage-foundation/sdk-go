package sdkgo

import (
	"context"
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
