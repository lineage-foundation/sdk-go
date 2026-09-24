package sdkgo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// defaultHTTPTimeout bounds how long a single request may take when the caller
// doesn't supply their own *http.Client.
const defaultHTTPTimeout = 30 * time.Second

// Config configures a Client: the mempool and storage node base URLs, an optional
// API key, and an optional *http.Client override.
type Config struct {
	// Mempool is the base URL of a mempool-capable node (supply, balances,
	// transaction status).
	Mempool string
	// Storage is the base URL of a storage-capable node (blocks, blockchain entries).
	Storage string
	// Valence is the base URL of a valence mailbox host, used by Wallet's
	// two-way payment methods (Make2WayPayment, FetchPending2WayPayment,
	// Accept2WayPayment, Reject2WayPayment) to exchange DRUID trade offers
	// with a counterparty.
	Valence string
	// APIKey, when set, is sent as the x-api-key header on every request.
	APIKey string
	// HTTPClient, when set, is used instead of a default *http.Client.
	HTTPClient *http.Client
}

// Client is a keyless read client for the Lineage /v1 API.
type Client struct {
	mempool    string
	storage    string
	valence    string
	apiKey     string
	httpClient *http.Client

	// itemInfoMu guards itemInfoCache.
	itemInfoMu sync.RWMutex
	// itemInfoCache memoizes successful GET /v1/items/{genesis_hash}
	// resolves, keyed by genesis hash. Item genesis facts are immutable, so
	// entries never expire and only HTTP 200 responses are stored (failures
	// stay retryable). Populated by resolveItemInfo; read during holdings
	// enrichment and by GetItemInfo.
	itemInfoCache map[string]ItemInfo
}

// NewClient builds a Client from the given Config. If cfg.HTTPClient is nil, a
// *http.Client with a sensible default timeout is used instead.
func NewClient(cfg Config) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultHTTPTimeout}
	}
	return &Client{
		mempool:       cfg.Mempool,
		storage:       cfg.Storage,
		valence:       cfg.Valence,
		apiKey:        cfg.APIKey,
		httpClient:    httpClient,
		itemInfoCache: make(map[string]ItemInfo),
	}
}

// doJSON executes an HTTP request against host+path. If body is non-nil it is
// marshaled as the JSON request body and Content-Type is set to
// application/json. The x-api-key header is set when the Client was configured
// with an API key. On a non-2xx response, the body is decoded as an
// application/problem+json APIError and returned as the error; on 2xx it is
// decoded into out (when out is non-nil).
func (c *Client) doJSON(ctx context.Context, method, host, path string, body, out any) error {
	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sdkgo: marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequestWithContext(ctx, method, host+path, reqBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, host+path, nil)
	}
	if err != nil {
		return fmt.Errorf("sdkgo: build request: %w", err)
	}

	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("x-api-key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sdkgo: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err != nil {
			return fmt.Errorf("sdkgo: %s %s: status %d, decode error body: %w", method, path, resp.StatusCode, err)
		}
		return &apiErr
	}

	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("sdkgo: %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// addressesQuery is the request body for POST /v1/balances/query, mirroring the
// server's AddressesQuery.
type addressesQuery struct {
	Addresses []string `json:"addresses"`
}

// hashesQuery is the request body for POST /v1/transactions/status:query, mirroring
// the server's HashesQuery.
type hashesQuery struct {
	Hashes []string `json:"hashes"`
}

// keysQuery is the request body for POST /v1/blockchain-entries/query, mirroring the
// server's KeysQuery.
type keysQuery struct {
	Keys []string `json:"keys"`
}

// Supply returns the total and currently issued token supply. Hits the mempool host.
func (c *Client) Supply(ctx context.Context) (SupplyResponse, error) {
	var out SupplyResponse
	err := c.doJSON(ctx, http.MethodGet, c.mempool, "/v1/supply", nil, &out)
	return out, err
}

// Balances returns UTXO balances for the given addresses via a GET request (the
// addresses are repeated as `address` query parameters). Hits the mempool host.
func (c *Client) Balances(ctx context.Context, addresses []string) (FetchBalanceResponse, error) {
	v := url.Values{}
	for _, a := range addresses {
		v.Add("address", a)
	}
	var out BalancesResponse
	err := c.doJSON(ctx, http.MethodGet, c.mempool, "/v1/balances?"+v.Encode(), nil, &out)
	return out.Balance, err
}

// QueryBalances returns UTXO balances for the given addresses via a POST request,
// suited to larger address batches than Balances. Hits the mempool host.
func (c *Client) QueryBalances(ctx context.Context, addresses []string) (FetchBalanceResponse, error) {
	var out BalancesResponse
	err := c.doJSON(ctx, http.MethodPost, c.mempool, "/v1/balances/query", addressesQuery{Addresses: addresses}, &out)
	return out.Balance, err
}

// TransactionStatus returns mempool status for the given transaction hashes via a GET
// request (the hashes are repeated as `hash` query parameters). Hits the mempool host.
func (c *Client) TransactionStatus(ctx context.Context, hashes []string) (map[string]TxStatus, error) {
	v := url.Values{}
	for _, h := range hashes {
		v.Add("hash", h)
	}
	out := map[string]TxStatus{}
	err := c.doJSON(ctx, http.MethodGet, c.mempool, "/v1/transactions/status?"+v.Encode(), nil, &out)
	return out, err
}

// QueryTransactionStatus returns mempool status for the given transaction hashes via
// a POST request, suited to larger hash batches than TransactionStatus. Hits the
// mempool host.
func (c *Client) QueryTransactionStatus(ctx context.Context, hashes []string) (map[string]TxStatus, error) {
	out := map[string]TxStatus{}
	err := c.doJSON(ctx, http.MethodPost, c.mempool, "/v1/transactions/status:query", hashesQuery{Hashes: hashes}, &out)
	return out, err
}

// SerializeTransactions serializes one or more transactions to hex-encoded
// bytes, without submitting them to the mempool. Stateless; not tied to any
// node's mempool or wallet, but the request is sent to the mempool host
// alongside this SDK's other `/v1/transactions*` calls.
func (c *Client) SerializeTransactions(ctx context.Context, txs []CreateTransaction) (SerializeTransactionsResponse, error) {
	var out SerializeTransactionsResponse
	err := c.doJSON(ctx, http.MethodPost, c.mempool, "/v1/transactions:serialize", SerializeTransactionsRequest{Transactions: txs}, &out)
	return out, err
}

// DeserializeTransactions decodes one or more hex-encoded serialized
// transactions, without submitting them to the mempool. Stateless; not tied
// to any node's mempool or wallet, but the request is sent to the mempool
// host alongside this SDK's other `/v1/transactions*` calls.
func (c *Client) DeserializeTransactions(ctx context.Context, hexTxs []string) (DeserializeTransactionsResponse, error) {
	var out DeserializeTransactionsResponse
	err := c.doJSON(ctx, http.MethodPost, c.mempool, "/v1/transactions:deserialize", DeserializeTransactionsRequest{Transactions: hexTxs}, &out)
	return out, err
}

// LatestBlock returns the most recently stored block. Hits the storage host.
func (c *Client) LatestBlock(ctx context.Context) (LatestBlockResponse, error) {
	var out LatestBlockResponse
	err := c.doJSON(ctx, http.MethodGet, c.storage, "/v1/blocks/latest", nil, &out)
	return out, err
}

// BlockByNum returns the stored block entry at the given block number. Hits the
// storage host.
func (c *Client) BlockByNum(ctx context.Context, num uint64) (BlockchainEntry, error) {
	var out BlockchainEntry
	path := "/v1/blocks/" + strconv.FormatUint(num, 10)
	err := c.doJSON(ctx, http.MethodGet, c.storage, path, nil, &out)
	return out, err
}

// Blocks batch-looks-up stored block entries by number; numbers with no stored block
// are omitted from the result rather than erroring. Hits the storage host.
func (c *Client) Blocks(ctx context.Context, nums []uint64) ([]BlockchainEntry, error) {
	v := url.Values{}
	for _, n := range nums {
		v.Add("num", strconv.FormatUint(n, 10))
	}
	out := []BlockchainEntry{}
	err := c.doJSON(ctx, http.MethodGet, c.storage, "/v1/blocks?"+v.Encode(), nil, &out)
	return out, err
}

// BlockchainEntry returns the stored blockchain entry (block or transaction) at the
// given raw storage key. Hits the storage host.
func (c *Client) BlockchainEntry(ctx context.Context, key string) (BlockchainEntry, error) {
	var out BlockchainEntry
	path := "/v1/blockchain-entries/" + url.PathEscape(key)
	err := c.doJSON(ctx, http.MethodGet, c.storage, path, nil, &out)
	return out, err
}

// QueryBlockchainEntries batch-looks-up stored blockchain entries by raw storage key;
// keys with no stored entry are omitted from the result rather than erroring. Hits
// the storage host.
func (c *Client) QueryBlockchainEntries(ctx context.Context, keys []string) ([]BlockchainEntry, error) {
	out := []BlockchainEntry{}
	err := c.doJSON(ctx, http.MethodPost, c.storage, "/v1/blockchain-entries/query", keysQuery{Keys: keys}, &out)
	return out, err
}
