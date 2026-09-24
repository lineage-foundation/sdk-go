package sdkgo

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
)

// ItemCreated records where an item class was minted: the block number and the
// hash of the genesis create transaction.
type ItemCreated struct {
	BlockNum uint64 `json:"block_num"`
	TxHash   string `json:"tx_hash"`
}

// ItemInfo is an item class's genesis facts, as returned by
// GET /v1/items/{genesis_hash} on the storage node. Field tags match the
// resolver wire contract verbatim (snake_case, no renames). Metadata and
// CreatorAddress are pointers so a JSON null decodes to nil.
type ItemInfo struct {
	GenesisHash    string      `json:"genesis_hash"`
	Metadata       *string     `json:"metadata"`
	TotalAmount    int64       `json:"total_amount"`
	Created        ItemCreated `json:"created"`
	CreatorAddress *string     `json:"creator_address"`
}

// cacheGetItemInfo returns the cached ItemInfo for genesisHash, if any.
func (c *Client) cacheGetItemInfo(genesisHash string) (ItemInfo, bool) {
	c.itemInfoMu.RLock()
	defer c.itemInfoMu.RUnlock()
	info, ok := c.itemInfoCache[genesisHash]
	return info, ok
}

// cacheSetItemInfo stores a successfully resolved ItemInfo for genesisHash.
func (c *Client) cacheSetItemInfo(genesisHash string, info ItemInfo) {
	c.itemInfoMu.Lock()
	defer c.itemInfoMu.Unlock()
	c.itemInfoCache[genesisHash] = info
}

// resolveItemInfo returns genesisHash's genesis facts, cache-first. On a cache
// miss it fetches GET {storage}/v1/items/{genesis_hash}, caching (and only
// caching) a successful 200 so failures stay retryable and immutable facts are
// fetched at most once per distinct hash. Errors when the storage host is
// unconfigured or the resolve fails.
func (c *Client) resolveItemInfo(ctx context.Context, genesisHash string) (ItemInfo, error) {
	if info, ok := c.cacheGetItemInfo(genesisHash); ok {
		return info, nil
	}
	if c.storage == "" {
		return ItemInfo{}, errors.New("sdkgo: storage host not configured")
	}
	var info ItemInfo
	path := "/v1/items/" + url.PathEscape(genesisHash)
	if err := c.doJSON(ctx, http.MethodGet, c.storage, path, nil, &info); err != nil {
		return ItemInfo{}, err
	}
	c.cacheSetItemInfo(genesisHash, info)
	return info, nil
}

// GetItemInfo resolves an item class's full genesis facts (metadata, total
// supply, and provenance) by its genesis hash, from the storage node. Results
// are memoized on this Client instance; a 404 (unknown item) or any other
// non-2xx response is returned as an error and is not cached (so it stays
// retryable). Shares the cache that holdings enrichment populates.
func (c *Client) GetItemInfo(ctx context.Context, genesisHash string) (ItemInfo, error) {
	return c.resolveItemInfo(ctx, genesisHash)
}

// fetchItemInfo warms the cache for genesisHash, ignoring any error. It is the
// best-effort entry point used by holdings enrichment, where a failed resolve
// simply leaves the item's metadata untouched.
func (c *Client) fetchItemInfo(ctx context.Context, genesisHash string) {
	_, _ = c.resolveItemInfo(ctx, genesisHash)
}

// balanceOptions holds the resolved settings for a balance listing.
type balanceOptions struct {
	enrich bool
}

// BalanceOption customizes a balance listing (see Wallet.FetchBalance).
type BalanceOption func(*balanceOptions)

// WithoutEnrichment disables item-metadata enrichment for a single balance
// listing: no resolver calls are issued and item metadata is left exactly as
// the node returned it.
func WithoutEnrichment() BalanceOption {
	return func(o *balanceOptions) { o.enrich = false }
}

// enrichBalance attaches each item's genesis metadata to the item UTXOs in bal,
// in place. It collects the distinct item genesis hashes, resolves the
// cache-misses concurrently (one goroutine per distinct miss), and writes the
// resolved metadata onto every matching item.
//
// Enrichment is best-effort: it never returns an error, a failed or unknown
// (404) resolve leaves that item's metadata untouched (so inline metadata is
// preserved and transferred items keep their nil), and each resolve goroutine
// recovers from any panic so enrichment can never fail the enclosing listing.
func (c *Client) enrichBalance(ctx context.Context, bal *FetchBalanceResponse) {
	defer func() { _ = recover() }()

	if c.storage == "" {
		return // no storage host configured: enrichment is silently skipped
	}

	hashes := make(map[string]struct{})
	for _, entries := range bal.AddressList {
		for _, e := range entries {
			if e.Value.Kind == AssetKindItem && e.Value.GenesisHash != "" {
				hashes[e.Value.GenesisHash] = struct{}{}
			}
		}
	}
	if len(hashes) == 0 {
		return
	}

	var wg sync.WaitGroup
	for h := range hashes {
		if _, ok := c.cacheGetItemInfo(h); ok {
			continue // already resolved on a previous listing
		}
		wg.Add(1)
		go func(hash string) {
			defer wg.Done()
			defer func() { _ = recover() }()
			c.fetchItemInfo(ctx, hash)
		}(h)
	}
	wg.Wait()

	for _, entries := range bal.AddressList {
		for i := range entries {
			if entries[i].Value.Kind != AssetKindItem {
				continue
			}
			// Only overwrite on a successful resolve (cache hit); a miss must
			// not clobber metadata the item already carried.
			if info, ok := c.cacheGetItemInfo(entries[i].Value.GenesisHash); ok {
				// Aliases the cached ItemInfo's metadata pointer, not a copy:
				// callers must treat entries[i].Value.Metadata as read-only.
				entries[i].Value.Metadata = info.Metadata
			}
		}
	}
}
