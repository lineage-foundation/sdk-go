package sdkgo

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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
