package sdkgo

import (
	"encoding/json"
	"fmt"
)

// AssetKind distinguishes the two chain asset variants carried by Asset.
type AssetKind string

const (
	// AssetKindToken is the native token asset.
	AssetKindToken AssetKind = "Token"
	// AssetKindItem is an item (data) asset.
	AssetKindItem AssetKind = "Item"
)

// Asset is the request-side chain asset value. It serializes using serde's default
// externally-tagged enum representation, matching prime::primitives::asset::Asset and
// sdk-js's IAssetToken/IAssetItem:
//
//	{"Token":<amount>}
//	{"Item":{"amount":<amount>,"genesis_hash":"<hex>","metadata":<string|null>}}
//
// This is NOT the same shape as the response-side ApiAsset, which is internally
// tagged with a "kind" field.
type Asset struct {
	Kind AssetKind

	// Amount is the token quantity (Token) or item count (Item).
	Amount int64

	// GenesisHash is set for Item assets: the genesis transaction hash the item
	// derives from.
	GenesisHash string

	// Metadata is optional free-form item metadata; nil serializes as null.
	Metadata *string
}

// NewTokenAsset builds a Token asset of the given amount.
func NewTokenAsset(amount int64) Asset {
	return Asset{Kind: AssetKindToken, Amount: amount}
}

// NewItemAsset builds an Item asset with the given amount, genesis hash, and
// optional metadata.
func NewItemAsset(amount int64, genesisHash string, metadata *string) Asset {
	return Asset{Kind: AssetKindItem, Amount: amount, GenesisHash: genesisHash, Metadata: metadata}
}

type assetItemPayload struct {
	Amount      int64   `json:"amount"`
	GenesisHash string  `json:"genesis_hash"`
	Metadata    *string `json:"metadata"`
}

type assetTokenEnvelope struct {
	Token int64 `json:"Token"`
}

type assetItemEnvelope struct {
	Item assetItemPayload `json:"Item"`
}

// MarshalJSON emits the externally-tagged enum shape serde produces for
// prime::primitives::asset::Asset.
func (a Asset) MarshalJSON() ([]byte, error) {
	switch a.Kind {
	case AssetKindToken:
		return json.Marshal(assetTokenEnvelope{Token: a.Amount})
	case AssetKindItem:
		return json.Marshal(assetItemEnvelope{Item: assetItemPayload{
			Amount:      a.Amount,
			GenesisHash: a.GenesisHash,
			Metadata:    a.Metadata,
		}})
	default:
		return nil, fmt.Errorf("sdkgo: Asset has no kind set (or unrecognized kind %q)", a.Kind)
	}
}

// UnmarshalJSON parses the externally-tagged enum shape back into an Asset.
func (a *Asset) UnmarshalJSON(data []byte) error {
	var probe struct {
		Token *int64            `json:"Token"`
		Item  *assetItemPayload `json:"Item"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return err
	}
	switch {
	case probe.Token != nil:
		*a = Asset{Kind: AssetKindToken, Amount: *probe.Token}
	case probe.Item != nil:
		*a = Asset{
			Kind:        AssetKindItem,
			Amount:      probe.Item.Amount,
			GenesisHash: probe.Item.GenesisHash,
			Metadata:    probe.Item.Metadata,
		}
	default:
		return fmt.Errorf("sdkgo: Asset JSON has neither \"Token\" nor \"Item\" key: %s", data)
	}
	return nil
}

// ApiAsset is the response-side chain asset shape returned by the `/v1` write
// endpoints (create transactions, items, payments). Unlike the request-side Asset,
// it is internally tagged by a "kind" field:
//
//	{"kind":"token","amount":<amount>}
//	{"kind":"item","amount":<amount>,"genesis_hash":<hex|null>,"metadata":<string|null>}
type ApiAsset struct {
	Kind        string  `json:"kind"`
	Amount      int64   `json:"amount"`
	GenesisHash *string `json:"genesis_hash,omitempty"`
	Metadata    *string `json:"metadata,omitempty"`
}
