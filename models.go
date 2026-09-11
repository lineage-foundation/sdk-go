package sdkgo

// OutPoint identifies a transaction output: the hash of the transaction that
// created it and the index into that transaction's outputs.
//
// Field order/tags are load-bearing: this struct's compact JSON encoding forms
// part of the signable-hash preimage and must be byte-identical to sdk-js's
// JSON.stringify(IOutPoint).
type OutPoint struct {
	THash string `json:"t_hash"`
	N     int    `json:"n"`
}

// TxOut is a single transaction output: the asset it carries, an optional
// locktime, and the destination script public key (address).
//
// Field order/tags are load-bearing: this struct's compact JSON encoding forms
// part of the signable-hash preimage and must be byte-identical to sdk-js's
// JSON.stringify(ITxOut).
type TxOut struct {
	Value           Asset  `json:"value"`
	Locktime        int    `json:"locktime"`
	ScriptPublicKey string `json:"script_public_key"`
}

// Pay2PkH is the pay-to-public-key-hash script-signature payload: the data that
// was signed, the resulting signature, the signer's public key, and the address
// version used to derive the destination address (nil for the current/default
// version).
type Pay2PkH struct {
	SignableData   string `json:"signable_data"`
	Signature      string `json:"signature"`
	PublicKey      string `json:"public_key"`
	AddressVersion *int   `json:"address_version"`
}

// ScriptSig is a transaction input's script signature, externally tagged by
// variant name (matching prime::script's CreateTxInScript enum on the wire).
// Currently only the Pay2PkH variant is supported by this SDK.
type ScriptSig struct {
	Pay2PkH *Pay2PkH `json:"Pay2PkH"`
}

// CreateTxIn is a transaction input as submitted to the `/v1/transactions`
// create-transaction endpoint.
type CreateTxIn struct {
	PreviousOut     *OutPoint `json:"previous_out"`
	ScriptSignature ScriptSig `json:"script_signature"`
}

// DruidExpectation is one leg of a two-way (DRUID) trade: the asset that must
// move from one party to another for the trade to be considered met.
type DruidExpectation struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Asset Asset  `json:"asset"`
}

// DruidInfo carries the DRUID (two-way trade) metadata for a transaction, mirroring
// prime::primitives::druid::DdeValues.
type DruidInfo struct {
	Druid        string             `json:"druid"`
	Participants int                `json:"participants"`
	Expectations []DruidExpectation `json:"expectations"`
	GenesisHash  *string            `json:"genesis_hash"`
}

// CreateTransaction is the request body for `POST /v1/transactions`: the inputs and
// outputs of the transaction to construct and submit, mirroring
// fleet_api::v1::tx_convert::CreateTransaction.
type CreateTransaction struct {
	Inputs    []CreateTxIn `json:"inputs"`
	Outputs   []TxOut      `json:"outputs"`
	Version   int          `json:"version"`
	Fees      []TxOut      `json:"fees,omitempty"`
	DruidInfo *DruidInfo   `json:"druid_info"`
}

// CreateTransactionsRequest is the top-level request body for
// `POST /v1/transactions`: one or more transactions keyed by an arbitrary
// caller-chosen identifier.
type CreateTransactionsRequest struct {
	Transactions map[string]CreateTransaction `json:"transactions"`
}

// TxOutputSummary is a single transaction output as reported back by a
// create-transaction response: the destination address and the asset sent to it.
type TxOutputSummary struct {
	Address string   `json:"address"`
	Asset   ApiAsset `json:"asset"`
}

// CreateTransactionsResponse is the response body for `POST /v1/transactions`.
type CreateTransactionsResponse struct {
	Transactions map[string]TxOutputSummary `json:"transactions"`
}

// BalanceTotal is the aggregate balance summary returned by
// `POST /v1/balances/query`: the total token amount and, per item genesis hash,
// the total item count.
type BalanceTotal struct {
	Tokens int64            `json:"tokens"`
	Items  map[string]int64 `json:"items"`
}

// BalanceEntry is a single unspent output contributing to a balance.
type BalanceEntry struct {
	OutPoint OutPoint `json:"out_point"`
	Value    Asset    `json:"value"`
}

// FetchBalanceResponse is the response body for `POST /v1/balances/query`.
type FetchBalanceResponse struct {
	Total       BalanceTotal              `json:"total"`
	AddressList map[string][]BalanceEntry `json:"address_list"`
}

// GenesisHashSpec selects how the genesis transaction hash of a newly created
// item asset is derived, matching prime::primitives::transaction::GenesisTxHashSpec.
type GenesisHashSpec string

const (
	// GenesisHashSpecCreate assigns a unique DRS transaction hash to the new item.
	GenesisHashSpecCreate GenesisHashSpec = "Create"
	// GenesisHashSpecDefault uses the well-known default item DRS transaction hash.
	GenesisHashSpecDefault GenesisHashSpec = "Default"
)

// CreateItemRequest is the request body for `POST /v1/items`.
type CreateItemRequest struct {
	ItemAmount      int64           `json:"item_amount"`
	GenesisHashSpec GenesisHashSpec `json:"genesis_hash_spec"`
	Metadata        *string         `json:"metadata,omitempty"`
	ScriptPublicKey *string         `json:"script_public_key,omitempty"`
	PublicKey       *string         `json:"public_key,omitempty"`
	Signature       *string         `json:"signature,omitempty"`
}

// CreateItemResponse is the response body for a mempool-node
// `POST /v1/items` call: the created item asset, the address it was created
// against, and the hash of the creation transaction.
type CreateItemResponse struct {
	Asset     ApiAsset `json:"asset"`
	ToAddress string   `json:"to_address"`
	TxHash    string   `json:"tx_hash"`
}

// CreateItemAcceptedResponse is the response body for a user-node
// `POST /v1/items` call, which only accepts the request for asynchronous
// processing.
type CreateItemAcceptedResponse struct {
	ItemAmount int64 `json:"item_amount"`
}

// BlockchainItemMetaType distinguishes the two kinds of stored blockchain entries.
type BlockchainItemMetaType string

const (
	// BlockchainItemMetaBlock marks an entry as a stored block.
	BlockchainItemMetaBlock BlockchainItemMetaType = "block"
	// BlockchainItemMetaTx marks an entry as a stored transaction.
	BlockchainItemMetaTx BlockchainItemMetaType = "tx"
)

// BlockchainItemMeta describes the position of a stored blockchain entry: either a
// block (by block number and transaction count) or a transaction (by block number
// and transaction index within that block).
type BlockchainItemMeta struct {
	Type     BlockchainItemMetaType `json:"type"`
	BlockNum int64                  `json:"block_num"`
	TxLen    int64                  `json:"tx_len,omitempty"`
	TxNum    int64                  `json:"tx_num,omitempty"`
}

// BlockchainEntry is a single stored blockchain entry as returned by
// `POST /v1/blockchain-entries/query`.
type BlockchainEntry struct {
	Key      string             `json:"key"`
	ItemMeta BlockchainItemMeta `json:"item_meta"`
	Data     any                `json:"data"`
}
