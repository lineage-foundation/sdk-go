package sdkgo

import (
	"bytes"
	"encoding/json"
	"fmt"
)

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
//
// GenesisHash is omitempty: Create2WTxHalf's constructed druid_info never
// sets it, and its JSON encoding must omit the key entirely to match
// sdk-js's create2WTxHalf output (and the shared create2WTxHalf.output
// vector) byte-for-byte -- sdk-js only adds an explicit genesis_hash:null at
// submission time. That explicit-null submission shape is a distinct wire
// type (see wallet.go's submissionDruidInfo), not this one.
type DruidInfo struct {
	Druid        string             `json:"druid"`
	Participants int                `json:"participants"`
	Expectations []DruidExpectation `json:"expectations"`
	GenesisHash  *string            `json:"genesis_hash,omitempty"`
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

// FetchBalanceResponse is the balance breakdown carried under the `balance` key of the
// `GET /v1/balances` / `POST /v1/balances/query` response body (see BalancesResponse).
type FetchBalanceResponse struct {
	Total       BalanceTotal              `json:"total"`
	AddressList map[string][]BalanceEntry `json:"address_list"`

	// addressOrder preserves the address_list object's key order as it
	// appeared in the JSON that produced this value (a Go map has no
	// intrinsic order). Input-gathering in tx.go walks address_list in this
	// order rather than sorting it, matching sdk-js's
	// Object.entries(fetchBalanceResponse.address_list) iteration order
	// byte-for-byte. Populated by UnmarshalJSON; nil for a FetchBalanceResponse
	// built by hand rather than decoded from JSON, which falls back to
	// address-sorted order.
	addressOrder []string
}

// UnmarshalJSON decodes a FetchBalanceResponse, additionally recording the
// address_list object's key order (see addressOrder), since Go's map type
// does not preserve it.
func (f *FetchBalanceResponse) UnmarshalJSON(data []byte) error {
	type alias FetchBalanceResponse
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*f = FetchBalanceResponse(a)

	var raw struct {
		AddressList json.RawMessage `json:"address_list"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	order, err := jsonObjectKeyOrder(raw.AddressList)
	if err != nil {
		return err
	}
	f.addressOrder = order
	return nil
}

// jsonObjectKeyOrder returns the top-level keys of the JSON object in raw, in
// the order they appear. Returns nil (no error) for an empty, null, or
// non-object raw value.
func jsonObjectKeyOrder(raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, nil
	}

	var keys []string
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("sdkgo: unexpected non-string object key %v", keyTok)
		}
		keys = append(keys, key)

		var discard json.RawMessage
		if err := dec.Decode(&discard); err != nil {
			return nil, err
		}
	}
	return keys, nil
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

// CreateItemRequest is the request body for `POST /v1/items`. Field order
// matches sdk-js's actual wire body (item.json's payload, minus the legacy
// "version" field that sdk-js's request interface omits); the server is
// serde/order-independent, so this is cosmetic, but it lets the request body
// be compared byte-for-byte against the vector in wallet_test.go.
type CreateItemRequest struct {
	ItemAmount      int64           `json:"item_amount"`
	ScriptPublicKey *string         `json:"script_public_key,omitempty"`
	PublicKey       *string         `json:"public_key,omitempty"`
	Signature       *string         `json:"signature,omitempty"`
	GenesisHashSpec GenesisHashSpec `json:"genesis_hash_spec"`
	// Metadata has no omitempty: sdk-js's JSON.stringify keeps an explicit
	// "metadata":null in the wire body rather than dropping the key, and
	// item.json's vector confirms that shape.
	Metadata *string `json:"metadata"`
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

// DifficultyTarget is a block header's committed PoW target (`bits`), decoded into
// its compact `nBits` form and its expanded 256-bit form, mirroring
// fleet_api::v1::difficulty::DifficultyTarget.
type DifficultyTarget struct {
	// Compact is the target in Bitcoin nBits form, e.g. "0x1d00ffff".
	Compact string `json:"compact"`
	// Target is the full 256-bit target as 64 lowercase hex characters (no 0x prefix).
	Target string `json:"target"`
}

// BlockchainEntry is a single stored blockchain entry (a block or a transaction), as
// returned by `GET /v1/blocks/{num}`, `GET /v1/blocks`, `GET /v1/blockchain-entries/{key}`
// and `POST /v1/blockchain-entries/query`, mirroring
// fleet_api::v1::blockchain::BlockchainEntryResponse.
type BlockchainEntry struct {
	Key      string             `json:"key"`
	ItemMeta BlockchainItemMeta `json:"item_meta"`
	Data     any                `json:"data"`
	// DifficultyTarget is set for block entries with a committed PoW target; nil for
	// transaction entries or legacy blocks with no committed target.
	DifficultyTarget *DifficultyTarget `json:"difficulty_target,omitempty"`
}

// SupplyResponse is the response body for `GET /v1/supply`.
type SupplyResponse struct {
	// Total is the fixed total token supply.
	Total uint64 `json:"total"`
	// Issued is the currently issued token supply.
	Issued uint64 `json:"issued"`
}

// LatestBlockResponse is the response body for `GET /v1/blocks/latest`: the raw stored
// block payload, plus its decoded PoW target.
type LatestBlockResponse struct {
	Block            any               `json:"block"`
	DifficultyTarget *DifficultyTarget `json:"difficulty_target"`
}

// TxStatusType is the mempool status of a transaction, mirroring
// fleet_core::interfaces::TxStatusType.
type TxStatusType string

const (
	// TxStatusPending indicates the transaction is still in the mempool.
	TxStatusPending TxStatusType = "Pending"
	// TxStatusConfirmed indicates the transaction has been mined into a block.
	TxStatusConfirmed TxStatusType = "Confirmed"
	// TxStatusRejected indicates the transaction was rejected by the mempool.
	TxStatusRejected TxStatusType = "Rejected"
)

// TxStatus is a single transaction's mempool status, as returned (keyed by
// transaction hash) by `GET /v1/transactions/status` and
// `POST /v1/transactions/status:query`.
type TxStatus struct {
	Status         TxStatusType `json:"status"`
	Timestamp      int64        `json:"timestamp"`
	AdditionalInfo string       `json:"additional_info"`
}

// SerializeTransactionsRequest is the request body for
// `POST /v1/transactions:serialize`: the transactions to serialize to
// hex-encoded bytes, mirroring fleet_api::v1::tx_convert::CreateTransaction.
type SerializeTransactionsRequest struct {
	Transactions []CreateTransaction `json:"transactions"`
}

// JsonSerializedTransaction is a single transaction serialized to hex, plus
// its resulting transaction hash.
type JsonSerializedTransaction struct {
	TxnHashHex string `json:"txn_hash_hex"`
	TxnHex     string `json:"txn_hex"`
}

// SerializeTransactionsResponse is the response body for
// `POST /v1/transactions:serialize`.
type SerializeTransactionsResponse struct {
	Transactions []JsonSerializedTransaction `json:"transactions"`
}

// DeserializeTransactionsRequest is the request body for
// `POST /v1/transactions:deserialize`: hex-encoded serialized transactions to
// decode.
type DeserializeTransactionsRequest struct {
	Transactions []string `json:"transactions"`
}

// DeserializeTransactionsResponse is the response body for
// `POST /v1/transactions:deserialize`.
type DeserializeTransactionsResponse struct {
	Transactions []CreateTransaction `json:"transactions"`
}

// BalancesResponse is the raw response body for `GET /v1/balances` and
// `POST /v1/balances/query`, wrapping the balance breakdown under a `balance` key.
// Client.Balances and Client.QueryBalances unwrap this and return the inner
// FetchBalanceResponse directly.
type BalancesResponse struct {
	Balance FetchBalanceResponse `json:"balance"`
}

// EncryptedTransaction is the on-disk/wire representation of a passphrase-
// encrypted CreateTransaction, matching sdk-js's ICreateTransactionEncrypted.
// It's what Wallet.Make2WayPayment returns (inside a PendingHalf) for the
// caller to persist until the counterparty accepts.
type EncryptedTransaction struct {
	Druid string `json:"druid"`
	Nonce string `json:"nonce"`
	Save  string `json:"save"`
}

// Pending2WTxStatus is the lifecycle status of a two-way (DRUID) trade as
// tracked on the valence mailbox, mirroring sdk-js's
// IPending2WTxDetails['status'].
type Pending2WTxStatus string

const (
	// Pending2WTxStatusPending marks an offer awaiting the counterparty's response.
	Pending2WTxStatusPending Pending2WTxStatus = "pending"
	// Pending2WTxStatusAccepted marks an offer the counterparty has accepted.
	Pending2WTxStatusAccepted Pending2WTxStatus = "accepted"
	// Pending2WTxStatusRejected marks an offer the counterparty has rejected.
	Pending2WTxStatusRejected Pending2WTxStatus = "rejected"
)

// Pending2WTxDetails is the payload stored under a valence mailbox entry for
// a two-way (DRUID) trade: both parties' expectations, the trade's current
// status, and the mempool host the initiating sender chose (so both parties
// submit their halves to the same node's DRUID pool). Mirrors sdk-js's
// IPending2WTxDetails. This struct is exchanged with valence in plaintext —
// it is never encrypted on the wire.
type Pending2WTxDetails struct {
	Druid               string            `json:"druid"`
	SenderExpectation   DruidExpectation  `json:"senderExpectation"`
	ReceiverExpectation DruidExpectation  `json:"receiverExpectation"`
	Status              Pending2WTxStatus `json:"status"`
	MempoolHost         string            `json:"mempoolHost"`
}

// PendingHalf is the caller-persisted record of a two-way payment this
// wallet initiated via Wallet.Make2WayPayment: the DRUID correlating the
// trade, this party's half of the transaction sealed at rest under the
// wallet's passphrase key, and both parties' expectations exactly as posted
// to valence (for FetchPending2WayPayment to match back up against the
// mailbox contents on a later call).
type PendingHalf struct {
	Druid               string               `json:"druid"`
	EncryptedHalf       EncryptedTransaction `json:"encryptedHalf"`
	SenderExpectation   DruidExpectation     `json:"senderExpectation"`
	ReceiverExpectation DruidExpectation     `json:"receiverExpectation"`
}
