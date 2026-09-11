package sdkgo

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestSignablePreimageSerialization is the load-bearing test for Task 6: the
// concatenation of json.Marshal(txOut) for each output followed by
// json.Marshal(&outPoint) must be byte-identical to sdk-js's
// JSON.stringify-produced preimage. Task 7 (the signable-hash implementation)
// depends on this holding exactly.
func TestSignablePreimageSerialization(t *testing.T) {
	b, err := os.ReadFile("internal/testvectors/signable.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v struct {
		OutPoint OutPoint `json:"outPoint"`
		TxOuts   []TxOut  `json:"txOuts"`
		Preimage string   `json:"preimage"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshal vector: %v", err)
	}

	var out strings.Builder
	for _, o := range v.TxOuts {
		j, err := json.Marshal(o)
		if err != nil {
			t.Fatalf("marshal TxOut: %v", err)
		}
		out.Write(j)
	}
	j, err := json.Marshal(&v.OutPoint)
	if err != nil {
		t.Fatalf("marshal OutPoint: %v", err)
	}
	out.Write(j)

	got := out.String()
	if got != v.Preimage {
		i := 0
		for i < len(got) && i < len(v.Preimage) && got[i] == v.Preimage[i] {
			i++
		}
		t.Fatalf("preimage mismatch at byte offset %d:\n got:  %s\n want: %s", i, got, v.Preimage)
	}
}

// TestAssetRequestJSONShape locks down the exact externally-tagged wire shape for
// the request-side Asset, independent of the preimage vector.
func TestAssetRequestJSONShape(t *testing.T) {
	tok := NewTokenAsset(1000)
	j, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token asset: %v", err)
	}
	if got, want := string(j), `{"Token":1000}`; got != want {
		t.Fatalf("token asset: got %s want %s", got, want)
	}

	meta := "hello"
	item := NewItemAsset(5, "abc123", &meta)
	j, err = json.Marshal(item)
	if err != nil {
		t.Fatalf("marshal item asset: %v", err)
	}
	if got, want := string(j), `{"Item":{"amount":5,"genesis_hash":"abc123","metadata":"hello"}}`; got != want {
		t.Fatalf("item asset: got %s want %s", got, want)
	}

	nilMetaItem := NewItemAsset(5, "abc123", nil)
	j, err = json.Marshal(nilMetaItem)
	if err != nil {
		t.Fatalf("marshal item asset (nil metadata): %v", err)
	}
	if got, want := string(j), `{"Item":{"amount":5,"genesis_hash":"abc123","metadata":null}}`; got != want {
		t.Fatalf("item asset (nil metadata): got %s want %s", got, want)
	}
}

// TestAssetRoundTrip checks that Asset survives an unmarshal/marshal round trip,
// as needed to load the txOuts/outPoint out of the JSON test vectors.
func TestAssetRoundTrip(t *testing.T) {
	var tok Asset
	if err := json.Unmarshal([]byte(`{"Token":1000}`), &tok); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	if tok.Kind != AssetKindToken || tok.Amount != 1000 {
		t.Fatalf("unmarshal token: got %+v", tok)
	}

	var item Asset
	if err := json.Unmarshal([]byte(`{"Item":{"amount":5,"genesis_hash":"abc123","metadata":null}}`), &item); err != nil {
		t.Fatalf("unmarshal item: %v", err)
	}
	if item.Kind != AssetKindItem || item.Amount != 5 || item.GenesisHash != "abc123" || item.Metadata != nil {
		t.Fatalf("unmarshal item: got %+v", item)
	}
}

// TestCreateTxInNullFields ensures previous_out serializes as null (not omitted)
// when unset, since a null previous_out is meaningful client-signed data.
func TestCreateTxInNullFields(t *testing.T) {
	in := CreateTxIn{
		PreviousOut: nil,
		ScriptSignature: ScriptSig{
			Pay2PkH: &Pay2PkH{
				SignableData:   "deadbeef",
				Signature:      "sig",
				PublicKey:      "pub",
				AddressVersion: nil,
			},
		},
	}
	j, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal CreateTxIn: %v", err)
	}
	want := `{"previous_out":null,"script_signature":{"Pay2PkH":{"signable_data":"deadbeef","signature":"sig","public_key":"pub","address_version":null}}}`
	if got := string(j); got != want {
		t.Fatalf("CreateTxIn: got %s want %s", got, want)
	}
}

// TestAPIError checks the error message falls back from Detail to Title.
func TestAPIError(t *testing.T) {
	withDetail := &APIError{Type: "about:blank", Title: "Bad Request", Status: 400, Detail: "amount must be positive"}
	if got, want := withDetail.Error(), "amount must be positive"; got != want {
		t.Fatalf("Error(): got %q want %q", got, want)
	}

	titleOnly := &APIError{Type: "about:blank", Title: "Bad Request", Status: 400}
	if got, want := titleOnly.Error(), "Bad Request"; got != want {
		t.Fatalf("Error(): got %q want %q", got, want)
	}

	var _ error = (*APIError)(nil)
}
