package sdkgo

import (
	"bytes"
	"encoding/json"
	"regexp"
	"testing"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// TestGenerateDRUID is the load-bearing test for Task 2: GenerateDRUID must
// produce a "DRUID0x" followed by 32 lowercase hex characters, matching
// sdk-js's generateDRUID output shape.
func TestGenerateDRUID(t *testing.T) {
	re := regexp.MustCompile(`^DRUID0x[0-9a-f]{32}$`)
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		got := GenerateDRUID()
		if !re.MatchString(got) {
			t.Fatalf("GenerateDRUID() = %q, does not match %s", got, re.String())
		}
		if seen[got] {
			t.Fatalf("GenerateDRUID() produced a repeat: %q", got)
		}
		seen[got] = true
	}
}

// TestCreate2WTxHalfAndConstructTxInsAddress is the load-bearing test for
// Task 2: Create2WTxHalf must replicate sdk-js's create2WTxHalf byte-for-byte
// (druid_info, per-input signable_data/signature/public_key, and outputs),
// and ConstructTxInsAddress must replicate sdk-js's constructTxInsAddress,
// against the shared golden vectors in twoway.json.
func TestCreate2WTxHalfAndConstructTxInsAddress(t *testing.T) {
	var v struct {
		Druid         string `json:"druid"`
		FixedKeypairs struct {
			Ours []struct {
				Address   string `json:"address"`
				PublicKey string `json:"public_key"`
				SecretKey string `json:"secret_key"`
			} `json:"ours"`
			Counterparty struct {
				Address   string `json:"address"`
				PublicKey string `json:"public_key"`
				SecretKey string `json:"secret_key"`
			} `json:"counterparty"`
		} `json:"fixedKeypairs"`
		Create2WTxHalf struct {
			Input struct {
				FetchBalanceResponse FetchBalanceResponse `json:"fetchBalanceResponse"`
				SenderExpectation    DruidExpectation     `json:"senderExpectation"`
				ReceiverExpectation  DruidExpectation     `json:"receiverExpectation"`
				ExcessAddress        string               `json:"excessAddress"`
				Locktime             int                  `json:"locktime"`
			} `json:"input"`
			Output struct {
				DruidInfo json.RawMessage `json:"druid_info"`
				Outputs   []TxOut         `json:"outputs"`
				Inputs    []CreateTxIn    `json:"inputs"`
			} `json:"output"`
		} `json:"create2WTxHalf"`
		ConstructTxInsAddress struct {
			Input   []CreateTxIn `json:"input"`
			Address string       `json:"address"`
		} `json:"constructTxInsAddress"`
	}
	loadVector(t, "twoway.json", &v)

	keyPairs := map[string]crypto.Keypair{}
	for _, kp := range v.FixedKeypairs.Ours {
		keyPairs[kp.Address] = crypto.Keypair{
			PublicKey: mustHexDecode(t, kp.PublicKey),
			SecretKey: mustHexDecode(t, kp.SecretKey),
		}
	}
	keyPairs[v.FixedKeypairs.Counterparty.Address] = crypto.Keypair{
		PublicKey: mustHexDecode(t, v.FixedKeypairs.Counterparty.PublicKey),
		SecretKey: mustHexDecode(t, v.FixedKeypairs.Counterparty.SecretKey),
	}

	in := v.Create2WTxHalf.Input
	// thisExpectation is the party's own half carried in druid_info
	// (sdk-js's senderExpectation); counterExpectation drives the inputs
	// gathered and the payment output (sdk-js's receiverExpectation).
	tx, err := Create2WTxHalf(v.Druid, in.SenderExpectation, in.ReceiverExpectation, in.FetchBalanceResponse, keyPairs, in.ExcessAddress, in.Locktime)
	if err != nil {
		t.Fatalf("Create2WTxHalf: %v", err)
	}

	// druid_info must match byte-for-byte against the RAW vector bytes
	// (compacted, not round-tripped through the DruidInfo struct): sdk-js's
	// create2WTxHalf output carries no genesis_hash key at all (it's only
	// added at submission time), and a struct round-trip through DruidInfo's
	// non-omitempty GenesisHash field would mask a regression that adds it
	// back in at construction. Compare compacted bytes directly instead,
	// mirroring TestCreatePaymentTx's raw-vector comparison.
	gotDruidInfoJSON, err := json.Marshal(tx.DruidInfo)
	if err != nil {
		t.Fatalf("marshal got druid_info: %v", err)
	}
	var wantDruidInfoBuf bytes.Buffer
	if err := json.Compact(&wantDruidInfoBuf, v.Create2WTxHalf.Output.DruidInfo); err != nil {
		t.Fatalf("compact want druid_info: %v", err)
	}
	wantDruidInfoJSON := wantDruidInfoBuf.Bytes()
	if !bytes.Equal(gotDruidInfoJSON, wantDruidInfoJSON) {
		t.Fatalf("druid_info mismatch:\n got:  %s\n want: %s", gotDruidInfoJSON, wantDruidInfoJSON)
	}

	// outputs must match byte-for-byte.
	gotOutputsJSON, err := json.Marshal(tx.Outputs)
	if err != nil {
		t.Fatalf("marshal got outputs: %v", err)
	}
	wantOutputsJSON, err := json.Marshal(v.Create2WTxHalf.Output.Outputs)
	if err != nil {
		t.Fatalf("marshal want outputs: %v", err)
	}
	if !bytes.Equal(gotOutputsJSON, wantOutputsJSON) {
		t.Fatalf("outputs mismatch:\n got:  %s\n want: %s", gotOutputsJSON, wantOutputsJSON)
	}

	// per-input signable_data/signature/public_key (and previous_out) must
	// match byte-for-byte.
	gotInputsJSON, err := json.Marshal(tx.Inputs)
	if err != nil {
		t.Fatalf("marshal got inputs: %v", err)
	}
	wantInputsJSON, err := json.Marshal(v.Create2WTxHalf.Output.Inputs)
	if err != nil {
		t.Fatalf("marshal want inputs: %v", err)
	}
	if !bytes.Equal(gotInputsJSON, wantInputsJSON) {
		t.Fatalf("inputs mismatch:\n got:  %s\n want: %s", gotInputsJSON, wantInputsJSON)
	}

	// ConstructTxInsAddress must match the vector's address, both for the
	// dedicated vector case and for the exact inputs Create2WTxHalf just
	// produced.
	if got := ConstructTxInsAddress(v.ConstructTxInsAddress.Input); got != v.ConstructTxInsAddress.Address {
		t.Fatalf("ConstructTxInsAddress(vector inputs) = %q, want %q", got, v.ConstructTxInsAddress.Address)
	}
	if got := ConstructTxInsAddress(tx.Inputs); got != v.ConstructTxInsAddress.Address {
		t.Fatalf("ConstructTxInsAddress(Create2WTxHalf inputs) = %q, want %q", got, v.ConstructTxInsAddress.Address)
	}
}
