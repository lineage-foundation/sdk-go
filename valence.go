package sdkgo

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lineage-foundation/sdk-go/crypto"
)

// valenceMessagesPath is the mailbox endpoint on a valence host: every
// mailbox operation (post an offer, read a mailbox, delete a settled entry)
// lives under this single path, matching sdk-js's IAPIRoute.ValenceSet /
// ValenceGet / ValenceDel (all "/messages", DELETE additionally suffixed
// with "/{id}").
const valenceMessagesPath = "/messages"

// ValenceClient is a client for a valence mailbox host: the plaintext
// message-relay service two-way payment counterparties use to exchange
// DRUID trade offers, acceptances, and rejections. Messages are sent and
// stored in plaintext — valence provides delivery and mailbox scoping, not
// confidentiality. Every request is authenticated by signing the target
// mailbox address's raw bytes with the caller's own keypair (see
// valenceSetAuthHeaders), matching sdk-js's generateVerificationHeaders.
type ValenceClient struct {
	host       string
	httpClient *http.Client
}

// newValenceClient builds a ValenceClient against host using httpClient.
func newValenceClient(host string, httpClient *http.Client) *ValenceClient {
	return &ValenceClient{host: host, httpClient: httpClient}
}

// valenceSetBody is the POST /messages request body, mirroring sdk-js's
// IRequestValenceSetBody<T>: the data id (here always the DRUID) plus the
// plaintext payload.
type valenceSetBody struct {
	ID   string             `json:"id"`
	Data Pending2WTxDetails `json:"data"`
}

// valenceAuthHeaders sets the address/public_key/signature headers a
// valence request must carry: address is the target mailbox's address
// (hex), public_key is the caller's own public key (hex), and signature is
// hex(ed25519.Sign(secretKey, []byte(address))) — a detached signature over
// the mailbox address string's raw UTF-8 bytes, unhashed. This matches
// sdk-js's generateVerificationHeaders byte-for-byte, including that the
// signing keypair need not be the mailbox address's own keypair: valence
// messages may be posted into (or deleted from) a counterparty's mailbox,
// signed by the sender's own key, as proof of a validly-held keypair rather
// than of mailbox ownership.
func valenceAuthHeaders(req *http.Request, address string, kp crypto.Keypair) {
	sig := crypto.Sign([]byte(address), kp.SecretKey)
	req.Header.Set("address", address)
	req.Header.Set("public_key", hex.EncodeToString(kp.PublicKey))
	req.Header.Set("signature", hex.EncodeToString(sig))
}

// do executes an authenticated valence request against v.host+path, signing
// with address/kp per valenceAuthHeaders. If body is non-nil it's marshaled
// as the JSON request body. On a non-2xx response the body is discarded and
// an error is returned; on 2xx, if out is non-nil, the response body is
// JSON-decoded into it.
func (v *ValenceClient) do(ctx context.Context, method, path, address string, kp crypto.Keypair, body, out any) error {
	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sdkgo: marshal valence request body: %w", err)
		}
		reqBody = bytes.NewReader(b)
	}

	var req *http.Request
	var err error
	if reqBody != nil {
		req, err = http.NewRequestWithContext(ctx, method, v.host+path, reqBody)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, v.host+path, nil)
	}
	if err != nil {
		return fmt.Errorf("sdkgo: build valence request: %w", err)
	}

	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	valenceAuthHeaders(req, address, kp)

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sdkgo: valence %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sdkgo: valence %s %s: status %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("sdkgo: valence %s %s: decode response: %w", method, path, err)
	}
	return nil
}

// Post places (or overwrites) the plaintext offer/status details under the
// mailbox identified by address (the DRUID, details.Druid, is the mailbox
// entry's id), signed by kp. Mirrors sdk-js's
// `POST /messages` (IAPIRoute.ValenceSet) call in make2WayPayment /
// handle2WTxResponse.
func (v *ValenceClient) Post(ctx context.Context, address string, kp crypto.Keypair, details Pending2WTxDetails) error {
	body := valenceSetBody{ID: details.Druid, Data: details}
	return v.do(ctx, http.MethodPost, valenceMessagesPath, address, kp, body, nil)
}

// Get returns the full contents of address's mailbox: a map of DRUID to the
// stored Pending2WTxDetails payload directly (not wrapped), signed by kp.
// Mirrors sdk-js's `GET /messages` (IAPIRoute.ValenceGet) call in
// fetchPending2WayPayment.
func (v *ValenceClient) Get(ctx context.Context, address string, kp crypto.Keypair) (map[string]Pending2WTxDetails, error) {
	out := map[string]Pending2WTxDetails{}
	err := v.do(ctx, http.MethodGet, valenceMessagesPath, address, kp, nil, &out)
	return out, err
}

// Delete removes the mailbox entry identified by druid from address's
// mailbox, signed by kp. Mirrors sdk-js's `DELETE /messages/{id}`
// (IAPIRoute.ValenceDel) call in fetchPending2WayPayment.
func (v *ValenceClient) Delete(ctx context.Context, druid, address string, kp crypto.Keypair) error {
	path := valenceMessagesPath + "/" + url.PathEscape(druid)
	return v.do(ctx, http.MethodDelete, path, address, kp, nil, nil)
}
