# vectorgen

`gen.ts` is a golden-vector generator for `internal/testvectors/*.json`. It is **not**
compiled or run as part of the Go module — it drives sdk-js (the canonical reference
implementation for all Lineage SDKs) directly against its internal, unexported crypto
primitives, so it must run from inside an sdk-js checkout.

Every vector is produced from fixed inputs (mnemonic, seeds, passphrase, outpoints) so
re-running this script against the same sdk-js commit reproduces byte-identical JSON.
Nothing here re-implements sdk-js crypto; it only calls it and dumps the results.

## Regenerating the vectors

```bash
cd /path/to/sdk-js
npm ci
npm run build

# Copy this file in at the same relative depth so its `../../src/...` imports resolve
# to sdk-js/src/...
mkdir -p internal/vectorgen
cp /path/to/sdk-go/internal/vectorgen/gen.ts internal/vectorgen/gen.ts

# sdk-js's tsconfig targets ES modules; compile this one script to CommonJS instead so
# it can be run directly with node (no ts-node/tsx dependency needed).
npx tsc internal/vectorgen/gen.ts \
  --module commonjs --target ES2019 --esModuleInterop --skipLibCheck \
  --resolveJsonModule --outDir internal/vectorgen/out

node internal/vectorgen/out/vectorgen/gen.js

# Six JSON files are written to the current directory (sdk-js repo root):
mv derivation.json signing.json signable.json keystore.json payment.json item.json \
  /path/to/sdk-go/internal/testvectors/

# Clean up the temporary copy — it must not be committed to sdk-js.
rm -rf internal/vectorgen
```

## Fixed inputs

- Mnemonic: `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`, empty BIP39 passphrase.
- Message-signing seed: 32 zero bytes (`"00".repeat(32)`).
- Keystore wallet passphrase: `TestPass123`.

## What each vector contains

- `derivation.json` — master key `xprivkey` + the first 3 derived keypairs (depth 0-2):
  child xprv, the 32-byte ed25519 seed sliced from it, public/secret key hex, and address.
- `signing.json` — a keypair generated from the fixed zero seed, plus a detached signature
  over a fixed message string.
- `signable.json` — a fixed `OutPoint`/`TxOut` pair, the sha3-256 signable hash over their
  JSON preimage, a signature over that hash, and the asset hashes for a `Token` and an
  `Item` asset.
- `keystore.json` — `mgmtClient.encryptKeypair()` run over the `signing.json` keypair under
  the fixed wallet passphrase, verified by round-tripping through `decryptKeypair()` before
  being written. Includes the passphrase, the plaintext pub/secret hex, and the encrypted
  `{address, nonce, version, save}` record.
- `payment.json` — a full UTXO transaction build (`getInputsForTx` → `createTx` →
  `updateSignatures`) spending a single fixed 5000-Token UTXO owned by the depth-0 keypair,
  paying 3000 Tokens to the depth-1 address with 2000 Tokens change back to the sender.
  Includes the input `fetchBalanceResponse` and the resulting signed `ICreateTxPayload`.
- `item.json` — an item-asset creation payload (`createItemPayload`) for the depth-2
  keypair, amount 250, default genesis-hash spec, no metadata.

## Notes for the keystore vector

`mgmtClient.passphraseKey` is a private field only ever set as a side effect of
`initNew`/`fromSeed`/`fromMasterKey`, all of which mint a fresh random master key — there
is no public entry point to set a fixed passphrase against a fixed, externally-supplied
keypair. `gen.ts` sets the field directly (`(client as any).passphraseKey = ...`); this is
still real sdk-js code underneath (`nacl.secretbox` in `mgmt.service.ts`), just reached by
bypassing the constructor's key-generation side effects. The script verifies this by
decrypting its own output with sdk-js's `decryptKeypair()` before writing the file, and
throws instead of emitting a vector if the round-trip doesn't match.
