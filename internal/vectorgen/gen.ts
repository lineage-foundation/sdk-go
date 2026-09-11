// Golden-vector generator for the Lineage Go SDK.
//
// This script is NOT run as part of sdk-go's build. It is copied into a checkout of
// sdk-js (the canonical reference implementation) and executed there, so it can import
// sdk-js's internal, unexported crypto primitives directly from `src/`. See README.md
// in this directory for exact run instructions.
//
// Every value below is derived from FIXED inputs (mnemonic, seeds, passphrase, outpoint,
// etc.) so that re-running this script against the same sdk-js commit reproduces
// byte-identical JSON. Six vector files are written to the current working directory;
// move them into sdk-go/internal/testvectors/.

import * as fs from 'fs';

import {
    generateKeypair,
    generateMasterKey,
    getNextDerivedKeypair,
    getPassphraseBuffer,
} from '../../src/mgmt/key.mgmt';
import { createItemPayload } from '../../src/mgmt/item.mgmt';
import {
    constructSignature,
    constructTxInOutSignableHash,
    constructTxInSignableAssetHash,
    updateSignatures,
} from '../../src/mgmt/script.mgmt';
import { createTx, getInputsForTx } from '../../src/mgmt/tx.mgmt';
import { mgmtClient } from '../../src/services/mgmt.service';
import { getHexStringBytes, getStringBytes } from '../../src/utils/general.utils';
import { IAssetToken, IFetchBalanceResponse, IKeypair } from '../../src/interfaces';

const MNEMONIC =
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSPHRASE = ''; // fixed empty BIP39 passphrase for derivation
const KEYSTORE_PASSPHRASE = 'TestPass123'; // fixed wallet passphrase for the keystore vector

const hex = (u: Uint8Array): string => Buffer.from(u).toString('hex');

function unwrap<T>(r: { isErr(): boolean; isOk(): boolean; value?: T; error?: unknown }): T {
    if (r.isErr()) throw new Error(`unwrap failed: ${JSON.stringify(r.error)}`);
    return r.value as T;
}

/* -------------------------------------------------------------------------- */
/* (a) derivation.json — master key + first 3 derived keypairs                */
/* -------------------------------------------------------------------------- */

const mk = unwrap(generateMasterKey(MNEMONIC, PASSPHRASE));

type DerivedKeypair = { depth: number; publicKey: Uint8Array; secretKey: Uint8Array; address: string };
const derivedKeypairs: DerivedKeypair[] = [];

const derivation: Record<string, unknown> = {
    mnemonic: MNEMONIC,
    passphrase: PASSPHRASE,
    xprivkey: mk.secret.xprivkey,
    depths: [] as unknown[],
};

for (let d = 0; d < 3; d++) {
    const child = mk.secret.deriveChild(d, true);
    const kp = unwrap(getNextDerivedKeypair(mk, d));
    derivedKeypairs.push({ depth: d, publicKey: kp.publicKey, secretKey: kp.secretKey, address: kp.address });
    (derivation.depths as unknown[]).push({
        depth: d,
        childXprv: child.xprivkey,
        edSeed32: hex(getStringBytes(child.xprivkey).slice(0, 32)),
        publicKey: hex(kp.publicKey),
        secretKey: hex(kp.secretKey),
        address: kp.address,
    });
}
fs.writeFileSync('derivation.json', JSON.stringify(derivation, null, 2));

/* -------------------------------------------------------------------------- */
/* (b) signing.json — message signing with a fixed 32-byte zero seed          */
/* -------------------------------------------------------------------------- */

const seed32 = getHexStringBytes('00'.repeat(32));
const kp = unwrap(generateKeypair(null, seed32));
const MESSAGE = 'lineage-test-message';
const signing = {
    seed32: hex(seed32),
    publicKey: hex(kp.publicKey),
    secretKey: hex(kp.secretKey),
    address: kp.address,
    message: MESSAGE,
    signatureHex: unwrap(constructSignature(getStringBytes(MESSAGE), kp.secretKey)),
};
fs.writeFileSync('signing.json', JSON.stringify(signing, null, 2));

/* -------------------------------------------------------------------------- */
/* (c) signable.json — TxIn/TxOut signable hash + asset hashes                */
/* -------------------------------------------------------------------------- */

const outPoint = { t_hash: 'g'.padEnd(32, '0'), n: 0 };
const txOuts = [{ value: { Token: 1000 }, locktime: 0, script_public_key: kp.address }];
const preimage = txOuts.map((o) => JSON.stringify(o)).join('') + JSON.stringify(outPoint);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const signableHash = constructTxInOutSignableHash(outPoint as any, txOuts as any);
const signable = {
    outPoint,
    txOuts,
    preimage,
    signableHash,
    signatureHex: unwrap(constructSignature(getStringBytes(signableHash), kp.secretKey)),
    assetTokenHash: constructTxInSignableAssetHash({ Token: 1000 }),
    assetItemHash: constructTxInSignableAssetHash({
        Item: { amount: 5, genesis_hash: 'gabc', metadata: null },
    }),
};
fs.writeFileSync('signable.json', JSON.stringify(signable, null, 2));

/* -------------------------------------------------------------------------- */
/* (d) keystore.json — mgmtClient.encryptKeypair() under a fixed passphrase   */
/* -------------------------------------------------------------------------- */

const client = new mgmtClient();
const passphraseBuf = unwrap(getPassphraseBuffer(KEYSTORE_PASSPHRASE));
// `passphraseKey` is a private field; mgmtClient only exposes it indirectly through
// initNew/fromSeed/fromMasterKey, all of which mint a fresh random master key. We want
// encryptKeypair() to run over a FIXED keypair, so we set the private field directly.
// This is real sdk-js code (nacl.secretbox via mgmt.service.ts) — nothing here re-implements it.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
(client as any).passphraseKey = passphraseBuf;

const keystoreKeypair: IKeypair = { address: kp.address, publicKey: kp.publicKey, secretKey: kp.secretKey, version: kp.version };
const encrypted = unwrap(client.encryptKeypair(keystoreKeypair));
// Round-trip through sdk-js's own decryptKeypair to prove the vector is genuine.
const decrypted = unwrap(client.decryptKeypair(encrypted));
if (
    hex(decrypted.publicKey) !== hex(keystoreKeypair.publicKey) ||
    hex(decrypted.secretKey) !== hex(keystoreKeypair.secretKey) ||
    decrypted.address !== keystoreKeypair.address
) {
    throw new Error('keystore round-trip mismatch — refusing to emit a bad vector');
}

const keystore = {
    passphrase: KEYSTORE_PASSPHRASE,
    plaintext: {
        publicKey: hex(keystoreKeypair.publicKey),
        secretKey: hex(keystoreKeypair.secretKey),
        address: keystoreKeypair.address,
        version: keystoreKeypair.version,
    },
    encrypted: {
        address: encrypted.address,
        nonce: encrypted.nonce,
        version: encrypted.version,
        save: encrypted.save,
    },
};
fs.writeFileSync('keystore.json', JSON.stringify(keystore, null, 2));

/* -------------------------------------------------------------------------- */
/* (e) payment.json — full UTXO tx build via getInputsForTx/createTx          */
/* -------------------------------------------------------------------------- */

const senderKp = derivedKeypairs[0]; // depth 0
const receiverKp = derivedKeypairs[1]; // depth 1
const senderKeypair: IKeypair = { address: senderKp.address, publicKey: senderKp.publicKey, secretKey: senderKp.secretKey, version: null };

const fetchBalanceResponse: IFetchBalanceResponse = {
    total: { tokens: 5000, items: {} },
    address_list: {
        [senderKp.address]: [
            { out_point: { t_hash: 'a'.repeat(64), n: 0 }, value: { Token: 5000 } },
        ],
    },
};

const paymentAsset: IAssetToken = { Token: 3000 };
const allKeypairs = new Map<string, IKeypair>([[senderKp.address, senderKeypair]]);

const txIns = unwrap(getInputsForTx(paymentAsset, fetchBalanceResponse, allKeypairs));
const builtTx = unwrap(createTx(receiverKp.address, paymentAsset, senderKp.address, null, txIns, 0));
const finalTx = unwrap(updateSignatures(builtTx, fetchBalanceResponse, allKeypairs));

const payment = {
    fetchBalanceResponse,
    paymentAddress: receiverKp.address,
    paymentAsset,
    excessAddress: senderKp.address,
    locktime: 0,
    senderAddress: senderKp.address,
    senderPublicKey: hex(senderKp.publicKey),
    createTxPayload: finalTx,
};
fs.writeFileSync('payment.json', JSON.stringify(payment, null, 2));

/* -------------------------------------------------------------------------- */
/* (f) item.json — item-asset creation payload via createItemPayload         */
/* -------------------------------------------------------------------------- */

const itemKp = derivedKeypairs[2]; // depth 2
const itemAmount = 250;
const itemPayload = unwrap(
    createItemPayload(itemKp.secretKey, itemKp.publicKey, null, itemAmount, true, null),
);
const item = {
    secretKey: hex(itemKp.secretKey),
    publicKey: hex(itemKp.publicKey),
    version: null,
    amount: itemAmount,
    defaultGenesisHashSpec: true,
    metadata: null,
    assetItemHash: constructTxInSignableAssetHash({
        Item: { amount: itemAmount, genesis_hash: '', metadata: null },
    }),
    payload: itemPayload,
};
fs.writeFileSync('item.json', JSON.stringify(item, null, 2));

// eslint-disable-next-line no-console
console.log('wrote derivation.json signing.json signable.json keystore.json payment.json item.json');
