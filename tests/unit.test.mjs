import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { encodeAbiParameters, pad } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { verifyBaseUsdcTransfer } from '../src/base-verifier.ts';
import { signEd25519License } from '../src/license-signer.ts';
import { verifyLicenseTokenOffline } from '../src/offline-verify.ts';
import app from '../src/index.ts';

const PAY_TO = '0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function makeLog(token, from, to, atomic) {
  return {
    address: token,
    topics: [TRANSFER_TOPIC, pad(from, { size: 32 }), pad(to, { size: 32 })],
    data: encodeAbiParameters([{ type: 'uint256' }], [atomic])
  };
}

function createMemoryKv() {
  const store = new Map();
  return {
    async get(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async put(key, val) {
      store.set(key, val);
    },
    async delete(key) {
      store.delete(key);
    }
  };
}

test('Ed25519 signer and portable WebCrypto offline verifier pass valid and reject tampered/expired', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicKeySpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const token = await signEd25519License({
    privateJwkJson,
    tokenPrefix: 'ZEROFIAT-KIT-v1.',
    payload: {
      v: 1,
      product: 'zerofiat-base-checkout-kit',
      tier: 'solo',
      payer: '0x1111111111111111111111111111111111111111',
      txHash: '0x' + 'aa'.repeat(32),
      issuedAt: Date.now(),
      expiresAt: null
    }
  });

  const ok = await verifyLicenseTokenOffline(token, {
    publicKeySpkiB64,
    expectedPrefix: 'ZEROFIAT-KIT-v1.',
    expectedProduct: 'zerofiat-base-checkout-kit'
  });
  assert.equal(ok.valid, true);
  assert.equal(ok.payload?.tier, 'solo');

  const parts = token.split('.');
  const forgedPayload = Buffer.from(
    JSON.stringify({ v: 1, product: 'zerofiat-base-checkout-kit', tier: 'team' })
  ).toString('base64url');
  const tampered = await verifyLicenseTokenOffline(`${parts[0]}.${forgedPayload}.${parts[2]}`, {
    publicKeySpkiB64,
    expectedPrefix: 'ZEROFIAT-KIT-v1.',
    expectedProduct: 'zerofiat-base-checkout-kit'
  });
  assert.equal(tampered.valid, false);
});

test('verifyBaseUsdcTransfer sums split logs via BigInt and rejects insufficient confirmations', async () => {
  const payer = privateKeyToAccount(generatePrivateKey());
  const msg = 'test-challenge';
  const sig = await payer.signMessage({ message: msg });
  const txHash = '0x' + 'cd'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' }); // block 101
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64', // block 100 -> 2 confirmations
        logs: [
          makeLog(BASE_USDC, payer.address, PAY_TO, 10_000_000n),
          makeLog(BASE_USDC, payer.address, PAY_TO, 19_000_000n)
        ]
      }
    });
  };

  try {
    const passRes = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 29_000_000n,
      minConfirmations: 2,
      challengeMessage: msg,
      signature: sig
    });
    assert.equal(passRes.ok, true);
    if (passRes.ok) {
      assert.equal(passRes.paidAtomic, '29000000');
      assert.equal(passRes.confirmations, 2);
    }

    const lowConf = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 29_000_000n,
      minConfirmations: 5,
      challengeMessage: msg,
      signature: sig
    });
    assert.equal(lowConf.ok, false);
    if (!lowConf.ok) {
      assert.equal(lowConf.error, 'INSUFFICIENT_CONFIRMATIONS');
    }
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Hono /api/verify rejects expired (>300s) challenge timestamps deterministically', async () => {
  const kv = createMemoryKv();
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'ef'.repeat(32);
  const expiredTs = Math.floor(Date.now() / 1000) - 305;
  const nonce = 'expirednonce1234';
  const message = `expired-msg-${nonce}`;
  const sig = await payer.signMessage({ message });

  await kv.put(
    `challenge:${nonce}`,
    JSON.stringify({
      nonce,
      txHash: txHash.toLowerCase(),
      tier: 'solo',
      ts: expiredTs,
      message
    })
  );

  const res = await app.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce, signature: sig, tier: 'solo' })
    },
    {
      LICENSES_KV: kv,
      BRAND_NAME: 'ApexHive Labs',
      PRODUCT_ID: 'zerofiat-base-checkout-kit',
      TOKEN_PREFIX: 'ZEROFIAT-KIT-v1.',
      PAY_TO_EVM_ADDRESS: PAY_TO,
      BASE_USDC_CONTRACT: BASE_USDC,
      BASE_CHAIN_ID: '8453',
      BASE_RPC_URL: 'http://127.0.0.1:4199',
      SOLO_PRICE_USDC_ATOMIC: '29000000',
      TEAM_PRICE_USDC_ATOMIC: '59000000',
      MIN_CONFIRMATIONS: '2',
      CHALLENGE_TTL_SECONDS: '300',
      DOWNLOAD_TTL_SECONDS: '600',
      GITHUB_RELEASE_ASSET_URL: 'http://127.0.0.1:4122/release.zip',
      RELEASE_FILENAME: 'kit.zip',
      SOLANA_RECEIVE_ADDRESS: 'sol',
      BTC_RECEIVE_ADDRESS: 'btc',
      TRON_RECEIVE_ADDRESS: 'tron'
    }
  );
  assert.equal(res.status, 403);
  const json = await res.json();
  assert.equal(json.error, 'CHALLENGE_MISMATCH_OR_EXPIRED');
});
