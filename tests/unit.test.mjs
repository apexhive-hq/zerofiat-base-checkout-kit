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

function baseEnv(kv, overrides = {}) {
  return {
    LICENSES_KV: kv,
    GLOBAL_CLAIMED_TX_KV: overrides.GLOBAL_CLAIMED_TX_KV ?? createMemoryKv(),
    BRAND_NAME: 'ApexHive Labs',
    PRODUCT_ID: 'zerofiat-base-checkout-kit',
    TOKEN_PREFIX: 'ZEROFIAT-KIT-v1.',
    PAY_TO_EVM_ADDRESS: PAY_TO,
    BASE_USDC_CONTRACT: BASE_USDC,
    BASE_CHAIN_ID: '8453',
    BASE_RPC_URL: 'http://127.0.0.1:4199',
    SUPPORTER_PRICE_USDC_ATOMIC: '5000000',
    TEAM_PRICE_USDC_ATOMIC: '49000000',
    HOSTED_FREE_QUOTA_ATOMIC: '10000000000',
    MIN_CONFIRMATIONS: '2',
    CHALLENGE_TTL_SECONDS: '300',
    DOWNLOAD_TTL_SECONDS: '600',
    GITHUB_RELEASE_ASSET_URL: 'http://127.0.0.1:4122/release.zip',
    RELEASE_FILENAME: 'kit.zip',
    SOLANA_RECEIVE_ADDRESS: 'sol',
    BTC_RECEIVE_ADDRESS: 'btc',
    TRON_RECEIVE_ADDRESS: 'tron',
    ...overrides
  };
}

test('Ed25519 signer and portable WebCrypto offline verifier pass supporter/team and reject tampered', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicKeySpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  for (const tier of ['supporter', 'team']) {
    const token = await signEd25519License({
      privateJwkJson,
      tokenPrefix: 'ZEROFIAT-KIT-v1.',
      payload: {
        v: 1,
        product: 'zerofiat-base-checkout-kit',
        tier,
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
    assert.equal(ok.payload?.tier, tier);
  }

  const token = await signEd25519License({
    privateJwkJson,
    tokenPrefix: 'ZEROFIAT-KIT-v1.',
    payload: {
      v: 1,
      product: 'zerofiat-base-checkout-kit',
      tier: 'supporter',
      payer: '0x1111111111111111111111111111111111111111',
      txHash: '0x' + 'aa'.repeat(32),
      issuedAt: Date.now(),
      expiresAt: null
    }
  });
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

test('verifyBaseUsdcTransfer sums split logs via BigInt, rejects low confirmations, and supports Hosted mode', async () => {
  const payer = privateKeyToAccount(generatePrivateKey());
  const msg = 'test-challenge';
  const sig = await payer.signMessage({ message: msg });
  const txHash = '0x' + 'cd'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [
          makeLog(BASE_USDC, payer.address, PAY_TO, 2_000_000n),
          makeLog(BASE_USDC, payer.address, PAY_TO, 3_000_000n)
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
      requiredAtomicAmount: 5_000_000n,
      minConfirmations: 2,
      challengeMessage: msg,
      signature: sig
    });
    assert.equal(passRes.ok, true);
    if (passRes.ok) {
      assert.equal(passRes.paidAtomic, '5000000');
      assert.equal(passRes.confirmations, 2);
    }

    const hostedPass = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 5_000_000n,
      minConfirmations: 2,
      requireSignature: false
    });
    assert.equal(hostedPass.ok, true);

    const lowConf = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 5_000_000n,
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
      tier: 'supporter',
      ts: expiredTs,
      message
    })
  );

  const res = await app.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce, signature: sig, tier: 'supporter' })
    },
    baseEnv(kv, {
      LICENSE_SIGNING_PRIVATE_JWK: '{}',
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    })
  );
  assert.equal(res.status, 403);
  const json = await res.json();
  assert.equal(json.error, 'CHALLENGE_MISMATCH_OR_EXPIRED');
});

test('Fail-closed 500 when signing/HMAC secrets missing, and 200 MIT cert delivery without GITHUB_RELEASE_READ_TOKEN', async () => {
  const kv = createMemoryKv();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'ab'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 5_000_000n)]
      }
    });
  };

  try {
    // 1. Missing secrets must fail closed with 500
    const envMissing = baseEnv(kv, {
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64
    });
    const chRes1 = await app.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier: 'supporter' })
      },
      envMissing
    );
    const ch1 = await chRes1.json();
    const sig1 = await payer.signMessage({ message: ch1.message });

    const failVerify = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch1.nonce, signature: sig1, tier: 'supporter' })
      },
      envMissing
    );
    assert.equal(failVerify.status, 500);

    const failDownload = await app.request('/api/download?token=abc', {}, envMissing);
    assert.equal(failDownload.status, 500);

    // 2. Valid secrets WITHOUT GITHUB_RELEASE_READ_TOKEN must succeed 200 with signed MIT certificate
    const envPublicMit = baseEnv(kv, {
      LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64,
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      PUBLIC_ARCHIVE_URL: ''
    });
    const chRes2 = await app.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier: 'supporter' })
      },
      envPublicMit
    );
    const ch2 = await chRes2.json();
    const sig2 = await payer.signMessage({ message: ch2.message });

    const okVerify = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch2.nonce, signature: sig2, tier: 'supporter' })
      },
      envPublicMit
    );
    assert.equal(okVerify.status, 200);
    const okJson = await okVerify.json();
    assert.ok(okJson.licenseToken.startsWith('ZEROFIAT-KIT-v1.'));

    const certRes = await app.request(okJson.downloadUrl, {}, envPublicMit);
    assert.equal(certRes.status, 200);
    const certJson = await certRes.json();
    assert.equal(certJson.openSourceLicense, 'MIT');
    assert.equal(certJson.licenseToken, okJson.licenseToken);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Hosted /api/hosted/verify enforces cached minAmount, optional sig, cumulative $10k cap, strict hex & CORS/UTF-8', async () => {
  const kv = createMemoryKv();
  const payer = privateKeyToAccount(generatePrivateKey());
  const attacker = privateKeyToAccount(generatePrivateKey());
  const merchant = '0x1234567890123456789012345678901234567890';
  const tx5k = '0x' + '61'.repeat(32);
  const tx6k = '0x' + '62'.repeat(32);
  const txBadHex = '0x' + '63'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    const h = String(req.params?.[0] ?? '').toLowerCase();
    if (h === txBadHex) {
      return Response.json({
        jsonrpc: '2.0',
        id: req.id,
        result: { status: '0x1', blockNumber: '0x', logs: [] }
      });
    }
    const amt = h === tx6k ? 6_000_000_000n : 5_000_000_000n;
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, payer.address, merchant, amt)]
      }
    });
  };

  try {
    const env = baseEnv(kv);

    // 1. Negative minAmountAtomic rejected before KV/RPC
    const badAmt = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx5k, merchantAddress: merchant, minAmountAtomic: '0' })
      },
      env
    );
    assert.equal(badAmt.status, 400);
    assert.equal(badAmt.headers.get('access-control-allow-origin'), '*');
    assert.ok(badAmt.headers.get('content-type')?.includes('charset=utf-8'));

    // 2. First $5,000 TX succeeds
    const r5k = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx5k, merchantAddress: merchant, minAmountAtomic: '5000000000' })
      },
      env
    );
    assert.equal(r5k.status, 200);

    // 3. Cached replay with higher minAmountAtomic ($6,000 > $5,000) MUST reject 403 INSUFFICIENT_AMOUNT
    const rReplayLow = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx5k, merchantAddress: merchant, minAmountAtomic: '6000000000' })
      },
      env
    );
    assert.equal(rReplayLow.status, 403);
    assert.equal((await rReplayLow.json()).error, 'INSUFFICIENT_AMOUNT');

    // 4. Cached replay with wrong EIP-191 signature MUST reject 403 INVALID_SIGNATURE
    const chalMsg = 'hosted-proof-msg';
    const badSig = await attacker.signMessage({ message: chalMsg });
    const rReplayBadSig = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: tx5k,
          merchantAddress: merchant,
          minAmountAtomic: '5000000000',
          challengeMessage: chalMsg,
          signature: badSig
        })
      },
      env
    );
    assert.equal(rReplayBadSig.status, 403);
    assert.equal((await rReplayBadSig.json()).error, 'INVALID_SIGNATURE');

    // 5. Cumulative cap check: $5k + $6k = $11k > $10k MUST return 402 QUOTA_EXCEEDED_10K
    const rOver = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx6k, merchantAddress: merchant })
      },
      env
    );
    assert.equal(rOver.status, 402);
    assert.equal((await rOver.json()).error, 'QUOTA_EXCEEDED_10K');

    // 6. Strict hex check rejects malformed blockNumber "0x" fail-closed 403
    const rHex = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txBadHex, merchantAddress: merchant })
      },
      env
    );
    assert.equal(rHex.status, 403);
    assert.equal((await rHex.json()).error, 'TX_NOT_CONFIRMED');

    // 7. Shared GLOBAL_CLAIMED_TX_KV blocks cross-product replay ("storefront:slimmcp" -> #2 "storefront:zerofiat")
    const globalKv = createMemoryKv();
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const envCross = baseEnv(kv, {
      GLOBAL_CLAIMED_TX_KV: globalKv,
      LICENSE_SIGNING_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: 'jwk' })),
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    });
    const txCross = '0x' + '64'.repeat(32);
    await globalKv.put(
      `global_tx:${txCross}`,
      JSON.stringify({
        scope: 'storefront:slimmcp',
        payer: payer.address,
        tier: 'indie',
        txHash: txCross,
        claimedAt: Date.now()
      })
    );
    globalThis.fetch = async (_url, init) => {
      const req = JSON.parse(String(init.body));
      if (req.method === 'eth_blockNumber') {
        return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
      }
      return Response.json({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          status: '0x1',
          blockNumber: '0x64',
          logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 5_000_000n)]
        }
      });
    };
    const chCross = await (
      await app.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: txCross, tier: 'supporter' })
        },
        envCross
      )
    ).json();
    const sigCross = await payer.signMessage({ message: chCross.message });
    const resCross = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txCross, nonce: chCross.nonce, signature: sigCross, tier: 'supporter' })
      },
      envCross
    );
    assert.equal(resCross.status, 403);
    assert.equal((await resCross.json()).error, 'TX_ALREADY_CLAIMED_ELSEWHERE');
  } finally {
    globalThis.fetch = origFetch;
  }
});
