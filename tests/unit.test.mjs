import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { encodeAbiParameters, pad } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { verifyBaseUsdcTransfer } from '../src/base-verifier.ts';
import { signEd25519License } from '../src/license-signer.ts';
import { verifyLicenseTokenOffline } from '../src/offline-verify.ts';
import app, { TxClaimLockDO, parsePositiveInt } from '../src/index.ts';

const PAY_TO = '0x1111111111111111111111111111111111111111';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const HOSTED_TOKEN = 'hosted-test-secret-token-0123456789abcdef';
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const BOOL_TRUE_HEX = '0x' + '0'.repeat(63) + '1';
const BOOL_FALSE_HEX = '0x' + '0'.repeat(64);

function makeLog(token, from, to, atomic) {
  return {
    address: token,
    topics: [TRANSFER_TOPIC, pad(from, { size: 32 }), pad(to, { size: 32 })],
    data: encodeAbiParameters([{ type: 'uint256' }], [atomic])
  };
}

function createMemoryTxLockNamespace() {
  const instances = new Map();
  return {
    idFromName(name) {
      return String(name).toLowerCase();
    },
    get(id) {
      const key = String(id);
      if (!instances.has(key)) {
        const storageMap = new Map();
        const ctx = {
          storage: {
            async get(k) {
              return storageMap.get(k);
            },
            async put(k, v) {
              // Yield a microtask to confirm runExclusive serializes async storage writes
              await Promise.resolve();
              storageMap.set(k, v);
            },
            async delete(k) {
              await Promise.resolve();
              return storageMap.delete(k);
            }
          }
        };
        instances.set(key, new TxClaimLockDO(ctx));
      }
      const instance = instances.get(key);
      return {
        fetch(input, init) {
          const req = input instanceof Request ? input : new Request(input, init);
          return instance.fetch(req);
        }
      };
    }
  };
}

function baseEnv(overrides = {}) {
  return {
    TX_CLAIM_LOCK: overrides.TX_CLAIM_LOCK ?? createMemoryTxLockNamespace(),
    BRAND_NAME: 'ApexHive Labs',
    PRODUCT_ID: 'zerofiat-base-checkout-kit',
    TOKEN_PREFIX: 'ZEROFIAT-KIT-v1.',
    PAY_TO_EVM_ADDRESS: PAY_TO,
    BASE_USDC_CONTRACT: BASE_USDC,
    BASE_CHAIN_ID: '8453',
    BASE_RPC_URL: 'http://127.0.0.1:4199',
    CHECKOUT_AMOUNT_USDC_ATOMIC: '1000000',
    MIN_CONFIRMATIONS: '2',
    CHALLENGE_TTL_SECONDS: '300',
    DOWNLOAD_TTL_SECONDS: '600',
    RELEASE_FILENAME: 'zerofiat-base-checkout-kit.zip',
    HOSTED_API_TOKEN: HOSTED_TOKEN,
    ...overrides
  };
}

test('Ed25519 signer and portable WebCrypto offline verifier pass standard cert and reject tampered', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicKeySpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const token = await signEd25519License({
    privateJwkJson,
    tokenPrefix: 'ZEROFIAT-KIT-v1.',
    payload: {
      v: 1,
      product: 'zerofiat-base-checkout-kit',
      tier: 'standard',
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
  assert.equal(ok.payload?.tier, 'standard');

  const parts = token.split('.');
  const forgedPayload = Buffer.from(
    JSON.stringify({ v: 1, product: 'zerofiat-base-checkout-kit', tier: 'standard', payer: '0x2222222222222222222222222222222222222222' })
  ).toString('base64url');
  const tampered = await verifyLicenseTokenOffline(`${parts[0]}.${forgedPayload}.${parts[2]}`, {
    publicKeySpkiB64,
    expectedPrefix: 'ZEROFIAT-KIT-v1.',
    expectedProduct: 'zerofiat-base-checkout-kit'
  });
  assert.equal(tampered.valid, false);
});

test('verifyBaseUsdcTransfer supports EOA, ERC-1271/EIP-6492 Smart Wallets, and multi-payer batch aggregation', async () => {
  const smartWalletAddr = '0x7777777777777777777777777777777777777777';
  const batchPayerA = '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const batchPayerB = '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const smartSigValid = '0x' + 'ab'.repeat(256); // 256-byte variable-length ABI smart wallet sig (>130 hex)
  const smartSigInvalid = '0x' + 'cd'.repeat(180);
  const txHash = '0x' + 'de'.repeat(32);
  const txBatch = '0x' + 'df'.repeat(32);

  let ethCallCount = 0;
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    if (req.method === 'eth_call') {
      ethCallCount += 1;
      const callData = String(req.params?.[0]?.data ?? '').toLowerCase();
      const validMarker = 'ab'.repeat(256);
      return Response.json({
        jsonrpc: '2.0',
        id: req.id,
        result: callData.includes(validMarker) ? BOOL_TRUE_HEX : BOOL_FALSE_HEX
      });
    }
    const h = String(req.params?.[0] ?? '').toLowerCase();
    if (h === txBatch) {
      return Response.json({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          status: '0x1',
          blockNumber: '0x64',
          logs: [
            makeLog(BASE_USDC, batchPayerA, PAY_TO, 400_000n),
            makeLog(BASE_USDC, batchPayerB, PAY_TO, 600_000n)
          ]
        }
      });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [
          makeLog(BASE_USDC, smartWalletAddr, PAY_TO, 500_000n),
          makeLog(BASE_USDC, smartWalletAddr, PAY_TO, 500_000n)
        ]
      }
    });
  };

  try {
    const smartOk = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 1_000_000n,
      minConfirmations: 2,
      challengeMessage: 'smart-wallet-msg',
      signature: smartSigValid
    });
    assert.equal(smartOk.ok, true);
    assert.ok(ethCallCount >= 1, 'Expected eth_call for ERC-1271/EIP-6492 smart wallet verification');
    if (smartOk.ok) {
      assert.equal(smartOk.payer, smartWalletAddr);
      assert.equal(smartOk.paidAtomic, '1000000');
    }

    const smartBad = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 1_000_000n,
      minConfirmations: 2,
      challengeMessage: 'smart-wallet-msg',
      signature: smartSigInvalid
    });
    assert.equal(smartBad.ok, false);
    if (!smartBad.ok) {
      assert.equal(smartBad.error, 'PAYMENT_OR_SIGNATURE_INVALID');
    }

    // Multi-payer batch tx: unsigned check aggregates recipient total (1_000_000),
    // while signed check rejects if neither individual payer met 1_000_000 alone
    const batchUnsigned = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash: txBatch,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 1_000_000n,
      minConfirmations: 2,
      requireSignature: false
    });
    assert.equal(batchUnsigned.ok, true);
    if (batchUnsigned.ok) {
      assert.equal(batchUnsigned.paidAtomic, '1000000');
      assert.equal(batchUnsigned.payer, batchPayerB);
    }

    const batchSigned = await verifyBaseUsdcTransfer({
      rpcUrl: 'http://127.0.0.1:4199',
      txHash: txBatch,
      expectedUsdcContract: BASE_USDC,
      expectedPayTo: PAY_TO,
      requiredAtomicAmount: 1_000_000n,
      minConfirmations: 2,
      challengeMessage: 'msg',
      signature: smartSigValid,
      requireSignature: true
    });
    assert.equal(batchSigned.ok, false);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Hosted /api/hosted/verify blocks unauthenticated lock-griefing, enforces 409 default, atomic DO GMV, and scope isolation', async () => {
  const lockNs = createMemoryTxLockNamespace();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const payer = privateKeyToAccount(generatePrivateKey());
  const merchant = '0x1234567890123456789012345678901234567890';
  const txOne = '0x' + '61'.repeat(32);
  const txTwo = '0x' + '62'.repeat(32);
  const txThree = '0x' + '63'.repeat(32);
  const txMultiScope = '0x' + '64'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    const h = String(req.params?.[0] ?? '').toLowerCase();
    if (h === txMultiScope) {
      return Response.json({
        jsonrpc: '2.0',
        id: req.id,
        result: {
          status: '0x1',
          blockNumber: '0x64',
          logs: [
            makeLog(BASE_USDC, payer.address, merchant, 1_000_000n),
            makeLog(BASE_USDC, payer.address, PAY_TO, 1_000_000n)
          ]
        }
      });
    }
    const amt = h === txOne || h === txTwo || h === txThree ? 6_000_000_000n : 1_000_000n;
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
    const env = baseEnv({
      TX_CLAIM_LOCK: lockNs,
      LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64,
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      PUBLIC_ARCHIVE_URL: ''
    });

    // 0a. Anonymous caller CANNOT consume/lock a third-party merchant's txHash (403 HOSTED_AUTH_REQUIRED)
    const griefAttempt = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txOne, merchantAddress: merchant, minAmountAtomic: '6000000000' })
      },
      env
    );
    assert.equal(griefAttempt.status, 403);
    assert.equal((await griefAttempt.json()).error, 'HOSTED_AUTH_REQUIRED');

    // 0b. Read-only consumeOnce: false succeeds without locking tx or mutating GMV
    const readOnlyRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: txOne,
          merchantAddress: merchant,
          minAmountAtomic: '6000000000',
          consumeOnce: false
        })
      },
      env
    );
    assert.equal(readOnlyRes.status, 200);
    const readOnlyJson = await readOnlyRes.json();
    assert.equal(readOnlyJson.consumed, false);
    assert.equal(readOnlyJson.cached, false);
    assert.equal(readOnlyJson.gmvAtomic, '0');

    // 1. Concurrent Promise.all race for txOne with HOSTED_API_TOKEN under strict single-use default:
    //    exactly 1 returns 200 (consumed=true, cached=false) and 4 return 409 TX_ALREADY_CLAIMED!
    const concurrentReqs = Array.from({ length: 5 }, () =>
      app.request(
        '/api/hosted/verify',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            Authorization: `Bearer ${HOSTED_TOKEN}`
          },
          body: JSON.stringify({ txHash: txOne, merchantAddress: merchant, minAmountAtomic: '6000000000' })
        },
        env
      )
    );
    const results = await Promise.all(concurrentReqs);
    const bodies = await Promise.all(results.map((r) => r.json()));
    assert.equal(results.filter((r) => r.status === 200).length, 1);
    assert.equal(results.filter((r) => r.status === 409).length, 4);
    assert.equal(bodies.filter((b) => b.ok === true && b.cached === false && b.consumed === true).length, 1);
    assert.equal(bodies.filter((b) => b.ok === false && b.error === 'TX_ALREADY_CLAIMED').length, 4);

    const q1 = await (await app.request(`/api/hosted/quota/${merchant}`, {}, env)).json();
    assert.equal(q1.gmvAtomic, '6000000000');
    assert.equal(q1.unlimitedFreeMit, true);

    // After locked, read-only consumeOnce: false reflects cached=true without re-counting GMV
    const cachedCheck = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: txOne,
          merchantAddress: merchant,
          minAmountAtomic: '6000000000',
          consumeOnce: false
        })
      },
      env
    );
    assert.equal(cachedCheck.status, 200);
    const cachedJson = await cachedCheck.json();
    assert.equal(cachedJson.cached, true);
    assert.equal(cachedJson.consumed, false);
    assert.equal(cachedJson.gmvAtomic, '6000000000');

    // 2. Concurrent distinct txHashes (txTwo & txThree) accumulate atomic DO GMV with zero lost updates
    const [r2, r3] = await Promise.all([
      app.request(
        '/api/hosted/verify',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-hosted-api-key': HOSTED_TOKEN
          },
          body: JSON.stringify({ txHash: txTwo, merchantAddress: merchant, minAmountAtomic: '6000000000' })
        },
        env
      ),
      app.request(
        '/api/hosted/verify',
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            Authorization: `Bearer ${HOSTED_TOKEN}`
          },
          body: JSON.stringify({ txHash: txThree, merchantAddress: merchant, minAmountAtomic: '6000000000' })
        },
        env
      )
    ]);
    assert.equal(r2.status, 200);
    assert.equal(r3.status, 200);
    const qAfter = await (await app.request(`/api/hosted/quota/${merchant}`, {}, env)).json();
    assert.equal(qAfter.gmvAtomic, '18000000000');

    // 3. Scope isolation: claiming txMultiScope via /api/hosted/verify MUST NOT grief/lock /api/verify!
    const hostedClaim = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${HOSTED_TOKEN}`
        },
        body: JSON.stringify({ txHash: txMultiScope, merchantAddress: merchant, minAmountAtomic: '1000000' })
      },
      env
    );
    assert.equal(hostedClaim.status, 200);

    const ch = await (
      await app.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: txMultiScope, tier: 'standard' })
        },
        env
      )
    ).json();
    const sig = await payer.signMessage({ message: ch.message });
    const vRes = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txMultiScope, nonce: ch.nonce, signature: sig, tier: 'standard' })
      },
      env
    );
    assert.equal(vRes.status, 200, 'Hosted claim must never block self-checkout /api/verify claim');

    // 4. Atomic download grant decrement under concurrent Promise.all: 5 requests -> 3 pass, 2 fail
    const vJson = await vRes.json();
    const dlConcurrent = await Promise.all(
      Array.from({ length: 5 }, () => app.request(vJson.downloadUrl, { method: 'GET' }, env))
    );
    assert.equal(dlConcurrent.filter((r) => r.status === 200).length, 3);
    assert.equal(dlConcurrent.filter((r) => r.status === 403).length, 2);

    // 5. Oversized JSON payload returns 413 PAYLOAD_TOO_LARGE
    const bigRes = await app.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: '0x' + 'a'.repeat(40_000) })
      },
      env
    );
    assert.equal(bigRes.status, 413);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Hosted /api/hosted/verify blocks unauthenticated host PAY_TO_EVM_ADDRESS and enforces server-bound challenge nonces', async () => {
  const lockNs = createMemoryTxLockNamespace();
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHost = '0x' + '71'.repeat(32);
  const txFlag = '0x' + '72'.repeat(32);

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
        logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 1_000_000n)]
      }
    });
  };

  try {
    const env = baseEnv({ TX_CLAIM_LOCK: lockNs });

    // 1. Unauthenticated hosted call targeting host PAY_TO_EVM_ADDRESS is blocked (403)
    const unauthHostRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txHost, merchantAddress: PAY_TO, minAmountAtomic: '1000000' })
      },
      env
    );
    assert.equal(unauthHostRes.status, 403);
    assert.equal((await unauthHostRes.json()).error, 'HOST_MERCHANT_SIGNATURE_REQUIRED');

    // 2. Raw client challengeMessage without server-issued nonce is rejected (400)
    const rawMsgSig = await payer.signMessage({ message: 'arbitrary-client-msg' });
    const rawMsgRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: txHost,
          merchantAddress: PAY_TO,
          challengeMessage: 'arbitrary-client-msg',
          signature: rawMsgSig
        })
      },
      env
    );
    assert.equal(rawMsgRes.status, 400);
    assert.equal((await rawMsgRes.json()).error, 'CHALLENGE_NONCE_REQUIRED');

    // 3. Server-issued hosted challenge (nonce + expiry) succeeds and nonce is single-use
    const chRes = await app.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txHost, scope: 'hosted', merchantAddress: PAY_TO })
      },
      env
    );
    assert.equal(chRes.status, 200);
    const ch = await chRes.json();
    assert.equal(ch.scope, 'hosted');
    const sig = await payer.signMessage({ message: ch.message });

    const okHostRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: txHost,
          merchantAddress: PAY_TO,
          minAmountAtomic: '1000000',
          nonce: ch.nonce,
          signature: sig
        })
      },
      env
    );
    assert.equal(okHostRes.status, 200);

    // Replaying the same nonce fails closed
    const replayNonceRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          txHash: txHost,
          merchantAddress: PAY_TO,
          minAmountAtomic: '1000000',
          nonce: ch.nonce,
          signature: sig
        })
      },
      env
    );
    assert.equal(replayNonceRes.status, 403);

    // 4. Explicit ALLOW_UNAUTHENTICATED_HOSTED_PAY_TO='true' + HOSTED_API_TOKEN permits opt-in
    const optInEnv = baseEnv({
      TX_CLAIM_LOCK: lockNs,
      ALLOW_UNAUTHENTICATED_HOSTED_PAY_TO: 'true'
    });
    const optInRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          Authorization: `Bearer ${HOSTED_TOKEN}`
        },
        body: JSON.stringify({ txHash: txFlag, merchantAddress: PAY_TO, minAmountAtomic: '1000000' })
      },
      optInEnv
    );
    assert.equal(optInRes.status, 200);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Transient 502 RPC errors preserve DO challenge nonce, and concurrent /api/verify nonce reuse is blocked', async () => {
  const lockNs = createMemoryTxLockNamespace();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + '88'.repeat(32);

  let rpcDown = true;
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    if (rpcDown) {
      return new Response('Upstream error', { status: 503 });
    }
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
        logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 1_000_000n)]
      }
    });
  };

  try {
    const env = baseEnv({
      TX_CLAIM_LOCK: lockNs,
      LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64,
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    });

    const ch = await (
      await app.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash, tier: 'standard' })
        },
        env
      )
    ).json();
    const sig = await payer.signMessage({ message: ch.message });

    // 1. Transient RPC failure returns 502 WITHOUT burning the nonce
    const r502 = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch.nonce, signature: sig, tier: 'standard' })
      },
      env
    );
    assert.equal(r502.status, 502);

    // 2. Once RPC recovers, two concurrent /api/verify calls with the SAME nonce yield 1 x 200 and 1 x 403!
    rpcDown = false;
    const [a, b] = await Promise.all([
      app.request(
        '/api/verify',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash, nonce: ch.nonce, signature: sig, tier: 'standard' })
        },
        env
      ),
      app.request(
        '/api/verify',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash, nonce: ch.nonce, signature: sig, tier: 'standard' })
        },
        env
      )
    ]);
    const statuses = [a.status, b.status].sort();
    assert.deepEqual(statuses, [200, 403]);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Transient eth_call RPC outage during ERC-1271/EIP-6492 signature check returns 502 RPC_UNAVAILABLE and preserves nonce', async () => {
  const lockNs = createMemoryTxLockNamespace();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const smartWalletAddr = '0x7777777777777777777777777777777777777777';
  const smartSigValid = '0x' + 'ab'.repeat(256);
  const txHash = '0x' + '91'.repeat(32);

  let ethCallOutage = true;
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    if (req.method === 'eth_call') {
      if (ethCallOutage) {
        return new Response('RPC Gateway Timeout', { status: 504 });
      }
      return Response.json({ jsonrpc: '2.0', id: req.id, result: BOOL_TRUE_HEX });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, smartWalletAddr, PAY_TO, 1_000_000n)]
      }
    });
  };

  try {
    const env = baseEnv({
      TX_CLAIM_LOCK: lockNs,
      LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64,
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    });

    const ch = await (
      await app.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash, tier: 'standard' })
        },
        env
      )
    ).json();

    // 1. Transient eth_call outage returns 502 RPC_UNAVAILABLE (NOT 403) and keeps nonce alive
    const outageRes = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch.nonce, signature: smartSigValid, tier: 'standard' })
      },
      env
    );
    assert.equal(outageRes.status, 502);
    assert.equal((await outageRes.json()).error, 'RPC_UNAVAILABLE');

    // 2. Retrying with the SAME nonce once eth_call RPC recovers succeeds 200
    ethCallOutage = false;
    const retryRes = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch.nonce, signature: smartSigValid, tier: 'standard' })
      },
      env
    );
    assert.equal(retryRes.status, 200);
    const retryJson = await retryRes.json();
    assert.equal(retryJson.payer, smartWalletAddr);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Bounded JSON parser rejects null/non-object JSON with 400 and enforces streaming byte cap before buffering', async () => {
  const env = baseEnv();

  for (const invalidBody of ['null', '[]', '"hello"', '123', 'true']) {
    const res = await app.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: invalidBody
      },
      env
    );
    assert.equal(res.status, 400, `Expected 400 for body ${invalidBody}`);
    assert.equal((await res.json()).error, 'INVALID_JSON');
  }

  // Oversized Content-Length rejected immediately
  const clRes = await app.request(
    '/api/challenge',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': '999999'
      },
      body: '{}'
    },
    env
  );
  assert.equal(clRes.status, 413);
});

test('Fail-closed 500 when PAY_TO_EVM_ADDRESS is placeholder or secrets missing, and rejects expired DO challenge', async () => {
  const lockNs = createMemoryTxLockNamespace();
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'ef'.repeat(32);

  // Placeholder PAY_TO_EVM_ADDRESS fails closed
  const placeholderEnv = baseEnv({
    TX_CLAIM_LOCK: lockNs,
    PAY_TO_EVM_ADDRESS: 'REPLACE_WITH_YOUR_EVM_ADDRESS',
    LICENSE_SIGNING_PRIVATE_JWK: '{}',
    DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  });
  const cfgRes = await app.request('/api/config', {}, placeholderEnv);
  const cfgJson = await cfgRes.json();
  assert.equal(cfgJson.payToAddress, null);
  assert.equal(cfgJson.payToConfigured, false);

  const chFail = await app.request(
    '/api/challenge',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, tier: 'standard' })
    },
    placeholderEnv
  );
  assert.equal(chFail.status, 500);
  assert.equal((await chFail.json()).error, 'SERVER_MISCONFIGURED');

  // Missing secrets fails closed
  const missingSecretsRes = await app.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce: 'n1', signature: '0x' + '11'.repeat(65), tier: 'standard' })
    },
    baseEnv({ TX_CLAIM_LOCK: lockNs })
  );
  assert.equal(missingSecretsRes.status, 500);

  // Expired DO challenge fails closed
  const nonce = 'expirednonce1234';
  const message = `expired-msg-${nonce}`;
  const sig = await payer.signMessage({ message });
  const chStub = lockNs.get(lockNs.idFromName(`challenge:${nonce}`));
  await chStub.fetch('https://lock.internal/challenge/create', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      record: {
        nonce,
        scope: 'checkout',
        txHash: txHash.toLowerCase(),
        tier: 'standard',
        ts: Math.floor(Date.now() / 1000) - 400,
        expiresAtMs: Date.now() - 10_000,
        message
      }
    })
  });

  const expiredRes = await app.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce, signature: sig, tier: 'standard' })
    },
    baseEnv({
      TX_CLAIM_LOCK: lockNs,
      LICENSE_SIGNING_PRIVATE_JWK: '{}',
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    })
  );
  assert.equal(expiredRes.status, 403);
  assert.equal((await expiredRes.json()).error, 'CHALLENGE_MISMATCH_OR_EXPIRED');
});

test('TxClaimLockDO isolates storage keys by scope and rejects cross-scope confusion even on same instance', async () => {
  const storageMap = new Map();
  const doInst = new TxClaimLockDO({
    storage: {
      async get(k) {
        return storageMap.get(k);
      },
      async put(k, v) {
        storageMap.set(k, v);
      }
    }
  });
  const txHash = '0x' + '99'.repeat(32);
  const merchant = '0x1234567890123456789012345678901234567890';
  const payer = '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd';

  const rHosted = await doInst.fetch(
    new Request('https://lock.internal/claim-hosted', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash,
        merchantAddress: merchant,
        payer,
        paidAtomic: '1000000',
        requiredAtomic: '1000000'
      })
    })
  );
  assert.equal(rHosted.status, 200);

  const rCheckout = await doInst.fetch(
    new Request('https://lock.internal/claim-checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, payer, tier: 'standard', paidAtomic: '1000000' })
    })
  );
  assert.equal(rCheckout.status, 200);

  const rHostedReplay = await doInst.fetch(
    new Request('https://lock.internal/claim-hosted', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash,
        merchantAddress: merchant,
        payer,
        paidAtomic: '1000000',
        requiredAtomic: '1000000'
      })
    })
  );
  assert.equal(rHostedReplay.status, 409);
});

test('Strict CORS ALLOWED_ORIGINS allowlist and security headers are enforced on Worker responses', async () => {
  const env = baseEnv({ ALLOWED_ORIGINS: 'https://checkout.example.com' });

  const preflightBad = await app.request(
    'https://worker.example.com/api/verify',
    {
      method: 'OPTIONS',
      headers: { Origin: 'https://evil.example' }
    },
    env
  );
  assert.equal(preflightBad.headers.get('access-control-allow-origin'), null);
  assert.equal(preflightBad.headers.get('x-frame-options'), 'DENY');
  assert.equal(preflightBad.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(preflightBad.headers.get('referrer-policy'), 'no-referrer');
  assert.ok(preflightBad.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"));

  const postBad = await app.request(
    'https://worker.example.com/api/challenge',
    {
      method: 'POST',
      headers: {
        Origin: 'https://evil.example',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ txHash: '0x' + 'aa'.repeat(32) })
    },
    env
  );
  assert.equal(postBad.status, 403);
  assert.equal((await postBad.json()).error, 'ORIGIN_NOT_ALLOWED');

  const postAllowed = await app.request(
    'https://worker.example.com/api/challenge',
    {
      method: 'POST',
      headers: {
        Origin: 'https://checkout.example.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ txHash: '0x' + 'aa'.repeat(32) })
    },
    env
  );
  assert.equal(postAllowed.status, 200);
  assert.equal(postAllowed.headers.get('access-control-allow-origin'), 'https://checkout.example.com');
  assert.ok(postAllowed.headers.get('vary')?.toLowerCase().includes('origin'));

  const sameOriginEnv = baseEnv({ ALLOWED_ORIGINS: '' });
  const sameOriginPost = await app.request(
    'https://worker.example.com/api/challenge',
    {
      method: 'POST',
      headers: {
        Origin: 'https://worker.example.com',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ txHash: '0x' + 'ab'.repeat(32) })
    },
    sameOriginEnv
  );
  assert.equal(sameOriginPost.status, 200);
  assert.equal(sameOriginPost.headers.get('access-control-allow-origin'), 'https://worker.example.com');

  const healthRes = await app.request(
    'https://worker.example.com/api/health',
    {
      method: 'GET',
      headers: { Origin: 'https://any.example' }
    },
    sameOriginEnv
  );
  assert.equal(healthRes.status, 200);
  assert.equal(healthRes.headers.get('access-control-allow-origin'), '*');
});

test('parsePositiveInt rejects NaN/non-positive env values fail-closed for MIN_CONFIRMATIONS and TTLs', async () => {
  assert.equal(parsePositiveInt('not-a-number', 2, 1), 2);
  assert.equal(parsePositiveInt('0', 2, 1), 2);
  assert.equal(parsePositiveInt('-5', 300, 60), 300);
  assert.equal(parsePositiveInt('10abc', 600, 120), 600);
  assert.equal(parsePositiveInt('45', 300, 60), 300);
  assert.equal(parsePositiveInt('120', 300, 60), 120);

  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'c1'.repeat(32);
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      // Same block as tx -> 1 confirmation
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x64' });
    }
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, payer.address, PAY_TO, 1_000_000n)]
      }
    });
  };

  try {
    const { privateKey } = generateKeyPairSync('ed25519');
    const env = baseEnv({
      MIN_CONFIRMATIONS: 'NaN',
      CHALLENGE_TTL_SECONDS: '-99',
      DOWNLOAD_TTL_SECONDS: 'invalid',
      LICENSE_SIGNING_PRIVATE_JWK: JSON.stringify(privateKey.export({ format: 'jwk' })),
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    });

    const chRes = await app.request(
      '/api/challenge',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier: 'standard' })
      },
      env
    );
    assert.equal(chRes.status, 200);
    const ch = await chRes.json();
    assert.equal(ch.expiresInSeconds, 300);

    // 1-confirmation tx MUST fail closed with 403 INSUFFICIENT_CONFIRMATIONS (falls back to 2, not NaN!)
    const sig = await payer.signMessage({ message: ch.message });
    const verifyRes = await app.request(
      '/api/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: ch.nonce, signature: sig, tier: 'standard' })
      },
      env
    );
    assert.equal(verifyRes.status, 403);
    assert.equal((await verifyRes.json()).error, 'INSUFFICIENT_CONFIRMATIONS');
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('TxClaimLockDO schedules alarms on challenge/download creation and alarm() purges expired records', async () => {
  const storageMap = new Map();
  const alarms = [];
  const doInst = new TxClaimLockDO({
    storage: {
      async get(k) {
        return storageMap.get(k);
      },
      async put(k, v) {
        storageMap.set(k, v);
      },
      async delete(k) {
        return storageMap.delete(k);
      },
      async setAlarm(t) {
        alarms.push(Number(t));
      }
    }
  });

  const txHash = '0x' + 'd2'.repeat(32);
  const pastExp = Date.now() - 5_000;
  const futureExp = Date.now() + 60_000;

  // Create expired challenge + future grant, verify setAlarm called
  await doInst.fetch(
    new Request('https://lock.internal/challenge/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        record: {
          nonce: 'n-exp',
          scope: 'checkout',
          txHash,
          tier: 'standard',
          ts: Math.floor(Date.now() / 1000) - 400,
          expiresAtMs: pastExp,
          message: 'expired'
        }
      })
    })
  );
  await doInst.fetch(
    new Request('https://lock.internal/download/create', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant: {
          txHash,
          payer: PAY_TO,
          tier: 'standard',
          remainingDownloads: 2,
          createdAt: Date.now(),
          expiresAtMs: futureExp
        }
      })
    })
  );
  assert.deepEqual(alarms, [pastExp, futureExp]);

  // alarm() deletes expired challenge while keeping active future grant
  await doInst.alarm();
  assert.equal(storageMap.has('challenge'), false);
  assert.equal(storageMap.has('grant'), true);

  // Expire grant and verify alarm() deletes it too
  storageMap.set('grant', { ...storageMap.get('grant'), expiresAtMs: Date.now() - 1000 });
  await doInst.alarm();
  assert.equal(storageMap.has('grant'), false);
});
