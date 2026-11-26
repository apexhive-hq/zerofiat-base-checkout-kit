import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';
import { encodeAbiParameters, pad } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { verifyBaseUsdcTransfer } from '../src/base-verifier.ts';
import { signEd25519License } from '../src/license-signer.ts';
import { verifyLicenseTokenOffline } from '../src/offline-verify.ts';
import app, { TxClaimLockDO } from '../src/index.ts';

const PAY_TO = '0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
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

function baseEnv(kv, overrides = {}) {
  return {
    LICENSES_KV: kv,
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

test('verifyBaseUsdcTransfer supports EOA and variable-length ERC-1271/EIP-6492 Smart Wallet signatures', async () => {
  const smartWalletAddr = '0x7777777777777777777777777777777777777777';
  const smartSigValid = '0x' + 'ab'.repeat(256); // 256-byte variable-length ABI smart wallet sig (>130 hex)
  const smartSigInvalid = '0x' + 'cd'.repeat(180);
  const txHash = '0x' + 'de'.repeat(32);

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
  } finally {
    globalThis.fetch = origFetch;
  }
});

test('Hosted /api/hosted/verify is unlimited Free MIT, race-safe under Promise.all DO lock, and blocks cross-scope reuse', async () => {
  const kv = createMemoryKv();
  const lockNs = createMemoryTxLockNamespace();
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwkJson = JSON.stringify(privateKey.export({ format: 'jwk' }));
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const payer = privateKeyToAccount(generatePrivateKey());
  const merchant = '0x1234567890123456789012345678901234567890';
  const tx6k = '0x' + '61'.repeat(32);
  const tx6kTwo = '0x' + '62'.repeat(32);
  const txCheckout = '0x' + '63'.repeat(32);

  const origFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const req = JSON.parse(String(init.body));
    if (req.method === 'eth_blockNumber') {
      return Response.json({ jsonrpc: '2.0', id: req.id, result: '0x65' });
    }
    const h = String(req.params?.[0] ?? '').toLowerCase();
    const to = h === txCheckout ? PAY_TO : merchant;
    const amt = h === txCheckout ? 1_000_000n : 6_000_000_000n;
    return Response.json({
      jsonrpc: '2.0',
      id: req.id,
      result: {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeLog(BASE_USDC, payer.address, to, amt)]
      }
    });
  };

  try {
    const env = baseEnv(kv, {
      TX_CLAIM_LOCK: lockNs,
      LICENSE_SIGNING_PRIVATE_JWK: privateJwkJson,
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64,
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      PUBLIC_ARCHIVE_URL: ''
    });

    // 1. Concurrent Promise.all race for tx6k: exactly 1 cached=false, 4 cached=true, GMV counted ONCE!
    const concurrentReqs = Array.from({ length: 5 }, () =>
      app.request(
        '/api/hosted/verify',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: tx6k, merchantAddress: merchant, minAmountAtomic: '6000000000' })
        },
        env
      )
    );
    const results = await Promise.all(concurrentReqs);
    const bodies = await Promise.all(results.map((r) => r.json()));
    for (const r of results) assert.equal(r.status, 200);
    assert.equal(bodies.filter((b) => b.cached === false).length, 1);
    assert.equal(bodies.filter((b) => b.cached === true).length, 4);

    const q1 = await (await app.request(`/api/hosted/quota/${merchant}`, {}, env)).json();
    assert.equal(q1.gmvAtomic, '6000000000');
    assert.equal(q1.unlimitedFreeMit, true);

    // 2. Second $6,000 TX -> $12,000 cumulative GMV succeeds 200 (zero $10k paywall!)
    const r2 = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx6kTwo, merchantAddress: merchant, minAmountAtomic: '6000000000' })
      },
      env
    );
    assert.equal(r2.status, 200);
    const j2 = await r2.json();
    assert.equal(j2.mode, 'free_mit');
    assert.equal(j2.gmvAtomic, '12000000000');

    // 3. Cross-scope lock check: txCheckout claimed in /api/verify cannot be reused in /api/hosted/verify
    const ch = await (
      await app.request(
        '/api/challenge',
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ txHash: txCheckout, tier: 'standard' })
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
        body: JSON.stringify({ txHash: txCheckout, nonce: ch.nonce, signature: sig, tier: 'standard' })
      },
      env
    );
    assert.equal(vRes.status, 200);

    const crossRes = await app.request(
      '/api/hosted/verify',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: txCheckout, merchantAddress: PAY_TO })
      },
      env
    );
    assert.equal(crossRes.status, 403);
    assert.equal((await crossRes.json()).error, 'TX_ALREADY_CLAIMED_ELSEWHERE');

    // 4. Oversized JSON payload returns 413 PAYLOAD_TOO_LARGE
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

test('Fail-closed 500 when secrets or TX_CLAIM_LOCK missing, and rejects expired challenge', async () => {
  const kv = createMemoryKv();
  const payer = privateKeyToAccount(generatePrivateKey());
  const txHash = '0x' + 'ef'.repeat(32);

  const missingSecretsRes = await app.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce: 'n1', signature: '0x' + '11'.repeat(65), tier: 'standard' })
    },
    baseEnv(kv)
  );
  assert.equal(missingSecretsRes.status, 500);

  const expiredTs = Math.floor(Date.now() / 1000) - 305;
  const nonce = 'expirednonce1234';
  const message = `expired-msg-${nonce}`;
  const sig = await payer.signMessage({ message });
  await kv.put(
    `challenge:${nonce}`,
    JSON.stringify({ nonce, txHash: txHash.toLowerCase(), tier: 'standard', ts: expiredTs, message })
  );

  const expiredRes = await app.request(
    '/api/verify',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash, nonce, signature: sig, tier: 'standard' })
    },
    baseEnv(kv, {
      LICENSE_SIGNING_PRIVATE_JWK: '{}',
      DOWNLOAD_HMAC_SECRET: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    })
  );
  assert.equal(expiredRes.status, 403);
  assert.equal((await expiredRes.json()).error, 'CHALLENGE_MISMATCH_OR_EXPIRED');
});
