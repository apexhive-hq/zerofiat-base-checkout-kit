import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyBaseUsdcTransfer, verifySmartWalletOrEoaSignature } from './base-verifier.ts';
import { streamReleaseOrPublicCertificate } from './github-release.ts';
import { signEd25519License } from './license-signer.ts';
import { TxClaimLockDO } from './tx-lock-do.ts';
import type {
  ChallengeRecord,
  DownloadGrantRecord,
  Env,
  HostedClaimRecord,
  Tier
} from './types.ts';

export { TxClaimLockDO };

const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
// Supports both 65-byte EOA signatures (130 hex) and variable-length ERC-1271 / EIP-6492 Smart Wallet ABI signatures
const SIG_RE = /^0x(?:[0-9a-fA-F]{2}){32,8192}$/;
const POSITIVE_INT_RE = /^[1-9]\d*$/;
const MAX_JSON_BODY_BYTES = 32_768;
const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base'
];

function getBaseRpcUrls(env: Env): string[] {
  if (env.BASE_RPC_URLS && env.BASE_RPC_URLS.trim()) {
    const parsed = env.BASE_RPC_URLS.split(',')
      .map((u) => u.trim())
      .filter(Boolean);
    if (parsed.length > 0) return parsed;
  }
  if (env.BASE_RPC_URL && env.BASE_RPC_URL.trim()) {
    return [env.BASE_RPC_URL.trim()];
  }
  return DEFAULT_BASE_RPC_URLS;
}

function randomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function hmacSha256Hex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return toHex(new Uint8Array(sig));
}

function getCheckoutAmountAtomic(env: Env): bigint {
  return BigInt(env.CHECKOUT_AMOUNT_USDC_ATOMIC || '1000000');
}

function buildChallengeMessage(params: {
  brand: string;
  product: string;
  tier: Tier;
  txHash: string;
  nonce: string;
  ts: number;
}): string {
  return [
    `${params.brand} ZeroFiat Checkout Proof`,
    `product=${params.product}`,
    `tier=${params.tier}`,
    `tx=${params.txHash.toLowerCase()}`,
    `nonce=${params.nonce}`,
    `ts=${params.ts}`
  ].join('\n');
}

async function parseBoundedJsonBody<T>(
  req: Request
): Promise<{ ok: true; data: T } | { ok: false; status: 400 | 413; error: string }> {
  const text = await req.text();
  if (new TextEncoder().encode(text).byteLength > MAX_JSON_BODY_BYTES) {
    return { ok: false, status: 413, error: 'PAYLOAD_TOO_LARGE' };
  }
  try {
    return { ok: true, data: JSON.parse(text) as T };
  } catch {
    return { ok: false, status: 400, error: 'INVALID_JSON' };
  }
}

const app = new Hono<{ Bindings: Env }>();

app.use(
  '/api/*',
  cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: [
      'Content-Type',
      'X-Payment',
      'X-Payment-Signature',
      'X-Payment-Address'
    ],
    exposeHeaders: ['X-Payment-Required']
  })
);

app.use('*', async (c, next) => {
  await next();
  const ct = c.res.headers.get('content-type');
  if (ct && (ct.startsWith('application/json') || ct.startsWith('text/html')) && !/charset=/i.test(ct)) {
    c.res.headers.set('content-type', `${ct}; charset=utf-8`);
  }
});

app.get('/api/health', (c) => {
  return c.json({
    ok: true,
    service: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    kvBound: Boolean(c.env.LICENSES_KV),
    durableObjectLockBound: Boolean(c.env.TX_CLAIM_LOCK),
    smartWalletSupport: ['EOA', 'ERC-1271', 'EIP-6492'],
    openSourceLicense: 'MIT',
    unlimitedFreeMit: true,
    supportEmail: 'apexhive.hq@proton.me'
  });
});

app.get('/api/config', (c) => {
  const checkoutAtomic = getCheckoutAmountAtomic(c.env);
  return c.json({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    tokenPrefix: c.env.TOKEN_PREFIX || 'ZEROFIAT-KIT-v1.',
    openSourceLicense: 'MIT',
    unlimitedFreeMit: true,
    smartWalletSupport: ['EOA', 'ERC-1271', 'EIP-6492'],
    publicRepoUrl: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    network: 'Base Mainnet',
    usdcContract: c.env.BASE_USDC_CONTRACT,
    payToAddress: c.env.PAY_TO_EVM_ADDRESS,
    publicKeySpkiB64: c.env.LICENSE_SIGNING_PUBLIC_SPKI_B64 ?? null,
    checkoutDemo: {
      tier: 'standard',
      label: 'Standard Verification Attestation (Self-Hosted MIT Rail)',
      usdc: String(Number(checkoutAtomic) / 1_000_000),
      atomic: checkoutAtomic.toString()
    },
    supportEmail: 'apexhive.hq@proton.me',
    selfCustodyWarning:
      'SELF-CUSTODY OR SMART WALLET ONLY: Send Base USDC from an EOA (MetaMask, Rabby) or Base Smart Wallet (Coinbase Smart Wallet, Safe — ERC-1271/EIP-6492 supported). NEVER send directly from a centralized exchange (CEX) withdrawal—exchange hot wallets cannot sign ownership challenges.'
  });
});

// ─── Free MIT Base USDC Verification Rail (Unlimited GMV, Atomic DO Lock) ────

app.get('/api/hosted/quota/:merchantAddress', async (c) => {
  const merchantRaw = (c.req.param('merchantAddress') ?? '').trim();
  if (!EVM_ADDR_RE.test(merchantRaw)) {
    return c.json(
      { error: 'INVALID_MERCHANT_ADDRESS', message: 'Expected 0x-prefixed 40-hex EVM address.' },
      400
    );
  }

  const merchantLower = merchantRaw.toLowerCase();
  const gmvRaw = await c.env.LICENSES_KV.get(`hosted_gmv:${merchantLower}`);
  const gmv = BigInt(gmvRaw || '0');

  return c.json({
    merchantAddress: merchantLower,
    gmvAtomic: gmv.toString(),
    unlimitedFreeMit: true,
    openSourceLicense: 'MIT'
  });
});

app.post('/api/hosted/verify', async (c) => {
  if (!c.env.TX_CLAIM_LOCK || !c.env.LICENSES_KV) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing TX_CLAIM_LOCK or LICENSES_KV binding.' },
      500
    );
  }

  const parsedBody = await parseBoundedJsonBody<{
    txHash?: string;
    merchantAddress?: string;
    minAmountAtomic?: string | number;
    expectedAmountAtomic?: string | number;
    challengeMessage?: string;
    signature?: string;
  }>(c.req.raw);
  if (!parsedBody.ok) {
    return c.json({ error: parsedBody.error }, parsedBody.status);
  }
  const body = parsedBody.data;

  const txHash = (body.txHash ?? '').trim();
  const merchantAddress = (body.merchantAddress ?? '').trim();

  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (!EVM_ADDR_RE.test(merchantAddress)) {
    return c.json(
      { error: 'INVALID_MERCHANT_ADDRESS', message: 'Expected 0x-prefixed 40-hex merchantAddress.' },
      400
    );
  }

  const rawMin = String(body.minAmountAtomic ?? body.expectedAmountAtomic ?? '1').trim();
  if (!POSITIVE_INT_RE.test(rawMin)) {
    return c.json(
      { error: 'INVALID_AMOUNT', message: 'minAmountAtomic must be a positive integer string.' },
      400
    );
  }
  const requiredAmount = BigInt(rawMin);

  const hasMsg = typeof body.challengeMessage === 'string' && body.challengeMessage.length > 0;
  const hasSig = typeof body.signature === 'string' && body.signature.trim().length > 0;
  if (hasMsg !== hasSig) {
    return c.json(
      { error: 'INVALID_SIGNATURE_PROOF', message: 'Provide both challengeMessage and signature, or omit both.' },
      400
    );
  }
  if (hasSig && !SIG_RE.test(body.signature!.trim())) {
    return c.json(
      {
        error: 'INVALID_SIGNATURE_PROOF',
        message: 'Expected 0x-prefixed even-length hex EOA or ERC-1271/EIP-6492 signature.'
      },
      400
    );
  }

  const txLower = txHash.toLowerCase();
  const merchantLower = merchantAddress.toLowerCase();
  const rpcUrls = getBaseRpcUrls(c.env);

  // 1. Verify Base Mainnet USDC Transfer + optional EOA/Smart-Wallet signature
  const verifyRes = await verifyBaseUsdcTransfer({
    rpcUrls,
    txHash: txLower,
    expectedUsdcContract: c.env.BASE_USDC_CONTRACT,
    expectedPayTo: merchantLower,
    requiredAtomicAmount: requiredAmount,
    minConfirmations: Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2')),
    challengeMessage: body.challengeMessage,
    signature: body.signature?.trim(),
    requireSignature: hasMsg && hasSig
  });

  if (!verifyRes.ok) {
    // Allow cached replay recovery if already claimed with matching merchant & amount?
    // When RPC passes above, fall through to atomic DO lock.
    return c.json({ error: verifyRes.error, message: verifyRes.message }, verifyRes.status);
  }

  // 2. Acquire atomic single-threaded Durable Object claim lock (zero KV race condition)
  const lockId = c.env.TX_CLAIM_LOCK.idFromName(txLower);
  const lockStub = c.env.TX_CLAIM_LOCK.get(lockId);
  const lockRes = await lockStub.fetch('https://lock.internal/claim-hosted', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      txHash: txLower,
      merchantAddress: merchantLower,
      payer: verifyRes.payer,
      paidAtomic: verifyRes.paidAtomic,
      requiredAtomic: requiredAmount.toString()
    })
  });

  const lockJson = (await lockRes.json()) as {
    ok: boolean;
    cached?: boolean;
    error?: string;
    message?: string;
    record?: HostedClaimRecord;
  };
  if (!lockRes.ok || !lockJson.ok || !lockJson.record) {
    return c.json(
      { error: lockJson.error || 'TX_ALREADY_CLAIMED', message: lockJson.message || 'Claim conflict.' },
      403
    );
  }

  // Re-verify optional signature against locked payer on cached hit
  if (lockJson.cached && hasMsg && hasSig) {
    const sigOk = await verifySmartWalletOrEoaSignature({
      rpcUrls,
      address: lockJson.record.payer,
      message: body.challengeMessage!,
      signature: body.signature!.trim()
    });
    if (!sigOk) {
      return c.json(
        { error: 'INVALID_SIGNATURE', message: 'Signature failed against locked payer address.' },
        403
      );
    }
  }

  const gmvKey = `hosted_gmv:${merchantLower}`;
  const currentGmv = BigInt((await c.env.LICENSES_KV.get(gmvKey)) || '0');
  let nextGmv = currentGmv;
  if (!lockJson.cached) {
    nextGmv = currentGmv + BigInt(verifyRes.paidAtomic);
    await c.env.LICENSES_KV.put(gmvKey, nextGmv.toString());
  }

  return c.json({
    ok: true,
    cached: Boolean(lockJson.cached),
    mode: 'free_mit',
    unlimitedFreeMit: true,
    txHash: txLower,
    merchantAddress: merchantLower,
    payer: lockJson.record.payer,
    paidAtomic: lockJson.record.paidAtomic,
    confirmations: verifyRes.confirmations,
    gmvAtomic: nextGmv.toString()
  });
});

// ─── Non-Custodial Checkout + Ed25519 Receipt Attestation Demo ──────────────

app.post('/api/challenge', async (c) => {
  const parsedBody = await parseBoundedJsonBody<{ txHash?: string; tier?: string }>(c.req.raw);
  if (!parsedBody.ok) {
    return c.json({ error: parsedBody.error }, parsedBody.status);
  }
  const body = parsedBody.data;

  const txHash = (body.txHash ?? '').trim();
  const tier = (body.tier ?? 'standard').trim() as Tier;

  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (tier !== 'standard') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be standard.' }, 400);
  }

  const ttl = Math.max(60, Number(c.env.CHALLENGE_TTL_SECONDS || '300'));
  const nonce = randomHex(16);
  const ts = Math.floor(Date.now() / 1000);
  const message = buildChallengeMessage({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    tier,
    txHash,
    nonce,
    ts
  });

  const record: ChallengeRecord = {
    nonce,
    txHash: txHash.toLowerCase(),
    tier,
    ts,
    message
  };

  await c.env.LICENSES_KV.put(`challenge:${nonce}`, JSON.stringify(record), {
    expirationTtl: ttl
  });

  return c.json({
    nonce,
    ts,
    expiresInSeconds: ttl,
    message
  });
});

app.post('/api/verify', async (c) => {
  if (
    !c.env.LICENSE_SIGNING_PRIVATE_JWK ||
    !c.env.DOWNLOAD_HMAC_SECRET ||
    c.env.DOWNLOAD_HMAC_SECRET.length < 16 ||
    !c.env.TX_CLAIM_LOCK
  ) {
    return c.json(
      {
        error: 'SERVER_MISCONFIGURED',
        message: 'Missing LICENSE_SIGNING_PRIVATE_JWK, DOWNLOAD_HMAC_SECRET, or TX_CLAIM_LOCK.'
      },
      500
    );
  }

  const parsedBody = await parseBoundedJsonBody<{
    txHash?: string;
    nonce?: string;
    signature?: string;
    tier?: string;
  }>(c.req.raw);
  if (!parsedBody.ok) {
    return c.json({ error: parsedBody.error }, parsedBody.status);
  }
  const body = parsedBody.data;

  const txHash = (body.txHash ?? '').trim();
  const nonce = (body.nonce ?? '').trim();
  const signature = (body.signature ?? '').trim();
  const tier = (body.tier ?? 'standard').trim() as Tier;

  if (!TX_HASH_RE.test(txHash) || !nonce || !SIG_RE.test(signature)) {
    return c.json(
      {
        error: 'INVALID_REQUEST',
        message: 'Provide valid txHash, nonce, and EOA or ERC-1271/EIP-6492 signature.'
      },
      400
    );
  }
  if (tier !== 'standard') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be standard.' }, 400);
  }

  const txLower = txHash.toLowerCase();
  const challengeKey = `challenge:${nonce}`;
  const challengeRaw = await c.env.LICENSES_KV.get(challengeKey);
  if (!challengeRaw) {
    return c.json(
      { error: 'CHALLENGE_EXPIRED_OR_MISSING', message: 'Challenge expired (>300s) or unknown.' },
      403
    );
  }

  const challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  const ttl = Math.max(60, Number(c.env.CHALLENGE_TTL_SECONDS || '300'));
  const nowSec = Math.floor(Date.now() / 1000);
  if (
    challenge.txHash !== txLower ||
    challenge.tier !== tier ||
    nowSec - challenge.ts > ttl
  ) {
    await c.env.LICENSES_KV.delete(challengeKey);
    return c.json(
      { error: 'CHALLENGE_MISMATCH_OR_EXPIRED', message: 'Challenge mismatch or expired.' },
      403
    );
  }

  const verifyRes = await verifyBaseUsdcTransfer({
    rpcUrls: getBaseRpcUrls(c.env),
    txHash: txLower,
    expectedUsdcContract: c.env.BASE_USDC_CONTRACT,
    expectedPayTo: c.env.PAY_TO_EVM_ADDRESS,
    requiredAtomicAmount: getCheckoutAmountAtomic(c.env),
    minConfirmations: Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2')),
    challengeMessage: challenge.message,
    signature,
    requireSignature: true
  });

  if (!verifyRes.ok) {
    if (verifyRes.error === 'PAYMENT_OR_SIGNATURE_INVALID') {
      await c.env.LICENSES_KV.delete(challengeKey);
    }
    return c.json({ error: verifyRes.error, message: verifyRes.message }, verifyRes.status);
  }

  // Atomic Durable Object lock prevents concurrent KV replay race conditions
  const lockId = c.env.TX_CLAIM_LOCK.idFromName(txLower);
  const lockStub = c.env.TX_CLAIM_LOCK.get(lockId);
  const lockRes = await lockStub.fetch('https://lock.internal/claim-checkout', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      txHash: txLower,
      payer: verifyRes.payer,
      tier,
      paidAtomic: verifyRes.paidAtomic
    })
  });

  const lockJson = (await lockRes.json()) as {
    ok: boolean;
    reclaimed?: boolean;
    error?: string;
    message?: string;
  };
  if (!lockRes.ok || !lockJson.ok) {
    await c.env.LICENSES_KV.delete(challengeKey);
    return c.json(
      {
        error: lockJson.error || 'TX_ALREADY_CLAIMED',
        message: lockJson.message || 'This transaction hash has already been claimed.'
      },
      403
    );
  }

  // Consume single-use challenge ONLY after TX, confirmations, signature, and DO lock succeed
  await c.env.LICENSES_KV.delete(challengeKey);

  const issuedAt = Date.now();
  const productId = c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit';
  const tokenPrefix = c.env.TOKEN_PREFIX || 'ZEROFIAT-KIT-v1.';

  const licenseToken = await signEd25519License({
    privateJwkJson: c.env.LICENSE_SIGNING_PRIVATE_JWK,
    tokenPrefix,
    payload: {
      v: 1,
      product: productId,
      tier,
      payer: verifyRes.payer,
      txHash: txLower,
      issuedAt,
      expiresAt: null
    }
  });

  const grantId = randomHex(16);
  const sigHex = await hmacSha256Hex(c.env.DOWNLOAD_HMAC_SECRET, grantId);
  const downloadToken = `${grantId}.${sigHex}`;
  const downloadTtl = Math.max(120, Number(c.env.DOWNLOAD_TTL_SECONDS || '600'));

  const grant: DownloadGrantRecord = {
    txHash: txLower,
    payer: verifyRes.payer,
    tier,
    remainingDownloads: 3,
    createdAt: issuedAt,
    licenseToken
  };

  await c.env.LICENSES_KV.put(`dl:${grantId}`, JSON.stringify(grant), {
    expirationTtl: downloadTtl
  });

  return c.json({
    ok: true,
    reclaimed: Boolean(lockJson.reclaimed),
    tier,
    payer: verifyRes.payer,
    txHash: txLower,
    paidAtomic: verifyRes.paidAtomic,
    licenseToken,
    downloadToken,
    downloadUrl: `/api/download?token=${encodeURIComponent(downloadToken)}`,
    downloadExpiresInSeconds: downloadTtl,
    publicRepoUrl: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit',
    certificate: {
      product: productId,
      tier,
      payer: verifyRes.payer,
      txHash: txLower,
      issuedAt,
      licenseToken,
      openSourceLicense: 'MIT'
    }
  });
});

app.get('/api/download', async (c) => {
  if (!c.env.DOWNLOAD_HMAC_SECRET || c.env.DOWNLOAD_HMAC_SECRET.length < 16) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing DOWNLOAD_HMAC_SECRET.' },
      500
    );
  }

  const token = (c.req.query('token') ?? '').trim();
  const match = /^([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(token);
  if (!match) {
    return c.json({ error: 'INVALID_DOWNLOAD_TOKEN' }, 403);
  }

  const [, grantId, sigHex] = match;
  const expectedSig = await hmacSha256Hex(c.env.DOWNLOAD_HMAC_SECRET, grantId);
  if (!constantTimeEqualHex(sigHex, expectedSig)) {
    return c.json({ error: 'INVALID_DOWNLOAD_TOKEN' }, 403);
  }

  const dlKey = `dl:${grantId}`;
  const raw = await c.env.LICENSES_KV.get(dlKey);
  if (!raw) {
    return c.json(
      { error: 'DOWNLOAD_TOKEN_EXPIRED', message: 'Download grant expired or exhausted.' },
      403
    );
  }

  const grant = JSON.parse(raw) as DownloadGrantRecord;
  if (grant.remainingDownloads <= 0) {
    await c.env.LICENSES_KV.delete(dlKey);
    return c.json({ error: 'DOWNLOAD_LIMIT_REACHED' }, 403);
  }

  const releaseRes = await streamReleaseOrPublicCertificate({
    publicArchiveUrl: c.env.PUBLIC_ARCHIVE_URL,
    downloadFilename: c.env.RELEASE_FILENAME || 'zerofiat-base-checkout-kit.zip',
    certificatePayload: {
      ok: true,
      product: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
      tier: grant.tier,
      payer: grant.payer,
      txHash: grant.txHash,
      issuedAt: grant.createdAt,
      licenseToken: grant.licenseToken ?? null
    }
  });

  if (releaseRes.status === 200) {
    const nextRemaining = grant.remainingDownloads - 1;
    if (nextRemaining <= 0) {
      await c.env.LICENSES_KV.delete(dlKey);
    } else {
      const downloadTtl = Math.max(120, Number(c.env.DOWNLOAD_TTL_SECONDS || '600'));
      await c.env.LICENSES_KV.put(
        dlKey,
        JSON.stringify({ ...grant, remainingDownloads: nextRemaining }),
        { expirationTtl: downloadTtl }
      );
    }
  }

  return releaseRes;
});

app.all('*', async (c) => {
  if (c.env.ASSETS) {
    return c.env.ASSETS.fetch(c.req.raw);
  }
  return c.text('Not Found', 404);
});

export default app;
