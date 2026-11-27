import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyBaseUsdcTransfer } from './base-verifier.ts';
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
const ZERO_EVM_ADDR = '0x0000000000000000000000000000000000000000';
// Supports both 65-byte EOA signatures (130 hex) and variable-length ERC-1271 / EIP-6492 Smart Wallet ABI signatures
const SIG_RE = /^0x(?:[0-9a-fA-F]{2}){32,8192}$/;
const POSITIVE_INT_RE = /^[1-9]\d*$/;
const MAX_JSON_BODY_BYTES = 32_768;
const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base'
];

const CSP_POLICY = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self'",
  "font-src 'self'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'"
].join('; ');

function getConfiguredPayTo(env: Env): string | null {
  const raw = (env.PAY_TO_EVM_ADDRESS ?? '').trim();
  if (!EVM_ADDR_RE.test(raw)) return null;
  if (raw.toLowerCase() === ZERO_EVM_ADDR) return null;
  return raw;
}

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

function parseAllowedOrigins(env: Env): Set<string> {
  const allowed = new Set<string>();
  if (!env.ALLOWED_ORIGINS) return allowed;
  for (const raw of env.ALLOWED_ORIGINS.split(',')) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed === '*') continue;
    try {
      allowed.add(new URL(trimmed).origin);
    } catch {
      // Ignore malformed origin entries
    }
  }
  return allowed;
}

function isOriginAllowed(origin: string, requestUrl: string, env: Env): boolean {
  if (!origin) return false;
  try {
    const normalized = new URL(origin).origin;
    const selfOrigin = new URL(requestUrl).origin;
    if (normalized === selfOrigin) return true;
    return parseAllowedOrigins(env).has(normalized);
  } catch {
    return false;
  }
}

function randomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqualStr(a: string, b: string): boolean {
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

export function parsePositiveInt(val: unknown, fallback: number, min = 1): number {
  const raw = typeof val === 'string' ? val.trim() : typeof val === 'number' ? String(val) : '';
  if (!POSITIVE_INT_RE.test(raw)) return Math.max(min, fallback);
  const n = Number(raw);
  if (!Number.isSafeInteger(n) || n < min) return Math.max(min, fallback);
  return n;
}

function getCheckoutAmountAtomic(env: Env): bigint {
  const raw = (env.CHECKOUT_AMOUNT_USDC_ATOMIC ?? '').trim();
  if (!POSITIVE_INT_RE.test(raw)) return 1_000_000n;
  return BigInt(raw);
}

function isValidHostedApiToken(req: Request, env: Env): boolean {
  const configured = (env.HOSTED_API_TOKEN ?? '').trim();
  if (configured.length < 16) return false;
  const authHeader = (req.headers.get('authorization') ?? '').trim();
  const bearer = authHeader.toLowerCase().startsWith('bearer ')
    ? authHeader.slice(7).trim()
    : '';
  const apiKey = (req.headers.get('x-hosted-api-key') ?? '').trim();
  const candidate = bearer || apiKey;
  if (!candidate) return false;
  return constantTimeEqualStr(candidate, configured);
}

function buildCheckoutChallengeMessage(params: {
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

function buildHostedChallengeMessage(params: {
  brand: string;
  product: string;
  merchantAddress: string;
  txHash: string;
  nonce: string;
  ts: number;
}): string {
  return [
    `${params.brand} ZeroFiat Hosted Proof`,
    `product=${params.product}`,
    `scope=hosted`,
    `merchant=${params.merchantAddress.toLowerCase()}`,
    `tx=${params.txHash.toLowerCase()}`,
    `nonce=${params.nonce}`,
    `ts=${params.ts}`
  ].join('\n');
}

async function parseBoundedJsonBody<T extends Record<string, unknown>>(
  req: Request
): Promise<{ ok: true; data: T } | { ok: false; status: 400 | 413; error: string }> {
  const clHeader = req.headers.get('content-length');
  if (clHeader !== null) {
    const contentLength = Number(clHeader);
    if (Number.isFinite(contentLength) && contentLength > MAX_JSON_BODY_BYTES) {
      return { ok: false, status: 413, error: 'PAYLOAD_TOO_LARGE' };
    }
  }

  let text = '';
  if (req.body) {
    const reader = req.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          totalBytes += value.byteLength;
          if (totalBytes > MAX_JSON_BODY_BYTES) {
            await reader.cancel().catch(() => undefined);
            return { ok: false, status: 413, error: 'PAYLOAD_TOO_LARGE' };
          }
          chunks.push(value);
        }
      }
    } finally {
      reader.releaseLock();
    }
    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    text = new TextDecoder().decode(merged);
  } else {
    text = await req.text();
    if (new TextEncoder().encode(text).byteLength > MAX_JSON_BODY_BYTES) {
      return { ok: false, status: 413, error: 'PAYLOAD_TOO_LARGE' };
    }
  }

  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return { ok: false, status: 400, error: 'INVALID_JSON' };
    }
    return { ok: true, data: parsed as T };
  } catch {
    return { ok: false, status: 400, error: 'INVALID_JSON' };
  }
}

function getChallengeStub(env: Env, nonce: string) {
  const id = env.TX_CLAIM_LOCK.idFromName(`challenge:${nonce}`);
  return env.TX_CLAIM_LOCK.get(id);
}

function getDownloadStub(env: Env, grantId: string) {
  const id = env.TX_CLAIM_LOCK.idFromName(`dl:${grantId}`);
  return env.TX_CLAIM_LOCK.get(id);
}

async function getHostedGmvAtomic(env: Env, merchantLower: string): Promise<string> {
  const gmvId = env.TX_CLAIM_LOCK.idFromName(`hosted-gmv:${merchantLower}`);
  const gmvStub = env.TX_CLAIM_LOCK.get(gmvId);
  const res = await gmvStub.fetch('https://lock.internal/gmv/get', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  });
  if (!res.ok) return '0';
  const json = (await res.json()) as { gmvAtomic?: string };
  return json.gmvAtomic ?? '0';
}

async function addHostedGmvAtomic(
  env: Env,
  merchantLower: string,
  deltaAtomic: string
): Promise<string> {
  const gmvId = env.TX_CLAIM_LOCK.idFromName(`hosted-gmv:${merchantLower}`);
  const gmvStub = env.TX_CLAIM_LOCK.get(gmvId);
  const res = await gmvStub.fetch('https://lock.internal/gmv/add', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ deltaAtomic })
  });
  if (!res.ok) {
    throw new Error('Failed to update atomic hosted GMV counter.');
  }
  const json = (await res.json()) as { gmvAtomic?: string };
  return json.gmvAtomic ?? '0';
}

const app = new Hono<{ Bindings: Env }>();

// Global strict HTTP security headers & UTF-8 content-type hygiene
app.use('*', async (c, next) => {
  await next();
  c.res.headers.set('Content-Security-Policy', CSP_POLICY);
  c.res.headers.set('X-Frame-Options', 'DENY');
  c.res.headers.set('X-Content-Type-Options', 'nosniff');
  c.res.headers.set('Referrer-Policy', 'no-referrer');
  const ct = c.res.headers.get('content-type');
  if (ct && (ct.startsWith('application/json') || ct.startsWith('text/html')) && !/charset=/i.test(ct)) {
    c.res.headers.set('content-type', `${ct}; charset=utf-8`);
  }
});

// Keep /api/health safe minimal (read-only status probe)
app.use(
  '/api/health',
  cors({
    origin: '*',
    allowMethods: ['GET', 'OPTIONS'],
    allowHeaders: ['Content-Type']
  })
);

// Restrict CORS on all verification/config/mutating API routes to same-origin or ALLOWED_ORIGINS allowlist
const apiCors = cors({
  origin: (origin, c) => (isOriginAllowed(origin, c.req.url, c.env) ? origin : null),
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: [
    'Content-Type',
    'Authorization',
    'X-Hosted-Api-Key',
    'X-Payment',
    'X-Payment-Signature',
    'X-Payment-Address'
  ],
  exposeHeaders: ['X-Payment-Required']
});

app.use('/api/*', async (c, next) => {
  if (c.req.path === '/api/health') {
    return next();
  }
  const origin = c.req.header('origin');
  if (origin && c.req.method !== 'GET' && c.req.method !== 'HEAD' && c.req.method !== 'OPTIONS') {
    if (!isOriginAllowed(origin, c.req.url, c.env)) {
      return c.json(
        {
          error: 'ORIGIN_NOT_ALLOWED',
          message: 'Cross-origin request rejected by ALLOWED_ORIGINS policy.'
        },
        403
      );
    }
  }
  return apiCors(c, next);
});

app.get('/api/health', (c) => {
  return c.json({
    ok: true,
    service: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    chainId: parsePositiveInt(c.env.BASE_CHAIN_ID, 8453, 1),
    durableObjectLockBound: Boolean(c.env.TX_CLAIM_LOCK),
    payToConfigured: Boolean(getConfiguredPayTo(c.env)),
    smartWalletSupport: ['EOA', 'ERC-1271', 'EIP-6492'],
    openSourceLicense: 'MIT',
    unlimitedFreeMit: true,
    supportEmail: 'apexhive.hq@proton.me'
  });
});

app.get('/api/config', (c) => {
  const checkoutAtomic = getCheckoutAmountAtomic(c.env);
  const payToAddress = getConfiguredPayTo(c.env);
  const publicKey = (c.env.LICENSE_SIGNING_PUBLIC_SPKI_B64 ?? '').trim();
  return c.json({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    tokenPrefix: c.env.TOKEN_PREFIX || 'ZEROFIAT-KIT-v1.',
    openSourceLicense: 'MIT',
    unlimitedFreeMit: true,
    smartWalletSupport: ['EOA', 'ERC-1271', 'EIP-6492'],
    publicRepoUrl: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit',
    chainId: parsePositiveInt(c.env.BASE_CHAIN_ID, 8453, 1),
    network: 'Base Mainnet',
    usdcContract: c.env.BASE_USDC_CONTRACT,
    payToAddress,
    payToConfigured: Boolean(payToAddress),
    publicKeySpkiB64: publicKey && !publicKey.startsWith('REPLACE_WITH_') ? publicKey : null,
    checkoutDemo: {
      tier: 'standard',
      label: 'Standard Verification Attestation (Self-Hosted MIT Rail)',
      usdc: String(Number(checkoutAtomic) / 1_000_000),
      atomic: checkoutAtomic.toString()
    },
    supportEmail: 'apexhive.hq@proton.me',
    selfCustodyWarning:
      'SELF-CUSTODY OR SMART WALLET ONLY: Send Base USDC from an EOA (MetaMask, Rabby) or Base Smart Wallet (Coinbase Smart Wallet, Safe — ERC-1271/EIP-6492 supported). NEVER send directly from a centralized exchange (CEX) withdrawal — exchange hot wallets cannot sign ownership challenges.'
  });
});

// ─── Base USDC Verification Rail (MIT, Atomic DO Lock) ─────────────────────────

app.get('/api/hosted/quota/:merchantAddress', async (c) => {
  if (!c.env.TX_CLAIM_LOCK) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing TX_CLAIM_LOCK binding.' },
      500
    );
  }
  const merchantRaw = (c.req.param('merchantAddress') ?? '').trim();
  if (!EVM_ADDR_RE.test(merchantRaw)) {
    return c.json(
      { error: 'INVALID_MERCHANT_ADDRESS', message: 'Expected 0x-prefixed 40-hex EVM address.' },
      400
    );
  }

  const merchantLower = merchantRaw.toLowerCase();
  const gmvAtomic = await getHostedGmvAtomic(c.env, merchantLower);

  return c.json({
    merchantAddress: merchantLower,
    gmvAtomic,
    unlimitedFreeMit: true,
    openSourceLicense: 'MIT'
  });
});

app.post('/api/hosted/verify', async (c) => {
  if (!c.env.TX_CLAIM_LOCK) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing TX_CLAIM_LOCK binding.' },
      500
    );
  }

  const parsedBody = await parseBoundedJsonBody<{
    txHash?: string;
    merchantAddress?: string;
    minAmountAtomic?: string | number;
    expectedAmountAtomic?: string | number;
    consumeOnce?: unknown;
    requireSignature?: unknown;
    nonce?: string;
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

  if (body.consumeOnce !== undefined && typeof body.consumeOnce !== 'boolean') {
    return c.json(
      { error: 'INVALID_REQUEST', message: 'consumeOnce must be a boolean when provided.' },
      400
    );
  }
  // Strict single-use anti-replay by default (returns 409 TX_ALREADY_CLAIMED on replay)
  const consumeOnce = body.consumeOnce !== false;

  const rawMin = String(body.minAmountAtomic ?? body.expectedAmountAtomic ?? '1').trim();
  if (!POSITIVE_INT_RE.test(rawMin)) {
    return c.json(
      { error: 'INVALID_AMOUNT', message: 'minAmountAtomic must be a positive integer string.' },
      400
    );
  }
  const requiredAmount = BigInt(rawMin);

  const txLower = txHash.toLowerCase();
  const merchantLower = merchantAddress.toLowerCase();
  const hostPayTo = getConfiguredPayTo(c.env);
  const isHostMerchant = Boolean(hostPayTo && merchantLower === hostPayTo.toLowerCase());
  const allowUnauthHostPayTo = c.env.ALLOW_UNAUTHENTICATED_HOSTED_PAY_TO === 'true';
  const hasHostedToken = isValidHostedApiToken(c.req.raw, c.env);

  const hasRawChallengeMsg =
    typeof body.challengeMessage === 'string' && body.challengeMessage.trim().length > 0;
  const nonce = typeof body.nonce === 'string' ? body.nonce.trim() : '';
  const signature = typeof body.signature === 'string' ? body.signature.trim() : '';
  const hasNonce = nonce.length > 0;
  const hasSig = signature.length > 0;

  if (hasRawChallengeMsg && !hasNonce) {
    return c.json(
      {
        error: 'CHALLENGE_NONCE_REQUIRED',
        message:
          'Signature verification requires a server-issued challenge nonce from POST /api/challenge (scope: "hosted").'
      },
      400
    );
  }

  if (isHostMerchant && !allowUnauthHostPayTo && (!hasNonce || !hasSig)) {
    return c.json(
      {
        error: 'HOST_MERCHANT_SIGNATURE_REQUIRED',
        message:
          'Targeting the host worker PAY_TO_EVM_ADDRESS on /api/hosted/verify requires a signed server-issued challenge (nonce + signature).'
      },
      403
    );
  }

  // Prevent unauthenticated Lock-Griefing DoS on third-party merchants:
  // creating a single-use claim lock (consumeOnce: true) requires either a signed payer challenge OR valid HOSTED_API_TOKEN.
  if (consumeOnce && !hasHostedToken && (!hasNonce || !hasSig)) {
    return c.json(
      {
        error: 'HOSTED_AUTH_REQUIRED',
        message:
          'Consuming/locking a hosted transaction (consumeOnce: true) requires either a signed server challenge (nonce + signature) or a valid HOSTED_API_TOKEN.'
      },
      403
    );
  }

  const mustVerifySignature =
    body.requireSignature === true ||
    hasNonce ||
    hasSig ||
    (isHostMerchant && !allowUnauthHostPayTo);

  let challengeRecord: ChallengeRecord | null = null;
  let challengeStub: ReturnType<typeof getChallengeStub> | null = null;

  if (mustVerifySignature) {
    if (!hasNonce || !hasSig) {
      return c.json(
        {
          error: 'INVALID_SIGNATURE_PROOF',
          message: 'Provide both server-issued nonce and signature when signature verification is active.'
        },
        400
      );
    }
    if (!SIG_RE.test(signature)) {
      return c.json(
        {
          error: 'INVALID_SIGNATURE_PROOF',
          message: 'Expected 0x-prefixed even-length hex EOA or ERC-1271/EIP-6492 signature.'
        },
        400
      );
    }

    challengeStub = getChallengeStub(c.env, nonce);
    const chValRes = await challengeStub.fetch('https://lock.internal/challenge/validate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        scope: 'hosted',
        merchantAddress: merchantLower,
        txHash: txLower
      })
    });
    const chValJson = (await chValRes.json()) as {
      ok: boolean;
      error?: string;
      message?: string;
      record?: ChallengeRecord;
    };
    if (!chValRes.ok || !chValJson.ok || !chValJson.record) {
      return c.json(
        {
          error: chValJson.error || 'CHALLENGE_EXPIRED_OR_MISSING',
          message: chValJson.message || 'Challenge mismatch or expired.'
        },
        403
      );
    }
    challengeRecord = chValJson.record;
  }

  const rpcUrls = getBaseRpcUrls(c.env);

  // 1. Verify Base Mainnet USDC Transfer + optional/required EOA/Smart-Wallet challenge signature
  const verifyRes = await verifyBaseUsdcTransfer({
    rpcUrls,
    txHash: txLower,
    expectedUsdcContract: c.env.BASE_USDC_CONTRACT,
    expectedPayTo: merchantLower,
    requiredAtomicAmount: requiredAmount,
    minConfirmations: parsePositiveInt(c.env.MIN_CONFIRMATIONS, 2, 1),
    challengeMessage: challengeRecord?.message,
    signature: hasSig ? signature : undefined,
    requireSignature: mustVerifySignature
  });

  if (!verifyRes.ok) {
    // Never burn challenge nonces on transient 502 RPC_UNAVAILABLE or 403 INSUFFICIENT_CONFIRMATIONS
    if (mustVerifySignature && challengeStub && verifyRes.error === 'PAYMENT_OR_SIGNATURE_INVALID') {
      await challengeStub.fetch('https://lock.internal/challenge/invalidate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}'
      });
    }
    return c.json({ error: verifyRes.error, message: verifyRes.message }, verifyRes.status);
  }

  // Atomically consume single-use hosted challenge nonce before claiming lock (prevents concurrent nonce reuse)
  if (mustVerifySignature && challengeStub) {
    const consumeChRes = await challengeStub.fetch('https://lock.internal/challenge/consume', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        scope: 'hosted',
        merchantAddress: merchantLower,
        txHash: txLower
      })
    });
    if (!consumeChRes.ok) {
      const errJson = (await consumeChRes.json()) as { error?: string; message?: string };
      return c.json(
        {
          error: errJson.error || 'CHALLENGE_EXPIRED_OR_MISSING',
          message: errJson.message || 'Challenge already used or expired.'
        },
        403
      );
    }
  }

  const lockId = c.env.TX_CLAIM_LOCK.idFromName(`hosted:${merchantLower}:${txLower}`);
  const lockStub = c.env.TX_CLAIM_LOCK.get(lockId);

  // Read-only status check when consumeOnce: false (never creates a lock or mutates GMV)
  if (!consumeOnce) {
    const statusRes = await lockStub.fetch('https://lock.internal/claim-hosted-status', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: txLower,
        merchantAddress: merchantLower,
        requiredAtomic: requiredAmount.toString()
      })
    });
    const statusJson = (await statusRes.json()) as {
      ok: boolean;
      cached?: boolean;
      error?: string;
      message?: string;
      record?: HostedClaimRecord | null;
    };
    if (!statusRes.ok || !statusJson.ok) {
      return c.json(
        {
          ok: false,
          error: statusJson.error || 'INSUFFICIENT_AMOUNT',
          message: statusJson.message || 'Cached amount check failed.'
        },
        403
      );
    }
    const gmvAtomic = await getHostedGmvAtomic(c.env, merchantLower);
    return c.json({
      ok: true,
      cached: Boolean(statusJson.cached),
      consumed: false,
      consumeOnce: false,
      mode: 'free_mit',
      unlimitedFreeMit: true,
      txHash: txLower,
      merchantAddress: merchantLower,
      payer: statusJson.record?.payer ?? verifyRes.payer,
      paidAtomic: statusJson.record?.paidAtomic ?? verifyRes.paidAtomic,
      confirmations: verifyRes.confirmations,
      gmvAtomic
    });
  }

  // 2. Acquire isolated, namespaced Durable Object claim lock (`hosted:<merchant>:<txHash>`)
  const lockRes = await lockStub.fetch('https://lock.internal/claim-hosted', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      txHash: txLower,
      merchantAddress: merchantLower,
      payer: verifyRes.payer,
      paidAtomic: verifyRes.paidAtomic,
      requiredAtomic: requiredAmount.toString(),
      consumeOnce: true
    })
  });

  const lockJson = (await lockRes.json()) as {
    ok: boolean;
    cached?: boolean;
    consumed?: boolean;
    error?: string;
    message?: string;
    record?: HostedClaimRecord;
  };
  if (!lockRes.ok || !lockJson.ok || !lockJson.record) {
    const errStatus = lockRes.status === 409 ? 409 : 403;
    return c.json(
      {
        ok: false,
        error: lockJson.error || 'TX_ALREADY_CLAIMED',
        message: lockJson.message || 'Claim conflict.'
      },
      errStatus
    );
  }

  // 3. Atomically update per-merchant GMV inside Durable Object state (zero KV RMW races)
  const gmvAtomic = await addHostedGmvAtomic(c.env, merchantLower, verifyRes.paidAtomic);

  return c.json({
    ok: true,
    cached: false,
    consumed: true,
    consumeOnce: true,
    mode: 'free_mit',
    unlimitedFreeMit: true,
    txHash: txLower,
    merchantAddress: merchantLower,
    payer: lockJson.record.payer,
    paidAtomic: lockJson.record.paidAtomic,
    confirmations: verifyRes.confirmations,
    gmvAtomic
  });
});

// ─── Non-Custodial Checkout + Ed25519 Receipt Attestation Demo ──────────────

app.post('/api/challenge', async (c) => {
  if (!c.env.TX_CLAIM_LOCK) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing TX_CLAIM_LOCK binding.' },
      500
    );
  }

  const parsedBody = await parseBoundedJsonBody<{
    txHash?: string;
    tier?: string;
    scope?: string;
    merchantAddress?: string;
  }>(c.req.raw);
  if (!parsedBody.ok) {
    return c.json({ error: parsedBody.error }, parsedBody.status);
  }
  const body = parsedBody.data;

  const txHash = (body.txHash ?? '').trim();
  const scopeRaw = (body.scope ?? 'checkout').trim();
  const tier = (body.tier ?? 'standard').trim() as Tier;

  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (scopeRaw !== 'checkout' && scopeRaw !== 'hosted') {
    return c.json({ error: 'INVALID_SCOPE', message: 'scope must be "checkout" or "hosted".' }, 400);
  }

  const brand = c.env.BRAND_NAME || 'ApexHive Labs';
  const product = c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit';
  const ttl = parsePositiveInt(c.env.CHALLENGE_TTL_SECONDS, 300, 60);
  const nonce = randomHex(16);
  const ts = Math.floor(Date.now() / 1000);
  const expiresAtMs = Date.now() + ttl * 1000;

  let record: ChallengeRecord;
  if (scopeRaw === 'hosted') {
    const merchantRaw = (body.merchantAddress ?? '').trim();
    if (!EVM_ADDR_RE.test(merchantRaw)) {
      return c.json(
        { error: 'INVALID_MERCHANT_ADDRESS', message: 'Expected 0x-prefixed 40-hex merchantAddress.' },
        400
      );
    }
    const merchantLower = merchantRaw.toLowerCase();
    const message = buildHostedChallengeMessage({
      brand,
      product,
      merchantAddress: merchantLower,
      txHash,
      nonce,
      ts
    });
    record = {
      nonce,
      scope: 'hosted',
      merchantAddress: merchantLower,
      txHash: txHash.toLowerCase(),
      tier: 'standard',
      ts,
      expiresAtMs,
      message
    };
  } else {
    if (!getConfiguredPayTo(c.env)) {
      return c.json(
        {
          error: 'SERVER_MISCONFIGURED',
          message: 'PAY_TO_EVM_ADDRESS is unset or placeholder; configure a valid 0x-prefixed EVM address.'
        },
        500
      );
    }
    if (tier !== 'standard') {
      return c.json({ error: 'INVALID_TIER', message: 'Tier must be standard.' }, 400);
    }
    const message = buildCheckoutChallengeMessage({
      brand,
      product,
      tier,
      txHash,
      nonce,
      ts
    });
    record = {
      nonce,
      scope: 'checkout',
      txHash: txHash.toLowerCase(),
      tier,
      ts,
      expiresAtMs,
      message
    };
  }

  const chStub = getChallengeStub(c.env, nonce);
  await chStub.fetch('https://lock.internal/challenge/create', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ record })
  });

  return c.json({
    nonce,
    scope: record.scope,
    ...(record.merchantAddress ? { merchantAddress: record.merchantAddress } : {}),
    ts,
    expiresInSeconds: ttl,
    message: record.message
  });
});

app.post('/api/verify', async (c) => {
  const payTo = getConfiguredPayTo(c.env);
  if (
    !payTo ||
    !c.env.LICENSE_SIGNING_PRIVATE_JWK ||
    !c.env.DOWNLOAD_HMAC_SECRET ||
    c.env.DOWNLOAD_HMAC_SECRET.length < 16 ||
    !c.env.TX_CLAIM_LOCK
  ) {
    return c.json(
      {
        error: 'SERVER_MISCONFIGURED',
        message:
          'Missing valid PAY_TO_EVM_ADDRESS, LICENSE_SIGNING_PRIVATE_JWK, DOWNLOAD_HMAC_SECRET, or TX_CLAIM_LOCK.'
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
  const challengeStub = getChallengeStub(c.env, nonce);
  const chValRes = await challengeStub.fetch('https://lock.internal/challenge/validate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scope: 'checkout', txHash: txLower, tier })
  });
  const chValJson = (await chValRes.json()) as {
    ok: boolean;
    error?: string;
    message?: string;
    record?: ChallengeRecord;
  };
  if (!chValRes.ok || !chValJson.ok || !chValJson.record) {
    return c.json(
      {
        error: chValJson.error || 'CHALLENGE_EXPIRED_OR_MISSING',
        message: chValJson.message || 'Challenge expired (>300s) or unknown.'
      },
      403
    );
  }
  const challenge = chValJson.record;

  const verifyRes = await verifyBaseUsdcTransfer({
    rpcUrls: getBaseRpcUrls(c.env),
    txHash: txLower,
    expectedUsdcContract: c.env.BASE_USDC_CONTRACT,
    expectedPayTo: payTo,
    requiredAtomicAmount: getCheckoutAmountAtomic(c.env),
    minConfirmations: parsePositiveInt(c.env.MIN_CONFIRMATIONS, 2, 1),
    challengeMessage: challenge.message,
    signature,
    requireSignature: true
  });

  if (!verifyRes.ok) {
    // Keep nonce on transient 502 RPC_UNAVAILABLE or 403 INSUFFICIENT_CONFIRMATIONS
    if (verifyRes.error === 'PAYMENT_OR_SIGNATURE_INVALID') {
      await challengeStub.fetch('https://lock.internal/challenge/invalidate', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}'
      });
    }
    return c.json({ error: verifyRes.error, message: verifyRes.message }, verifyRes.status);
  }

  // Atomically consume single-use challenge nonce before acquiring claim lock (prevents concurrent nonce reuse)
  const chConsumeRes = await challengeStub.fetch('https://lock.internal/challenge/consume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ scope: 'checkout', txHash: txLower, tier })
  });
  if (!chConsumeRes.ok) {
    const errJson = (await chConsumeRes.json()) as { error?: string; message?: string };
    return c.json(
      {
        error: errJson.error || 'CHALLENGE_EXPIRED_OR_MISSING',
        message: errJson.message || 'Challenge already used or expired.'
      },
      403
    );
  }

  // Isolated self-checkout DO lock (`checkout:<txHash>`) cannot be poisoned by /api/hosted/verify
  const lockId = c.env.TX_CLAIM_LOCK.idFromName(`checkout:${txLower}`);
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
    return c.json(
      {
        error: lockJson.error || 'TX_ALREADY_CLAIMED',
        message: lockJson.message || 'This transaction hash has already been claimed.'
      },
      403
    );
  }

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
  const downloadTtl = parsePositiveInt(c.env.DOWNLOAD_TTL_SECONDS, 600, 120);

  const grant = {
    txHash: txLower,
    payer: verifyRes.payer,
    tier,
    remainingDownloads: 3,
    createdAt: issuedAt,
    expiresAtMs: issuedAt + downloadTtl * 1000,
    licenseToken
  };

  const dlStub = getDownloadStub(c.env, grantId);
  await dlStub.fetch('https://lock.internal/download/create', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grant })
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
  if (
    !c.env.DOWNLOAD_HMAC_SECRET ||
    c.env.DOWNLOAD_HMAC_SECRET.length < 16 ||
    !c.env.TX_CLAIM_LOCK
  ) {
    return c.json(
      { error: 'SERVER_MISCONFIGURED', message: 'Missing DOWNLOAD_HMAC_SECRET or TX_CLAIM_LOCK.' },
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
  if (!constantTimeEqualStr(sigHex, expectedSig)) {
    return c.json({ error: 'INVALID_DOWNLOAD_TOKEN' }, 403);
  }

  const dlStub = getDownloadStub(c.env, grantId);
  const consumeRes = await dlStub.fetch('https://lock.internal/download/consume', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}'
  });
  const consumeJson = (await consumeRes.json()) as {
    ok: boolean;
    error?: string;
    message?: string;
    grant?: DownloadGrantRecord;
  };
  if (!consumeRes.ok || !consumeJson.ok || !consumeJson.grant) {
    return c.json(
      {
        error: consumeJson.error || 'DOWNLOAD_TOKEN_EXPIRED',
        message: consumeJson.message || 'Download grant expired or exhausted.'
      },
      403
    );
  }

  const grant = consumeJson.grant;
  return streamReleaseOrPublicCertificate({
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
});

app.all('*', async (c) => {
  if (c.env.ASSETS) {
    const assetRes = await c.env.ASSETS.fetch(c.req.raw);
    return new Response(assetRes.body, {
      status: assetRes.status,
      statusText: assetRes.statusText,
      headers: new Headers(assetRes.headers)
    });
  }
  return c.text('Not Found', 404);
});

export default app;
