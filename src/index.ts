import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { verifyMessage } from 'viem';
import { verifyBaseUsdcTransfer } from './base-verifier.ts';
import { streamReleaseOrPublicCertificate } from './github-release.ts';
import { signEd25519License } from './license-signer.ts';
import { verifyLicenseTokenOffline } from './offline-verify.ts';
import type {
  ChallengeRecord,
  DownloadGrantRecord,
  Env,
  HostedClaimRecord,
  Tier
} from './types.ts';

const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;
const SIG_RE = /^0x[0-9a-fA-F]{130}$/;
const POSITIVE_INT_RE = /^[1-9]\d*$/;
const SCOPE_STOREFRONT = 'storefront:zerofiat';
const DEFAULT_HOSTED_FREE_QUOTA_ATOMIC = 10_000_000_000n;
const DEFAULT_BASE_RPC_URLS = [
  'https://mainnet.base.org',
  'https://base-rpc.publicnode.com',
  'https://1rpc.io/base'
];

interface GlobalClaimRecord {
  scope: string;
  payer: string;
  tier: string;
  txHash: string;
  claimedAt: number;
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

function getTierPriceAtomic(env: Env, tier: Tier): bigint {
  if (tier === 'team') {
    return BigInt(env.TEAM_PRICE_USDC_ATOMIC || '49000000');
  }
  return BigInt(env.SUPPORTER_PRICE_USDC_ATOMIC || env.SOLO_PRICE_USDC_ATOMIC || '5000000');
}

function getHostedFreeQuotaAtomic(env: Env): bigint {
  return BigInt(env.HOSTED_FREE_QUOTA_ATOMIC || DEFAULT_HOSTED_FREE_QUOTA_ATOMIC.toString());
}

async function checkTeamLicenseHeader(
  env: Env,
  licenseHeader: string | undefined
): Promise<boolean> {
  if (!licenseHeader || !env.LICENSE_SIGNING_PUBLIC_SPKI_B64) {
    return false;
  }
  const verified = await verifyLicenseTokenOffline(licenseHeader.trim(), {
    publicKeySpkiB64: env.LICENSE_SIGNING_PUBLIC_SPKI_B64,
    expectedPrefix: env.TOKEN_PREFIX || 'ZEROFIAT-KIT-v1.',
    expectedProduct: env.PRODUCT_ID || 'zerofiat-base-checkout-kit'
  });
  return verified.valid && verified.payload?.tier === 'team';
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
      'X-Payment-Address',
      'X-ApexHive-License'
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
    globalKvBound: Boolean(c.env.GLOBAL_CLAIMED_TX_KV),
    openSourceLicense: 'MIT',
    hostedFreeQuotaAtomic: getHostedFreeQuotaAtomic(c.env).toString(),
    supportEmail: 'apexhive.hq@proton.me'
  });
});

app.get('/api/config', (c) => {
  const supporterAtomic = getTierPriceAtomic(c.env, 'supporter');
  const teamAtomic = getTierPriceAtomic(c.env, 'team');
  const freeQuotaAtomic = getHostedFreeQuotaAtomic(c.env);
  return c.json({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    tokenPrefix: c.env.TOKEN_PREFIX || 'ZEROFIAT-KIT-v1.',
    openSourceLicense: 'MIT',
    publicRepoUrl: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    network: 'Base Mainnet',
    usdcContract: c.env.BASE_USDC_CONTRACT,
    payToAddress: c.env.PAY_TO_EVM_ADDRESS,
    publicKeySpkiB64: c.env.LICENSE_SIGNING_PUBLIC_SPKI_B64 ?? null,
    hostedFreeQuotaAtomic: freeQuotaAtomic.toString(),
    tiers: {
      supporter: {
        label: 'Sponsor / Supporter (Optional MIT Backing)',
        usdc: String(Number(supporterAtomic) / 1_000_000),
        atomic: supporterAtomic.toString()
      },
      team: {
        label: 'Team / Hosted Pro (Unlimited Hosted API + 5 Seats)',
        usdc: String(Number(teamAtomic) / 1_000_000),
        atomic: teamAtomic.toString()
      }
    },
    supportEmail: 'apexhive.hq@proton.me',
    optionalRails: {
      solanaUsdc: c.env.SOLANA_RECEIVE_ADDRESS,
      bitcoin: c.env.BTC_RECEIVE_ADDRESS,
      tronTrxUsdt: c.env.TRON_RECEIVE_ADDRESS
    },
    selfCustodyWarning:
      'SELF-CUSTODY WALLET ONLY: Send Base USDC ONLY from a wallet you control (MetaMask, Rabby, Coinbase Wallet). NEVER send directly from a centralized exchange (CEX) withdrawal—exchange hot wallets cannot sign the EIP-191 ownership challenge. Sent from a CEX by mistake or paying via Solana/BTC/TRON? Contact apexhive.hq@proton.me with your txHash.'
  });
});

// ─── Cloud Hosted Verify API (Free up to $10,000 USDC cumulative GMV) ───────

app.get('/api/hosted/quota/:merchantAddress', async (c) => {
  const merchantRaw = (c.req.param('merchantAddress') ?? '').trim();
  if (!EVM_ADDR_RE.test(merchantRaw)) {
    return c.json(
      { error: 'INVALID_MERCHANT_ADDRESS', message: 'Expected 0x-prefixed 40-hex EVM address.' },
      400
    );
  }

  const merchantLower = merchantRaw.toLowerCase();
  const freeQuota = getHostedFreeQuotaAtomic(c.env);
  const gmvRaw = await c.env.LICENSES_KV.get(`hosted_gmv:${merchantLower}`);
  const gmv = BigInt(gmvRaw || '0');
  const freeRemaining = freeQuota > gmv ? freeQuota - gmv : 0n;
  const proUnlocked = await checkTeamLicenseHeader(c.env, c.req.header('X-ApexHive-License'));

  return c.json({
    merchantAddress: merchantLower,
    gmvAtomic: gmv.toString(),
    freeQuotaAtomic: freeQuota.toString(),
    freeRemainingAtomic: freeRemaining.toString(),
    proUnlocked
  });
});

app.post('/api/hosted/verify', async (c) => {
  let body: {
    txHash?: string;
    merchantAddress?: string;
    minAmountAtomic?: string | number;
    expectedAmountAtomic?: string | number;
    challengeMessage?: string;
    signature?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  // Validate inputs BEFORE touching KV or RPC
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
      { error: 'INVALID_SIGNATURE_PROOF', message: 'Expected 0x-prefixed 130-hex EIP-191 signature.' },
      400
    );
  }

  const txLower = txHash.toLowerCase();
  const merchantLower = merchantAddress.toLowerCase();
  const freeQuota = getHostedFreeQuotaAtomic(c.env);
  const proUnlocked = await checkTeamLicenseHeader(c.env, c.req.header('X-ApexHive-License'));

  // 1. Idempotent cache hit: MUST re-check paidAtomic >= requiredAmount AND optional signature
  const claimedKey = `hosted_claimed:${txLower}`;
  const existingRaw = await c.env.LICENSES_KV.get(claimedKey);
  if (existingRaw) {
    const existing = JSON.parse(existingRaw) as HostedClaimRecord;
    if (existing.merchantAddress.toLowerCase() !== merchantLower) {
      return c.json(
        {
          error: 'TX_ALREADY_CLAIMED',
          message: 'Transaction hash has already been verified for another merchantAddress.'
        },
        403
      );
    }
    if (BigInt(existing.paidAtomic) < requiredAmount) {
      return c.json(
        {
          error: 'INSUFFICIENT_AMOUNT',
          message: `Cached transfer amount (${existing.paidAtomic}) is below required minAmountAtomic (${requiredAmount.toString()}).`
        },
        403
      );
    }
    if (hasMsg && hasSig) {
      const sigOk = await verifyMessage({
        address: existing.payer as `0x${string}`,
        message: body.challengeMessage!,
        signature: body.signature!.trim() as `0x${string}`
      }).catch(() => false);
      if (!sigOk) {
        return c.json(
          { error: 'INVALID_SIGNATURE', message: 'EIP-191 signature failed against cached payer address.' },
          403
        );
      }
    }

    const gmvRaw = await c.env.LICENSES_KV.get(`hosted_gmv:${merchantLower}`);
    const gmv = BigInt(gmvRaw || '0');
    const freeRemaining = freeQuota > gmv ? freeQuota - gmv : 0n;
    return c.json({
      ok: true,
      cached: true,
      mode: existing.mode,
      txHash: txLower,
      merchantAddress: merchantLower,
      payer: existing.payer,
      paidAtomic: existing.paidAtomic,
      gmvAtomic: gmv.toString(),
      freeQuotaAtomic: freeQuota.toString(),
      freeRemainingAtomic: freeRemaining.toString(),
      proUnlocked
    });
  }

  // 2. Pre-RPC quota check
  const gmvKey = `hosted_gmv:${merchantLower}`;
  const gmvRaw = await c.env.LICENSES_KV.get(gmvKey);
  const currentGmv = BigInt(gmvRaw || '0');
  if (currentGmv >= freeQuota && !proUnlocked) {
    return c.json(
      {
        error: 'QUOTA_EXCEEDED_10K',
        message:
          'Free $10,000 USDC Hosted API quota reached for this merchantAddress. Self-host the MIT code for free or upgrade to Team / Hosted Pro (49 USDC) and pass X-ApexHive-License.',
        merchantAddress: merchantLower,
        gmvAtomic: currentGmv.toString(),
        freeQuotaAtomic: freeQuota.toString(),
        freeRemainingAtomic: '0',
        selfHostRepo: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit',
        upgradeTier: 'team',
        supportEmail: 'apexhive.hq@proton.me'
      },
      402
    );
  }

  // 3. Verify Base Mainnet USDC Transfer directly to caller's merchantAddress
  const verifyRes = await verifyBaseUsdcTransfer({
    rpcUrls: getBaseRpcUrls(c.env),
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
    return c.json({ error: verifyRes.error, message: verifyRes.message }, verifyRes.status);
  }

  // 4. Enforce cumulative cap: currentGmv + txAmount <= freeQuota (unless valid Team license)
  const paidBig = BigInt(verifyRes.paidAtomic);
  const nextGmv = currentGmv + paidBig;
  if (nextGmv > freeQuota && !proUnlocked) {
    return c.json(
      {
        error: 'QUOTA_EXCEEDED_10K',
        message:
          'Adding this transaction exceeds the free $10,000 USDC Hosted API quota. Self-host MIT free or pass a valid Team / Hosted Pro X-ApexHive-License.',
        merchantAddress: merchantLower,
        gmvAtomic: currentGmv.toString(),
        txPaidAtomic: paidBig.toString(),
        freeQuotaAtomic: freeQuota.toString(),
        freeRemainingAtomic: (freeQuota > currentGmv ? freeQuota - currentGmv : 0n).toString(),
        selfHostRepo: 'https://github.com/apexhive-hq/zerofiat-base-checkout-kit',
        upgradeTier: 'team',
        supportEmail: 'apexhive.hq@proton.me'
      },
      402
    );
  }

  const mode: 'free_tier' | 'hosted_pro' = proUnlocked ? 'hosted_pro' : 'free_tier';
  const claimRecord: HostedClaimRecord = {
    txHash: txLower,
    merchantAddress: merchantLower,
    payer: verifyRes.payer,
    paidAtomic: verifyRes.paidAtomic,
    mode,
    verifiedAt: Date.now()
  };

  await Promise.all([
    c.env.LICENSES_KV.put(claimedKey, JSON.stringify(claimRecord)),
    c.env.LICENSES_KV.put(gmvKey, nextGmv.toString())
  ]);

  const freeRemaining = freeQuota > nextGmv ? freeQuota - nextGmv : 0n;
  return c.json({
    ok: true,
    cached: false,
    mode,
    txHash: txLower,
    merchantAddress: merchantLower,
    payer: verifyRes.payer,
    paidAtomic: verifyRes.paidAtomic,
    confirmations: verifyRes.confirmations,
    gmvAtomic: nextGmv.toString(),
    freeQuotaAtomic: freeQuota.toString(),
    freeRemainingAtomic: freeRemaining.toString(),
    proUnlocked
  });
});

// ─── Storefront Non-Custodial Checkout (Supporter 5 USDC / Team 49 USDC) ───

app.post('/api/challenge', async (c) => {
  let body: { txHash?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const tier = (body.tier ?? 'supporter').trim() as Tier;

  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (tier !== 'supporter' && tier !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be supporter or team.' }, 400);
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
  // Check required secrets and shared KV BEFORE touching challenge keys
  if (
    !c.env.LICENSE_SIGNING_PRIVATE_JWK ||
    !c.env.DOWNLOAD_HMAC_SECRET ||
    c.env.DOWNLOAD_HMAC_SECRET.length < 16 ||
    !c.env.GLOBAL_CLAIMED_TX_KV
  ) {
    return c.json(
      {
        error: 'SERVER_MISCONFIGURED',
        message: 'Missing LICENSE_SIGNING_PRIVATE_JWK, DOWNLOAD_HMAC_SECRET, or GLOBAL_CLAIMED_TX_KV.'
      },
      500
    );
  }

  let body: { txHash?: string; nonce?: string; signature?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const nonce = (body.nonce ?? '').trim();
  const signature = (body.signature ?? '').trim();
  const tier = (body.tier ?? 'supporter').trim() as Tier;

  if (!TX_HASH_RE.test(txHash) || !nonce || !SIG_RE.test(signature)) {
    return c.json(
      { error: 'INVALID_REQUEST', message: 'Provide valid txHash, nonce, and EIP-191 signature.' },
      400
    );
  }
  if (tier !== 'supporter' && tier !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be supporter or team.' }, 400);
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
    requiredAtomicAmount: getTierPriceAtomic(c.env, tier),
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

  // Enforce shared cross-product GLOBAL_CLAIMED_TX_KV before claiming
  const globalKey = `global_tx:${txLower}`;
  const globalRaw = await c.env.GLOBAL_CLAIMED_TX_KV.get(globalKey);
  if (globalRaw) {
    const globalRec = JSON.parse(globalRaw) as GlobalClaimRecord;
    if (globalRec.scope !== SCOPE_STOREFRONT) {
      await c.env.LICENSES_KV.delete(challengeKey);
      return c.json(
        {
          error: 'TX_ALREADY_CLAIMED_ELSEWHERE',
          message: `This transaction hash has already been claimed on ${globalRec.scope}.`
        },
        403
      );
    }
    if (
      globalRec.payer?.toLowerCase() !== verifyRes.payer.toLowerCase() ||
      globalRec.tier !== tier
    ) {
      await c.env.LICENSES_KV.delete(challengeKey);
      return c.json(
        { error: 'TX_ALREADY_CLAIMED', message: 'This transaction hash has already been claimed.' },
        403
      );
    }
  }

  // Consume single-use challenge ONLY after TX, confirmations, signature, and global scope succeed
  await c.env.LICENSES_KV.delete(challengeKey);

  const claimedKey = `claimed_tx:${txLower}`;
  const existingClaimRaw = await c.env.LICENSES_KV.get(claimedKey);
  let reclaimed = false;
  if (existingClaimRaw) {
    const existing = JSON.parse(existingClaimRaw) as { payer?: string; tier?: Tier };
    if (
      existing.payer?.toLowerCase() === verifyRes.payer.toLowerCase() &&
      existing.tier === tier
    ) {
      reclaimed = true;
    } else {
      return c.json(
        { error: 'TX_ALREADY_CLAIMED', message: 'This transaction hash has already been claimed.' },
        403
      );
    }
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
  const downloadTtl = Math.max(120, Number(c.env.DOWNLOAD_TTL_SECONDS || '600'));

  const grant: DownloadGrantRecord = {
    txHash: txLower,
    payer: verifyRes.payer,
    tier,
    remainingDownloads: 3,
    createdAt: issuedAt,
    licenseToken
  };

  const kvWrites: Array<Promise<void>> = [
    c.env.LICENSES_KV.put(`dl:${grantId}`, JSON.stringify(grant), {
      expirationTtl: downloadTtl
    })
  ];
  if (!reclaimed) {
    const globalRecord: GlobalClaimRecord = {
      scope: SCOPE_STOREFRONT,
      payer: verifyRes.payer,
      tier,
      txHash: txLower,
      claimedAt: issuedAt
    };
    kvWrites.push(
      c.env.LICENSES_KV.put(
        claimedKey,
        JSON.stringify({
          txHash: txLower,
          payer: verifyRes.payer,
          tier,
          paidAtomic: verifyRes.paidAtomic,
          issuedAt
        })
      ),
      c.env.GLOBAL_CLAIMED_TX_KV.put(globalKey, JSON.stringify(globalRecord))
    );
  }
  await Promise.all(kvWrites);

  return c.json({
    ok: true,
    reclaimed,
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
    assetUrl: c.env.GITHUB_RELEASE_ASSET_URL,
    publicArchiveUrl: c.env.PUBLIC_ARCHIVE_URL,
    githubToken: c.env.GITHUB_RELEASE_READ_TOKEN,
    downloadFilename: c.env.RELEASE_FILENAME || 'zerofiat-base-checkout-kit-v2.0.0.zip',
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
