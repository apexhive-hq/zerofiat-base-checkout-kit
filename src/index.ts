import { Hono } from 'hono';
import { verifyBaseUsdcTransfer } from './base-verifier.ts';
import { streamPrivateGithubRelease } from './github-release.ts';
import { signEd25519License } from './license-signer.ts';
import type {
  ChallengeRecord,
  DownloadGrantRecord,
  Env,
  Tier
} from './types.ts';

const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

function randomHex(byteCount = 16): string {
  const bytes = new Uint8Array(byteCount);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function getTierPriceAtomic(env: Env, tier: Tier): bigint {
  const raw = tier === 'team' ? env.TEAM_PRICE_USDC_ATOMIC : env.SOLO_PRICE_USDC_ATOMIC;
  return BigInt(raw || (tier === 'team' ? '59000000' : '29000000'));
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

app.get('/api/health', (c) => {
  return c.json({
    ok: true,
    service: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    kvBound: Boolean(c.env.LICENSES_KV)
  });
});

app.get('/api/config', (c) => {
  return c.json({
    brand: c.env.BRAND_NAME || 'ApexHive Labs',
    product: c.env.PRODUCT_ID || 'zerofiat-base-checkout-kit',
    tokenPrefix: c.env.TOKEN_PREFIX || 'ZEROFIAT-KIT-v1.',
    chainId: Number(c.env.BASE_CHAIN_ID || '8453'),
    network: 'Base Mainnet',
    usdcContract: c.env.BASE_USDC_CONTRACT,
    payToAddress: c.env.PAY_TO_EVM_ADDRESS,
    publicKeySpkiB64: c.env.LICENSE_SIGNING_PUBLIC_SPKI_B64 ?? null,
    tiers: {
      solo: {
        label: 'Solo Indie License (1 Project)',
        usdc: '29',
        atomic: c.env.SOLO_PRICE_USDC_ATOMIC || '29000000'
      },
      team: {
        label: 'Team Agency License (Unlimited Projects)',
        usdc: '59',
        atomic: c.env.TEAM_PRICE_USDC_ATOMIC || '59000000'
      }
    },
    optionalRails: {
      solanaUsdc: c.env.SOLANA_RECEIVE_ADDRESS,
      bitcoin: c.env.BTC_RECEIVE_ADDRESS,
      tronTrxUsdt: c.env.TRON_RECEIVE_ADDRESS
    },
    selfCustodyWarning:
      'SELF-CUSTODY WALLET ONLY: Send Base USDC ONLY from a wallet you control (MetaMask, Rabby, Coinbase Wallet). NEVER send directly from a centralized exchange (CEX) withdrawal—exchange hot wallets cannot sign the EIP-191 ownership challenge.'
  });
});

app.post('/api/challenge', async (c) => {
  let body: { txHash?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const tier = (body.tier ?? 'solo').trim() as Tier;

  if (!TX_HASH_RE.test(txHash)) {
    return c.json({ error: 'INVALID_TX_HASH', message: 'Expected 0x-prefixed 64-hex txHash.' }, 400);
  }
  if (tier !== 'solo' && tier !== 'team') {
    return c.json({ error: 'INVALID_TIER', message: 'Tier must be solo or team.' }, 400);
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
  let body: { txHash?: string; nonce?: string; signature?: string; tier?: string };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'INVALID_JSON' }, 400);
  }

  const txHash = (body.txHash ?? '').trim();
  const nonce = (body.nonce ?? '').trim();
  const signature = (body.signature ?? '').trim();
  const tier = (body.tier ?? 'solo').trim() as Tier;

  if (!TX_HASH_RE.test(txHash) || !nonce || !/^0x[0-9a-fA-F]{130}$/.test(signature)) {
    return c.json(
      { error: 'INVALID_REQUEST', message: 'Provide valid txHash, nonce, and EIP-191 signature.' },
      400
    );
  }
  if (tier !== 'solo' && tier !== 'team') {
    return c.json({ error: 'INVALID_TIER' }, 400);
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

  // Single-use challenge deletion before RPC verification
  await c.env.LICENSES_KV.delete(challengeKey);

  const challenge = JSON.parse(challengeRaw) as ChallengeRecord;
  const ttl = Math.max(60, Number(c.env.CHALLENGE_TTL_SECONDS || '300'));
  const nowSec = Math.floor(Date.now() / 1000);
  if (
    challenge.txHash !== txLower ||
    challenge.tier !== tier ||
    nowSec - challenge.ts > ttl
  ) {
    return c.json(
      { error: 'CHALLENGE_MISMATCH_OR_EXPIRED', message: 'Challenge mismatch or expired.' },
      403
    );
  }

  const claimedKey = `claimed_tx:${txLower}`;
  const alreadyClaimed = await c.env.LICENSES_KV.get(claimedKey);
  if (alreadyClaimed) {
    return c.json(
      { error: 'TX_ALREADY_CLAIMED', message: 'This transaction hash has already been claimed.' },
      403
    );
  }

  const verifyRes = await verifyBaseUsdcTransfer({
    rpcUrl: c.env.BASE_RPC_URL,
    txHash: txLower,
    expectedUsdcContract: c.env.BASE_USDC_CONTRACT,
    expectedPayTo: c.env.PAY_TO_EVM_ADDRESS,
    requiredAtomicAmount: getTierPriceAtomic(c.env, tier),
    minConfirmations: Math.max(1, Number(c.env.MIN_CONFIRMATIONS || '2')),
    challengeMessage: challenge.message,
    signature
  });

  if (!verifyRes.ok) {
    return c.json({ error: verifyRes.error, message: verifyRes.message }, verifyRes.status);
  }

  if (!c.env.LICENSE_SIGNING_PRIVATE_JWK) {
    return c.json({ error: 'SERVER_MISCONFIGURED', message: 'Missing signing secret.' }, 500);
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

  const downloadToken = randomHex(24);
  const downloadTtl = Math.max(120, Number(c.env.DOWNLOAD_TTL_SECONDS || '600'));
  const grant: DownloadGrantRecord = {
    txHash: txLower,
    payer: verifyRes.payer,
    tier,
    remainingDownloads: 3,
    createdAt: issuedAt
  };

  await Promise.all([
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
    c.env.LICENSES_KV.put(`dl:${downloadToken}`, JSON.stringify(grant), {
      expirationTtl: downloadTtl
    })
  ]);

  return c.json({
    ok: true,
    tier,
    payer: verifyRes.payer,
    txHash: txLower,
    paidAtomic: verifyRes.paidAtomic,
    licenseToken,
    downloadToken,
    downloadUrl: `/api/download?token=${downloadToken}`,
    downloadExpiresInSeconds: downloadTtl
  });
});

app.get('/api/download', async (c) => {
  const token = (c.req.query('token') ?? '').trim();
  if (!/^[0-9a-f]{32,64}$/.test(token)) {
    return c.json({ error: 'INVALID_DOWNLOAD_TOKEN' }, 403);
  }

  const dlKey = `dl:${token}`;
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

  const releaseRes = await streamPrivateGithubRelease({
    assetUrl: c.env.GITHUB_RELEASE_ASSET_URL,
    githubToken: c.env.GITHUB_RELEASE_READ_TOKEN,
    downloadFilename: c.env.RELEASE_FILENAME || 'zerofiat-base-checkout-kit-v1.0.0.zip'
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
