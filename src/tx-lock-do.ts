import type { ChallengeRecord, DownloadGrantRecord, Env, Tier } from './types.ts';

export interface DurableClaimRecord {
  scope: 'checkout' | 'hosted';
  txHash: string;
  payer: string;
  tier?: Tier;
  merchantAddress?: string;
  paidAtomic: string;
  claimedAt: number;
}

interface StoredDownloadGrant extends DownloadGrantRecord {
  expiresAtMs: number;
}

interface DoStateLike {
  storage: {
    get<T = unknown>(key: string): Promise<T | undefined>;
    put<T = unknown>(key: string, value: T): Promise<void>;
    delete?(key: string): Promise<boolean>;
    setAlarm?(scheduledTime: number | Date): Promise<void>;
  };
}

const TX_HASH_RE = /^0x[0-9a-f]{64}$/;
const EVM_ADDR_RE = /^0x[0-9a-f]{40}$/;
const NON_NEGATIVE_INT_RE = /^\d+$/;

function checkoutClaimKey(txHash: string): string {
  return `claim:checkout:${txHash}`;
}

function hostedClaimKey(merchantAddress: string, txHash: string): string {
  return `claim:hosted:${merchantAddress}:${txHash}`;
}

function validateChallengeAgainst(
  record: ChallengeRecord,
  expected: {
    scope: 'checkout' | 'hosted';
    txHash: string;
    tier?: Tier;
    merchantAddress?: string;
  },
  nowMs: number
): { ok: true } | { ok: false; error: string; message: string } {
  const fallbackExp = Number.isFinite(record.ts) ? (record.ts + 300) * 1000 : 0;
  const expiresAtMs =
    typeof record.expiresAtMs === 'number' && Number.isFinite(record.expiresAtMs)
      ? record.expiresAtMs
      : fallbackExp;
  if (!Number.isFinite(expiresAtMs) || nowMs > expiresAtMs) {
    return {
      ok: false,
      error: 'CHALLENGE_MISMATCH_OR_EXPIRED',
      message: 'Challenge expired.'
    };
  }
  const recordScope = record.scope ?? 'checkout';
  if (recordScope !== expected.scope) {
    return {
      ok: false,
      error: 'CHALLENGE_MISMATCH_OR_EXPIRED',
      message: 'Challenge scope mismatch.'
    };
  }
  if (record.txHash.toLowerCase() !== expected.txHash) {
    return {
      ok: false,
      error: 'CHALLENGE_MISMATCH_OR_EXPIRED',
      message: 'Challenge txHash mismatch.'
    };
  }
  if (expected.scope === 'checkout' && expected.tier && record.tier !== expected.tier) {
    return {
      ok: false,
      error: 'CHALLENGE_MISMATCH_OR_EXPIRED',
      message: 'Challenge tier mismatch.'
    };
  }
  if (
    expected.scope === 'hosted' &&
    (record.merchantAddress ?? '').toLowerCase() !== (expected.merchantAddress ?? '')
  ) {
    return {
      ok: false,
      error: 'CHALLENGE_MISMATCH_OR_EXPIRED',
      message: 'Challenge merchantAddress mismatch.'
    };
  }
  return { ok: true };
}

/**
 * Strongly-consistent Cloudflare Durable Object handling scoped txHash claim locks,
 * single-use challenge nonces, atomic download grant decrements, and per-merchant GMV counters.
 * Serializes concurrent HTTP requests inside one single-threaded instance,
 * eliminating Workers KV eventual-consistency double-claim and counter races.
 */
export class TxClaimLockDO {
  private readonly ctx: DoStateLike;
  private queue: Promise<void> = Promise.resolve();

  constructor(ctx: DoStateLike, _env?: Env) {
    this.ctx = ctx;
  }

  private runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.then(
      () => undefined,
      () => undefined
    );
    return next;
  }

  private async deleteKey(key: string): Promise<void> {
    if (this.ctx.storage.delete) {
      await this.ctx.storage.delete(key);
    } else {
      await this.ctx.storage.put(key, null);
    }
  }

  async alarm(): Promise<void> {
    return this.runExclusive(async () => {
      const now = Date.now();
      const challenge = await this.ctx.storage.get<ChallengeRecord | null>('challenge');
      if (challenge) {
        const fallbackExp = Number.isFinite(challenge.ts) ? (challenge.ts + 300) * 1000 : 0;
        const exp =
          typeof challenge.expiresAtMs === 'number' && Number.isFinite(challenge.expiresAtMs)
            ? challenge.expiresAtMs
            : fallbackExp;
        if (!Number.isFinite(exp) || now >= exp) {
          await this.deleteKey('challenge');
        }
      }

      const grant = await this.ctx.storage.get<StoredDownloadGrant | null>('grant');
      if (grant) {
        if (
          !Number.isFinite(grant.expiresAtMs) ||
          now >= grant.expiresAtMs ||
          grant.remainingDownloads <= 0
        ) {
          await this.deleteKey('grant');
        }
      }
    });
  }

  async fetch(request: Request): Promise<Response> {
    return this.runExclusive(async () => {
      const url = new URL(request.url);
      if (request.method !== 'POST') {
        return Response.json({ ok: false, error: 'METHOD_NOT_ALLOWED' }, { status: 405 });
      }

      const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;

      if (url.pathname === '/claim-checkout') {
        const txHash = String(body.txHash ?? '').trim().toLowerCase();
        const payer = String(body.payer ?? '').trim().toLowerCase();
        const tier = String(body.tier ?? 'standard') as Tier;
        const paidAtomic = String(body.paidAtomic ?? '0');

        if (!TX_HASH_RE.test(txHash) || !EVM_ADDR_RE.test(payer)) {
          return Response.json({ ok: false, error: 'INVALID_LOCK_PARAMS' }, { status: 400 });
        }

        const storageKey = checkoutClaimKey(txHash);
        const existing = await this.ctx.storage.get<DurableClaimRecord>(storageKey);

        if (existing) {
          if (existing.payer.toLowerCase() === payer && existing.tier === tier) {
            return Response.json({ ok: true, reclaimed: true, record: existing });
          }
          return Response.json(
            {
              ok: false,
              error: 'TX_ALREADY_CLAIMED',
              message: 'This transaction hash has already been claimed.'
            },
            { status: 403 }
          );
        }

        const record: DurableClaimRecord = {
          scope: 'checkout',
          txHash,
          payer,
          tier,
          paidAtomic,
          claimedAt: Date.now()
        };
        await this.ctx.storage.put(storageKey, record);
        return Response.json({ ok: true, reclaimed: false, record });
      }

      if (url.pathname === '/claim-hosted') {
        const txHash = String(body.txHash ?? '').trim().toLowerCase();
        const merchantAddress = String(body.merchantAddress ?? '').trim().toLowerCase();
        const payer = String(body.payer ?? '').trim().toLowerCase();
        const paidAtomic = String(body.paidAtomic ?? '0');
        const requiredAtomicRaw = String(body.requiredAtomic ?? '1');
        // Strict single-use anti-replay is the default so naive `if (res.ok)` callers are never tricked by cached replays.
        const consumeOnce = body.consumeOnce !== false;

        if (
          !TX_HASH_RE.test(txHash) ||
          !EVM_ADDR_RE.test(merchantAddress) ||
          !EVM_ADDR_RE.test(payer) ||
          !NON_NEGATIVE_INT_RE.test(requiredAtomicRaw)
        ) {
          return Response.json({ ok: false, error: 'INVALID_LOCK_PARAMS' }, { status: 400 });
        }
        const requiredAtomic = BigInt(requiredAtomicRaw);

        const storageKey = hostedClaimKey(merchantAddress, txHash);
        const existing = await this.ctx.storage.get<DurableClaimRecord>(storageKey);

        if (existing) {
          if (consumeOnce) {
            return Response.json(
              {
                ok: false,
                error: 'TX_ALREADY_CLAIMED',
                message: 'This transaction hash has already been consumed for this merchantAddress.'
              },
              { status: 409 }
            );
          }

          if (BigInt(existing.paidAtomic) < requiredAtomic) {
            return Response.json(
              {
                ok: false,
                error: 'INSUFFICIENT_AMOUNT',
                message: `Cached transfer amount (${existing.paidAtomic}) is below required minAmountAtomic (${requiredAtomic.toString()}).`
              },
              { status: 403 }
            );
          }
          return Response.json({ ok: true, cached: true, consumed: false, record: existing });
        }

        if (!consumeOnce) {
          return Response.json({ ok: true, cached: false, consumed: false, record: null });
        }

        const record: DurableClaimRecord = {
          scope: 'hosted',
          txHash,
          merchantAddress,
          payer,
          paidAtomic,
          claimedAt: Date.now()
        };
        await this.ctx.storage.put(storageKey, record);
        return Response.json({ ok: true, cached: false, consumed: true, record });
      }

      if (url.pathname === '/claim-hosted-status') {
        const txHash = String(body.txHash ?? '').trim().toLowerCase();
        const merchantAddress = String(body.merchantAddress ?? '').trim().toLowerCase();
        const requiredAtomicRaw = String(body.requiredAtomic ?? '1');
        if (
          !TX_HASH_RE.test(txHash) ||
          !EVM_ADDR_RE.test(merchantAddress) ||
          !NON_NEGATIVE_INT_RE.test(requiredAtomicRaw)
        ) {
          return Response.json({ ok: false, error: 'INVALID_LOCK_PARAMS' }, { status: 400 });
        }
        const requiredAtomic = BigInt(requiredAtomicRaw);
        const existing = await this.ctx.storage.get<DurableClaimRecord>(
          hostedClaimKey(merchantAddress, txHash)
        );
        if (!existing) {
          return Response.json({ ok: true, cached: false, consumed: false, record: null });
        }
        if (BigInt(existing.paidAtomic) < requiredAtomic) {
          return Response.json(
            {
              ok: false,
              error: 'INSUFFICIENT_AMOUNT',
              message: `Cached transfer amount (${existing.paidAtomic}) is below required minAmountAtomic (${requiredAtomic.toString()}).`
            },
            { status: 403 }
          );
        }
        return Response.json({ ok: true, cached: true, consumed: false, record: existing });
      }

      if (url.pathname === '/challenge/create') {
        const record = body.record as ChallengeRecord | undefined;
        if (!record || !record.nonce || !TX_HASH_RE.test(record.txHash.toLowerCase())) {
          return Response.json({ ok: false, error: 'INVALID_CHALLENGE' }, { status: 400 });
        }
        const fallbackExp = Number.isFinite(record.ts) ? (record.ts + 300) * 1000 : 0;
        const expiresAtMs =
          typeof record.expiresAtMs === 'number' && Number.isFinite(record.expiresAtMs)
            ? record.expiresAtMs
            : fallbackExp;
        if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
          return Response.json({ ok: false, error: 'INVALID_CHALLENGE' }, { status: 400 });
        }
        await this.ctx.storage.put('challenge', { ...record, expiresAtMs });
        await this.ctx.storage.setAlarm?.(expiresAtMs);
        return Response.json({ ok: true });
      }

      if (url.pathname === '/challenge/validate' || url.pathname === '/challenge/consume') {
        const record = await this.ctx.storage.get<ChallengeRecord | null>('challenge');
        if (!record) {
          return Response.json(
            { ok: false, error: 'CHALLENGE_EXPIRED_OR_MISSING', message: 'Challenge expired or unknown.' },
            { status: 403 }
          );
        }
        const check = validateChallengeAgainst(
          record,
          {
            scope: (String(body.scope ?? 'checkout') as 'checkout' | 'hosted'),
            txHash: String(body.txHash ?? '').trim().toLowerCase(),
            tier: body.tier ? (String(body.tier) as Tier) : undefined,
            merchantAddress: body.merchantAddress
              ? String(body.merchantAddress).trim().toLowerCase()
              : undefined
          },
          Date.now()
        );
        if (!check.ok) {
          await this.deleteKey('challenge');
          return Response.json({ ok: false, error: check.error, message: check.message }, { status: 403 });
        }
        if (url.pathname === '/challenge/consume') {
          await this.deleteKey('challenge');
        }
        return Response.json({ ok: true, record });
      }

      if (url.pathname === '/challenge/invalidate') {
        await this.deleteKey('challenge');
        return Response.json({ ok: true });
      }

      if (url.pathname === '/download/create') {
        const grant = body.grant as StoredDownloadGrant | undefined;
        if (
          !grant ||
          !TX_HASH_RE.test(grant.txHash.toLowerCase()) ||
          !Number.isFinite(grant.expiresAtMs) ||
          grant.expiresAtMs <= 0
        ) {
          return Response.json({ ok: false, error: 'INVALID_GRANT' }, { status: 400 });
        }
        await this.ctx.storage.put('grant', grant);
        await this.ctx.storage.setAlarm?.(grant.expiresAtMs);
        return Response.json({ ok: true });
      }

      if (url.pathname === '/download/consume') {
        const grant = await this.ctx.storage.get<StoredDownloadGrant | null>('grant');
        if (!grant) {
          return Response.json(
            { ok: false, error: 'DOWNLOAD_TOKEN_EXPIRED', message: 'Download grant expired or exhausted.' },
            { status: 403 }
          );
        }
        if (!Number.isFinite(grant.expiresAtMs) || Date.now() > grant.expiresAtMs) {
          await this.deleteKey('grant');
          return Response.json(
            { ok: false, error: 'DOWNLOAD_TOKEN_EXPIRED', message: 'Download grant expired or exhausted.' },
            { status: 403 }
          );
        }
        if (grant.remainingDownloads <= 0) {
          await this.deleteKey('grant');
          return Response.json({ ok: false, error: 'DOWNLOAD_LIMIT_REACHED' }, { status: 403 });
        }
        const nextRemaining = grant.remainingDownloads - 1;
        if (nextRemaining <= 0) {
          await this.deleteKey('grant');
        } else {
          await this.ctx.storage.put('grant', { ...grant, remainingDownloads: nextRemaining });
        }
        return Response.json({ ok: true, grant, remainingDownloads: nextRemaining });
      }

      if (url.pathname === '/gmv/add') {
        const deltaRaw = String(body.deltaAtomic ?? '0').trim();
        if (!NON_NEGATIVE_INT_RE.test(deltaRaw)) {
          return Response.json({ ok: false, error: 'INVALID_GMV_DELTA' }, { status: 400 });
        }
        const current = BigInt((await this.ctx.storage.get<string>('gmvAtomic')) ?? '0');
        const next = current + BigInt(deltaRaw);
        await this.ctx.storage.put('gmvAtomic', next.toString());
        return Response.json({ ok: true, gmvAtomic: next.toString() });
      }

      if (url.pathname === '/gmv/get') {
        const current = (await this.ctx.storage.get<string>('gmvAtomic')) ?? '0';
        return Response.json({ ok: true, gmvAtomic: current });
      }

      return Response.json({ ok: false, error: 'UNKNOWN_LOCK_ACTION' }, { status: 404 });
    });
  }
}
