import type { Env, Tier } from './types.ts';

export interface DurableClaimRecord {
  scope: 'checkout' | 'hosted';
  txHash: string;
  payer: string;
  tier?: Tier;
  merchantAddress?: string;
  paidAtomic: string;
  claimedAt: number;
}

interface DoStateLike {
  storage: {
    get<T = unknown>(key: string): Promise<T | undefined>;
    put<T = unknown>(key: string, value: T): Promise<void>;
  };
}

/**
 * Strongly-consistent Cloudflare Durable Object locking each txHash atomically.
 * Serializes concurrent HTTP requests for the same txHash inside one single-threaded instance,
 * eliminating Workers KV eventual-consistency double-claim races.
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

  async fetch(request: Request): Promise<Response> {
    return this.runExclusive(async () => {
      const url = new URL(request.url);
      if (request.method !== 'POST') {
        return Response.json({ ok: false, error: 'METHOD_NOT_ALLOWED' }, { status: 405 });
      }

      const body = (await request.json()) as Record<string, unknown>;
      const existing = await this.ctx.storage.get<DurableClaimRecord>('claim');

      if (url.pathname === '/claim-checkout') {
        const txHash = String(body.txHash ?? '').toLowerCase();
        const payer = String(body.payer ?? '').toLowerCase();
        const tier = String(body.tier ?? 'standard') as Tier;
        const paidAtomic = String(body.paidAtomic ?? '0');

        if (existing) {
          if (existing.scope !== 'checkout') {
            return Response.json(
              {
                ok: false,
                error: 'TX_ALREADY_CLAIMED_ELSEWHERE',
                message: `Transaction hash was already claimed under scope "${existing.scope}".`
              },
              { status: 403 }
            );
          }
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
        await this.ctx.storage.put('claim', record);
        return Response.json({ ok: true, reclaimed: false, record });
      }

      if (url.pathname === '/claim-hosted') {
        const txHash = String(body.txHash ?? '').toLowerCase();
        const merchantAddress = String(body.merchantAddress ?? '').toLowerCase();
        const payer = String(body.payer ?? '').toLowerCase();
        const paidAtomic = String(body.paidAtomic ?? '0');
        const requiredAtomic = BigInt(String(body.requiredAtomic ?? '1'));

        if (existing) {
          if (existing.scope !== 'hosted') {
            return Response.json(
              {
                ok: false,
                error: 'TX_ALREADY_CLAIMED_ELSEWHERE',
                message: `Transaction hash was already claimed under scope "${existing.scope}".`
              },
              { status: 403 }
            );
          }
          if ((existing.merchantAddress ?? '').toLowerCase() !== merchantAddress) {
            return Response.json(
              {
                ok: false,
                error: 'TX_ALREADY_CLAIMED',
                message: 'Transaction hash has already been verified for another merchantAddress.'
              },
              { status: 403 }
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
          return Response.json({ ok: true, cached: true, record: existing });
        }

        const record: DurableClaimRecord = {
          scope: 'hosted',
          txHash,
          merchantAddress,
          payer,
          paidAtomic,
          claimedAt: Date.now()
        };
        await this.ctx.storage.put('claim', record);
        return Response.json({ ok: true, cached: false, record });
      }

      return Response.json({ ok: false, error: 'UNKNOWN_LOCK_ACTION' }, { status: 404 });
    });
  }
}
