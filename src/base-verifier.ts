import { verifyMessage } from 'viem';

const ERC20_TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

interface RpcLog {
  address: string;
  topics: string[];
  data: string;
}

interface RpcReceipt {
  status: string;
  blockNumber: string;
  logs: RpcLog[];
}

export type BaseVerifyResult =
  | {
      ok: true;
      payer: string;
      confirmations: number;
      paidAtomic: string;
    }
  | {
      ok: false;
      status: 403 | 502;
      error: string;
      message: string;
    };

function normalizeTopicAddress(topic: string): string {
  return `0x${topic.slice(-40).toLowerCase()}`;
}

async function rpcCall<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params })
  });
  if (!res.ok) {
    throw new Error(`RPC HTTP ${res.status}`);
  }
  const json = (await res.json()) as { result?: T; error?: { message?: string } };
  if (json.error) {
    throw new Error(`RPC error: ${json.error.message ?? 'unknown'}`);
  }
  return json.result as T;
}

/**
 * Statelessly verifies a Base ERC-20 USDC Transfer receipt + EIP-191 payer signature.
 * Uses BigInt micro-unit math (6 decimals) to avoid floating-point rounding bugs.
 */
export async function verifyBaseUsdcTransfer(input: {
  rpcUrl: string;
  txHash: string;
  expectedUsdcContract: string;
  expectedPayTo: string;
  requiredAtomicAmount: bigint;
  minConfirmations: number;
  challengeMessage: string;
  signature: string;
}): Promise<BaseVerifyResult> {
  let receipt: RpcReceipt | null;
  let latestBlockHex: string;

  try {
    [receipt, latestBlockHex] = await Promise.all([
      rpcCall<RpcReceipt | null>(input.rpcUrl, 'eth_getTransactionReceipt', [
        input.txHash.toLowerCase()
      ]),
      rpcCall<string>(input.rpcUrl, 'eth_blockNumber', [])
    ]);
  } catch (err) {
    return {
      ok: false,
      status: 502,
      error: 'RPC_UNAVAILABLE',
      message: err instanceof Error ? err.message : 'Base JSON-RPC request failed'
    };
  }

  if (!receipt || receipt.status !== '0x1') {
    return {
      ok: false,
      status: 403,
      error: 'TX_NOT_CONFIRMED',
      message: 'Transaction receipt is missing or reverted.'
    };
  }

  const txBlock = BigInt(receipt.blockNumber);
  const headBlock = BigInt(latestBlockHex);
  const confirmations = headBlock >= txBlock ? Number(headBlock - txBlock) + 1 : 0;
  if (confirmations < input.minConfirmations) {
    return {
      ok: false,
      status: 403,
      error: 'INSUFFICIENT_CONFIRMATIONS',
      message: `Need at least ${input.minConfirmations} confirmations (got ${confirmations}).`
    };
  }

  const expectedUsdc = input.expectedUsdcContract.toLowerCase();
  const expectedPayTo = input.expectedPayTo.toLowerCase();

  const payerTotals = new Map<string, bigint>();
  for (const log of receipt.logs ?? []) {
    if (log.address?.toLowerCase() !== expectedUsdc) continue;
    if (!log.topics || log.topics.length < 3) continue;
    if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC) continue;

    const from = normalizeTopicAddress(log.topics[1]);
    const to = normalizeTopicAddress(log.topics[2]);
    if (to !== expectedPayTo) continue;

    const value = BigInt(log.data || '0x0');
    payerTotals.set(from, (payerTotals.get(from) ?? 0n) + value);
  }

  for (const [fromAddr, paid] of payerTotals.entries()) {
    if (paid < input.requiredAtomicAmount) continue;
    const sigOk = await verifyMessage({
      address: fromAddr as `0x${string}`,
      message: input.challengeMessage,
      signature: input.signature as `0x${string}`
    }).catch(() => false);

    if (sigOk) {
      return {
        ok: true,
        payer: fromAddr,
        confirmations,
        paidAtomic: paid.toString()
      };
    }
  }

  return {
    ok: false,
    status: 403,
    error: 'PAYMENT_OR_SIGNATURE_INVALID',
    message:
      'No Base USDC Transfer to the configured receive address met the tier price with a matching EIP-191 payer signature.'
  };
}
