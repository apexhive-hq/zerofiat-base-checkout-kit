import { createPublicClient, custom } from 'viem';
import { base } from 'viem/chains';

const ERC20_TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const STRICT_HEX_RE = /^0x[0-9a-fA-F]+$/;

function parseStrictHexBigInt(val: unknown): bigint | null {
  if (typeof val !== 'string' || !STRICT_HEX_RE.test(val)) return null;
  return BigInt(val);
}

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

export class RpcUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RpcUnavailableError';
  }
}

class ContractRevertError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContractRevertError';
  }
}

function normalizeTopicAddress(topic: string): string {
  return `0x${topic.slice(-40).toLowerCase()}`;
}

async function rpcCallSingle<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  let res: Response;
  try {
    res = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(6000)
    });
  } catch (err) {
    throw new RpcUnavailableError(err instanceof Error ? err.message : 'RPC fetch failed');
  }
  if (!res.ok) {
    throw new RpcUnavailableError(`RPC HTTP ${res.status}`);
  }
  let json: { result?: T; error?: { code?: number; message?: string } };
  try {
    json = (await res.json()) as { result?: T; error?: { code?: number; message?: string } };
  } catch (err) {
    throw new RpcUnavailableError(err instanceof Error ? err.message : 'Malformed RPC JSON');
  }
  if (json.error) {
    const msg = json.error.message ?? 'unknown';
    if (json.error.code === 3 || /revert/i.test(msg)) {
      throw new ContractRevertError(`RPC execution reverted: ${msg}`);
    }
    throw new RpcUnavailableError(`RPC error: ${msg}`);
  }
  return json.result as T;
}

async function rpcCallWithFailover<T>(
  urls: string[],
  method: string,
  params: unknown[]
): Promise<T> {
  let lastError: unknown;
  for (const url of urls) {
    try {
      return await rpcCallSingle<T>(url, method, params);
    } catch (err) {
      if (err instanceof ContractRevertError) {
        throw err;
      }
      lastError = err;
    }
  }
  throw new RpcUnavailableError(
    `All Base RPC endpoints failed: ${lastError instanceof Error ? lastError.message : 'unknown'}`
  );
}

/**
 * Verifies EOA (EIP-191) AND Smart Contract Wallet (ERC-1271 / EIP-6492) signatures
 * via viem publicClient.verifyMessage backed by multi-RPC Base failover transport.
 * Throws RpcUnavailableError if eth_call transport fails across all RPC endpoints.
 */
export async function verifySmartWalletOrEoaSignature(input: {
  rpcUrls: string[];
  address: string;
  message: string;
  signature: string;
}): Promise<boolean> {
  let transportErr: RpcUnavailableError | null = null;
  const client = createPublicClient({
    chain: base,
    transport: custom({
      async request({ method, params }) {
        try {
          return await rpcCallWithFailover(
            input.rpcUrls,
            method,
            Array.isArray(params) ? params : []
          );
        } catch (err) {
          if (err instanceof RpcUnavailableError) {
            transportErr = err;
          }
          throw err;
        }
      }
    })
  });

  let result: boolean;
  try {
    result = await client.verifyMessage({
      address: input.address as `0x${string}`,
      message: input.message,
      signature: input.signature as `0x${string}`
    });
  } catch (err) {
    if (transportErr) {
      throw transportErr;
    }
    if (err instanceof RpcUnavailableError) {
      throw err;
    }
    return false;
  }
  // viem's verifyErc6492 wraps transport errors into CallExecutionError -> VerificationError -> false;
  // surface any captured RPC transport failure so callers return 502 and preserve challenge nonces.
  if (!result && transportErr) {
    throw transportErr;
  }
  return result;
}

/**
 * Verifies a Base ERC-20 USDC Transfer receipt + EOA / Smart-Wallet signature.
 * Uses BigInt micro-unit math (6 decimals) to avoid floating-point rounding bugs.
 */
export async function verifyBaseUsdcTransfer(input: {
  rpcUrl?: string;
  rpcUrls?: string[];
  txHash: string;
  expectedUsdcContract: string;
  expectedPayTo: string;
  requiredAtomicAmount: bigint;
  minConfirmations: number;
  challengeMessage?: string;
  signature?: string;
  requireSignature?: boolean;
}): Promise<BaseVerifyResult> {
  const urls =
    input.rpcUrls && input.rpcUrls.length > 0
      ? input.rpcUrls
      : input.rpcUrl
        ? [input.rpcUrl]
        : ['https://mainnet.base.org'];

  let receipt: RpcReceipt | null;
  let latestBlockHex: string;

  try {
    [receipt, latestBlockHex] = await Promise.all([
      rpcCallWithFailover<RpcReceipt | null>(urls, 'eth_getTransactionReceipt', [
        input.txHash.toLowerCase()
      ]),
      rpcCallWithFailover<string>(urls, 'eth_blockNumber', [])
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

  const txBlock = parseStrictHexBigInt(receipt.blockNumber);
  const headBlock = parseStrictHexBigInt(latestBlockHex);
  if (txBlock === null || headBlock === null) {
    return {
      ok: false,
      status: 403,
      error: 'TX_NOT_CONFIRMED',
      message: 'Malformed or non-hex block number returned by Base RPC.'
    };
  }
  const minConfs =
    Number.isSafeInteger(input.minConfirmations) && input.minConfirmations >= 1
      ? input.minConfirmations
      : 2;
  const confirmationsBig = headBlock >= txBlock ? headBlock - txBlock + 1n : 0n;
  const confirmations =
    confirmationsBig > BigInt(Number.MAX_SAFE_INTEGER)
      ? Number.MAX_SAFE_INTEGER
      : Number(confirmationsBig);
  if (confirmations < minConfs) {
    return {
      ok: false,
      status: 403,
      error: 'INSUFFICIENT_CONFIRMATIONS',
      message: `Need at least ${minConfs} confirmations (got ${confirmations}).`
    };
  }

  const expectedUsdc = input.expectedUsdcContract.toLowerCase();
  const expectedPayTo = input.expectedPayTo.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(expectedUsdc) || !/^0x[0-9a-f]{40}$/.test(expectedPayTo)) {
    return {
      ok: false,
      status: 403,
      error: 'PAYMENT_NOT_FOUND',
      message: 'Invalid USDC contract or payTo address configuration.'
    };
  }

  const payerTotals = new Map<string, bigint>();
  let recipientTotal = 0n;
  let topPayer = '';
  let topPayerAmount = 0n;

  for (const log of receipt.logs ?? []) {
    if (log.address?.toLowerCase() !== expectedUsdc) continue;
    if (!log.topics || log.topics.length < 3) continue;
    if (log.topics[0]?.toLowerCase() !== ERC20_TRANSFER_TOPIC) continue;

    const from = normalizeTopicAddress(log.topics[1]);
    const to = normalizeTopicAddress(log.topics[2]);
    if (to !== expectedPayTo) continue;

    const value = parseStrictHexBigInt(log.data);
    if (value === null || value <= 0n) continue;
    const nextFromTotal = (payerTotals.get(from) ?? 0n) + value;
    payerTotals.set(from, nextFromTotal);
    recipientTotal += value;
    if (nextFromTotal > topPayerAmount) {
      topPayerAmount = nextFromTotal;
      topPayer = from;
    }
  }

  const requireSig = input.requireSignature !== false;
  if (!requireSig) {
    if (recipientTotal >= input.requiredAtomicAmount && topPayer) {
      return {
        ok: true,
        payer: topPayer,
        confirmations,
        paidAtomic: recipientTotal.toString()
      };
    }
    return {
      ok: false,
      status: 403,
      error: 'PAYMENT_NOT_FOUND',
      message: 'No Base USDC Transfer to the target merchant address met the required amount.'
    };
  }

  for (const [fromAddr, paid] of payerTotals.entries()) {
    if (paid < input.requiredAtomicAmount) continue;
    if (!input.challengeMessage || !input.signature) continue;
    let sigOk: boolean;
    try {
      sigOk = await verifySmartWalletOrEoaSignature({
        rpcUrls: urls,
        address: fromAddr,
        message: input.challengeMessage,
        signature: input.signature
      });
    } catch (err) {
      if (err instanceof RpcUnavailableError) {
        return {
          ok: false,
          status: 502,
          error: 'RPC_UNAVAILABLE',
          message: err.message
        };
      }
      throw err;
    }

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
      'No Base USDC Transfer to the configured receive address met the required amount with a matching EOA or Smart Wallet (ERC-1271/EIP-6492) signature.'
  };
}
