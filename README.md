# `zerofiat-base-checkout-kit` (`v2.1.0`) — ApexHive Labs

> **100% Free MIT non-custodial Base USDC payment verifier with EOA + Smart Wallet (`ERC-1271` / `EIP-6492`) signature verification, Cloudflare Durable Object atomic anti-replay locks (`TxClaimLockDO`), and portable Ed25519 attestation certificates.**

- **Live Reference Worker:** https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev

---

## Architecture Overview

```text
+-------------------------------------------------------------------+
|  Browser / Backend Checkout Client (EOA, Coinbase Smart Wallet,   |
|  Safe — EOA EIP-191 + ERC-1271 / EIP-6492 supported)              |
|  1. Self-custody Base USDC transfer -> merchantAddress / payTo    |
|  2. Calls /api/hosted/verify OR /api/challenge -> /api/verify     |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|  zerofiat-base-checkout-kit (Cloudflare Workers Free + DO + KV)   |
|  - Multi-RPC Base JSON-RPC failover (BASE_RPC_URLS)               |
|  - Strict BigInt 6-decimal ERC-20 Transfer log aggregation        |
|  - viem publicClient.verifyMessage (EOA + ERC-1271 + EIP-6492)    |
|  - TxClaimLockDO SQLite Durable Object atomic txHash lock         |
|  - Portable WebCrypto Ed25519 receipt signing & offline verifier  |
+-------------------------------------------------------------------+
```

---

## Stateless Verification Endpoints (100% Free MIT Rail)

Verify Base Mainnet USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) transfers directly to **your** `merchantAddress` with atomic anti-replay protection and unlimited GMV:

```bash
# 1. Check cumulative verified GMV for a merchantAddress (0 KV writes)
curl https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev/api/hosted/quota/0xYourMerchantAddress

# 2. Verify a settled Base USDC transaction (idempotent + Durable Object locked)
curl -X POST https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev/api/hosted/verify \
  -H "Content-Type: application/json" \
  -d '{"txHash":"0x...","merchantAddress":"0xYourMerchantAddress","minAmountAtomic":"1000000"}'
```

---

## Quickstart: Self-Host on Cloudflare Workers Free

```bash
git clone https://github.com/apexhive-hq/zerofiat-base-checkout-kit.git
cd zerofiat-base-checkout-kit
pnpm install --ignore-scripts
pnpm exec playwright install chromium
pnpm run typecheck
pnpm test
```

Configure KV storage and signing secrets on your Cloudflare account (Workers Free Tier supports SQLite-backed Durable Objects via `new_sqlite_classes`):

```bash
wrangler kv namespace create LICENSES_KV
node scripts/gen-dev-keys.mjs
wrangler secret put LICENSE_SIGNING_PRIVATE_JWK
wrangler secret put DOWNLOAD_HMAC_SECRET
wrangler deploy
```

---

## Security & Resilience Design

- **Zero Custody:** Workers hold zero wallet private keys or treasury spending rights; Base USDC settles directly to your public `PAY_TO_EVM_ADDRESS` or `merchantAddress`.
- **Smart Contract Wallet Support (`ERC-1271` / `EIP-6492`):** Accepts variable-length ABI signatures and verifies via `viem` `publicClient.verifyMessage` over multi-RPC Base transport (`BASE_RPC_URLS`), supporting Coinbase Smart Wallet and Safe alongside standard EOAs.
- **Atomic Replay Lock (`TxClaimLockDO`):** Every `txHash` claim routes through a single-threaded SQLite-backed Durable Object (`TX_CLAIM_LOCK`), eliminating Workers KV eventual-consistency race conditions under concurrent requests.
- **Challenge Nonce Retention & Failover:** Unconfirmed transactions (`INSUFFICIENT_CONFIRMATIONS`) preserve challenge nonces for immediate retries, while `BASE_RPC_URLS` fails over across Base RPC endpoints on `429`/`5xx`/timeouts.
- **Fail-Closed Secrets & Bounded Payloads:** Missing `LICENSE_SIGNING_PRIVATE_JWK`, `DOWNLOAD_HMAC_SECRET`, or `TX_CLAIM_LOCK` fails closed with HTTP `500 SERVER_MISCONFIGURED`; JSON bodies are strictly bounded (`32 KiB`).

---

## License

MIT Open Source (`$0`). Support contact: `apexhive.hq@proton.me`.

Optional Base USDC tips for MIT maintenance: `0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206`
