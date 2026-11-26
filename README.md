# `zerofiat-base-checkout-kit` (`v2.1.0`) — ApexHive Labs

> **100% Free MIT non-custodial Base USDC payment verifier with EOA + Smart Wallet (`ERC-1271` / `EIP-6492`) signature verification, Cloudflare Durable Object atomic anti-replay locks (`TxClaimLockDO`), and portable Ed25519 attestation certificates.**

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
|  zerofiat-base-checkout-kit (Cloudflare Workers Free + DO)        |
|  - Multi-RPC Base JSON-RPC failover (BASE_RPC_URLS)               |
|  - Strict BigInt 6-decimal ERC-20 Transfer log aggregation        |
|  - viem publicClient.verifyMessage (EOA + ERC-1271 + EIP-6492)    |
|  - TxClaimLockDO SQLite Durable Object: scoped claim locks,       |
|    single-use nonces, atomic download grants, and merchant GMV    |
|  - Portable WebCrypto Ed25519 receipt signing & offline verifier  |
+-------------------------------------------------------------------+
```

---

## Verification Endpoints (100% Free MIT Rail)

Verify Base Mainnet USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) transfers directly to **your** `merchantAddress` with atomic single-use anti-replay protection (`409 TX_ALREADY_CLAIMED` on replays by default) and unlimited GMV:

```bash
# 1. Check cumulative verified GMV for a merchantAddress (atomic DO read)
curl https://your-worker.example.workers.dev/api/hosted/quota/0xYourMerchantAddress

# 2. Consume/lock a settled Base USDC transaction (strict single-use consumeOnce=true default)
#    Requires either HOSTED_API_TOKEN (backend) OR a server-issued signed challenge (nonce + signature)
curl -X POST https://your-worker.example.workers.dev/api/hosted/verify \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $HOSTED_API_TOKEN" \
  -d '{"txHash":"0x...","merchantAddress":"0xYourMerchantAddress","minAmountAtomic":"1000000"}'

# 3. Read-only on-chain status inspection (consumeOnce: false — never creates a lock or mutates GMV)
curl -X POST https://your-worker.example.workers.dev/api/hosted/verify \
  -H "Content-Type: application/json" \
  -d '{"txHash":"0x...","merchantAddress":"0xYourMerchantAddress","minAmountAtomic":"1000000","consumeOnce":false}'

# 4. Signed hosted verification (required when targeting the worker's own PAY_TO_EVM_ADDRESS)
curl -X POST https://your-worker.example.workers.dev/api/challenge \
  -H "Content-Type: application/json" \
  -d '{"txHash":"0x...","scope":"hosted","merchantAddress":"0xYourMerchantAddress"}'
```

---

## Quickstart: Self-Host on Cloudflare Workers Free

Requires **Node `>=22.18.0` LTS** (or Node `24+`, for unflagged `.ts` test execution) and `pnpm`.

```bash
git clone https://github.com/apexhive-hq/zerofiat-base-checkout-kit.git
cd zerofiat-base-checkout-kit
pnpm install --ignore-scripts
pnpm exec playwright install chromium
pnpm run typecheck
pnpm test
```

Customize `wrangler.toml` before deploying (the worker fails closed with `500 SERVER_MISCONFIGURED` if `PAY_TO_EVM_ADDRESS` is left as a placeholder):

1. Set `PAY_TO_EVM_ADDRESS` in `wrangler.toml` (or `.dev.vars` locally) to your own `0x`-prefixed Base Mainnet receive address.
2. Generate your own Ed25519 signing keypair and update `LICENSE_SIGNING_PUBLIC_SPKI_B64` in `wrangler.toml` with the printed public SPKI Base64 string:
   ```bash
   node scripts/gen-dev-keys.mjs
   ```
3. Set `ALLOWED_ORIGINS` (comma-separated origins, empty = same-origin only). Zero KV namespace setup is required — all locks, challenge nonces, download grants, and merchant GMV counters run inside SQLite-backed Durable Objects (`TxClaimLockDO`).
4. Upload secrets and deploy (Workers Free Tier supports SQLite-backed Durable Objects via `new_sqlite_classes`):

```bash
wrangler secret put LICENSE_SIGNING_PRIVATE_JWK
wrangler secret put DOWNLOAD_HMAC_SECRET
wrangler secret put HOSTED_API_TOKEN
wrangler deploy
```

---

## Security & Resilience Design

- **Zero Custody & Fail-Closed Target Address:** Workers hold zero wallet private keys or treasury spending rights; Base USDC settles directly to your configured `PAY_TO_EVM_ADDRESS` or `merchantAddress`, and `/api/challenge` (`scope: "checkout"`) + `/api/verify` fail closed (`500 SERVER_MISCONFIGURED`) if `PAY_TO_EVM_ADDRESS` is unset or a placeholder.
- **Smart Contract Wallet Support (`ERC-1271` / `EIP-6492`):** Accepts variable-length ABI signatures and verifies via `viem` `publicClient.verifyMessage` over multi-RPC Base transport (`BASE_RPC_URLS`), supporting Coinbase Smart Wallet and Safe alongside standard EOAs.
- **Anti-Griefing Hosted Locks & Atomic Durable Object State (`TxClaimLockDO`):**
  - Scoped claim keys (`hosted:<merchant>:<txHash>` vs `checkout:<txHash>`) prevent `/api/hosted/verify` from locking `/api/verify` claims.
  - Creating a single-use lock (`consumeOnce: true`, default returning `409 TX_ALREADY_CLAIMED` on replays) requires either a signed server-issued payer challenge (`nonce` + `signature`) or a valid `HOSTED_API_TOKEN`, blocking anonymous third-party Lock-Griefing DoS. Read-only `consumeOnce: false` checks never write locks or mutate GMV.
  - Unauthenticated `/api/hosted/verify` calls targeting the host `PAY_TO_EVM_ADDRESS` are blocked (`403 HOST_MERCHANT_SIGNATURE_REQUIRED`) unless authenticated via a signed server nonce or explicit `ALLOW_UNAUTHENTICATED_HOSTED_PAY_TO = "true"`.
  - Challenge nonces, download grant decrements (`remainingDownloads`), and per-merchant `hosted-gmv` counters all execute inside atomic `TxClaimLockDO` instances, eliminating KV eventual-consistency races.
- **Strict CORS, Bounded Streams & Security Headers:** API mutating/verification routes reject disallowed cross-origin requests against `ALLOWED_ORIGINS` (same-origin default; `/api/health` kept minimal read-only). JSON bodies enforce the `32 KiB` limit via streaming byte counting before full buffering and reject `null`/non-object JSON with `400 INVALID_JSON`. Every Worker response sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.
- **Challenge Nonce Retention & Failover:** Transient `502 RPC_UNAVAILABLE` and `403 INSUFFICIENT_CONFIRMATIONS` responses preserve challenge nonces for immediate retries, while `BASE_RPC_URLS` fails over across Base RPC endpoints on `429`/`5xx`/timeouts.

---

## License

MIT Open Source (`$0`). Support contact: `apexhive.hq@proton.me`.
