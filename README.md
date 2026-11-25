# `zerofiat-base-checkout-kit` (`v2.0.0`) — ApexHive Labs

> **Non-custodial Base USDC payment verifier, EIP-191 ownership proof, offline Ed25519 licensing, and Free-Until-$10K Hosted Verify API built for Cloudflare Workers Free Tier (`$0/mo`, MIT Open Source).**

- **Live Hosted API & Quota Dashboard:** https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev

---

## Architecture Overview

```text
+-------------------------------------------------------------------+
|  Browser / Backend Checkout Client                                |
|  1. Self-custody Base USDC transfer -> merchantAddress / payTo    |
|  2. Calls Hosted API OR self-hosted Worker endpoint               |
+---------------------------------+---------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------+
|  zerofiat-base-checkout-kit (Cloudflare Workers + Workers KV)     |
|  - Multi-RPC Base JSON-RPC failover (BASE_RPC_URLS)               |
|  - Exact BigInt 6-decimal ERC-20 Transfer log aggregation         |
|  - EIP-191 viem.verifyMessage ownership proof + replay protection |
|  - Portable WebCrypto Ed25519 license signing & offline verifier  |
+-------------------------------------------------------------------+
```

---

## Hosted Verify API (Free up to `$10,000 USDC` Cumulative GMV)

Verify Base Mainnet USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) settlements sent directly to **your** `merchantAddress` without provisioning infrastructure:

```bash
# 1. Check live cumulative verified GMV & remaining free quota (0 KV writes)
curl https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev/api/hosted/quota/0xYourMerchantAddress

# 2. Verify a settled Base USDC transaction (idempotent anti-replay)
curl -X POST https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev/api/hosted/verify \
  -H "Content-Type: application/json" \
  -d '{"txHash":"0x...","merchantAddress":"0xYourMerchantAddress","minAmountAtomic":"5000000"}'

# 3. Above $10,000 USDC cumulative GMV, self-host MIT free OR attach a Hosted Pro token:
curl -X POST https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev/api/hosted/verify \
  -H "Content-Type: application/json" \
  -H "X-ApexHive-License: ZEROFIAT-KIT-v1.<payload>.<sig>" \
  -d '{"txHash":"0x...","merchantAddress":"0xYourMerchantAddress"}'
```

---

## Quickstart: Self-Host on Cloudflare Workers Free

```bash
git clone https://github.com/apexhive-hq/zerofiat-base-checkout-kit.git
cd zerofiat-base-checkout-kit
pnpm install --ignore-scripts
pnpm run typecheck
pnpm test
```

Configure isolated KV storage and ephemeral attestation secrets on your Cloudflare account:

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
- **Same-Payer Re-Claim Recovery:** Verified original payers can safely re-claim Ed25519 tokens and download grants if a tab closes, while mismatched signers/tiers are rejected (`403 TX_ALREADY_CLAIMED`).
- **Challenge Nonce Retention:** Unconfirmed transactions (`INSUFFICIENT_CONFIRMATIONS`) and transient RPC failures preserve challenge nonces so immediate retries succeed cleanly.
- **Multi-RPC Failover:** Comma-separated `BASE_RPC_URLS` automatically fail over across Base JSON-RPC endpoints on `429`/`5xx`/network timeouts.
- **Fail-Closed Production Secrets:** Missing `LICENSE_SIGNING_PRIVATE_JWK` or `DOWNLOAD_HMAC_SECRET` fails closed with HTTP `500 SERVER_MISCONFIGURED`.

---

## License & Commercial Support

MIT Open Source (`$0`). Managed Hosted Verify API (free up to `$10,000 USDC` cumulative verified GMV), commercial multi-seat licenses, and community sponsorship are available on the [ApexHive Labs Storefront](https://zerofiat-base-checkout-kit.apexhive-hq.workers.dev). Support: `apexhive.hq@proton.me`.
