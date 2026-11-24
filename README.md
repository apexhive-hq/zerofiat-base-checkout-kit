# `zerofiat-base-checkout-kit` (`v1.0.0`) — ApexHive Labs

> **Zero-custody Base USDC checkout, Cloudflare Workers KV replay protection, EIP-191 ownership verification, offline Ed25519 license signing, and Private GitHub Release `.zip` streaming—built for Cloudflare Workers Free Tier (`$0/mo`, no credit card, no D1, no R2).**

---

## Architecture Overview

1. **Public Receive-Address Only:** The Worker never holds wallet private keys or treasury spending rights. Base Mainnet USDC (`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`) settles directly into your public `PAY_TO_EVM_ADDRESS`.
2. **EIP-191 Challenge + Anti-Replay (`Workers KV`):**
   - `POST /api/challenge` issues a single-use `300s` challenge nonce stored in `LICENSES_KV`.
   - `POST /api/verify` deletes the nonce, checks `claimed_tx:<txHash>` in `LICENSES_KV`, queries Base JSON-RPC (`eth_getTransactionReceipt` + `eth_blockNumber`), sums `Transfer(from, to, value)` logs using exact `BigInt` 6-decimal math, and verifies `viem.verifyMessage` against the sending wallet (`from`).
3. **Instant Fulfillment:**
   - Issues an offline-verifiable WebCrypto **Ed25519 license token** (`src/offline-verify.ts` runs in Node `>=20`, browsers, and Workers).
   - Stores a short-lived `600s` capped download grant (`dl:<token>`, max 3 downloads) and streams your Private GitHub Release `.zip` via `GET /api/download?token=...` (`0 ms` Worker CPU while streaming I/O).

---

## Step-by-Step Deployment Guide (`$0` Cloudflare Workers Free Tier)

### 1. Install & Run Local Tests

```bash
pnpm install --ignore-scripts
pnpm run typecheck
pnpm test
```

### 2. Create Your Cloudflare Workers KV Namespace

```bash
wrangler kv namespace create LICENSES_KV
```

Copy the returned `id` into `wrangler.toml` under `[[kv_namespaces]]`.

### 3. Generate an Isolated Ed25519 License Signing Keypair

```bash
node scripts/gen-dev-keys.mjs
```

Set the private key as a Cloudflare Worker secret (this key only attests product licenses and holds **zero crypto funds**):

```bash
wrangler secret put LICENSE_SIGNING_PRIVATE_JWK
```

And set `LICENSE_SIGNING_PUBLIC_SPKI_B64` in `wrangler.toml` `[vars]` (or `.dev.vars` locally) so clients/CLIs can inspect your public verification key via `GET /api/config`.

### 4. Attach Your Private GitHub Release Asset (Optional for Digital Downloads)

1. Upload your release archive (e.g. `zerofiat-base-checkout-kit-v1.0.0.zip`) to a private GitHub repository release.
2. Create a fine-grained GitHub PAT with **Contents: Read-only** scoped strictly to that single repository.
3. Update `GITHUB_RELEASE_ASSET_URL` in `wrangler.toml` (using the GitHub API asset endpoint `https://api.github.com/repos/<owner>/<repo>/releases/assets/<asset_id>`) and store the read-only token as a Worker secret:

```bash
wrangler secret put GITHUB_RELEASE_READ_TOKEN
```

### 5. Configure Receive Address & Pricing

Edit `[vars]` in `wrangler.toml`:
- `PAY_TO_EVM_ADDRESS`: Your Base Mainnet self-custody / Safe receive address.
- `SOLO_PRICE_USDC_ATOMIC`: `29000000` (`29 USDC`, 6 decimals).
- `TEAM_PRICE_USDC_ATOMIC`: `59000000` (`59 USDC`, 6 decimals).
- `MIN_CONFIRMATIONS`: `2` (recommended for Base Mainnet finality).

### 6. Deploy

```bash
wrangler deploy
```

---

## Security Checklist

- **Self-Custody Warning:** Buyers must send from a wallet they control (MetaMask, Rabby, Coinbase Wallet)—never a centralized exchange withdrawal—so they can sign the EIP-191 ownership proof.
- **No Private Treasury Keys:** Only `PAY_TO_EVM_ADDRESS` (public) and `LICENSE_SIGNING_PRIVATE_JWK` (non-financial attestation secret) exist in Worker config.
- **Replay Protection:** Both `challenge:<nonce>` (deleted before RPC verification) and `claimed_tx:<txHash>` are enforced in `LICENSES_KV`.

---

## License

MIT — © ApexHive Labs
