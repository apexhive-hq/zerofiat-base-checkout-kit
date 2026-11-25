import assert from 'node:assert/strict';
import { execSync, spawn } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join, resolve } from 'node:path';
import test from 'node:test';
import { chromium } from 'playwright';
import { encodeAbiParameters, pad } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { verifyLicenseTokenOffline } from '../src/offline-verify.ts';

const KIT_DIR = process.cwd();
const HQ_ROOT = resolve(KIT_DIR, '..', '..');
const CACHES_DIR = join(HQ_ROOT, '.caches');

const PAY_TO = '0x32eceaC45DBED9E555dAb80346aBd4Ab9C676206';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const WRONG_USDC = '0x9999999999999999999999999999999999999999';
const WRONG_RECIPIENT = '0x8888888888888888888888888888888888888888';
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

function makeTransferLog(tokenAddr, fromAddr, toAddr, atomicValue) {
  return {
    address: tokenAddr,
    topics: [
      TRANSFER_TOPIC,
      pad(fromAddr, { size: 32 }),
      pad(toAddr, { size: 32 })
    ],
    data: encodeAbiParameters([{ type: 'uint256' }], [atomicValue])
  };
}

async function waitForServer(url, timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url);
      if (res.ok) return;
    } catch {
      // Retry until ready
    }
    await new Promise((r) => setTimeout(r, 400));
  }
  throw new Error(`Timed out waiting for ${url}`);
}

test('zerofiat-base-checkout-kit v2.0 Hosted API ($10k GMV + 402 + Team unlock) + money-safety + Playwright UI', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const payerAcct = privateKeyToAccount(generatePrivateKey());
  const attackerAcct = privateKeyToAccount(generatePrivateKey());
  const merchantAcct = privateKeyToAccount(generatePrivateKey());
  const otherMerchantAcct = privateKeyToAccount(generatePrivateKey());

  const TX_SUPPORTER = '0x' + 'aa'.repeat(32);
  const TX_TEAM = '0x' + 'bb'.repeat(32);
  const TX_UNDERPAY = '0x' + 'cc'.repeat(32);
  const TX_WRONG_RECIPIENT = '0x' + 'dd'.repeat(32);
  const TX_WRONG_TOKEN = '0x' + 'ee'.repeat(32);
  const TX_REVERTED = '0x' + 'ff'.repeat(32);
  const TX_CONFS = '0x' + '12'.repeat(32);
  const TX_TIER_CONFLICT = '0x' + '34'.repeat(32);
  const TX_WALLET_SUPPORTER = '0x' + '56'.repeat(32);
  const TX_HOSTED_6K = '0x' + '78'.repeat(32);
  const TX_HOSTED_4K = '0x' + '9a'.repeat(32);
  const TX_HOSTED_EXTRA = '0x' + 'bc'.repeat(32);

  let headBlockHex = '0x65'; // block 101 => 2 confirmations for block 0x64
  let flakyHits = 0;
  let okHits = 0;

  const receipts = new Map([
    [
      TX_SUPPORTER,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 5_000_000n)]
      }
    ],
    [
      TX_TEAM,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 49_000_000n)]
      }
    ],
    [
      TX_UNDERPAY,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 4_990_000n)]
      }
    ],
    [
      TX_WRONG_RECIPIENT,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, WRONG_RECIPIENT, 5_000_000n)]
      }
    ],
    [
      TX_WRONG_TOKEN,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(WRONG_USDC, payerAcct.address, PAY_TO, 5_000_000n)]
      }
    ],
    [
      TX_REVERTED,
      {
        status: '0x0',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 5_000_000n)]
      }
    ],
    [
      TX_CONFS,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 5_000_000n)]
      }
    ],
    [
      TX_TIER_CONFLICT,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 49_000_000n)]
      }
    ],
    [
      TX_WALLET_SUPPORTER,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 5_000_000n)]
      }
    ],
    [
      TX_HOSTED_6K,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, merchantAcct.address, 6_000_000_000n)]
      }
    ],
    [
      TX_HOSTED_4K,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, merchantAcct.address, 4_000_000_000n)]
      }
    ],
    [
      TX_HOSTED_EXTRA,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, merchantAcct.address, 10_000_000n)]
      }
    ]
  ]);

  // 1. Mock Base JSON-RPC server (4121) with /flaky (429/500) + /ok failover
  const rpcPort = 4121;
  const rpcServer = createServer((req, res) => {
    if (req.url?.startsWith('/flaky')) {
      flakyHits += 1;
      const status = flakyHits % 2 === 1 ? 429 : 500;
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: `Simulated upstream HTTP ${status}` }));
      return;
    }

    okHits += 1;
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      const parsed = JSON.parse(body);
      const calls = Array.isArray(parsed) ? parsed : [parsed];
      const replies = calls.map((call) => {
        if (call.method === 'eth_blockNumber') {
          return { jsonrpc: '2.0', id: call.id, result: headBlockHex };
        }
        if (call.method === 'eth_getTransactionReceipt') {
          const hash = String(call.params?.[0] ?? '').toLowerCase();
          return { jsonrpc: '2.0', id: call.id, result: receipts.get(hash) ?? null };
        }
        return { jsonrpc: '2.0', id: call.id, error: { code: -32601, message: 'Method not found' } };
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(Array.isArray(parsed) ? replies : replies[0]));
    });
  });

  // 2. Mock Release Asset server (4122)
  const expectedToken = 'ghp_local_mock_release_token_zero_secret';
  const mockZipBytes = Buffer.from('PK\x03\x04zerofiat-base-checkout-kit-v2.0.0-verified-payload');
  const expectedZipSha256 = createHash('sha256').update(mockZipBytes).digest('hex');
  const releasePort = 4122;
  const releaseServer = createServer((req, res) => {
    assert.equal(req.headers.authorization, `Bearer ${expectedToken}`);
    assert.equal(req.headers.accept, 'application/octet-stream');
    res.writeHead(200, {
      'content-type': 'application/zip',
      'content-length': String(mockZipBytes.length)
    });
    res.end(mockZipBytes);
  });

  await new Promise((r) => rpcServer.listen(rpcPort, '127.0.0.1', r));
  await new Promise((r) => releaseServer.listen(releasePort, '127.0.0.1', r));

  // 3. Boot Wrangler local dev on 4120 using global wrangler from PATH
  const wranglerPort = 4120;
  const baseUrl = `http://127.0.0.1:${wranglerPort}`;
  const wranglerStateDir = join(KIT_DIR, '.wrangler-state');
  const devVarsPath = join(KIT_DIR, '.dev.vars');

  if (existsSync(wranglerStateDir)) rmSync(wranglerStateDir, { recursive: true, force: true });
  writeFileSync(
    devVarsPath,
    [
      `LICENSE_SIGNING_PRIVATE_JWK=${JSON.stringify(privateJwk)}`,
      `LICENSE_SIGNING_PUBLIC_SPKI_B64=${publicSpkiB64}`,
      `DOWNLOAD_HMAC_SECRET=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789`,
      `GITHUB_RELEASE_READ_TOKEN=${expectedToken}`,
      `GITHUB_RELEASE_ASSET_URL=http://127.0.0.1:${releasePort}/releases/assets/1`,
      `BASE_RPC_URLS=http://127.0.0.1:${rpcPort}/flaky,http://127.0.0.1:${rpcPort}/ok`,
      `BASE_RPC_URL=http://127.0.0.1:${rpcPort}/flaky`,
      `MIN_CONFIRMATIONS=2`
    ].join('\n'),
    'utf8'
  );

  const wranglerBin = process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler';
  const wranglerProc = spawn(
    wranglerBin,
    ['dev', '--local', '--port', String(wranglerPort), '--ip', '127.0.0.1', '--persist-to', '.wrangler-state'],
    {
      cwd: KIT_DIR,
      shell: true,
      env: {
        ...process.env,
        APPDATA: join(CACHES_DIR, 'roaming'),
        LOCALAPPDATA: join(CACHES_DIR, 'local'),
        XDG_CONFIG_HOME: join(CACHES_DIR, 'xdg'),
        WRANGLER_SEND_METRICS: 'false'
      },
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );

  try {
    await waitForServer(`${baseUrl}/api/health`);

    // 4. Config & Open-Core v2.0 check
    const cfgRes = await fetch(`${baseUrl}/api/config`);
    assert.equal(cfgRes.status, 200);
    const cfgJson = await cfgRes.json();
    assert.equal(cfgJson.openSourceLicense, 'MIT');
    assert.equal(cfgJson.supportEmail, 'apexhive.hq@proton.me');
    assert.equal(cfgJson.tiers.supporter.atomic, '5000000');
    assert.equal(cfgJson.tiers.team.atomic, '49000000');
    assert.equal(cfgJson.hostedFreeQuotaAtomic, '10000000000');

    async function issueChallenge(txHash, tier) {
      const res = await fetch(`${baseUrl}/api/challenge`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier })
      });
      assert.equal(res.status, 200);
      return await res.json();
    }

    // 4a. Confirmation check retains challenge nonce across 1-conf failure -> 2-conf retry
    headBlockHex = '0x64'; // 1 confirmation
    const chConf = await issueChallenge(TX_CONFS, 'supporter');
    const sigConf = await payerAcct.signMessage({ message: chConf.message });
    const vConfLow = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_CONFS, nonce: chConf.nonce, signature: sigConf, tier: 'supporter' })
    });
    assert.equal(vConfLow.status, 403);
    assert.equal((await vConfLow.json()).error, 'INSUFFICIENT_CONFIRMATIONS');

    headBlockHex = '0x65'; // 2 confirmations -> same nonce + signature succeeds
    const vConfOk = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_CONFS, nonce: chConf.nonce, signature: sigConf, tier: 'supporter' })
    });
    assert.equal(vConfOk.status, 200);
    const confOkJson = await vConfOk.json();
    assert.equal(confOkJson.ok, true);
    assert.equal(confOkJson.reclaimed, false);
    assert.equal(
      (await verifyLicenseTokenOffline(confOkJson.licenseToken, {
        publicKeySpkiB64: publicSpkiB64,
        expectedPrefix: 'ZEROFIAT-KIT-v1.',
        expectedProduct: 'zerofiat-base-checkout-kit'
      })).valid,
      true
    );

    // Verify RPC failover across 429/500
    assert.ok(flakyHits >= 2, `Expected >=2 /flaky failover probes, got ${flakyHits}`);
    assert.ok(okHits >= 2, `Expected >=2 /ok RPC completions, got ${okHits}`);

    // 4b. Hosted Verify API (<$10k free -> idempotent replay -> >=$10k 402 -> Team token unlocks -> 200 hosted_pro)
    const qInitRes = await fetch(`${baseUrl}/api/hosted/quota/${merchantAcct.address}`);
    assert.equal(qInitRes.status, 200);
    const qInit = await qInitRes.json();
    assert.equal(qInit.gmvAtomic, '0');
    assert.equal(qInit.freeQuotaAtomic, '10000000000');
    assert.equal(qInit.freeRemainingAtomic, '10000000000');
    assert.equal(qInit.proUnlocked, false);

    // First $6,000 USDC hosted verify (free_tier)
    const h6k = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: TX_HOSTED_6K,
        merchantAddress: merchantAcct.address,
        minAmountAtomic: '6000000000'
      })
    });
    assert.equal(h6k.status, 200);
    const h6kJson = await h6k.json();
    assert.equal(h6kJson.ok, true);
    assert.equal(h6kJson.cached, false);
    assert.equal(h6kJson.mode, 'free_tier');
    assert.equal(h6kJson.gmvAtomic, '6000000000');
    assert.equal(h6kJson.freeRemainingAtomic, '4000000000');

    // Replay TX_HOSTED_6K -> cached: true WITHOUT double-counting GMV
    const h6kReplay = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_HOSTED_6K, merchantAddress: merchantAcct.address })
    });
    assert.equal(h6kReplay.status, 200);
    const h6kReplayJson = await h6kReplay.json();
    assert.equal(h6kReplayJson.cached, true);
    assert.equal(h6kReplayJson.gmvAtomic, '6000000000');

    // Different merchant claiming TX_HOSTED_6K -> 403 TX_ALREADY_CLAIMED
    const h6kCross = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_HOSTED_6K, merchantAddress: otherMerchantAcct.address })
    });
    assert.equal(h6kCross.status, 403);

    // Second $4,000 USDC hosted verify -> hits $10,000 cap
    const h4k = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_HOSTED_4K, merchantAddress: merchantAcct.address })
    });
    assert.equal(h4k.status, 200);
    const h4kJson = await h4k.json();
    assert.equal(h4kJson.gmvAtomic, '10000000000');
    assert.equal(h4kJson.freeRemainingAtomic, '0');

    // Beyond $10,000 without Team license -> 402 QUOTA_EXCEEDED_10K
    const hQuotaBlocked = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_HOSTED_EXTRA, merchantAddress: merchantAcct.address })
    });
    assert.equal(hQuotaBlocked.status, 402);
    const blockedJson = await hQuotaBlocked.json();
    assert.equal(blockedJson.error, 'QUOTA_EXCEEDED_10K');

    // Passing Supporter token (5 USDC) must NOT unlock Hosted Pro -> still 402
    const hSupporterBlocked = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-ApexHive-License': confOkJson.licenseToken
      },
      body: JSON.stringify({ txHash: TX_HOSTED_EXTRA, merchantAddress: merchantAcct.address })
    });
    assert.equal(hSupporterBlocked.status, 402);

    // Purchase Team / Hosted Pro (49 USDC) -> signed team token -> unlocks Hosted API past $10k
    const chTeamApi = await issueChallenge(TX_TEAM, 'team');
    const sigTeamApi = await payerAcct.signMessage({ message: chTeamApi.message });
    const vTeamApi = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_TEAM, nonce: chTeamApi.nonce, signature: sigTeamApi, tier: 'team' })
    });
    assert.equal(vTeamApi.status, 200);
    const teamJson = await vTeamApi.json();
    assert.equal(teamJson.tier, 'team');

    const hUnlocked = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-ApexHive-License': teamJson.licenseToken
      },
      body: JSON.stringify({ txHash: TX_HOSTED_EXTRA, merchantAddress: merchantAcct.address })
    });
    assert.equal(hUnlocked.status, 200);
    const hUnlockedJson = await hUnlocked.json();
    assert.equal(hUnlockedJson.ok, true);
    assert.equal(hUnlockedJson.mode, 'hosted_pro');
    assert.equal(hUnlockedJson.proUnlocked, true);
    assert.equal(hUnlockedJson.gmvAtomic, '10010000000');

    const qProRes = await fetch(`${baseUrl}/api/hosted/quota/${merchantAcct.address}`, {
      headers: { 'X-ApexHive-License': teamJson.licenseToken }
    });
    assert.equal((await qProRes.json()).proUnlocked, true);

    // 4c. Supporter 5 USDC claim + 3-download cap + same-payer re-claim fresh grant
    const chSup = await issueChallenge(TX_SUPPORTER, 'supporter');
    const sigSup = await payerAcct.signMessage({ message: chSup.message });
    const vSup = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_SUPPORTER, nonce: chSup.nonce, signature: sigSup, tier: 'supporter' })
    });
    assert.equal(vSup.status, 200);
    const supJson = await vSup.json();
    assert.equal(supJson.reclaimed, false);
    assert.equal(
      (await verifyLicenseTokenOffline(supJson.licenseToken, {
        publicKeySpkiB64: publicSpkiB64,
        expectedPrefix: 'ZEROFIAT-KIT-v1.',
        expectedProduct: 'zerofiat-base-checkout-kit'
      })).valid,
      true
    );

    for (let i = 0; i < 3; i += 1) {
      const dl = await fetch(`${baseUrl}${supJson.downloadUrl}`);
      assert.equal(dl.status, 200);
      const buf = Buffer.from(await dl.arrayBuffer());
      assert.equal(createHash('sha256').update(buf).digest('hex'), expectedZipSha256);
    }
    const dl4 = await fetch(`${baseUrl}${supJson.downloadUrl}`);
    assert.equal(dl4.status, 403);

    // Same-payer re-claim issues fresh licenseToken + fresh HMAC downloadUrl
    const chReclaim = await issueChallenge(TX_SUPPORTER, 'supporter');
    const sigReclaim = await payerAcct.signMessage({ message: chReclaim.message });
    const vReclaim = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_SUPPORTER, nonce: chReclaim.nonce, signature: sigReclaim, tier: 'supporter' })
    });
    assert.equal(vReclaim.status, 200);
    const reclaimJson = await vReclaim.json();
    assert.equal(reclaimJson.ok, true);
    assert.equal(reclaimJson.reclaimed, true);
    assert.notEqual(reclaimJson.downloadToken, supJson.downloadToken);
    const dlReclaim = await fetch(`${baseUrl}${reclaimJson.downloadUrl}`);
    assert.equal(dlReclaim.status, 200);
    const reclaimZipBuf = Buffer.from(await dlReclaim.arrayBuffer());
    assert.equal(createHash('sha256').update(reclaimZipBuf).digest('hex'), expectedZipSha256);

    // Attacker re-claim on TX_SUPPORTER -> 403
    const chAttackerSup = await issueChallenge(TX_SUPPORTER, 'supporter');
    const sigAttackerSup = await attackerAcct.signMessage({ message: chAttackerSup.message });
    const vAttackerSup = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: TX_SUPPORTER,
        nonce: chAttackerSup.nonce,
        signature: sigAttackerSup,
        tier: 'supporter'
      })
    });
    assert.equal(vAttackerSup.status, 403);

    // Tier mismatch re-claim by same payer -> 403 TX_ALREADY_CLAIMED
    const chTier1 = await issueChallenge(TX_TIER_CONFLICT, 'supporter');
    const sigTier1 = await payerAcct.signMessage({ message: chTier1.message });
    const vTier1 = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_TIER_CONFLICT, nonce: chTier1.nonce, signature: sigTier1, tier: 'supporter' })
    });
    assert.equal(vTier1.status, 200);

    const chTier2 = await issueChallenge(TX_TIER_CONFLICT, 'team');
    const sigTier2 = await payerAcct.signMessage({ message: chTier2.message });
    const vTier2 = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_TIER_CONFLICT, nonce: chTier2.nonce, signature: sigTier2, tier: 'team' })
    });
    assert.equal(vTier2.status, 403);
    assert.equal((await vTier2.json()).error, 'TX_ALREADY_CLAIMED');

    // 4d. Negative guards (underpay, wrong recipient, wrong token, reverted, wrong signer)
    for (const [tx, tier, signer] of [
      [TX_UNDERPAY, 'supporter', payerAcct],
      [TX_WRONG_RECIPIENT, 'supporter', payerAcct],
      [TX_WRONG_TOKEN, 'supporter', payerAcct],
      [TX_REVERTED, 'supporter', payerAcct],
      [TX_WALLET_SUPPORTER, 'supporter', attackerAcct]
    ]) {
      const chNeg = await issueChallenge(tx, tier);
      const sigNeg = await signer.signMessage({ message: chNeg.message });
      const vNeg = await fetch(`${baseUrl}/api/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx, nonce: chNeg.nonce, signature: sigNeg, tier })
      });
      assert.equal(vNeg.status, 403);
    }

    // 5. Playwright Headless UI verification (no-wallet hidden check + 1440x900 & 375x812 + Quota Checker + 1-click #wallet-pay-btn)
    process.env.PLAYWRIGHT_BROWSERS_PATH = join(CACHES_DIR, 'ms-playwright');
    const browser = await chromium.launch({ headless: true });
    try {
      const noWalletCtx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
      const noWalletPage = await noWalletCtx.newPage();
      await noWalletPage.goto(baseUrl, { waitUntil: 'networkidle' });
      assert.equal(
        await noWalletPage.locator('#wallet-pay-btn').isVisible(),
        false,
        '#wallet-pay-btn MUST remain hidden when window.ethereum is absent'
      );
      await noWalletCtx.close();

      for (const vp of [
        { name: 'desktop', width: 1440, height: 900 },
        { name: 'mobile', width: 375, height: 812 }
      ]) {
        const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
        const page = await context.newPage();
        const consoleErrors = [];
        const pageErrors = [];
        page.on('console', (msg) => {
          if (msg.type() === 'error') consoleErrors.push(msg.text());
        });
        page.on('pageerror', (err) => pageErrors.push(err.message));

        await page.addInitScript(
          ({ payerAddr, mockTxHash }) => {
            window.__walletCalls = [];
            window.ethereum = {
              async request({ method, params }) {
                window.__walletCalls.push({ method, params });
                if (method === 'eth_requestAccounts') return [payerAddr];
                if (method === 'eth_chainId') return '0x2105';
                if (method === 'wallet_switchEthereumChain') return null;
                if (method === 'eth_sendTransaction') return mockTxHash;
                throw new Error(`Unexpected ethereum RPC method: ${method}`);
              }
            };
          },
          { payerAddr: payerAcct.address, mockTxHash: TX_WALLET_SUPPORTER }
        );

        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        assert.equal((await page.locator('#pay-to-address').textContent())?.trim(), PAY_TO);
        assert.equal(await page.locator('#self-custody-warning').isVisible(), true);
        const bodyText = await page.locator('body').innerText();
        assert.ok(bodyText.includes('apexhive.hq@proton.me'), 'Support email must be visible');
        assert.ok(bodyText.includes('MIT'), 'MIT Open-Source copy must be visible');
        assert.ok(bodyText.includes('$10,000'), 'Free $10k Hosted API quota must be visible');
        assert.ok(bodyText.includes('Open-Core Pricing'), 'Clean Open-Core Pricing heading required');
        assert.equal(bodyText.includes('Zero Personal Code Paywalls'), false);
        assert.equal(bodyText.includes('steady forever'), false);

        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth > window.innerWidth
        );
        assert.equal(overflow, false, `Horizontal overflow at ${vp.name} (${vp.width}px)`);

        if (vp.name === 'desktop') {
          // Test Live Quota Checker widget
          await page.fill('#quota-address-input', merchantAcct.address);
          await page.click('#check-quota-btn');
          await page.waitForSelector('#quota-result:not([hidden])');
          const quotaText = await page.locator('#quota-result').textContent();
          assert.ok(quotaText?.includes('10,010.00 USDC'), `Expected GMV 10,010.00 USDC, got: ${quotaText}`);

          // Test 1-click wallet pay button labels (5 USDC supporter -> 49 USDC team -> 5 USDC supporter)
          assert.equal((await page.locator('#wallet-pay-btn').textContent())?.trim(), 'Pay 5 USDC with Wallet');
          await page.selectOption('#tier-select', 'team');
          assert.equal((await page.locator('#wallet-pay-btn').textContent())?.trim(), 'Pay 49 USDC with Wallet');
          await page.selectOption('#tier-select', 'supporter');
          assert.equal((await page.locator('#wallet-pay-btn').textContent())?.trim(), 'Pay 5 USDC with Wallet');

          await page.click('#wallet-pay-btn');
          await page.waitForFunction(
            (expectedHash) => document.querySelector('#tx-hash-input')?.value === expectedHash,
            TX_WALLET_SUPPORTER
          );

          const walletCalls = await page.evaluate(() => window.__walletCalls);
          const sendTxCall = walletCalls.find((c) => c.method === 'eth_sendTransaction');
          assert.ok(sendTxCall, 'Expected eth_sendTransaction call from #wallet-pay-btn');
          const txParam = sendTxCall.params[0];
          assert.equal(txParam.to.toLowerCase(), BASE_USDC.toLowerCase());
          const expectedDataPrefix =
            '0xa9059cbb' + PAY_TO.toLowerCase().replace('0x', '').padStart(64, '0');
          const expectedAmountHex = (5_000_000n).toString(16).padStart(64, '0');
          assert.equal(txParam.data.toLowerCase(), expectedDataPrefix + expectedAmountHex);

          await page.click('#challenge-btn');
          await page.waitForSelector('#challenge-box:not([hidden])');
          const msgText = await page.inputValue('#challenge-text');
          const sigSup = await payerAcct.signMessage({ message: msgText });
          await page.fill('#signature-input', sigSup);
          await page.click('#verify-btn');
          await page.waitForSelector('#license-result:not([hidden])');
          const dlHref = await page.locator('#download-link').getAttribute('href');
          assert.ok(dlHref?.startsWith('/api/download?token='));
          const tokText = await page.locator('#raw-token').textContent();
          assert.ok(tokText?.startsWith('ZEROFIAT-KIT-v1.'));
        }

        assert.deepEqual(consoleErrors, [], `Console errors at ${vp.name}: ${consoleErrors.join('; ')}`);
        assert.deepEqual(pageErrors, [], `Page errors at ${vp.name}: ${pageErrors.join('; ')}`);
        await context.close();
      }
    } finally {
      await browser.close();
    }
  } finally {
    if (process.platform === 'win32' && wranglerProc.pid) {
      try {
        execSync(`taskkill /pid ${wranglerProc.pid} /T /F`, { stdio: 'ignore' });
      } catch {
        // Already exited
      }
    } else {
      wranglerProc.kill('SIGTERM');
    }
    await new Promise((r) => setTimeout(r, 600));
    rpcServer.close();
    releaseServer.close();
    if (existsSync(devVarsPath)) rmSync(devVarsPath, { force: true });
    if (existsSync(wranglerStateDir)) rmSync(wranglerStateDir, { recursive: true, force: true });
  }
});
