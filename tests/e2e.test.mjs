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

async function waitForServer(url, timeoutMs = 30000) {
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

test('zerofiat-base-checkout-kit Workers KV E2E + GH Release proxy + Playwright 375px/1440px UI', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const payerAcct = privateKeyToAccount(generatePrivateKey());
  const attackerAcct = privateKeyToAccount(generatePrivateKey());

  const TX_SOLO = '0x' + '1a'.repeat(32);
  const TX_TEAM = '0x' + '2b'.repeat(32);
  const TX_UNDERPAY = '0x' + '3c'.repeat(32);
  const TX_WRONG_RECIPIENT = '0x' + '4d'.repeat(32);
  const TX_WRONG_TOKEN = '0x' + '5e'.repeat(32);
  const TX_REVERTED = '0x' + '6f'.repeat(32);

  const receipts = new Map([
    [
      TX_SOLO,
      {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 29_000_000n)]
      }
    ],
    [
      TX_TEAM,
      {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 59_000_000n)]
      }
    ],
    [
      TX_UNDERPAY,
      {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 28_990_000n)]
      }
    ],
    [
      TX_WRONG_RECIPIENT,
      {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, WRONG_RECIPIENT, 29_000_000n)]
      }
    ],
    [
      TX_WRONG_TOKEN,
      {
        status: '0x1',
        blockNumber: '0x64',
        logs: [makeTransferLog(WRONG_USDC, payerAcct.address, PAY_TO, 29_000_000n)]
      }
    ],
    [
      TX_REVERTED,
      {
        status: '0x0',
        blockNumber: '0x64',
        logs: []
      }
    ]
  ]);

  // 1. Mock Base JSON-RPC on 127.0.0.1:4121
  const rpcServer = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => {
      raw += c;
    });
    req.on('end', () => {
      const payload = JSON.parse(raw);
      res.setHeader('content-type', 'application/json');
      if (payload.method === 'eth_blockNumber') {
        res.end(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result: '0x68' }));
        return;
      }
      if (payload.method === 'eth_getTransactionReceipt') {
        const hash = String(payload.params?.[0] ?? '').toLowerCase();
        res.end(
          JSON.stringify({
            jsonrpc: '2.0',
            id: payload.id,
            result: receipts.get(hash) ?? null
          })
        );
        return;
      }
      res.end(JSON.stringify({ jsonrpc: '2.0', id: payload.id, result: null }));
    });
  });

  // 2. Mock Private GitHub Release server on 127.0.0.1:4122
  const syntheticZipBytes = Buffer.from('PK\x03\x04ZEROFIAT-BASE-CHECKOUT-KIT-V1-ARCHIVE-TEST', 'utf8');
  const expectedSha256 = createHash('sha256').update(syntheticZipBytes).digest('hex');
  const EXPECTED_MOCK_PAT = 'ghp_mock_test_token_for_local_qa_only';

  const releaseServer = createServer((req, res) => {
    if (req.headers.authorization !== `Bearer ${EXPECTED_MOCK_PAT}`) {
      res.writeHead(401);
      res.end('Unauthorized');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/octet-stream' });
    res.end(syntheticZipBytes);
  });

  await Promise.all([
    new Promise((r) => rpcServer.listen(4121, '127.0.0.1', r)),
    new Promise((r) => releaseServer.listen(4122, '127.0.0.1', r))
  ]);

  const devVarsPath = join(KIT_DIR, '.dev.vars');
  const wranglerStateDir = join(KIT_DIR, '.wrangler-state');
  writeFileSync(
    devVarsPath,
    [
      `LICENSE_SIGNING_PRIVATE_JWK=${JSON.stringify(privateJwk)}`,
      `LICENSE_SIGNING_PUBLIC_SPKI_B64=${publicSpkiB64}`,
      `GITHUB_RELEASE_READ_TOKEN=${EXPECTED_MOCK_PAT}`
    ].join('\n'),
    'utf8'
  );

  const wranglerEnv = {
    ...process.env,
    APPDATA: join(CACHES_DIR, 'appdata'),
    LOCALAPPDATA: join(CACHES_DIR, 'localappdata'),
    XDG_CONFIG_HOME: join(CACHES_DIR, 'xdg-config'),
    PLAYWRIGHT_BROWSERS_PATH: join(CACHES_DIR, 'ms-playwright'),
    WRANGLER_SEND_METRICS: 'false'
  };

  let wranglerLogs = '';
  const wranglerProc = spawn(
    'wrangler.cmd',
    [
      'dev',
      '--local',
      '--ip',
      '127.0.0.1',
      '--port',
      '4120',
      '--persist-to',
      '.wrangler-state',
      '--var',
      'BASE_RPC_URL:http://127.0.0.1:4121',
      '--var',
      'MIN_CONFIRMATIONS:1',
      '--var',
      'GITHUB_RELEASE_ASSET_URL:http://127.0.0.1:4122/asset.zip'
    ],
    {
      cwd: KIT_DIR,
      env: wranglerEnv,
      shell: true,
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  wranglerProc.stdout?.on('data', (d) => {
    wranglerLogs += d.toString();
  });
  wranglerProc.stderr?.on('data', (d) => {
    wranglerLogs += d.toString();
  });

  try {
    const baseUrl = 'http://127.0.0.1:4120';
    try {
      await waitForServer(`${baseUrl}/api/health`, 30000);
    } catch (err) {
      throw new Error(`${err.message}\n--- WRANGLER LOGS ---\n${wranglerLogs}`);
    }

    // Config assertions
    const cfgRes = await fetch(`${baseUrl}/api/config`);
    assert.equal(cfgRes.status, 200);
    const cfg = await cfgRes.json();
    assert.equal(cfg.payToAddress, PAY_TO);
    assert.equal(cfg.tiers.solo.atomic, '29000000');
    assert.equal(cfg.tiers.team.atomic, '59000000');

    async function issueChallenge(txHash, tier = 'solo') {
      const r = await fetch(`${baseUrl}/api/challenge`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier })
      });
      assert.equal(r.status, 200);
      return r.json();
    }

    // 3. Valid 29 USDC Solo TX -> 200 license + Private GH Release .zip SHA-256 match
    const chSolo = await issueChallenge(TX_SOLO, 'solo');
    const sigSolo = await payerAcct.signMessage({ message: chSolo.message });
    const vSolo = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_SOLO, nonce: chSolo.nonce, signature: sigSolo, tier: 'solo' })
    });
    assert.equal(vSolo.status, 200);
    const vSoloJson = await vSolo.json();
    assert.equal(vSoloJson.ok, true);
    assert.ok(vSoloJson.licenseToken.startsWith('ZEROFIAT-KIT-v1.'));
    const offlineCheck = await verifyLicenseTokenOffline(vSoloJson.licenseToken, {
      publicKeySpkiB64: publicSpkiB64,
      expectedPrefix: 'ZEROFIAT-KIT-v1.',
      expectedProduct: 'zerofiat-base-checkout-kit'
    });
    assert.equal(offlineCheck.valid, true);
    assert.equal(offlineCheck.payload?.tier, 'solo');

    // Download asset and verify exact SHA-256 match + 3-download cap enforcement
    for (let i = 0; i < 3; i++) {
      const dl = await fetch(`${baseUrl}${vSoloJson.downloadUrl}`);
      assert.equal(dl.status, 200);
      const buf = Buffer.from(await dl.arrayBuffer());
      assert.equal(createHash('sha256').update(buf).digest('hex'), expectedSha256);
    }
    const dl4 = await fetch(`${baseUrl}${vSoloJson.downloadUrl}`);
    assert.equal(dl4.status, 403);

    // 4. Negative security checks -> all 403
    // 4a. Replay same TX
    const chRep = await issueChallenge(TX_SOLO, 'solo');
    const sigRep = await payerAcct.signMessage({ message: chRep.message });
    const vRep = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_SOLO, nonce: chRep.nonce, signature: sigRep, tier: 'solo' })
    });
    assert.equal(vRep.status, 403);
    assert.equal((await vRep.json()).error, 'TX_ALREADY_CLAIMED');

    // 4b. Consumed nonce
    const vConsumed = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_UNDERPAY, nonce: chSolo.nonce, signature: sigSolo, tier: 'solo' })
    });
    assert.equal(vConsumed.status, 403);

    // 4c. Underpay (28.99 USDC)
    const chUnder = await issueChallenge(TX_UNDERPAY, 'solo');
    const sigUnder = await payerAcct.signMessage({ message: chUnder.message });
    const vUnder = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_UNDERPAY, nonce: chUnder.nonce, signature: sigUnder, tier: 'solo' })
    });
    assert.equal(vUnder.status, 403);

    // 4d. Wrong recipient
    const chWrongRec = await issueChallenge(TX_WRONG_RECIPIENT, 'solo');
    const sigWrongRec = await payerAcct.signMessage({ message: chWrongRec.message });
    const vWrongRec = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_WRONG_RECIPIENT, nonce: chWrongRec.nonce, signature: sigWrongRec, tier: 'solo' })
    });
    assert.equal(vWrongRec.status, 403);

    // 4e. Wrong USDC token contract
    const chWrongTok = await issueChallenge(TX_WRONG_TOKEN, 'solo');
    const sigWrongTok = await payerAcct.signMessage({ message: chWrongTok.message });
    const vWrongTok = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_WRONG_TOKEN, nonce: chWrongTok.nonce, signature: sigWrongTok, tier: 'solo' })
    });
    assert.equal(vWrongTok.status, 403);

    // 4f. Reverted TX
    const chRev = await issueChallenge(TX_REVERTED, 'solo');
    const sigRev = await payerAcct.signMessage({ message: chRev.message });
    const vRev = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_REVERTED, nonce: chRev.nonce, signature: sigRev, tier: 'solo' })
    });
    assert.equal(vRev.status, 403);

    // 4g. Wrong EIP-191 signer hijacking TX_TEAM
    const chHijack = await issueChallenge(TX_TEAM, 'team');
    const sigHijack = await attackerAcct.signMessage({ message: chHijack.message });
    const vHijack = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_TEAM, nonce: chHijack.nonce, signature: sigHijack, tier: 'team' })
    });
    assert.equal(vHijack.status, 403);

    // 5. Playwright 1.64.1 Headless UI verification (1440x900 & 375x812)
    process.env.PLAYWRIGHT_BROWSERS_PATH = join(CACHES_DIR, 'ms-playwright');
    const browser = await chromium.launch({ headless: true });
    try {
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

        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        assert.equal((await page.locator('#pay-to-address').textContent())?.trim(), PAY_TO);
        assert.equal(await page.locator('#self-custody-warning').isVisible(), true);

        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth > window.innerWidth
        );
        assert.equal(overflow, false, `Horizontal overflow at ${vp.name} (${vp.width}px)`);

        if (vp.name === 'desktop') {
          await page.selectOption('#tier-select', 'team');
          await page.fill('#tx-hash-input', TX_TEAM);
          await page.click('#challenge-btn');
          await page.waitForSelector('#challenge-box:not([hidden])');
          const msgText = await page.inputValue('#challenge-text');
          const sigTeam = await payerAcct.signMessage({ message: msgText });
          await page.fill('#signature-input', sigTeam);
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
