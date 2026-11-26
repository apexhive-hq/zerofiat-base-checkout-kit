import assert from 'node:assert/strict';
import { execSync, spawn } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { existsSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { encodeAbiParameters, pad } from 'viem';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { verifyLicenseTokenOffline } from '../src/offline-verify.ts';

const KIT_DIR = process.cwd();
const HOSTED_TOKEN = 'hosted-e2e-secret-token-0123456789abcdef';

const PAY_TO = '0x1111111111111111111111111111111111111111';
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const WRONG_USDC = '0x9999999999999999999999999999999999999999';
const WRONG_RECIPIENT = '0x8888888888888888888888888888888888888888';
const TRANSFER_TOPIC =
  '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const BOOL_TRUE_HEX = '0x' + '0'.repeat(63) + '1';
const BOOL_FALSE_HEX = '0x' + '0'.repeat(64);

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

function resolveWranglerLaunch() {
  const localJs = join(KIT_DIR, 'node_modules', 'wrangler', 'bin', 'wrangler.js');
  if (existsSync(localJs)) {
    return { command: process.execPath, prefixArgs: [localJs], shell: false };
  }
  const localWin = join(KIT_DIR, 'node_modules', '.bin', 'wrangler.cmd');
  const localPosix = join(KIT_DIR, 'node_modules', '.bin', 'wrangler');
  if (process.platform === 'win32' && existsSync(localWin)) {
    return { command: localWin, prefixArgs: [], shell: true };
  }
  if (process.platform !== 'win32' && existsSync(localPosix)) {
    return { command: localPosix, prefixArgs: [], shell: false };
  }
  return {
    command: process.platform === 'win32' ? 'wrangler.cmd' : 'wrangler',
    prefixArgs: [],
    shell: process.platform === 'win32'
  };
}

test('zerofiat-base-checkout-kit v2.1 Free MIT + ERC-1271 Smart Wallet + Durable Object Lock + Playwright UI', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const payerAcct = privateKeyToAccount(generatePrivateKey());
  const attackerAcct = privateKeyToAccount(generatePrivateKey());
  const merchantAcct = privateKeyToAccount(generatePrivateKey());
  const otherMerchantAcct = privateKeyToAccount(generatePrivateKey());
  const smartWalletAddr = '0x7777777777777777777777777777777777777777';
  const SMART_WALLET_SIG_VALID = '0x' + 'ab'.repeat(256);
  const SMART_WALLET_SIG_INVALID = '0x' + 'cd'.repeat(180);

  const TX_STANDARD = '0x' + 'aa'.repeat(32);
  const TX_SMART_WALLET = '0x' + 'bb'.repeat(32);
  const TX_UNDERPAY = '0x' + 'cc'.repeat(32);
  const TX_WRONG_RECIPIENT = '0x' + 'dd'.repeat(32);
  const TX_WRONG_TOKEN = '0x' + 'ee'.repeat(32);
  const TX_REVERTED = '0x' + 'ff'.repeat(32);
  const TX_CONFS = '0x' + '12'.repeat(32);
  const TX_WALLET_DEMO = '0x' + '56'.repeat(32);
  const TX_HOSTED_6K = '0x' + '78'.repeat(32);
  const TX_HOSTED_6K_TWO = '0x' + '9a'.repeat(32);

  let headBlockHex = '0x65';
  let flakyHits = 0;
  let okHits = 0;

  const receipts = new Map([
    [
      TX_STANDARD,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 1_000_000n)]
      }
    ],
    [
      TX_SMART_WALLET,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: smartWalletAddr,
        logs: [makeTransferLog(BASE_USDC, smartWalletAddr, PAY_TO, 1_000_000n)]
      }
    ],
    [
      TX_UNDERPAY,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 990_000n)]
      }
    ],
    [
      TX_WRONG_RECIPIENT,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, WRONG_RECIPIENT, 1_000_000n)]
      }
    ],
    [
      TX_WRONG_TOKEN,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(WRONG_USDC, payerAcct.address, PAY_TO, 1_000_000n)]
      }
    ],
    [
      TX_REVERTED,
      {
        status: '0x0',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 1_000_000n)]
      }
    ],
    [
      TX_CONFS,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 1_000_000n)]
      }
    ],
    [
      TX_WALLET_DEMO,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, PAY_TO, 1_000_000n)]
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
      TX_HOSTED_6K_TWO,
      {
        status: '0x1',
        blockNumber: '0x64',
        from: payerAcct.address,
        logs: [makeTransferLog(BASE_USDC, payerAcct.address, merchantAcct.address, 6_000_000_000n)]
      }
    ]
  ]);

  // 1. Mock Base JSON-RPC server (ephemeral port) supporting /flaky failover + ERC-1271/EIP-6492 eth_call
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
        if (call.method === 'eth_call') {
          const callData = String(call.params?.[0]?.data ?? '').toLowerCase();
          const validMarker = 'ab'.repeat(256);
          return {
            jsonrpc: '2.0',
            id: call.id,
            result: callData.includes(validMarker) ? BOOL_TRUE_HEX : BOOL_FALSE_HEX
          };
        }
        return { jsonrpc: '2.0', id: call.id, error: { code: -32601, message: 'Method not found' } };
      });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(Array.isArray(parsed) ? replies : replies[0]));
    });
  });

  // 2. Mock Archive server (ephemeral port)
  const mockZipBytes = Buffer.from('PK\x03\x04zerofiat-base-checkout-kit-v2.1.0-verified-payload');
  const expectedZipSha256 = createHash('sha256').update(mockZipBytes).digest('hex');
  const releaseServer = createServer((_req, res) => {
    res.writeHead(200, {
      'content-type': 'application/zip',
      'content-length': String(mockZipBytes.length)
    });
    res.end(mockZipBytes);
  });

  await new Promise((r) => rpcServer.listen(0, '127.0.0.1', r));
  await new Promise((r) => releaseServer.listen(0, '127.0.0.1', r));
  const rpcPort = rpcServer.address().port;
  const releasePort = releaseServer.address().port;

  // 3. Boot Wrangler local dev using local node_modules/.bin/wrangler
  const wranglerPort = 4120;
  const baseUrl = `http://127.0.0.1:${wranglerPort}`;
  const wranglerStateDir = join(KIT_DIR, '.wrangler-state');
  const devVarsPath = join(KIT_DIR, '.dev.vars');

  if (existsSync(wranglerStateDir)) rmSync(wranglerStateDir, { recursive: true, force: true });
  writeFileSync(
    devVarsPath,
    [
      `PAY_TO_EVM_ADDRESS=${PAY_TO}`,
      `HOSTED_API_TOKEN=${HOSTED_TOKEN}`,
      `LICENSE_SIGNING_PRIVATE_JWK=${JSON.stringify(privateJwk)}`,
      `LICENSE_SIGNING_PUBLIC_SPKI_B64=${publicSpkiB64}`,
      `DOWNLOAD_HMAC_SECRET=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789`,
      `PUBLIC_ARCHIVE_URL=http://127.0.0.1:${releasePort}/main.zip`,
      `BASE_RPC_URLS=http://127.0.0.1:${rpcPort}/flaky,http://127.0.0.1:${rpcPort}/ok`,
      `BASE_RPC_URL=http://127.0.0.1:${rpcPort}/flaky`,
      `MIN_CONFIRMATIONS=2`
    ].join('\n'),
    'utf8'
  );

  const wranglerLaunch = resolveWranglerLaunch();
  const wranglerEnv = {
    ...process.env,
    WRANGLER_SEND_METRICS: 'false'
  };
  if (process.env.WRANGLER_CACHE_DIR) {
    wranglerEnv.APPDATA = join(process.env.WRANGLER_CACHE_DIR, 'roaming');
    wranglerEnv.LOCALAPPDATA = join(process.env.WRANGLER_CACHE_DIR, 'local');
    wranglerEnv.XDG_CONFIG_HOME = join(process.env.WRANGLER_CACHE_DIR, 'xdg');
  }

  const wranglerProc = spawn(
    wranglerLaunch.command,
    [
      ...wranglerLaunch.prefixArgs,
      'dev',
      '--local',
      '--port',
      String(wranglerPort),
      '--ip',
      '127.0.0.1',
      '--persist-to',
      '.wrangler-state'
    ],
    {
      cwd: KIT_DIR,
      shell: wranglerLaunch.shell,
      env: wranglerEnv,
      stdio: ['ignore', 'pipe', 'pipe']
    }
  );
  const wranglerLogs = [];
  const pushLog = (chunk) => {
    wranglerLogs.push(String(chunk));
    if (wranglerLogs.length > 40) wranglerLogs.shift();
  };
  wranglerProc.stdout?.on('data', pushLog);
  wranglerProc.stderr?.on('data', pushLog);

  try {
    try {
      await waitForServer(`${baseUrl}/api/health`);
    } catch (err) {
      throw new Error(`${err.message}\nWrangler logs:\n${wranglerLogs.join('')}`);
    }

    // 4. Health, Config & Strict Security Header checks
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.headers.get('x-frame-options'), 'DENY');
    assert.equal(healthRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(healthRes.headers.get('referrer-policy'), 'no-referrer');
    assert.ok(healthRes.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"));

    const healthJson = await healthRes.json();
    assert.equal(healthJson.durableObjectLockBound, true);
    assert.equal(healthJson.unlimitedFreeMit, true);
    assert.deepEqual(healthJson.smartWalletSupport, ['EOA', 'ERC-1271', 'EIP-6492']);

    const cfgJson = await (await fetch(`${baseUrl}/api/config`)).json();
    assert.equal(cfgJson.openSourceLicense, 'MIT');
    assert.equal(cfgJson.unlimitedFreeMit, true);
    assert.equal(cfgJson.supportEmail, 'apexhive.hq@proton.me');
    assert.equal(cfgJson.checkoutDemo.atomic, '1000000');

    // Cross-origin disallowed POST rejected by CORS / ALLOWED_ORIGINS policy
    const crossOriginPost = await fetch(`${baseUrl}/api/challenge`, {
      method: 'POST',
      headers: {
        Origin: 'https://evil.example',
        'content-type': 'application/json'
      },
      body: JSON.stringify({ txHash: TX_STANDARD, tier: 'standard' })
    });
    assert.equal(crossOriginPost.status, 403);
    assert.equal(crossOriginPost.headers.get('access-control-allow-origin'), null);

    async function issueChallenge(txHash, tier = 'standard') {
      const res = await fetch(`${baseUrl}/api/challenge`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier })
      });
      assert.equal(res.status, 200);
      return await res.json();
    }

    // 4a. Confirmation check retains challenge nonce across 1-conf failure -> 2-conf retry
    headBlockHex = '0x64';
    const chConf = await issueChallenge(TX_CONFS);
    const sigConf = await payerAcct.signMessage({ message: chConf.message });
    const vConfLow = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_CONFS, nonce: chConf.nonce, signature: sigConf, tier: 'standard' })
    });
    assert.equal(vConfLow.status, 403);
    assert.equal((await vConfLow.json()).error, 'INSUFFICIENT_CONFIRMATIONS');

    headBlockHex = '0x65';
    const vConfOk = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_CONFS, nonce: chConf.nonce, signature: sigConf, tier: 'standard' })
    });
    assert.equal(vConfOk.status, 200);
    const confOkJson = await vConfOk.json();
    assert.equal(confOkJson.reclaimed, false);
    assert.equal(
      (await verifyLicenseTokenOffline(confOkJson.licenseToken, {
        publicKeySpkiB64: publicSpkiB64,
        expectedPrefix: 'ZEROFIAT-KIT-v1.',
        expectedProduct: 'zerofiat-base-checkout-kit'
      })).valid,
      true
    );

    assert.ok(flakyHits >= 2, `Expected >=2 /flaky failover probes, got ${flakyHits}`);
    assert.ok(okHits >= 2, `Expected >=2 /ok RPC completions, got ${okHits}`);

    // 4b. ERC-1271 / EIP-6492 Smart Wallet variable-length signature (>130 hex) in real wrangler dev
    const chSmartBad = await issueChallenge(TX_SMART_WALLET);
    const vSmartBad = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: TX_SMART_WALLET,
        nonce: chSmartBad.nonce,
        signature: SMART_WALLET_SIG_INVALID,
        tier: 'standard'
      })
    });
    assert.equal(vSmartBad.status, 403);
    assert.equal((await vSmartBad.json()).error, 'PAYMENT_OR_SIGNATURE_INVALID');

    const chSmartOk = await issueChallenge(TX_SMART_WALLET);
    const vSmartOk = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: TX_SMART_WALLET,
        nonce: chSmartOk.nonce,
        signature: SMART_WALLET_SIG_VALID,
        tier: 'standard'
      })
    });
    assert.equal(vSmartOk.status, 200);
    const smartOkJson = await vSmartOk.json();
    assert.equal(smartOkJson.payer, smartWalletAddr);

    // 4c. Real Durable Object TxClaimLockDO atomic race test (5 parallel /api/hosted/verify requests)
    //     Unauthenticated consumeOnce: true blocked (403 HOSTED_AUTH_REQUIRED)
    const griefBlocked = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: TX_HOSTED_6K,
        merchantAddress: merchantAcct.address,
        minAmountAtomic: '6000000000'
      })
    });
    assert.equal(griefBlocked.status, 403);
    assert.equal((await griefBlocked.json()).error, 'HOSTED_AUTH_REQUIRED');

    //     Strict single-use default with HOSTED_API_TOKEN: 1 x 200 consumed, 4 x 409 TX_ALREADY_CLAIMED, GMV counted once
    const concurrentHosted = await Promise.all(
      Array.from({ length: 5 }, () =>
        fetch(`${baseUrl}/api/hosted/verify`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            Authorization: `Bearer ${HOSTED_TOKEN}`
          },
          body: JSON.stringify({
            txHash: TX_HOSTED_6K,
            merchantAddress: merchantAcct.address,
            minAmountAtomic: '6000000000'
          })
        })
      )
    );
    const concurrentBodies = await Promise.all(concurrentHosted.map((r) => r.json()));
    assert.equal(concurrentHosted.filter((r) => r.status === 200).length, 1);
    assert.equal(concurrentHosted.filter((r) => r.status === 409).length, 4);
    assert.equal(concurrentBodies.filter((b) => b.ok === true && b.cached === false && b.consumed === true).length, 1);
    assert.equal(concurrentBodies.filter((b) => b.ok === false && b.error === 'TX_ALREADY_CLAIMED').length, 4);

    // Explicit consumeOnce: false returns cached=true without re-counting GMV
    const hostedCached = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        txHash: TX_HOSTED_6K,
        merchantAddress: merchantAcct.address,
        minAmountAtomic: '6000000000',
        consumeOnce: false
      })
    });
    assert.equal(hostedCached.status, 200);
    assert.equal((await hostedCached.json()).cached, true);

    const quota1 = await (await fetch(`${baseUrl}/api/hosted/quota/${merchantAcct.address}`)).json();
    assert.equal(quota1.gmvAtomic, '6000000000');

    // Different merchant claiming TX_HOSTED_6K -> 403 PAYMENT_NOT_FOUND
    const h6kCross = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${HOSTED_TOKEN}`
      },
      body: JSON.stringify({ txHash: TX_HOSTED_6K, merchantAddress: otherMerchantAcct.address })
    });
    assert.equal(h6kCross.status, 403);

    // Unauthenticated /api/hosted/verify targeting host PAY_TO_EVM_ADDRESS is blocked (403)
    const hHostUnauth = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_STANDARD, merchantAddress: PAY_TO, minAmountAtomic: '1000000' })
    });
    assert.equal(hHostUnauth.status, 403);
    assert.equal((await hHostUnauth.json()).error, 'HOST_MERCHANT_SIGNATURE_REQUIRED');

    // Unlimited GMV accumulation in atomic DO state -> 200 OK
    const h6kTwo = await fetch(`${baseUrl}/api/hosted/verify`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        Authorization: `Bearer ${HOSTED_TOKEN}`
      },
      body: JSON.stringify({ txHash: TX_HOSTED_6K_TWO, merchantAddress: merchantAcct.address })
    });
    assert.equal(h6kTwo.status, 200);
    const h6kTwoJson = await h6kTwo.json();
    assert.equal(h6kTwoJson.mode, 'free_mit');
    assert.equal(h6kTwoJson.gmvAtomic, '12000000000');

    // 4d. Standard checkout claim + 3-download cap + same-payer re-claim + attacker block
    const chStd = await issueChallenge(TX_STANDARD);
    const sigStd = await payerAcct.signMessage({ message: chStd.message });
    const vStd = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_STANDARD, nonce: chStd.nonce, signature: sigStd, tier: 'standard' })
    });
    assert.equal(vStd.status, 200);
    const stdJson = await vStd.json();

    // Concurrent 5x GET /api/download on 3-download DO grant -> strictly 3 x 200, 2 x 403
    const dlBatch = await Promise.all(
      Array.from({ length: 5 }, () => fetch(`${baseUrl}${stdJson.downloadUrl}`))
    );
    assert.equal(dlBatch.filter((r) => r.status === 200).length, 3);
    assert.equal(dlBatch.filter((r) => r.status === 403).length, 2);
    for (const r of dlBatch) {
      if (r.status === 200) {
        const buf = Buffer.from(await r.arrayBuffer());
        assert.equal(createHash('sha256').update(buf).digest('hex'), expectedZipSha256);
      }
    }

    const chReclaim = await issueChallenge(TX_STANDARD);
    const sigReclaim = await payerAcct.signMessage({ message: chReclaim.message });
    const vReclaim = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_STANDARD, nonce: chReclaim.nonce, signature: sigReclaim, tier: 'standard' })
    });
    assert.equal(vReclaim.status, 200);
    const reclaimJson = await vReclaim.json();
    assert.equal(reclaimJson.reclaimed, true);

    const chAttacker = await issueChallenge(TX_STANDARD);
    const sigAttacker = await attackerAcct.signMessage({ message: chAttacker.message });
    const vAttacker = await fetch(`${baseUrl}/api/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ txHash: TX_STANDARD, nonce: chAttacker.nonce, signature: sigAttacker, tier: 'standard' })
    });
    assert.equal(vAttacker.status, 403);

    // 4e. Negative guards
    for (const [tx, signer] of [
      [TX_UNDERPAY, payerAcct],
      [TX_WRONG_RECIPIENT, payerAcct],
      [TX_WRONG_TOKEN, payerAcct],
      [TX_REVERTED, payerAcct],
      [TX_WALLET_DEMO, attackerAcct]
    ]) {
      const chNeg = await issueChallenge(tx);
      const sigNeg = await signer.signMessage({ message: chNeg.message });
      const vNeg = await fetch(`${baseUrl}/api/verify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash: tx, nonce: chNeg.nonce, signature: sigNeg, tier: 'standard' })
      });
      assert.equal(vNeg.status, 403);
    }

    // 5. Playwright Headless UI verification
    const { chromium } = await import('playwright');
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
          { payerAddr: payerAcct.address, mockTxHash: TX_WALLET_DEMO }
        );

        await page.goto(baseUrl, { waitUntil: 'networkidle' });
        assert.equal((await page.locator('#pay-to-address').textContent())?.trim(), PAY_TO);
        assert.equal(await page.locator('#self-custody-warning').isVisible(), true);
        const bodyText = await page.locator('body').innerText();
        assert.ok(bodyText.includes('apexhive.hq@proton.me'));
        assert.ok(bodyText.includes('MIT'));
        assert.ok(bodyText.includes('ERC-1271'));
        assert.ok(bodyText.includes('Durable Object'));
        assert.equal(bodyText.includes('$10k'), false);
        assert.equal(bodyText.includes('gmvAtomic: "0"'), false);

        const overflow = await page.evaluate(
          () => document.documentElement.scrollWidth > window.innerWidth
        );
        assert.equal(overflow, false, `Horizontal overflow at ${vp.name} (${vp.width}px)`);

        if (vp.name === 'desktop') {
          await page.fill('#quota-address-input', merchantAcct.address);
          await page.click('#check-quota-btn');
          await page.waitForSelector('#quota-result:not([hidden])');
          const quotaText = await page.locator('#quota-result').textContent();
          assert.ok(quotaText?.includes('12,000.00 USDC'), `Expected GMV 12,000.00 USDC, got: ${quotaText}`);

          assert.equal((await page.locator('#wallet-pay-btn').textContent())?.trim(), 'Pay 1 USDC with Wallet');
          await page.click('#wallet-pay-btn');
          await page.waitForFunction(
            (expectedHash) => document.querySelector('#tx-hash-input')?.value === expectedHash,
            TX_WALLET_DEMO
          );

          await page.click('#challenge-btn');
          await page.waitForSelector('#challenge-box:not([hidden])');
          const msgText = await page.inputValue('#challenge-text');
          const sigDemo = await payerAcct.signMessage({ message: msgText });
          await page.fill('#signature-input', sigDemo);
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
    await new Promise((r) => setTimeout(r, 900));
    rpcServer.close();
    releaseServer.close();
    if (existsSync(devVarsPath)) {
      try {
        rmSync(devVarsPath, { force: true });
      } catch {
        // ignore Windows handle release delay
      }
    }
    if (existsSync(wranglerStateDir)) {
      try {
        rmSync(wranglerStateDir, { recursive: true, force: true, maxRetries: 15, retryDelay: 250 });
      } catch {
        // ignore Windows SQLite DO handle release delay
      }
    }
  }
});
