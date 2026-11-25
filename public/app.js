(function () {
  const tierSelect = document.getElementById('tier-select');
  const payToEl = document.getElementById('pay-to-address');
  const usdcEl = document.getElementById('usdc-contract');
  const warningEl = document.getElementById('self-custody-warning');
  const copyBtn = document.getElementById('copy-address-btn');
  const walletPayBtn = document.getElementById('wallet-pay-btn');
  const walletPayStatus = document.getElementById('wallet-pay-status');
  const txInput = document.getElementById('tx-hash-input');
  const challengeBtn = document.getElementById('challenge-btn');
  const walletSignBtn = document.getElementById('wallet-sign-btn');
  const challengeBox = document.getElementById('challenge-box');
  const challengeText = document.getElementById('challenge-text');
  const challengeNonce = document.getElementById('challenge-nonce');
  const sigInput = document.getElementById('signature-input');
  const verifyForm = document.getElementById('verify-form');
  const errorBox = document.getElementById('status-error');
  const resultBox = document.getElementById('license-result');
  const downloadLinkEl = document.getElementById('download-link');
  const rawTokenEl = document.getElementById('raw-token');
  const quotaInput = document.getElementById('quota-address-input');
  const checkQuotaBtn = document.getElementById('check-quota-btn');
  const quotaResult = document.getElementById('quota-result');

  let activeNonce = '';
  let cachedTiers = {
    supporter: { usdc: '5', atomic: '5000000' },
    team: { usdc: '49', atomic: '49000000' }
  };

  function updateWalletPayLabel() {
    if (!walletPayBtn) return;
    const t = cachedTiers[tierSelect.value] || cachedTiers.supporter;
    walletPayBtn.textContent = `Pay ${t.usdc} USDC with Wallet`;
  }

  function revealWalletButtonsIfInjected() {
    if (typeof window.ethereum !== 'undefined') {
      if (walletPayBtn) {
        updateWalletPayLabel();
        walletPayBtn.hidden = false;
      }
      if (walletSignBtn) walletSignBtn.hidden = false;
    }
  }

  function encodeErc20Transfer(recipient, atomicAmount) {
    const cleanAddr = recipient.toLowerCase().replace(/^0x/, '').padStart(64, '0');
    const amountHex = BigInt(atomicAmount).toString(16).padStart(64, '0');
    return `0xa9059cbb${cleanAddr}${amountHex}`;
  }

  function formatAtomicUsdc(atomicStr) {
    const val = BigInt(atomicStr || '0');
    const whole = val / 1_000_000n;
    const cents = (val % 1_000_000n) / 10_000n;
    return `${whole.toLocaleString('en-US')}.${cents.toString().padStart(2, '0')} USDC`;
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
    resultBox.hidden = true;
  }

  function clearError() {
    errorBox.hidden = true;
    errorBox.textContent = '';
  }

  async function loadConfig() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) return;
      const cfg = await res.json();
      if (cfg.payToAddress) payToEl.textContent = cfg.payToAddress;
      if (cfg.usdcContract) usdcEl.textContent = cfg.usdcContract;
      if (cfg.tiers) {
        cachedTiers = cfg.tiers;
        updateWalletPayLabel();
      }
      if (cfg.selfCustodyWarning) warningEl.textContent = cfg.selfCustodyWarning;
      if (cfg.optionalRails) {
        const sol = document.getElementById('sol-address');
        const btc = document.getElementById('btc-address');
        const tron = document.getElementById('tron-address');
        if (sol && cfg.optionalRails.solanaUsdc) sol.textContent = cfg.optionalRails.solanaUsdc;
        if (btc && cfg.optionalRails.bitcoin) btc.textContent = cfg.optionalRails.bitcoin;
        if (tron && cfg.optionalRails.tronTrxUsdt) tron.textContent = cfg.optionalRails.tronTrxUsdt;
      }
    } catch {
      // Fallback defaults stay visible
    }
  }

  tierSelect.addEventListener('change', updateWalletPayLabel);

  if (checkQuotaBtn && quotaInput && quotaResult) {
    checkQuotaBtn.addEventListener('click', async () => {
      const addr = quotaInput.value.trim();
      if (!/^0x[0-9a-fA-F]{40}$/.test(addr)) {
        quotaResult.textContent = 'Enter a valid 0x-prefixed 40-hex EVM merchantAddress.';
        quotaResult.hidden = false;
        return;
      }
      try {
        const res = await fetch(`/api/hosted/quota/${encodeURIComponent(addr)}`);
        const data = await res.json();
        if (!res.ok) {
          quotaResult.textContent = data.message || data.error || 'Quota lookup failed.';
          quotaResult.hidden = false;
          return;
        }
        quotaResult.textContent =
          `Verified GMV: ${formatAtomicUsdc(data.gmvAtomic)} | Free Remaining: ${formatAtomicUsdc(data.freeRemainingAtomic)} of ${formatAtomicUsdc(data.freeQuotaAtomic)} | Pro Unlocked: ${data.proUnlocked ? 'Yes' : 'No'}`;
        quotaResult.hidden = false;
      } catch (err) {
        quotaResult.textContent = 'Network error checking quota: ' + (err.message || String(err));
        quotaResult.hidden = false;
      }
    });
  }

  if (walletPayBtn) {
    walletPayBtn.addEventListener('click', async () => {
      clearError();
      if (!window.ethereum) {
        showError('No browser wallet detected. Send Base USDC manually and paste your txHash.');
        return;
      }
      try {
        const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        const from = accounts[0];
        const chainId = await window.ethereum.request({ method: 'eth_chainId' });
        if (String(chainId).toLowerCase() !== '0x2105') {
          try {
            await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: '0x2105' }]
            });
          } catch (switchErr) {
            if (switchErr && switchErr.code === 4902) {
              await window.ethereum.request({
                method: 'wallet_addEthereumChain',
                params: [
                  {
                    chainId: '0x2105',
                    chainName: 'Base',
                    nativeCurrency: { name: 'Ether', symbol: 'ETH', decimals: 18 },
                    rpcUrls: ['https://mainnet.base.org'],
                    blockExplorerUrls: ['https://basescan.org']
                  }
                ]
              });
            } else {
              throw switchErr;
            }
          }
        }

        const t = cachedTiers[tierSelect.value] || cachedTiers.supporter;
        const payTo = payToEl.textContent.trim();
        const usdcAddr = usdcEl.textContent.trim();
        const data = encodeErc20Transfer(payTo, t.atomic);
        const txHash = await window.ethereum.request({
          method: 'eth_sendTransaction',
          params: [{ from, to: usdcAddr, data, value: '0x0' }]
        });
        txInput.value = txHash;
        if (walletPayStatus) {
          walletPayStatus.textContent = `Submitted ${txHash}. Wait for confirmations, then click "1. Generate EIP-191 Challenge".`;
          walletPayStatus.hidden = false;
        }
      } catch (err) {
        showError('Wallet payment failed: ' + (err.message || String(err)));
      }
    });
  }

  copyBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(payToEl.textContent.trim());
      copyBtn.textContent = 'Copied';
      setTimeout(() => {
        copyBtn.textContent = 'Copy';
      }, 1500);
    } catch {
      copyBtn.textContent = 'Copy manually';
    }
  });

  challengeBtn.addEventListener('click', async () => {
    clearError();
    const txHash = txInput.value.trim();
    const tier = tierSelect.value;
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) {
      showError('Enter a valid 0x-prefixed 64-character Base transaction hash first.');
      return;
    }

    try {
      const res = await fetch('/api/challenge', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, tier })
      });
      const data = await res.json();
      if (!res.ok) {
        showError(data.message || data.error || 'Failed to generate challenge.');
        return;
      }
      activeNonce = data.nonce;
      challengeNonce.textContent = data.nonce;
      challengeText.value = data.message;
      challengeBox.hidden = false;
      if (typeof window.ethereum !== 'undefined') {
        walletSignBtn.hidden = false;
      }
    } catch (err) {
      showError('Network error generating challenge: ' + (err.message || String(err)));
    }
  });

  walletSignBtn.addEventListener('click', async () => {
    clearError();
    if (!window.ethereum || !challengeText.value) return;
    try {
      const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
      const account = accounts[0];
      const signature = await window.ethereum.request({
        method: 'personal_sign',
        params: [challengeText.value, account]
      });
      sigInput.value = signature;
    } catch (err) {
      showError('Wallet signature rejected: ' + (err.message || String(err)));
    }
  });

  verifyForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    clearError();

    const txHash = txInput.value.trim();
    const signature = sigInput.value.trim();
    const tier = tierSelect.value;

    if (!activeNonce) {
      showError('Generate an EIP-191 challenge first.');
      return;
    }

    try {
      const res = await fetch('/api/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ txHash, nonce: activeNonce, signature, tier })
      });
      const data = await res.json();
      if (!res.ok) {
        showError((data.error ? data.error + ': ' : '') + (data.message || 'Verification failed.'));
        return;
      }
      downloadLinkEl.href = data.downloadUrl;
      rawTokenEl.textContent = data.licenseToken;
      resultBox.hidden = false;
    } catch (err) {
      showError('Network error verifying payment: ' + (err.message || String(err)));
    }
  });

  revealWalletButtonsIfInjected();
  loadConfig();
})();
