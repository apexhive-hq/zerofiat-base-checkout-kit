(function () {
  const tierSelect = document.getElementById('tier-select');
  const payToEl = document.getElementById('pay-to-address');
  const usdcEl = document.getElementById('usdc-contract');
  const warningEl = document.getElementById('self-custody-warning');
  const copyBtn = document.getElementById('copy-address-btn');
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

  let activeNonce = '';

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

  loadConfig();
})();
