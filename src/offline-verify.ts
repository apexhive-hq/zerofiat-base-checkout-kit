import type { LicensePayload } from './types.ts';

function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  const bin = atob(b64.trim());
  const buf = new ArrayBuffer(bin.length);
  const out = new Uint8Array(buf);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
}

function base64UrlDecode(b64url: string): Uint8Array<ArrayBuffer> {
  const padded =
    b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  return base64ToBytes(padded);
}

function utf8Bytes(str: string): Uint8Array<ArrayBuffer> {
  const encoded = new TextEncoder().encode(str);
  const out = new Uint8Array(new ArrayBuffer(encoded.byteLength));
  out.set(encoded);
  return out;
}

/**
 * Portable WebCrypto Ed25519 offline receipt/attestation verifier
 * (works in Cloudflare Workers, Node >=20, and browsers).
 */
export async function verifyLicenseTokenOffline(
  token: string,
  options: {
    publicKeySpkiB64: string;
    expectedPrefix: string;
    expectedProduct: string;
    nowMs?: number;
  }
): Promise<{ valid: boolean; reason?: string; payload?: LicensePayload }> {
  const trimmed = token.trim();
  if (!trimmed.startsWith(options.expectedPrefix)) {
    return { valid: false, reason: 'Invalid certificate token prefix.' };
  }

  const parts = trimmed.slice(options.expectedPrefix.length).split('.');
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return { valid: false, reason: 'Malformed token structure.' };
  }

  const [payloadB64Url, sigB64Url] = parts;

  try {
    const spkiBytes = base64ToBytes(options.publicKeySpkiB64);
    const key = await crypto.subtle.importKey(
      'spki',
      spkiBytes,
      { name: 'Ed25519' },
      false,
      ['verify']
    );

    const signingInput = utf8Bytes(`${options.expectedPrefix}${payloadB64Url}`);
    const sigBytes = base64UrlDecode(sigB64Url);
    const sigOk = await crypto.subtle.verify('Ed25519', key, sigBytes, signingInput);
    if (!sigOk) {
      return { valid: false, reason: 'Invalid Ed25519 signature.' };
    }

    const payload = JSON.parse(
      new TextDecoder().decode(base64UrlDecode(payloadB64Url))
    ) as LicensePayload;

    if (
      payload.v !== 1 ||
      payload.product !== options.expectedProduct ||
      payload.tier !== 'standard' ||
      !/^0x[0-9a-fA-F]{40}$/.test(payload.payer) ||
      !/^0x[0-9a-fA-F]{64}$/.test(payload.txHash)
    ) {
      return { valid: false, reason: 'Invalid certificate payload fields.' };
    }

    const now = options.nowMs ?? Date.now();
    if (payload.expiresAt !== null && now > payload.expiresAt) {
      return { valid: false, reason: 'Certificate token expired.', payload };
    }

    return { valid: true, payload };
  } catch (err) {
    return {
      valid: false,
      reason: err instanceof Error ? err.message : 'Verification failed.'
    };
  }
}
