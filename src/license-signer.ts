import type { LicensePayload } from './types.ts';

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export async function signEd25519License(input: {
  privateJwkJson: string;
  tokenPrefix: string;
  payload: LicensePayload;
}): Promise<string> {
  const jwk = JSON.parse(input.privateJwkJson) as JsonWebKey;
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    false,
    ['sign']
  );

  const payloadBytes = new TextEncoder().encode(JSON.stringify(input.payload));
  const payloadB64Url = base64UrlEncode(payloadBytes);
  const signingInput = new TextEncoder().encode(`${input.tokenPrefix}${payloadB64Url}`);
  const sigBuf = await crypto.subtle.sign('Ed25519', key, signingInput);
  const sigB64Url = base64UrlEncode(new Uint8Array(sigBuf));

  return `${input.tokenPrefix}${payloadB64Url}.${sigB64Url}`;
}
