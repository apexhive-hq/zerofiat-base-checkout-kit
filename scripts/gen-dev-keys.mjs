import { generateKeyPairSync } from 'node:crypto';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const privateJwk = privateKey.export({ format: 'jwk' });
const publicSpkiB64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

console.log(
  JSON.stringify(
    {
      LICENSE_SIGNING_PRIVATE_JWK: JSON.stringify(privateJwk),
      LICENSE_SIGNING_PUBLIC_SPKI_B64: publicSpkiB64
    },
    null,
    2
  )
);
