export type Tier = 'standard';

export interface TxClaimLockNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  };
}

export interface Env {
  ASSETS: Fetcher;
  TX_CLAIM_LOCK: TxClaimLockNamespace;
  BRAND_NAME: string;
  PRODUCT_ID: string;
  TOKEN_PREFIX: string;
  PAY_TO_EVM_ADDRESS: string;
  BASE_USDC_CONTRACT: string;
  BASE_CHAIN_ID: string;
  BASE_RPC_URL: string;
  BASE_RPC_URLS?: string;
  CHECKOUT_AMOUNT_USDC_ATOMIC?: string;
  MIN_CONFIRMATIONS: string;
  CHALLENGE_TTL_SECONDS: string;
  DOWNLOAD_TTL_SECONDS: string;
  PUBLIC_ARCHIVE_URL?: string;
  RELEASE_FILENAME: string;
  ALLOWED_ORIGINS?: string;
  ALLOW_UNAUTHENTICATED_HOSTED_PAY_TO?: string;
  HOSTED_API_TOKEN?: string;
  LICENSE_SIGNING_PRIVATE_JWK?: string;
  LICENSE_SIGNING_PUBLIC_SPKI_B64?: string;
  DOWNLOAD_HMAC_SECRET?: string;
}

export interface ChallengeRecord {
  nonce: string;
  scope?: 'checkout' | 'hosted';
  merchantAddress?: string;
  txHash: string;
  tier: Tier;
  ts: number;
  expiresAtMs?: number;
  message: string;
}

export interface DownloadGrantRecord {
  txHash: string;
  payer: string;
  tier: Tier;
  remainingDownloads: number;
  createdAt: number;
  licenseToken?: string;
}

export interface LicensePayload {
  v: 1;
  product: string;
  tier: Tier;
  payer: string;
  txHash: string;
  issuedAt: number;
  expiresAt: number | null;
}

export interface HostedClaimRecord {
  scope: 'hosted';
  txHash: string;
  merchantAddress: string;
  payer: string;
  paidAtomic: string;
  claimedAt: number;
}
