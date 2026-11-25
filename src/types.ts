export type Tier = 'supporter' | 'team';

export interface Env {
  ASSETS: Fetcher;
  LICENSES_KV: KVNamespace;
  GLOBAL_CLAIMED_TX_KV: KVNamespace;
  BRAND_NAME: string;
  PRODUCT_ID: string;
  TOKEN_PREFIX: string;
  PAY_TO_EVM_ADDRESS: string;
  BASE_USDC_CONTRACT: string;
  BASE_CHAIN_ID: string;
  BASE_RPC_URL: string;
  BASE_RPC_URLS?: string;
  SUPPORTER_PRICE_USDC_ATOMIC?: string;
  SOLO_PRICE_USDC_ATOMIC?: string;
  TEAM_PRICE_USDC_ATOMIC: string;
  HOSTED_FREE_QUOTA_ATOMIC?: string;
  MIN_CONFIRMATIONS: string;
  CHALLENGE_TTL_SECONDS: string;
  DOWNLOAD_TTL_SECONDS: string;
  PUBLIC_ARCHIVE_URL?: string;
  GITHUB_RELEASE_ASSET_URL: string;
  RELEASE_FILENAME: string;
  SOLANA_RECEIVE_ADDRESS: string;
  BTC_RECEIVE_ADDRESS: string;
  TRON_RECEIVE_ADDRESS: string;
  LICENSE_SIGNING_PRIVATE_JWK?: string;
  LICENSE_SIGNING_PUBLIC_SPKI_B64?: string;
  DOWNLOAD_HMAC_SECRET?: string;
  GITHUB_RELEASE_READ_TOKEN?: string;
}

export interface ChallengeRecord {
  nonce: string;
  txHash: string;
  tier: Tier;
  ts: number;
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
  tier: Tier | 'solo';
  payer: string;
  txHash: string;
  issuedAt: number;
  expiresAt: number | null;
}

export interface HostedClaimRecord {
  txHash: string;
  merchantAddress: string;
  payer: string;
  paidAtomic: string;
  mode: 'free_tier' | 'hosted_pro';
  verifiedAt: number;
}
