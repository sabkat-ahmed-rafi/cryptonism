export type ArgonOptions = {
  time?: number;
  mem?: number;
  hashLen?: number;
}

export interface DecryptGeneratedKeyParams {
  base64Salt: string;
  base64IV: string;
  base64EncryptedVaultKey: string;
  password: string;
  options?: ArgonOptions;
  trackAttempts?: TrackAttemptsOptions;
}


export interface TrackAttemptsOptions {
  enable: true;
  id: string;
  maxAttempts: number;
}

export type AttemptTrackerConfig = {
  id: string;
  maxAttempts: number;
};