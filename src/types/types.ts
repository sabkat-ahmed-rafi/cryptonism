import { DecryptionError } from "../errors/DecryptionError";

export type ArgonOptions = {
  time?: number;
  mem?: number;
  hashLen?: number;
}

export interface DecryptGeneratedKeyParams {
  salt: string;
  iv: string;
  encryptedKey: string;
  password: string;
  argonConfig?: ArgonOptions;
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

type DecryptSuccess = { decryptedKey: Uint8Array; attempts: number };
type DecryptFailure = { error: DecryptionError; attempts?: number };
export type DecryptGeneratedKeyResult = DecryptSuccess | DecryptFailure;
