import { DecryptionError } from "../errors/DecryptionError";
import { RecoverEncryptionError } from "../errors/RecoverEncryptionError";

// Argon config type
export type ArgonOptions = {
  time?: number;
  mem?: number;
  hashLen?: number;
}

// Generate Encrypted Key related types 
export interface GenerateEncryptedKeyParams {
  password: string,
  argonConfig?: ArgonOptions
}

export type GenerateEncryptedKeyResult = {
  encryptedKey: string;
  salt: string;
  iv: string;
  recoveryPhrase: string;
  encryptedRecoveryKey: string;
  recoverySalt: string;
  recoveryIV: string;
}

// Decrypt generated key related types 
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


// Recover Encrypted key related typs 
export interface RecoverEncryptedKeyParams {
  recoveryMnemonic: string,
  encryptedRecoveryKey: string,
  recoverySalt: string,
  recoveryIV: string,
  argonConfig?: ArgonOptions
}

export type RecoverEncryptedKeyResult = 
  | { success: true; decryptedKey: Uint8Array }
  | { success: false; error: RecoverEncryptionError };


// Rotate Password After Recovery types 
export interface rotatePasswordAfterRecoveryParams {
  recoveredDecryptedKey: Uint8Array,
  newPassword: string,
  argonConfig?: ArgonOptions
}

export type rotatePasswordAfterRecoveryResults = {
  encryptedKey: string;
  salt: string;
  iv: string;
}