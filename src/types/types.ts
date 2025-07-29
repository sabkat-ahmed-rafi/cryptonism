import { DecryptionError } from "../errors/DecryptionError";
import { EncryptionError } from "../errors/EncryptionError";
import { PasswordRotationError } from "../errors/PasswordRotationError";
import { RecoverEncryptionError } from "../errors/RecoverEncryptionError";

// Argon config type
export type ArgonConfig = {
  time?: number;
  mem?: number;
  hashLen?: number;
}

// Generate Encrypted Key related types 
export interface GenerateEncryptedKeyParams {
  password: string,
  argonConfig?: ArgonConfig
}

export type GenerateEncryptedKeySuccess = {
  success: true;
  encryptedKey: string;
  salt: string;
  iv: string;
  recoveryPhrase: string;
  encryptedRecoveryKey: string;
  recoverySalt: string;
  recoveryIV: string;
}

export type GenerateEncryptedKeyFailure = {
  success: false;
  error: EncryptionError;
};

export type GenerateEncryptedKeyResult = GenerateEncryptedKeySuccess | GenerateEncryptedKeyFailure;

// Decrypt generated key related types 
export interface DecryptGeneratedKeyParams {
  salt: string;
  iv: string;
  encryptedKey: string;
  password: string;
  argonConfig?: ArgonConfig;
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

type DecryptSuccess = { success: true, decryptedKey: Uint8Array; attempts: number };
type DecryptFailure = { success: false, error: DecryptionError; attempts?: number };
export type DecryptGeneratedKeyResult = DecryptSuccess | DecryptFailure;

// Rotate Password related types 
export interface RotatePasswordParams {
  encryptedKey: string,
  salt: string,
  iv: string,
  oldPassword: string,
  newPassword: string,
  argonConfig?: ArgonConfig
}

export type RotatePasswordSuccess = {
  success: true;
  encryptedKey: string;
  salt: string;
  iv: string;
};

export type RotatePasswordFailure = {
  success: false;
  error: PasswordRotationError;
};

export type RotatePasswordReturn = RotatePasswordSuccess | RotatePasswordFailure;

// Recover Encrypted key related typs 
export interface RecoverEncryptedKeyParams {
  recoveryMnemonic: string,
  encryptedRecoveryKey: string,
  recoverySalt: string,
  recoveryIV: string,
  argonConfig?: ArgonConfig
}

export type RecoverEncryptedKeyResult = 
  | { success: true; decryptedKey: Uint8Array }
  | { success: false; error: RecoverEncryptionError };


// Rotate Password After Recovery types 
export interface rotatePasswordAfterRecoveryParams {
  recoveredDecryptedKey: Uint8Array,
  newPassword: string,
  argonConfig?: ArgonConfig
}

export type RotatePasswordAfterRecoverySuccess = {
  success: true;
  encryptedKey: string;
  salt: string;
  iv: string;
};

export type RotatePasswordAfterRecoveryFailure = {
  success: false;
  error: PasswordRotationError;
};

export type RotatePasswordAfterRecoveryResult =
  | RotatePasswordAfterRecoverySuccess
  | RotatePasswordAfterRecoveryFailure;

// EncryptSecret related type
export interface EncryptSecretParams {
  secret: string,
  decryptedKey: Uint8Array
}

export type EncryptedSecretSuccess = {
  success: true;
  encryptedSecret: string;
  iv: string;
};

export type EncryptedSecretFailure = {
  success: false;
  error: EncryptionError;
};

export type EncryptedSecretResult = EncryptedSecretSuccess | EncryptedSecretFailure;

// DecryptSecret related type
export interface DecryptSecretParams {
  encryptedSecret: string,
  iv: string,
  decryptedKey: Uint8Array
}

export type DecryptSecretResult = 
| { success: true; decryptedSecret: string }
| { success: false; error: DecryptionError };
