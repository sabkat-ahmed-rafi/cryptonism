// Exporting core functions
export * from './crypto-engine/generateEncryptedKey';
export * from './crypto-engine/decryptGeneratedKey';
export * from './crypto-engine/rotatePassword';
export * from './crypto-engine/recoverEncryptedKey';
export * from './crypto-engine/rotatePasswordAfterRecovery';
export * from './crypto-engine/encryptSecret';
export * from './crypto-engine/decryptSecret';

// Exporting error classes
export * from './errors/EncryptionError';
export * from './errors/DecryptionError';
export * from './errors/PasswordRotationError';
export * from './errors/RecoverEncryptionError';