# Type Definitions

This page documents all TypeScript interfaces and types used throughout the encryption utilities library.

## Core Types

### ArgonConfig

Configuration for Argon2id password hashing algorithm.

```typescript
interface ArgonConfig {
  time: number;     // Number of iterations (1-10 recommended)
  mem: number;      // Memory usage in KB (32768-262144 recommended)
  hashLen: number;  // Output hash length in bytes (32 recommended)
}
```

**Usage:**
```typescript
const customConfig: ArgonConfig = {
  time: 4,
  mem: 65536,    // 64MB
  hashLen: 32
};
```

### AttemptTracker

Configuration for tracking failed authentication attempts.

```typescript
interface AttemptTracker {
  enable: boolean;      // Enable/disable attempt tracking
  id: string;          // Unique identifier (usually user ID)
  maxAttempts: number; // Maximum allowed failed attempts
}
```

**Usage:**
```typescript
const tracker: AttemptTracker = {
  enable: true,
  id: `user-${userId}`,
  maxAttempts: 5
};
```

## Function Parameter Types

### GenerateEncryptedKeyParams

Parameters for `generateEncryptedKey` function.

```typescript
interface GenerateEncryptedKeyParams {
  password: string;
  argonConfig?: ArgonConfig;
}
```

### DecryptGeneratedKeyParams

Parameters for `decryptGeneratedKey` function.

```typescript
interface DecryptGeneratedKeyParams {
  salt: string;
  iv: string;
  encryptedKey: string;
  password: string;
  argonConfig?: ArgonConfig;
  trackAttempts?: AttemptTracker;
}
```

### EncryptSecretParams

Parameters for `encryptSecret` function.

```typescript
interface EncryptSecretParams {
  secret: string;
  decryptedKey: Uint8Array;
}
```

### DecryptSecretParams

Parameters for `decryptSecret` function.

```typescript
interface DecryptSecretParams {
  encryptedSecret: string;
  iv: string;
  decryptedKey: Uint8Array;
}
```

### RecoverEncryptedKeyParams

Parameters for `recoverEncryptedKey` function.

```typescript
interface RecoverEncryptedKeyParams {
  recoveryMnemonic: string;
  encryptedRecoveryKey: string;
  recoverySalt: string;
  recoveryIV: string;
  argonConfig?: ArgonConfig;
}
```

### RotatePasswordParams

Parameters for `rotatePassword` function.

```typescript
interface RotatePasswordParams {
  encryptedKey: string;
  salt: string;
  iv: string;
  oldPassword: string;
  newPassword: string;
  argonConfig?: ArgonConfig;
}
```

### rotatePasswordAfterRecoveryParams

Parameters for `rotatePasswordAfterRecovery` function.

```typescript
interface rotatePasswordAfterRecoveryParams {
  recoveredDecryptedKey: Uint8Array;
  newPassword: string;
  argonConfig?: ArgonConfig;
}
```

## Function Return Types

### Result Pattern

All functions follow a consistent result pattern:

```typescript
type Result<TSuccess, TError = Error> = 
  | ({ success: true } & TSuccess)
  | { success: false; error: TError };
```

### GenerateEncryptedKeyResult

Return type for `generateEncryptedKey` function.

```typescript
type GenerateEncryptedKeyResult = Result<{
  encryptedKey: string;        // Base64 encrypted key
  salt: string;                // Base64 salt
  iv: string;                  // Base64 IV
  recoveryPhrase: string;      // 12-word mnemonic
  encryptedRecoveryKey: string;// Base64 encrypted recovery key
  recoverySalt: string;        // Base64 recovery salt
  recoveryIV: string;          // Base64 recovery IV
}, EncryptionError>;
```

### DecryptGeneratedKeyResult

Return type for `decryptGeneratedKey` function.

```typescript
type DecryptGeneratedKeyResult = Result<{
  decryptedKey: Uint8Array;
  attempts: number;
}, DecryptionError>;
```

### EncryptedSecretResult

Return type for `encryptSecret` function.

```typescript
type EncryptedSecretResult = Result<{
  encryptedSecret: string;  // Base64 encrypted data
  iv: string;              // Base64 IV
}, EncryptionError>;
```

### DecryptSecretResult

Return type for `decryptSecret` function.

```typescript
type DecryptSecretResult = Result<{
  decryptedSecret: string;
}, DecryptionError>;
```

### RecoverEncryptedKeyResult

Return type for `recoverEncryptedKey` function.

```typescript
type RecoverEncryptedKeyResult = Result<{
  decryptedKey: Uint8Array;
}, RecoverEncryptionError>;
```

### RotatePasswordReturn

Return type for `rotatePassword` function.

```typescript
type RotatePasswordReturn = Result<{
  encryptedKey: string;  // Base64 new encrypted key
  salt: string;          // Base64 new salt
  iv: string;           // Base64 new IV
}, PasswordRotationError>;
```

### RotatePasswordAfterRecoveryResult

Return type for `rotatePasswordAfterRecovery` function.

```typescript
type RotatePasswordAfterRecoveryResult = Result<{
  encryptedKey: string;  // Base64 encrypted key
  salt: string;          // Base64 salt
  iv: string;           // Base64 IV
}, PasswordRotationError>;
```

## Utility Types

### Base64String

Type alias for base64-encoded strings.

```typescript
type Base64String = string;
```

### MnemonicPhrase

Type alias for BIP39 mnemonic phrases.

```typescript
type MnemonicPhrase = string; // 12 words separated by spaces
```

## Next Steps

- [📚 Explore Function Documentation](/functions/)
- [⚠️ Learn About Error Types](/reference/errors.md)
- [🛡️ Review Security Guidelines](/reference/security.md)