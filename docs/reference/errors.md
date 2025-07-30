# Error Reference

This page documents all error types used throughout the encryption utilities library and provides guidance on handling them.


## Error Types

### EncryptionError

Thrown when encryption operations fail.

```typescript
class EncryptionError extends CryptoLibraryError {
  constructor(message: string = 'Encryption operation failed') {
    super(message);
  }
}
```

**Common Causes:**
- Invalid encryption key format
- Insufficient system memory
- Browser crypto API failure
- Invalid input data

**Example:**
```typescript
const result = await encryptSecret({
  secret: 'my-secret',
  decryptedKey: invalidKey
});

if (!result.success && result.error instanceof EncryptionError) {
  console.error('Encryption failed:', result.error.message);
  // Handle encryption failure
}
```

### DecryptionError

Thrown when decryption operations fail.

```typescript
class DecryptionError extends CryptoLibraryError {
  constructor(message: string = 'Decryption operation failed') {
    super(message);
  }
}
```

**Common Causes:**
- Wrong decryption key
- Corrupted encrypted data
- Invalid initialization vector (IV)
- Data tampering (AES-GCM authentication failure)
- Wrong password

**Example:**
```typescript
const result = await decryptSecret({
  encryptedSecret: 'encrypted-data',
  iv: 'initialization-vector',
  decryptedKey: wrongKey
});

if (!result.success && result.error instanceof DecryptionError) {
  console.error('Decryption failed - possibly wrong key or corrupted data');
  // Handle decryption failure
}
```

### PasswordRotationError

Thrown when password rotation operations fail.

```typescript
class PasswordRotationError extends CryptoLibraryError {
  constructor(message: string = 'Password rotation failed') {
    super(message);
  }
}
```

**Common Causes:**
- Incorrect old password
- Encryption failure during re-encryption
- Invalid key data
- System resource constraints

**Example:**
```typescript
const result = await rotatePassword({
  encryptedKey: vault.encryptedKey,
  salt: vault.salt,
  iv: vault.iv,
  oldPassword: 'wrong-password',
  newPassword: 'new-password'
});

if (!result.success && result.error instanceof PasswordRotationError) {
  console.error('Password rotation failed - check old password');
  // Handle rotation failure
}
```

### RecoverEncryptionError

Thrown when key recovery operations fail.

```typescript
class RecoverEncryptionError extends CryptoLibraryError {
  constructor(message: string = 'Key recovery failed') {
    super(message);
  }
}
```

**Common Causes:**
- Invalid recovery mnemonic phrase
- Corrupted recovery data
- Wrong recovery parameters
- Missing recovery information

**Example:**
```typescript
const result = await recoverEncryptedKey({
  recoveryMnemonic: 'invalid mnemonic phrase',
  encryptedRecoveryKey: recoveryData.encryptedRecoveryKey,
  recoverySalt: recoveryData.recoverySalt,
  recoveryIV: recoveryData.recoveryIV
});

if (!result.success && result.error instanceof RecoverEncryptionError) {
  console.error('Recovery failed - check mnemonic phrase');
  // Handle recovery failure
}
```


## Best Practices

### ✅ Do

- Always check the `success` property before accessing result data
- Handle specific error types when appropriate
- Provide user-friendly error messages
- Log errors with sufficient context for debugging
- Validate inputs before performing crypto operations
- Use try-catch blocks for unexpected errors

### ❌ Don't

- Ignore error handling
- Expose technical error details to users
- Log sensitive data (keys, passwords) in error messages
- Assume operations will always succeed
- Use generic error handling for all scenarios
- Suppress errors without proper handling

## Next Steps

- [📚 Explore Function Documentation](/functions/)
- [🛡️ Learn Security Best Practices](/reference/security.md)