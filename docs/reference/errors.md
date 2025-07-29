# Error Reference

This page documents all error types used throughout the encryption utilities library and provides guidance on handling them.

## Error Hierarchy

All library errors extend the base `Error` class and follow a consistent naming pattern.

```typescript
// Base error class
class CryptoLibraryError extends Error {
  constructor(message: string = 'A cryptographic operation failed') {
    super(message);
    this.name = this.constructor.name;
  }
}
```

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

## Error Handling Patterns

### Basic Error Handling

```typescript
async function handleCryptoOperation() {
  const result = await someEncryptionFunction(params);
  
  if (result.success) {
    // Handle success
    return result.data;
  } else {
    // Handle error
    console.error('Operation failed:', result.error.message);
    throw result.error;
  }
}
```

### Specific Error Type Handling

```typescript
async function handleSpecificErrors() {
  const result = await decryptGeneratedKey(params);
  
  if (!result.success) {
    if (result.error instanceof DecryptionError) {
      // Specific handling for decryption errors
      showUserMessage('Invalid password. Please try again.');
    } else {
      // Generic error handling
      showUserMessage('An unexpected error occurred.');
    }
    return null;
  }
  
  return result.decryptedKey;
}
```

### Comprehensive Error Handling

```typescript
async function comprehensiveErrorHandling(operation: () => Promise<any>) {
  try {
    const result = await operation();
    
    if (!result.success) {
      switch (result.error.constructor) {
        case EncryptionError:
          logError('Encryption failed', result.error);
          return { success: false, userMessage: 'Failed to encrypt data' };
          
        case DecryptionError:
          logError('Decryption failed', result.error);
          return { success: false, userMessage: 'Invalid password or corrupted data' };
          
        case PasswordRotationError:
          logError('Password rotation failed', result.error);
          return { success: false, userMessage: 'Failed to change password' };
          
        case RecoverEncryptionError:
          logError('Recovery failed', result.error);
          return { success: false, userMessage: 'Invalid recovery phrase' };
          
        default:
          logError('Unknown crypto error', result.error);
          return { success: false, userMessage: 'An unexpected error occurred' };
      }
    }
    
    return { success: true, data: result };
    
  } catch (error) {
    logError('Unexpected error', error);
    return { success: false, userMessage: 'System error occurred' };
  }
}
```

## Error Context and Debugging

### Adding Context to Errors

```typescript
class ContextualError extends Error {
  constructor(
    message: string,
    public context: Record<string, any> = {},
    public originalError?: Error
  ) {
    super(message);
    this.name = this.constructor.name;
  }
}

function wrapCryptoError(error: Error, context: Record<string, any>): ContextualError {
  return new ContextualError(
    `Crypto operation failed: ${error.message}`,
    context,
    error
  );
}

// Usage
try {
  const result = await encryptSecret({ secret, decryptedKey });
  if (!result.success) {
    throw wrapCryptoError(result.error, {
      operation: 'encryptSecret',
      secretLength: secret.length,
      keyLength: decryptedKey.length
    });
  }
} catch (error) {
  console.error('Error with context:', error);
}
```

### Error Logging

```typescript
interface ErrorLog {
  timestamp: Date;
  errorType: string;
  message: string;
  userId?: string;
  operation?: string;
  context?: Record<string, any>;
}

function logCryptoError(
  error: Error,
  userId?: string,
  operation?: string,
  context?: Record<string, any>
): void {
  const errorLog: ErrorLog = {
    timestamp: new Date(),
    errorType: error.constructor.name,
    message: error.message,
    userId,
    operation,
    context
  };
  
  // Log to your logging system
  console.error('Crypto Error:', errorLog);
  
  // Send to error tracking service
  // errorTracker.captureError(errorLog);
}

// Usage
const result = await decryptGeneratedKey(params);
if (!result.success) {
  logCryptoError(
    result.error,
    userId,
    'decryptGeneratedKey',
    { attempts: result.attempts }
  );
}
```

## User-Friendly Error Messages

### Error Message Mapping

```typescript
const userFriendlyMessages: Record<string, string> = {
  EncryptionError: 'Unable to secure your data. Please try again.',
  DecryptionError: 'Unable to access your data. Please check your password.',
  PasswordRotationError: 'Unable to change your password. Please verify your current password.',
  RecoverEncryptionError: 'Recovery failed. Please check your recovery phrase.',
};

function getUserFriendlyMessage(error: Error): string {
  return userFriendlyMessages[error.constructor.name] || 
         'An unexpected error occurred. Please try again.';
}
```

### Contextual User Messages

```typescript
function getContextualErrorMessage(error: Error, context: string): string {
  const baseMessage = getUserFriendlyMessage(error);
  
  switch (context) {
    case 'login':
      if (error instanceof DecryptionError) {
        return 'Invalid password. Please try again.';
      }
      break;
      
    case 'recovery':
      if (error instanceof RecoverEncryptionError) {
        return 'Invalid recovery phrase. Please check your 12-word phrase and try again.';
      }
      break;
      
    case 'password-change':
      if (error instanceof PasswordRotationError) {
        return 'Unable to change password. Please verify your current password is correct.';
      }
      break;
  }
  
  return baseMessage;
}
```

## Error Prevention

### Input Validation

```typescript
function validateEncryptionInputs(secret: string, key: Uint8Array): void {
  if (!secret || secret.length === 0) {
    throw new Error('Secret cannot be empty');
  }
  
  if (!key || key.length !== 32) {
    throw new Error('Invalid encryption key length');
  }
}

function validateRecoveryPhrase(phrase: string): void {
  const words = phrase.trim().split(/\s+/);
  if (words.length !== 12) {
    throw new Error('Recovery phrase must be exactly 12 words');
  }
}
```

### Defensive Programming

```typescript
async function safeEncryptSecret(secret: string, decryptedKey: Uint8Array) {
  try {
    // Validate inputs
    validateEncryptionInputs(secret, decryptedKey);
    
    // Perform operation
    const result = await encryptSecret({ secret, decryptedKey });
    
    if (!result.success) {
      throw result.error;
    }
    
    return result;
    
  } catch (error) {
    // Log error with context
    logCryptoError(error, undefined, 'safeEncryptSecret', {
      secretLength: secret?.length,
      keyProvided: !!decryptedKey
    });
    
    // Re-throw with user-friendly message
    throw new Error(getUserFriendlyMessage(error));
  }
}
```

## Testing Error Scenarios

### Unit Tests for Error Handling

```typescript
describe('Error Handling', () => {
  test('should handle invalid key gracefully', async () => {
    const invalidKey = new Uint8Array(16); // Wrong size
    
    const result = await encryptSecret({
      secret: 'test',
      decryptedKey: invalidKey
    });
    
    expect(result.success).toBe(false);
    expect(result.error).toBeInstanceOf(EncryptionError);
  });
  
  test('should handle wrong password', async () => {
    const result = await decryptGeneratedKey({
      salt: 'valid-salt',
      iv: 'valid-iv',
      encryptedKey: 'valid-encrypted-key',
      password: 'wrong-password'
    });
    
    expect(result.success).toBe(false);
    expect(result.error).toBeInstanceOf(DecryptionError);
  });
});
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

## Error Recovery Strategies

### Retry Logic

```typescript
async function withRetry<T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  delay: number = 1000
): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, delay * attempt));
      }
    }
  }
  
  throw lastError!;
}
```

### Graceful Degradation

```typescript
async function getSecretWithFallback(secretId: string, userId: string) {
  try {
    // Try to decrypt secret
    return await getDecryptedSecret(secretId, userId);
  } catch (error) {
    if (error instanceof DecryptionError) {
      // Return encrypted version if decryption fails
      return await getEncryptedSecret(secretId, userId);
    }
    throw error;
  }
}
```

## Next Steps

- [📚 Explore Function Documentation](/functions/)
- [🔧 See Error Handling Examples](/examples.md)
- [🛡️ Learn Security Best Practices](/reference/security.md)