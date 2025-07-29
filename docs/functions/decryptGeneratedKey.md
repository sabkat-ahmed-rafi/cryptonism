# decryptGeneratedKey

Unlocks an encrypted key using a password, with optional attempt tracking for brute force protection.

<div class="function-signature">
decryptGeneratedKey(params: DecryptGeneratedKeyParams): Promise&lt;DecryptGeneratedKeyResult&gt;
</div>

## Parameters

<table class="parameter-table">
<tr>
<th>Parameter</th>
<th>Type</th>
<th>Required</th>
<th>Description</th>
</tr>
<tr>
<td>salt</td>
<td>string</td>
<td>✅</td>
<td>Base64 salt from key generation</td>
</tr>
<tr>
<td>iv</td>
<td>string</td>
<td>✅</td>
<td>Base64 initialization vector from key generation</td>
</tr>
<tr>
<td>encryptedKey</td>
<td>string</td>
<td>✅</td>
<td>Base64 encrypted key from key generation</td>
</tr>
<tr>
<td>password</td>
<td>string</td>
<td>✅</td>
<td>User's master password</td>
</tr>
<tr>
<td>argonConfig</td>
<td>ArgonConfig</td>
<td>❌</td>
<td>Must match the config used during generation</td>
</tr>
<tr>
<td>trackAttempts</td>
<td>AttemptTracker</td>
<td>❌</td>
<td>Configuration for attempt tracking</td>
</tr>
</table>

## Return Value

### Success Response
<span class="status-badge status-success">Success: true</span>

```typescript
{
  success: true,
  decryptedKey: Uint8Array,  // The unlocked encryption key
  attempts: number           // Current attempt count (if tracking enabled)
}
```

### Error Response
<span class="status-badge status-error">Success: false</span>

```typescript
{
  success: false,
  error: DecryptionError,
  attempts?: number          // Current attempt count (if tracking enabled)
}
```

## Usage Examples

### Basic Usage

```typescript
import { decryptGeneratedKey } from '@your-org/encryption-utils';

// Data from your database
const vaultData = {
  salt: 'base64-salt-string',
  iv: 'base64-iv-string', 
  encryptedKey: 'base64-encrypted-key'
};

const result = await decryptGeneratedKey({
  salt: vaultData.salt,
  iv: vaultData.iv,
  encryptedKey: vaultData.encryptedKey,
  password: 'user-entered-password'
});

if (result.success) {
  const { decryptedKey } = result;
  // Now you can use this key to encrypt/decrypt secrets
  console.log('Vault unlocked successfully!');
} else {
  console.error('Failed to unlock vault:', result.error.message);
}
```

### With Attempt Tracking

```typescript
const result = await decryptGeneratedKey({
  salt: vaultData.salt,
  iv: vaultData.iv,
  encryptedKey: vaultData.encryptedKey,
  password: userPassword,
  trackAttempts: {
    enable: true,
    id: `user-${userId}`,     // Unique identifier for this user
    maxAttempts: 5            // Lock after 5 failed attempts
  }
});

if (result.success) {
  console.log('Login successful!');
} else {
  console.error(`Login failed. Attempts: ${result.attempts}/5`);
  
  if (result.attempts >= 5) {
    console.error('Account locked due to too many failed attempts');
    // Implement account lockout logic
  }
}
```

### With Custom Argon2 Config

```typescript
// Must match the config used during generateEncryptedKey
const customConfig = {
  time: 5,
  mem: 131072,
  hashLen: 32
};

const result = await decryptGeneratedKey({
  salt: vaultData.salt,
  iv: vaultData.iv,
  encryptedKey: vaultData.encryptedKey,
  password: userPassword,
  argonConfig: customConfig
});
```

## Security Features

### 🛡️ Brute Force Protection
- **Attempt Tracking**: Configurable failed attempt limits
- **User-Specific**: Track attempts per user ID
- **Automatic Reset**: Successful login resets attempt counter

### 🔐 Cryptographic Security
- **Argon2id**: Memory-hard password hashing
- **AES-GCM**: Authenticated decryption with integrity checking
- **Constant Time**: Operations designed to prevent timing attacks

## Attempt Tracking Configuration

### AttemptTracker Interface

```typescript
interface AttemptTracker {
  enable: boolean;      // Enable/disable tracking
  id: string;          // Unique identifier (usually user ID)
  maxAttempts: number; // Maximum allowed failed attempts
}
```

### Recommended Settings

| Use Case | Max Attempts | Lockout Strategy |
|----------|--------------|------------------|
| Consumer App | 5-10 | Temporary lockout |
| Enterprise | 3-5 | Account lockout |
| High Security | 3 | Permanent lockout |

## Implementation Patterns

### Login Flow

```typescript
async function loginUser(userId: string, password: string) {
  const vaultData = await getUserVault(userId);
  
  const result = await decryptGeneratedKey({
    ...vaultData,
    password,
    trackAttempts: {
      enable: true,
      id: userId,
      maxAttempts: 5
    }
  });
  
  if (result.success) {
    // Store decrypted key in secure session
    await createUserSession(userId, result.decryptedKey);
    return { success: true };
  } else {
    // Handle failed login
    if (result.attempts >= 5) {
      await lockUserAccount(userId);
      return { success: false, locked: true };
    }
    return { success: false, attempts: result.attempts };
  }
}
```

### Session Management

```typescript
// Store decrypted key securely in memory
const userSessions = new Map<string, {
  decryptedKey: Uint8Array;
  expiresAt: Date;
}>();

function storeUserSession(userId: string, decryptedKey: Uint8Array) {
  userSessions.set(userId, {
    decryptedKey,
    expiresAt: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
  });
}

function getUserKey(userId: string): Uint8Array | null {
  const session = userSessions.get(userId);
  if (!session || session.expiresAt < new Date()) {
    userSessions.delete(userId);
    return null;
  }
  return session.decryptedKey;
}
```

## Error Handling

### Common Error Scenarios

| Error | Cause | Solution |
|-------|-------|----------|
| Wrong Password | Incorrect password entered | Ask user to retry |
| Too Many Attempts | Exceeded maxAttempts | Implement lockout |
| Invalid Data | Corrupted vault data | Check data integrity |
| Config Mismatch | Different Argon2 config | Use original config |

### Error Response Example

```typescript
if (!result.success) {
  switch (result.error.constructor) {
    case DecryptionError:
      if (result.attempts >= maxAttempts) {
        showError('Account locked. Contact support.');
      } else {
        showError(`Wrong password. ${maxAttempts - result.attempts} attempts remaining.`);
      }
      break;
    default:
      showError('Login failed. Please try again.');
  }
}
```

## Best Practices

### ✅ Do
- Always check the `success` property first
- Implement proper session management
- Use attempt tracking in production
- Clear decrypted keys from memory when done
- Validate input parameters

### ❌ Don't
- Store decrypted keys in localStorage
- Log decrypted keys or passwords
- Skip error handling
- Use different Argon2 configs than generation
- Allow unlimited login attempts

## Performance Considerations

- **Argon2 is intentionally slow** - expect 100ms-2s depending on config
- **Memory usage** - Argon2 uses significant RAM during operation
- **CPU intensive** - Consider rate limiting on servers

## Related Functions

- [`generateEncryptedKey`](generateEncryptedKey.md) - Create the encrypted key
- [`rotatePassword`](rotatePassword.md) - Change password
- [`recoverEncryptedKey`](recoverEncryptedKey.md) - Recover with mnemonic

## Next Steps

- [🔐 Learn to encrypt secrets](encryptSecret.md)
- [🔄 Set up password rotation](rotatePassword.md)
- [🛡️ Implement security best practices](/reference/security.md)