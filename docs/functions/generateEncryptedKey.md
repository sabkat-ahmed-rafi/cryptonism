# generateEncryptedKey

Creates a new encrypted key protected by a password, along with a recovery system using a mnemonic phrase.

<div class="function-signature">
generateEncryptedKey(params: GenerateEncryptedKeyParams): Promise&lt;GenerateEncryptedKeyResult&gt;
</div>

## Parameters

<table class="parameter-table">
<tr>
<th style="color: #161616ff;">Parameter</th>
<th style="color: #161616ff;">Type</th>
<th style="color: #161616ff;">Required</th>
<th style="color: #161616ff;">Description</th>
</tr>
<tr>
<td>password</td>
<td>string</td>
<td>✅</td>
<td>Master password to protect the generated key</td>
</tr>
<tr>
<td>argonConfig</td>
<td>ArgonConfig</td>
<td>❌</td>
<td>Custom Argon2 parameters (uses defaults if not provided)</td>
</tr>
</table>

## Return Value

### Success Response
<span class="status-badge status-success">Success: true</span>

```typescript
{
  success: true,
  encryptedKey: string,        // Base64 encrypted key
  salt: string,                // Base64 salt for password derivation
  iv: string,                  // Base64 initialization vector
  recoveryPhrase: string,      // 12-word mnemonic phrase ❌ Don't store
  encryptedRecoveryKey: string,// Base64 encrypted recovery key
  recoverySalt: string,        // Base64 recovery salt
  recoveryIV: string          // Base64 recovery IV
}
```

### Error Response
<span class="status-badge status-error">Success: false</span>

```typescript
{
  success: false,
  error: EncryptionError
}
```

## Usage Example

### Basic Usage

```typescript
import { generateEncryptedKey } from 'cryptonism';

const result = await generateEncryptedKey({
  password: 'user-master-password'
});

if (result.success) {
  // Store these in your database
  const vaultData = {
    encryptedKey: result.encryptedKey,
    salt: result.salt,
    iv: result.iv,
    encryptedRecoveryKey: result.encryptedRecoveryKey,
    recoverySalt: result.recoverySalt,
    recoveryIV: result.recoveryIV
  };
  
  // CRITICAL: Show recovery phrase to user ONCE
  alert(`Save this recovery phrase: ${result.recoveryPhrase}`);
  
} else {
  console.error('Key generation failed:', result.error.message);
}
```

### With Custom Argon2 Configuration

```typescript
const result = await generateEncryptedKey({
  password: 'user-master-password',
  argonConfig: {
    time: 5,      // More iterations for higher security
    mem: 131072,  // 128MB memory usage
    hashLen: 32   // 32-byte output
  }
});
```

## Security Features

### 🔐 Dual Protection System
- **Password Protection**: Key encrypted with Argon2id-derived password
- **Recovery Protection**: Same key encrypted with mnemonic-derived password

### 🛡️ Cryptographic Strength
- **AES-GCM**: Authenticated encryption prevents tampering
- **Argon2id**: Memory-hard password hashing resists attacks
- **Random Generation**: Cryptographically secure random values

### 🔑 Recovery System
- **12-word Mnemonic**: BIP39-compatible recovery phrase
- **Independent Encryption**: Recovery system works even if password is lost
- **One-time Display**: Recovery phrase shown only during generation

## Implementation Details

### Key Generation Process

1. **Generate Random Salt** (32 bytes)
2. **Derive Password Key** using Argon2id
3. **Generate Master Key** (32 bytes random)
4. **Encrypt Master Key** with password-derived key
5. **Generate Recovery Phrase** (12 words from entropy)
6. **Encrypt Master Key** with recovery-derived key

### Storage Requirements

You need to store these values in your database:

```typescript
interface UserRecord {
  userId: string;
  encryptedKey: string;     // Main encrypted key
  salt: string;             // Password salt
  iv: string;               // Password IV
  encryptedRecoveryKey: string; // Recovery encrypted key
  recoverySalt: string;     // Recovery salt
  recoveryIV: string;       // Recovery IV
  createdAt: Date;
}
```

## Best Practices

### ✅ Do
- Store all returned values in your database recovery phrase
- Show recovery phrase to user immediately
- Require user to confirm they've saved the recovery phrase
- Validate password strength before calling

### ❌ Don't
- Log the recovery phrase
- Store the recovery phrase in your database
- Reuse salts or IVs
- Skip error handling
- Use weak passwords


## Related Functions

- [`decryptGeneratedKey`](decryptGeneratedKey.md) - Unlock the generated key
- [`recoverEncryptedKey`](recoverEncryptedKey.md) - Recover using mnemonic
- [`rotatePassword`](rotatePassword.md) - Change password later

## Next Steps

- [🔄 Set up password rotation](/functions/rotatePassword.md)
- [🛡️ Understand security model](/reference/security.md)