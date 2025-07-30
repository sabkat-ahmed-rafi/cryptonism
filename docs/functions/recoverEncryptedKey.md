# recoverEncryptedKey

Recovers the decrypted key using a mnemonic recovery phrase when the user has forgotten their password.

<div class="function-signature">
recoverEncryptedKey(params: RecoverEncryptedKeyParams): Promise&lt;RecoverEncryptedKeyResult&gt;
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
<td>recoveryMnemonic</td>
<td>string</td>
<td>✅</td>
<td>12-word recovery phrase from generateEncryptedKey</td>
</tr>
<tr>
<td>encryptedRecoveryKey</td>
<td>string</td>
<td>✅</td>
<td>Base64 encrypted recovery key from generateEncryptedKey</td>
</tr>
<tr>
<td>recoverySalt</td>
<td>string</td>
<td>✅</td>
<td>Base64 recovery salt from generateEncryptedKey</td>
</tr>
<tr>
<td>recoveryIV</td>
<td>string</td>
<td>✅</td>
<td>Base64 recovery IV from generateEncryptedKey</td>
</tr>
<tr>
<td>argonConfig</td>
<td>ArgonConfig</td>
<td>❌</td>
<td>Must match config used during key generation</td>
</tr>
</table>

## Return Value

### Success Response
<span class="status-badge status-success">Success: true</span>

```typescript
{
  success: true,
  decryptedKey: Uint8Array  // The recovered encryption key
}
```

### Error Response
<span class="status-badge status-error">Success: false</span>

```typescript
{
  success: false,
  error: RecoverEncryptionError
}
```

## Usage Examples

### Basic Recovery

```typescript
import { recoverEncryptedKey } from 'cryptonism';

// Recovery data from your database
const recoveryData = {
  encryptedRecoveryKey: 'base64-encrypted-recovery-key',
  recoverySalt: 'base64-recovery-salt',
  recoveryIV: 'base64-recovery-iv'
};

// User provides their 12-word recovery phrase
const recoveryPhrase = 'word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12';

const result = await recoverEncryptedKey({
  recoveryMnemonic: recoveryPhrase,
  encryptedRecoveryKey: recoveryData.encryptedRecoveryKey,
  recoverySalt: recoveryData.recoverySalt,
  recoveryIV: recoveryData.recoveryIV
});

if (result.success) {
  const { decryptedKey } = result;
  console.log('Key recovered successfully!');
  // Now user can access their encrypted secrets
} else {
  console.error('Recovery failed:', result.error.message);
}
```

### Complete Recovery Workflow

```typescript
async function recoverUserAccount(userId: string, recoveryPhrase: string) {
  try {
    // 1. Get recovery data from database
    const recoveryData = await getUserRecoveryData(userId);
    if (!recoveryData) {
      throw new Error('No recovery data found for user');
    }
    
    // 2. Attempt recovery
    const recoverResult = await recoverEncryptedKey({
      recoveryMnemonic: recoveryPhrase.trim(),
      encryptedRecoveryKey: recoveryData.encryptedRecoveryKey,
      recoverySalt: recoveryData.recoverySalt,
      recoveryIV: recoveryData.recoveryIV
    });
    
    if (!recoverResult.success) {
      throw new Error('Invalid recovery phrase');
    }
    
    // 3. Recovery successful - now user should set new password
    return {
      success: true,
      decryptedKey: recoverResult.decryptedKey,
      message: 'Recovery successful. Please set a new password.'
    };
    
  } catch (error) {
    console.error('Recovery error:', error.message);
    return {
      success: false,
      error: error.message
    };
  }
}
```

### Recovery with New Password Setup

```typescript
async function recoverAndSetNewPassword(
  userId: string, 
  recoveryPhrase: string, 
  newPassword: string
) {
  // 1. Recover the key
  const recoveryData = await getUserRecoveryData(userId);
  const recoverResult = await recoverEncryptedKey({
    recoveryMnemonic: recoveryPhrase,
    ...recoveryData
  });
  
  if (!recoverResult.success) {
    throw new Error('Invalid recovery phrase');
  }
  
  // 2. Set new password using the recovered key
  const rotateResult = await rotatePasswordAfterRecovery({
    recoveredDecryptedKey: recoverResult.decryptedKey,
    newPassword: newPassword
  });
  
  if (!rotateResult.success) {
    throw new Error('Failed to set new password');
  }
  
  // 3. Update database with new encrypted key data
  await updateUserVault(userId, {
    encryptedKey: rotateResult.encryptedKey,
    salt: rotateResult.salt,
    iv: rotateResult.iv
  });
  
  return { success: true, message: 'Password reset successfully' };
}
```

## Security Features

### 🔐 Mnemonic-Based Recovery
- **BIP39 Compatible**: Uses standard 12-word mnemonic phrases
- **Independent System**: Works even if password is completely lost
- **Cryptographically Secure**: Based on random entropy

### 🛡️ Security Properties
- **Same Key**: Recovers the exact same key as the original
- **Argon2id Protection**: Recovery phrase is processed through Argon2id
- **AES-GCM Decryption**: Uses authenticated encryption for recovery data

## Recovery Phrase Format

### Valid Format
```
word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
```

### Input Validation

```typescript
function validateRecoveryPhrase(phrase: string): boolean {
  const words = phrase.trim().split(/\s+/);
  
  // Must be exactly 12 words
  if (words.length !== 12) {
    return false;
  }
  
  // Each word should be from BIP39 wordlist (optional validation)
  // You can add BIP39 wordlist validation here
  
  return true;
}

// Usage
const userInput = 'abandon ability able about above absent absorb abstract absurd abuse access accident';
if (!validateRecoveryPhrase(userInput)) {
  console.error('Invalid recovery phrase format');
}
```

## Error Scenarios

| Error Type | Cause | Solution |
|------------|-------|----------|
| Invalid Phrase | Wrong recovery words | User must provide correct phrase |
| Corrupted Data | Database corruption | Check recovery data integrity |
| Wrong Config | Different Argon2 config | Use original generation config |
| Format Error | Invalid base64 data | Verify data storage |

## Best Practices

### ✅ Do
- Validate recovery phrase format before attempting recovery
- Require users to set a new password after recovery
- Log recovery attempts for security monitoring
- Clear recovery phrase from memory after use
- Provide clear error messages for invalid phrases

### ❌ Don't
- Store recovery phrases in your database
- Log recovery phrases in application logs
- Allow recovery without setting a new password
- Skip validation of recovery phrase format
- Expose detailed error information to users

## Security Considerations

### Recovery Phrase Security
- **One-Time Display**: Only shown during initial key generation
- **User Responsibility**: Users must store phrase securely offline
- **No Database Storage**: Never store recovery phrases in your system
- **Offline Storage**: Recommend physical storage (paper, hardware)

### Attack Vectors
- **Brute Force**: 12-word phrases have 2^128 entropy (practically unbreakable)
- **Social Engineering**: Educate users about phrase security
- **Phishing**: Warn users never to enter phrases on suspicious sites

## Database Schema

```sql
-- Recovery data stored in user vault
CREATE TABLE user_vaults (
  user_id UUID PRIMARY KEY,
  -- Main encryption data
  encrypted_key TEXT NOT NULL,
  salt TEXT NOT NULL,
  iv TEXT NOT NULL,
  -- Recovery data (recovery phrase NOT stored)
  encrypted_recovery_key TEXT NOT NULL,
  recovery_salt TEXT NOT NULL,
  recovery_iv TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## Related Functions

- [`generateEncryptedKey`](generateEncryptedKey.md) - Creates the recovery system
- [`rotatePasswordAfterRecovery`](rotatePasswordAfterRecovery.md) - Set new password after recovery
- [`decryptGeneratedKey`](decryptGeneratedKey.md) - Normal password-based unlock

## Next Steps

- [🔄 Set up new password after recovery](rotatePasswordAfterRecovery.md)
- [🔑 Learn about key generation](generateEncryptedKey.md)
- [🛡️ Understand security best practices](/reference/security.md)