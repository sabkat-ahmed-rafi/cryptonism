# rotatePasswordAfterRecovery

Sets a new password after successful key recovery using a mnemonic phrase. This function takes a recovered decrypted key and encrypts it with a new password.

<div class="function-signature">
rotatePasswordAfterRecovery(params: rotatePasswordAfterRecoveryParams): Promise&lt;RotatePasswordAfterRecoveryResult&gt;
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
<td>recoveredDecryptedKey</td>
<td>Uint8Array</td>
<td>✅</td>
<td>Decrypted key from recoverEncryptedKey</td>
</tr>
<tr>
<td>newPassword</td>
<td>string</td>
<td>✅</td>
<td>New password to protect the key</td>
</tr>
<tr>
<td>argonConfig</td>
<td>ArgonConfig</td>
<td>❌</td>
<td>Argon2 configuration (uses defaults if not provided)</td>
</tr>
</table>

## Return Value

### Success Response
<span class="status-badge status-success">Success: true</span>

```typescript
{
  success: true,
  encryptedKey: string,  // Base64 encrypted key with new password
  salt: string,          // Base64 new salt
  iv: string            // Base64 new IV
}
```

### Error Response
<span class="status-badge status-error">Success: false</span>

```typescript
{
  success: false,
  error: PasswordRotationError
}
```

## Usage Examples

### Complete Recovery Flow

```typescript
import { recoverEncryptedKey, rotatePasswordAfterRecovery } from 'cryptonism';

async function completeAccountRecovery(
  userId: string,
  recoveryPhrase: string,
  newPassword: string
) {
  try {
    // 1. Get recovery data from database
    const recoveryData = await getUserRecoveryData(userId);
    
    // 2. Recover the key using mnemonic
    const recoverResult = await recoverEncryptedKey({
      recoveryMnemonic: recoveryPhrase,
      encryptedRecoveryKey: recoveryData.encryptedRecoveryKey,
      recoverySalt: recoveryData.recoverySalt,
      recoveryIV: recoveryData.recoveryIV
    });
    
    if (!recoverResult.success) {
      throw new Error('Invalid recovery phrase');
    }
    
    // 3. Set new password with recovered key
    const rotateResult = await rotatePasswordAfterRecovery({
      recoveredDecryptedKey: recoverResult.decryptedKey,
      newPassword: newPassword
    });
    
    if (!rotateResult.success) {
      throw new Error('Failed to set new password');
    }
    
    // 4. Update user's vault with new password-protected data
    await updateUserVault(userId, {
      encryptedKey: rotateResult.encryptedKey,
      salt: rotateResult.salt,
      iv: rotateResult.iv,
      recoveredAt: new Date()
    });
    
    // 5. Log security event
    await logSecurityEvent(userId, 'account_recovered');
    
    return { 
      success: true, 
      message: 'Account recovered and new password set successfully' 
    };
    
  } catch (error) {
    console.error('Recovery error:', error.message);
    return { success: false, error: error.message };
  }
}
```

## Security Features

### 🔐 Fresh Encryption
- **New Cryptographic Material**: Generates fresh salt and IV
- **Same Master Key**: Preserves access to all existing encrypted data
- **Strong Protection**: Uses Argon2id for password-based key derivation

### 🛡️ Security Properties
- **Forward Secrecy**: Recovery phrase cannot be used to access new password-protected data
- **Data Continuity**: All previously encrypted secrets remain accessible
- **Integrity Protection**: AES-GCM ensures data authenticity

## Process Flow

### Recovery to New Password Flow

1. **User Provides Recovery Phrase**
   - 12-word mnemonic phrase entered by user
   - Phrase validated for format and word count

2. **Key Recovery**
   - `recoverEncryptedKey` extracts the master key
   - Master key is now available in memory

3. **New Password Setup**
   - User provides new password
   - Password validated for strength requirements

4. **Re-encryption**
   - Generate new salt and IV
   - Derive new key from new password using Argon2id
   - Encrypt master key with new derived key

5. **Database Update**
   - Replace old vault data with new encrypted data
   - Log recovery event for security audit


## Error Handling

### Common Error Scenarios

| Error Type | Cause | Solution |
|------------|-------|----------|
| Invalid Key | Corrupted recovered key | Re-attempt recovery |
| Weak Password | New password doesn't meet requirements | Validate before submission |
| Database Error | Failed to update vault | Use transactions |
| Memory Error | Insufficient system resources | Check system resources |


## Best Practices

### ✅ Do
- Validate recovery phrase format before processing
- Enforce strong password requirements
- Use database transactions for atomic updates
- Log recovery events for security monitoring
- Clear sensitive data from memory after use
- Invalidate existing sessions after recovery
- Require email verification for recovery attempts

### ❌ Don't
- Skip password strength validation
- Store recovery phrases in your database
- Log sensitive data (keys, passwords, phrases)
- Allow recovery without proper authentication
- Skip error handling
- Reuse old cryptographic material

## Security Considerations

### Recovery Security
- **One-Time Use**: Consider invalidating recovery data after use
- **Rate Limiting**: Limit recovery attempts per time period
- **Audit Trail**: Log all recovery attempts for security review
- **Session Management**: Invalidate all existing sessions after recovery


## Related Functions

- [`recoverEncryptedKey`](recoverEncryptedKey.md) - Recover key using mnemonic
- [`rotatePassword`](rotatePassword.md) - Normal password rotation
- [`generateEncryptedKey`](generateEncryptedKey.md) - Initial key creation

## Next Steps

- [🔑 Learn about key recovery](/functions/recoverEncryptedKey.md)
- [🔄 Understand password rotation](/functions/rotatePassword.md)
- [🛡️ Review security best practices](/reference/security.md)