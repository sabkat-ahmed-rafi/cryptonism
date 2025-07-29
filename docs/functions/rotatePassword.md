# rotatePassword

Changes a user's password while preserving access to all encrypted data. The function re-encrypts the key with a new password-derived key.

<div class="function-signature">
rotatePassword(params: RotatePasswordParams): Promise&lt;RotatePasswordReturn&gt;
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
<td>encryptedKey</td>
<td>string</td>
<td>✅</td>
<td>Base64 encrypted key from user's vault</td>
</tr>
<tr>
<td>salt</td>
<td>string</td>
<td>✅</td>
<td>Base64 salt from user's vault</td>
</tr>
<tr>
<td>iv</td>
<td>string</td>
<td>✅</td>
<td>Base64 IV from user's vault</td>
</tr>
<tr>
<td>oldPassword</td>
<td>string</td>
<td>✅</td>
<td>User's current password</td>
</tr>
<tr>
<td>newPassword</td>
<td>string</td>
<td>✅</td>
<td>User's new password</td>
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
  encryptedKey: string,  // New Base64 encrypted key
  salt: string,          // New Base64 salt
  iv: string            // New Base64 IV
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

### Basic Password Change

```typescript
import { rotatePassword } from '@your-org/encryption-utils';

async function changeUserPassword(
  userId: string, 
  oldPassword: string, 
  newPassword: string
) {
  try {
    // 1. Get current vault data from database
    const currentVault = await getUserVault(userId);
    
    // 2. Rotate the password
    const result = await rotatePassword({
      encryptedKey: currentVault.encryptedKey,
      salt: currentVault.salt,
      iv: currentVault.iv,
      oldPassword: oldPassword,
      newPassword: newPassword
    });
    
    if (!result.success) {
      throw new Error('Password rotation failed');
    }
    
    // 3. Update database with new encrypted data
    await updateUserVault(userId, {
      encryptedKey: result.encryptedKey,
      salt: result.salt,
      iv: result.iv,
      updatedAt: new Date()
    });
    
    return { success: true, message: 'Password changed successfully' };
    
  } catch (error) {
    console.error('Password change error:', error.message);
    return { success: false, error: error.message };
  }
}
```

### Password Change with Validation

```typescript
async function securePasswordChange(
  userId: string,
  oldPassword: string,
  newPassword: string
) {
  // 1. Validate new password strength
  if (!isPasswordStrong(newPassword)) {
    throw new Error('New password does not meet security requirements');
  }
  
  // 2. Verify old password first
  const vault = await getUserVault(userId);
  const verifyResult = await decryptGeneratedKey({
    salt: vault.salt,
    iv: vault.iv,
    encryptedKey: vault.encryptedKey,
    password: oldPassword
  });
  
  if (!verifyResult.success) {
    throw new Error('Current password is incorrect');
  }
  
  // 3. Perform password rotation
  const rotateResult = await rotatePassword({
    encryptedKey: vault.encryptedKey,
    salt: vault.salt,
    iv: vault.iv,
    oldPassword: oldPassword,
    newPassword: newPassword
  });
  
  if (!rotateResult.success) {
    throw new Error('Failed to change password');
  }
  
  // 4. Update database
  await updateUserVault(userId, {
    encryptedKey: rotateResult.encryptedKey,
    salt: rotateResult.salt,
    iv: rotateResult.iv
  });
  
  // 5. Log security event
  await logSecurityEvent(userId, 'password_changed');
  
  return { success: true };
}

function isPasswordStrong(password: string): boolean {
  return password.length >= 12 && 
         /[A-Z]/.test(password) && 
         /[a-z]/.test(password) && 
         /[0-9]/.test(password) && 
         /[^A-Za-z0-9]/.test(password);
}
```

### Bulk Password Rotation (Admin)

```typescript
async function rotatePasswordsForUsers(
  userIds: string[], 
  adminPassword: string,
  newPasswordGenerator: (userId: string) => string
) {
  const results = [];
  
  for (const userId of userIds) {
    try {
      const vault = await getUserVault(userId);
      const newPassword = newPasswordGenerator(userId);
      
      const result = await rotatePassword({
        encryptedKey: vault.encryptedKey,
        salt: vault.salt,
        iv: vault.iv,
        oldPassword: adminPassword, // Assuming admin knows current password
        newPassword: newPassword
      });
      
      if (result.success) {
        await updateUserVault(userId, result);
        results.push({ userId, success: true });
      } else {
        results.push({ userId, success: false, error: result.error.message });
      }
      
    } catch (error) {
      results.push({ userId, success: false, error: error.message });
    }
  }
  
  return results;
}
```

## Security Features

### 🔐 Secure Key Rotation
- **No Data Loss**: All encrypted secrets remain accessible
- **Fresh Cryptographic Material**: New salt and IV for enhanced security
- **Atomic Operation**: Either succeeds completely or fails safely

### 🛡️ Security Properties
- **Forward Secrecy**: Old password cannot decrypt new encrypted key
- **Backward Compatibility**: New password can access all existing data
- **Integrity Protection**: AES-GCM ensures data hasn't been tampered with

## Process Flow

### Internal Steps

1. **Decrypt with Old Password**
   - Use old password + old salt to derive decryption key
   - Decrypt the master key using old IV

2. **Generate New Cryptographic Material**
   - Generate new random salt (32 bytes)
   - Generate new random IV (12 bytes)

3. **Encrypt with New Password**
   - Use new password + new salt to derive encryption key
   - Encrypt the same master key using new IV

4. **Return New Vault Data**
   - Return new encrypted key, salt, and IV

### Database Update Pattern

```typescript
// Atomic database update
async function updateUserVault(userId: string, newVaultData: VaultData) {
  const transaction = await db.beginTransaction();
  
  try {
    // Update main vault data
    await transaction.query(`
      UPDATE user_vaults 
      SET encrypted_key = ?, salt = ?, iv = ?, updated_at = NOW()
      WHERE user_id = ?
    `, [newVaultData.encryptedKey, newVaultData.salt, newVaultData.iv, userId]);
    
    // Log the password change
    await transaction.query(`
      INSERT INTO security_events (user_id, event_type, timestamp)
      VALUES (?, 'password_changed', NOW())
    `, [userId]);
    
    await transaction.commit();
  } catch (error) {
    await transaction.rollback();
    throw error;
  }
}
```

## Error Handling

### Common Error Scenarios

| Error Type | Cause | Solution |
|------------|-------|----------|
| Wrong Old Password | Incorrect current password | Verify old password first |
| Weak New Password | New password doesn't meet requirements | Validate before rotation |
| Database Error | Failed to update vault | Use database transactions |
| Crypto Error | Encryption/decryption failure | Check system resources |

### Comprehensive Error Handling

```typescript
async function handlePasswordRotation(userId: string, oldPass: string, newPass: string) {
  try {
    const result = await rotatePassword({
      // ... parameters
    });
    
    if (!result.success) {
      // Handle specific rotation errors
      if (result.error instanceof PasswordRotationError) {
        // Could be wrong old password or crypto failure
        return { success: false, message: 'Unable to change password. Please verify your current password.' };
      }
    }
    
    return { success: true };
    
  } catch (error) {
    // Handle unexpected errors
    console.error('Unexpected error during password rotation:', error);
    return { success: false, message: 'An unexpected error occurred. Please try again.' };
  }
}
```

## REST API Example

```typescript
app.post('/api/change-password', async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const userId = req.user.id;
    
    // Validate input
    if (!oldPassword || !newPassword) {
      return res.status(400).json({ error: 'Both old and new passwords are required' });
    }
    
    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({ 
        error: 'New password must be at least 12 characters with mixed case, numbers, and symbols' 
      });
    }
    
    // Get current vault
    const vault = await getUserVault(userId);
    if (!vault) {
      return res.status(404).json({ error: 'User vault not found' });
    }
    
    // Rotate password
    const result = await rotatePassword({
      encryptedKey: vault.encryptedKey,
      salt: vault.salt,
      iv: vault.iv,
      oldPassword,
      newPassword
    });
    
    if (!result.success) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }
    
    // Update database
    await updateUserVault(userId, {
      encryptedKey: result.encryptedKey,
      salt: result.salt,
      iv: result.iv
    });
    
    res.json({ message: 'Password changed successfully' });
    
  } catch (error) {
    console.error('Password change API error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

## Best Practices

### ✅ Do
- Verify old password before attempting rotation
- Validate new password strength
- Use database transactions for atomic updates
- Log password change events for security
- Clear old password from memory immediately
- Require re-authentication for sensitive operations

### ❌ Don't
- Skip old password verification
- Allow weak new passwords
- Log passwords in application logs
- Perform rotation without proper error handling
- Store passwords in plain text anywhere
- Allow password rotation without user authentication

## Performance Considerations

### Timing
- **Argon2 Processing**: Expect 100ms-2s depending on configuration
- **Database Updates**: Minimal overhead for vault updates
- **Memory Usage**: Temporary spike during key derivation

### Optimization Tips
- Use appropriate Argon2 parameters for your environment
- Consider rate limiting password change attempts
- Implement proper session management
- Use connection pooling for database operations

## Security Considerations

### Password Policy
```typescript
interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  preventReuse: number; // Number of previous passwords to check
}

const defaultPolicy: PasswordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  preventReuse: 5
};
```

### Rate Limiting
```typescript
// Implement rate limiting for password changes
const passwordChangeAttempts = new Map<string, number>();

function checkRateLimit(userId: string): boolean {
  const attempts = passwordChangeAttempts.get(userId) || 0;
  if (attempts >= 3) { // Max 3 password changes per hour
    return false;
  }
  passwordChangeAttempts.set(userId, attempts + 1);
  return true;
}
```

## Related Functions

- [`decryptGeneratedKey`](decryptGeneratedKey.md) - Verify old password
- [`rotatePasswordAfterRecovery`](rotatePasswordAfterRecovery.md) - Set password after recovery
- [`generateEncryptedKey`](generateEncryptedKey.md) - Initial key creation

## Next Steps

- [🔄 Learn about recovery-based rotation](rotatePasswordAfterRecovery.md)
- [🔑 Understand key management](decryptGeneratedKey.md)
- [🛡️ Review security best practices](/reference/security.md)