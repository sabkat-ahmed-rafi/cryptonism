# rotatePasswordAfterRecovery

Sets a new password after successful key recovery using a mnemonic phrase. This function takes a recovered decrypted key and encrypts it with a new password.

<div class="function-signature">
rotatePasswordAfterRecovery(params: rotatePasswordAfterRecoveryParams): Promise&lt;RotatePasswordAfterRecoveryResult&gt;
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
import { recoverEncryptedKey, rotatePasswordAfterRecovery } from '@your-org/encryption-utils';

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

### Recovery with Password Validation

```typescript
async function secureRecoveryWithValidation(
  userId: string,
  recoveryPhrase: string,
  newPassword: string,
  confirmPassword: string
) {
  // 1. Validate inputs
  if (newPassword !== confirmPassword) {
    throw new Error('Passwords do not match');
  }
  
  if (!isPasswordStrong(newPassword)) {
    throw new Error('Password does not meet security requirements');
  }
  
  // 2. Perform recovery
  const recoveryData = await getUserRecoveryData(userId);
  const recoverResult = await recoverEncryptedKey({
    recoveryMnemonic: recoveryPhrase.trim(),
    ...recoveryData
  });
  
  if (!recoverResult.success) {
    throw new Error('Invalid recovery phrase');
  }
  
  // 3. Set new password
  const rotateResult = await rotatePasswordAfterRecovery({
    recoveredDecryptedKey: recoverResult.decryptedKey,
    newPassword: newPassword
  });
  
  if (!rotateResult.success) {
    throw new Error('Failed to set new password');
  }
  
  // 4. Update database atomically
  await updateUserVaultAfterRecovery(userId, rotateResult);
  
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

### React Recovery Component

```typescript
function AccountRecoveryForm({ userId }: { userId: string }) {
  const [step, setStep] = useState<'phrase' | 'password' | 'success'>('phrase');
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoveredKey, setRecoveredKey] = useState<Uint8Array | null>(null);
  
  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      // Validate recovery phrase format
      const words = recoveryPhrase.trim().split(/\s+/);
      if (words.length !== 12) {
        setError('Recovery phrase must be exactly 12 words');
        return;
      }
      
      // Attempt recovery
      const recoveryData = await getUserRecoveryData(userId);
      const result = await recoverEncryptedKey({
        recoveryMnemonic: recoveryPhrase,
        ...recoveryData
      });
      
      if (result.success) {
        setRecoveredKey(result.decryptedKey);
        setStep('password');
      } else {
        setError('Invalid recovery phrase. Please check your words and try again.');
      }
      
    } catch (err) {
      setError('Recovery failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      if (newPassword !== confirmPassword) {
        setError('Passwords do not match');
        return;
      }
      
      if (!isPasswordStrong(newPassword)) {
        setError('Password must be at least 12 characters with mixed case, numbers, and symbols');
        return;
      }
      
      const result = await rotatePasswordAfterRecovery({
        recoveredDecryptedKey: recoveredKey!,
        newPassword: newPassword
      });
      
      if (result.success) {
        await updateUserVault(userId, result);
        setStep('success');
      } else {
        setError('Failed to set new password. Please try again.');
      }
      
    } catch (err) {
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  if (step === 'phrase') {
    return (
      <form onSubmit={handleRecoverySubmit}>
        <h2>Account Recovery</h2>
        <div>
          <label>Enter your 12-word recovery phrase:</label>
          <textarea
            value={recoveryPhrase}
            onChange={(e) => setRecoveryPhrase(e.target.value)}
            placeholder="word1 word2 word3 ..."
            rows={3}
            disabled={loading}
            required
          />
        </div>
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={loading}>
          {loading ? 'Recovering...' : 'Recover Account'}
        </button>
      </form>
    );
  }
  
  if (step === 'password') {
    return (
      <form onSubmit={handlePasswordSubmit}>
        <h2>Set New Password</h2>
        <p>✅ Recovery successful! Please set a new password for your account.</p>
        
        <div>
          <label>New Password:</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            disabled={loading}
            required
          />
        </div>
        
        <div>
          <label>Confirm Password:</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            disabled={loading}
            required
          />
        </div>
        
        {error && <div className="error">{error}</div>}
        <button type="submit" disabled={loading}>
          {loading ? 'Setting Password...' : 'Set New Password'}
        </button>
      </form>
    );
  }
  
  return (
    <div>
      <h2>✅ Recovery Complete!</h2>
      <p>Your account has been recovered and your new password has been set.</p>
      <button onClick={() => window.location.href = '/login'}>
        Go to Login
      </button>
    </div>
  );
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

## Database Operations

### Atomic Update Pattern

```typescript
async function updateUserVaultAfterRecovery(
  userId: string, 
  newVaultData: { encryptedKey: string; salt: string; iv: string }
) {
  const transaction = await db.beginTransaction();
  
  try {
    // Update vault with new password-protected data
    await transaction.query(`
      UPDATE user_vaults 
      SET encrypted_key = ?, salt = ?, iv = ?, recovered_at = NOW()
      WHERE user_id = ?
    `, [newVaultData.encryptedKey, newVaultData.salt, newVaultData.iv, userId]);
    
    // Log security event
    await transaction.query(`
      INSERT INTO security_events (user_id, event_type, timestamp, details)
      VALUES (?, 'account_recovered', NOW(), 'Password reset after recovery')
    `, [userId]);
    
    // Optionally invalidate all existing sessions
    await transaction.query(`
      DELETE FROM user_sessions WHERE user_id = ?
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
| Invalid Key | Corrupted recovered key | Re-attempt recovery |
| Weak Password | New password doesn't meet requirements | Validate before submission |
| Database Error | Failed to update vault | Use transactions |
| Memory Error | Insufficient system resources | Check system resources |

### Comprehensive Error Handling

```typescript
async function handleRecoveryPasswordRotation(
  recoveredKey: Uint8Array,
  newPassword: string
) {
  try {
    // Validate inputs
    if (!recoveredKey || recoveredKey.length !== 32) {
      throw new Error('Invalid recovered key');
    }
    
    if (!isPasswordStrong(newPassword)) {
      throw new Error('Password does not meet security requirements');
    }
    
    const result = await rotatePasswordAfterRecovery({
      recoveredDecryptedKey: recoveredKey,
      newPassword: newPassword
    });
    
    if (!result.success) {
      if (result.error instanceof PasswordRotationError) {
        throw new Error('Failed to set new password. Please try again.');
      }
      throw new Error('An unexpected error occurred.');
    }
    
    return result;
    
  } catch (error) {
    console.error('Recovery password rotation error:', error);
    throw error;
  }
}
```

## REST API Example

```typescript
app.post('/api/recover-account', async (req, res) => {
  try {
    const { recoveryPhrase, newPassword, confirmPassword } = req.body;
    const { userId } = req.params;
    
    // Validate input
    if (!recoveryPhrase || !newPassword || !confirmPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match' });
    }
    
    if (!isPasswordStrong(newPassword)) {
      return res.status(400).json({ 
        error: 'Password must be at least 12 characters with mixed case, numbers, and symbols' 
      });
    }
    
    // Validate recovery phrase format
    const words = recoveryPhrase.trim().split(/\s+/);
    if (words.length !== 12) {
      return res.status(400).json({ error: 'Recovery phrase must be exactly 12 words' });
    }
    
    // Get recovery data
    const recoveryData = await getUserRecoveryData(userId);
    if (!recoveryData) {
      return res.status(404).json({ error: 'No recovery data found' });
    }
    
    // Attempt recovery
    const recoverResult = await recoverEncryptedKey({
      recoveryMnemonic: recoveryPhrase,
      ...recoveryData
    });
    
    if (!recoverResult.success) {
      return res.status(400).json({ error: 'Invalid recovery phrase' });
    }
    
    // Set new password
    const rotateResult = await rotatePasswordAfterRecovery({
      recoveredDecryptedKey: recoverResult.decryptedKey,
      newPassword: newPassword
    });
    
    if (!rotateResult.success) {
      return res.status(500).json({ error: 'Failed to set new password' });
    }
    
    // Update database
    await updateUserVaultAfterRecovery(userId, rotateResult);
    
    res.json({ message: 'Account recovered successfully' });
    
  } catch (error) {
    console.error('Recovery API error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
```

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

### Password Policy
```typescript
interface RecoveryPasswordPolicy {
  minLength: number;
  requireMixedCase: boolean;
  requireNumbers: boolean;
  requireSymbols: boolean;
  preventCommonPasswords: boolean;
  preventPersonalInfo: boolean;
}

const recoveryPasswordPolicy: RecoveryPasswordPolicy = {
  minLength: 12,
  requireMixedCase: true,
  requireNumbers: true,
  requireSymbols: true,
  preventCommonPasswords: true,
  preventPersonalInfo: true
};
```

## Related Functions

- [`recoverEncryptedKey`](recoverEncryptedKey.md) - Recover key using mnemonic
- [`rotatePassword`](rotatePassword.md) - Normal password rotation
- [`generateEncryptedKey`](generateEncryptedKey.md) - Initial key creation

## Next Steps

- [🔑 Learn about key recovery](recoverEncryptedKey.md)
- [🔄 Understand password rotation](rotatePassword.md)
- [🛡️ Review security best practices](/reference/security.md)