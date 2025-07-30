# decryptSecret

Decrypts sensitive data that was encrypted using `encryptSecret`, using AES-GCM with a decrypted key.

<div class="function-signature">
decryptSecret(params: DecryptSecretParams): Promise&lt;DecryptSecretResult&gt;
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
<td>encryptedSecret</td>
<td>string</td>
<td>✅</td>
<td>Base64 encrypted data from encryptSecret</td>
</tr>
<tr>
<td>iv</td>
<td>string</td>
<td>✅</td>
<td>Base64 initialization vector from encryptSecret</td>
</tr>
<tr>
<td>decryptedKey</td>
<td>Uint8Array</td>
<td>✅</td>
<td>Decrypted key from decryptGeneratedKey</td>
</tr>
</table>

## Return Value

### Success Response
<span class="status-badge status-success">Success: true</span>

```typescript
{
  success: true,
  decryptedSecret: string  // The original secret data
}
```

### Error Response
<span class="status-badge status-error">Success: false</span>

```typescript
{
  success: false,
  error: DecryptionError
}
```

## Usage Examples

### Basic Usage

```typescript
import { decryptSecret } from 'cryptonism';

// Data retrieved from your database
const secretRecord = {
  encryptedSecret: 'base64-encrypted-data',
  iv: 'base64-iv-string'
};

const result = await decryptSecret({
  encryptedSecret: secretRecord.encryptedSecret,
  iv: secretRecord.iv,
  decryptedKey: userDecryptedKey  // From decryptGeneratedKey
});

if (result.success) {
  console.log('Secret:', result.decryptedSecret);
  // Use the decrypted secret (API key, password, etc.)
} else {
  console.error('Decryption failed:', result.error.message);
}
```

### Complete Retrieval Workflow

```typescript
async function getUserSecret(userId: string, secretId: string, password: string) {
  try {
    // 1. Unlock user's vault
    const vaultData = await getUserVault(userId);
    const unlockResult = await decryptGeneratedKey({
      salt: vaultData.salt,
      iv: vaultData.iv,
      encryptedKey: vaultData.encryptedKey,
      password
    });
    
    if (!unlockResult.success) {
      throw new Error('Failed to unlock vault');
    }
    
    // 2. Get encrypted secret from database
    const secretRecord = await getSecretFromDatabase(secretId, userId);
    if (!secretRecord) {
      throw new Error('Secret not found');
    }
    
    // 3. Decrypt the secret
    const decryptResult = await decryptSecret({
      encryptedSecret: secretRecord.encryptedSecret,
      iv: secretRecord.iv,
      decryptedKey: unlockResult.decryptedKey
    });
    
    if (!decryptResult.success) {
      throw new Error('Failed to decrypt secret');
    }
    
    return {
      id: secretRecord.id,
      name: secretRecord.name,
      secret: decryptResult.decryptedSecret,
      createdAt: secretRecord.createdAt
    };
    
  } catch (error) {
    console.error('Error retrieving secret:', error.message);
    throw error;
  }
}
```

### Decrypting Multiple Secrets

```typescript
async function decryptMultipleSecrets(
  secretRecords: Array<{encryptedSecret: string, iv: string}>,
  decryptedKey: Uint8Array
) {
  const decryptedSecrets = [];
  
  for (const record of secretRecords) {
    const result = await decryptSecret({
      encryptedSecret: record.encryptedSecret,
      iv: record.iv,
      decryptedKey
    });
    
    if (result.success) {
      decryptedSecrets.push(result.decryptedSecret);
    } else {
      console.error('Failed to decrypt a secret:', result.error.message);
      // Decide whether to continue or fail completely
    }
  }
  
  return decryptedSecrets;
}
```

### Handling Different Data Types

```typescript
// Decrypt JSON data
const jsonResult = await decryptSecret({
  encryptedSecret: record.encryptedSecret,
  iv: record.iv,
  decryptedKey
});

if (jsonResult.success) {
  const parsedData = JSON.parse(jsonResult.decryptedSecret);
  console.log('Username:', parsedData.username);
  console.log('Token:', parsedData.token);
}

// Decrypt connection string
const dbResult = await decryptSecret({
  encryptedSecret: dbRecord.encryptedSecret,
  iv: dbRecord.iv,
  decryptedKey
});

if (dbResult.success) {
  const connectionString = dbResult.decryptedSecret;
  const db = new Database(connectionString);
}
```

## Security Features

### 🔐 AES-GCM Decryption
- **Authenticated Decryption**: Verifies data integrity during decryption
- **Tamper Detection**: Fails if data has been modified
- **256-bit Security**: Uses AES-256 for maximum security

### 🛡️ Security Guarantees
- **Integrity Verification**: Automatically detects tampering
- **Authentication**: Ensures data came from legitimate encryption
- **Confidentiality**: Only correct key can decrypt the data

## Error Handling

### Common Error Scenarios

| Error Type | Cause | Solution |
|------------|-------|----------|
| Wrong Key | Different key used for decryption | Use correct decrypted key |
| Tampered Data | Data modified after encryption | Check data integrity |
| Invalid IV | Corrupted or wrong IV | Verify IV from database |
| Format Error | Invalid base64 encoding | Check data storage |

### Detailed Error Handling

```typescript
const result = await decryptSecret({
  encryptedSecret: record.encryptedSecret,
  iv: record.iv,
  decryptedKey: userKey
});

if (!result.success) {
  // Log error for debugging (don't expose to user)
  console.error('Decryption error:', result.error);
  
  // User-friendly error messages
  if (result.error instanceof DecryptionError) {
    // Could be wrong password, corrupted data, or tampering
    showUserError('Unable to decrypt secret. Please verify your password.');
  } else {
    showUserError('An error occurred while retrieving your secret.');
  }
  
  return null;
}
```

## Performance Considerations

### Decryption Speed
- **Very Fast**: AES-GCM decryption is extremely fast
- **Minimal Overhead**: Microseconds for typical secrets
- **Scalable**: Can decrypt thousands of secrets quickly

### Memory Usage
- **Temporary**: Only holds data during decryption
- **Automatic Cleanup**: JavaScript garbage collection handles cleanup
- **No Persistence**: Doesn't store decrypted data

## Best Practices

### ✅ Do
- Always check the `success` property before using the result
- Handle decryption errors gracefully
- Clear sensitive data from memory when done
- Validate that you have the correct encrypted data and IV
- Use the same decrypted key that was used for encryption

### ❌ Don't
- Log decrypted secrets or keys
- Store decrypted secrets in persistent storage
- Ignore decryption errors
- Reuse decrypted data without re-validation
- Display raw error messages to users

## Security Considerations

### Data Integrity
- **Automatic Verification**: AES-GCM automatically verifies data hasn't been tampered with
- **Fail-Safe**: Decryption fails completely if any bit is modified
- **No Partial Decryption**: Either succeeds completely or fails completely

### Key Management
- **Use Fresh Keys**: Always get decrypted key from `decryptGeneratedKey`
- **Don't Cache Keys**: Retrieve keys when needed, don't store long-term
- **Session Management**: Clear keys when user session ends

## Related Functions

- [`encryptSecret`](encryptSecret.md) - Encrypt data to create the encrypted secret
- [`decryptGeneratedKey`](decryptGeneratedKey.md) - Get the decrypted key needed
- [`generateEncryptedKey`](generateEncryptedKey.md) - Create the initial key system

## Next Steps

- [🔐 Learn about encrypting secrets](encryptSecret.md)
- [🔑 Understand key management](decryptGeneratedKey.md)
- [🛡️ Review security best practices](/reference/security.md)