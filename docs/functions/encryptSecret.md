# encryptSecret

Encrypts sensitive data using a decrypted key obtained from `decryptGeneratedKey`.

<div class="function-signature">
encryptSecret(params: EncryptSecretParams): Promise&lt;EncryptedSecretResult&gt;
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
<td>secret</td>
<td>string</td>
<td>✅</td>
<td>The sensitive data to encrypt</td>
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
  encryptedSecret: string,  // Base64 encrypted data
  iv: string               // Base64 initialization vector
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

## Usage Examples

### Basic Usage

```typescript
import { encryptSecret } from 'cryptonism';

// Assuming you have a decrypted key from decryptGeneratedKey
const result = await encryptSecret({
  secret: 'my-api-key-abc123',
  decryptedKey: userDecryptedKey
});

if (result.success) {
  // Store these values in your database
  const secretRecord = {
    encryptedSecret: result.encryptedSecret,
    iv: result.iv,
  };
  
  await saveSecretToDatabase(secretRecord);
  console.log('Secret encrypted and saved!');
} else {
  console.error('Encryption failed:', result.error.message);
}
```

### Encrypting Multiple Secrets

```typescript
async function encryptMultipleSecrets(secrets: string[], decryptedKey: Uint8Array) {
  const encryptedSecrets = [];
  
  for (const secret of secrets) {
    const result = await encryptSecret({
      secret,
      decryptedKey
    });
    
    if (result.success) {
      encryptedSecrets.push({
        encryptedSecret: result.encryptedSecret,
        iv: result.iv
      });
    } else {
      throw new Error(`Failed to encrypt secret: ${result.error.message}`);
    }
  }
  
  return encryptedSecrets;
}

// Usage
const secrets = ['password123', 'api-key-xyz', 'database-url'];
const encrypted = await encryptMultipleSecrets(secrets, decryptedKey);
```


## Security Features

### 🔐 AES-GCM Encryption
- **Authenticated Encryption**: Provides both confidentiality and integrity
- **Unique IVs**: Each encryption uses a fresh random IV
- **256-bit Security**: Uses AES-256 for maximum security

### 🛡️ Security Properties
- **Confidentiality**: Data is unreadable without the key
- **Integrity**: Tampering is detected and prevents decryption
- **Authenticity**: Ensures data hasn't been modified

## Data Types

### Supported Secret Types

The `secret` parameter accepts any string data:

```typescript
// API Keys
await encryptSecret({ secret: 'sk-1234567890abcdef', decryptedKey });

// Passwords
await encryptSecret({ secret: 'user-password-123', decryptedKey });

// JSON Data
await encryptSecret({ 
  secret: JSON.stringify({ username: 'john', token: 'abc123' }), 
  decryptedKey 
});

// Large Text
await encryptSecret({ secret: largeTextDocument, decryptedKey });

// URLs with credentials
await encryptSecret({ 
  secret: 'postgresql://user:pass@host:5432/db', 
  decryptedKey 
});
```

## Storage Patterns

### Database Schema

```sql
CREATE TABLE user_secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id),
  name VARCHAR(255) NOT NULL,
  encrypted_secret TEXT NOT NULL,
  iv VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

### TypeScript Interface

```typescript
interface SecretRecord {
  id: string;
  userId: string;
  name: string;
  encryptedSecret: string;  // Base64 encrypted data
  iv: string;              // Base64 IV
  createdAt: Date;
  updatedAt: Date;
}
```

## Performance Considerations

### Encryption Speed
- **Fast Operation**: AES-GCM is very fast (microseconds for typical secrets)
- **No Significant Overhead**: Minimal performance impact
- **Scalable**: Can encrypt thousands of secrets quickly

### Memory Usage
- **Minimal Memory**: Only holds data during encryption
- **No Persistent Storage**: Doesn't store keys or data in memory
- **Garbage Collection**: Data is automatically cleaned up

## Error Scenarios

| Error Type | Cause | Solution |
|------------|-------|----------|
| Invalid Key | Wrong key format/size | Use key from decryptGeneratedKey |
| Empty Secret | Empty string provided | Validate input before encryption |
| Memory Error | Insufficient memory | Check available system memory |
| Crypto Error | Browser crypto API failure | Check browser compatibility |

## Best Practices

### ✅ Do
- Use fresh decrypted key from `decryptGeneratedKey`
- Store both `encryptedSecret` and `iv` in your database
- Validate secret data before encryption
- Handle errors appropriately
- Use meaningful names for stored secrets

### ❌ Don't
- Reuse IVs (they're generated automatically)
- Store decrypted secrets in your database
- Log the secret data or decrypted key
- Skip error handling
- Encrypt empty or null values without validation

## Related Functions

- [`decryptGeneratedKey`](decryptGeneratedKey.md) - Get the decrypted key needed
- [`decryptSecret`](decryptSecret.md) - Decrypt the encrypted secret
- [`generateEncryptedKey`](generateEncryptedKey.md) - Create the initial key

## Next Steps

- [🔓 Learn to decrypt secrets](/functions/decryptSecret.md)
- [🛡️ Review security best practices](/reference/security.md)