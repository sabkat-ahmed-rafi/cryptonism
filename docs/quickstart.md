# Get Start

This guide will help you get started with cryptonism Library in just a few minutes.

## Installation

```bash
npm install cryptonism

```

## Basic Usage

### 1. Lock Your App

First, create an encrypted key that will protect all your secrets:

```typescript
import { generateEncryptedKey } from 'cryptonism';

const result = await generateEncryptedKey({
  password: 'your-master-password'
});

if (result.success) {
  // Store these values in your database
  const vaultData = {
    encryptedKey: result.encryptedKey,
    salt: result.salt,
    iv: result.iv,
    // Recovery data
    encryptedRecoveryKey: result.encryptedRecoveryKey,
    recoverySalt: result.recoverySalt,
    recoveryIV: result.recoveryIV
  };
  
  // IMPORTANT: Show recovery phrase to user ONCE
  console.log('Recovery phrase:', result.recoveryPhrase);
  // User should write this down and store it safely or memorize it
}
```

### 2. Unlock Your App

When the user returns, decrypt the key to access their vault:

```typescript
import { decryptGeneratedKey } from 'cryptonism';

const unlockResult = await decryptGeneratedKey({
  salt: vaultData.salt,
  iv: vaultData.iv,
  encryptedKey: vaultData.encryptedKey,
  password: 'your-master-password'
});

if (unlockResult.success) {
  const { decryptedKey } = unlockResult;
  // Now you can encrypt/decrypt secrets using this decryptedKey
}
```

### 3. Encrypt Each Secrets

Encrypt sensitive data using your decryptedkey:

```typescript
import { encryptSecret } from 'cryptonism';

const secretResult = await encryptSecret({
  secret: 'my-api-key-12345',
  decryptedKey: decryptedKey
});

if (secretResult.success) {
  // Store in database
  const secretData = {
    encryptedSecret: secretResult.encryptedSecret,
    iv: secretResult.iv
  };
}
```

### 4. Decrypt Each Secrets

Decrypt your stored secrets:

```typescript
import { decryptSecret } from 'cryptonism';

const retrieveResult = await decryptSecret({
  encryptedSecret: secretData.encryptedSecret,
  iv: secretData.iv,
  decryptedKey: decryptedKey
});

if (retrieveResult.success) {
  console.log('Secret:', retrieveResult.decryptedSecret);
  // Output: "my-api-key-12345"
}
```

## Error Handling

All functions return a object with a `success` boolean:

```typescript
const result = await encryptSecret({
  secret: 'test',
  decryptedKey: key
});

if (result.success) {
  // Use result.encryptedSecret, result.iv
} else {
  // Handle result.error
  console.error('Encryption failed:', result.error.message);
}
```

## Security Best Practices

1. **Never log or store decrypted keys**
2. **Always validate user input**
3. **Implement proper session management**
4. **Show recovery phrases once and alert user to store it offline**

## Next Steps

- [⚙️ Configure Argon2 Parameters](/configuration.md)
- [🔄 Learn About Password Rotation](/functions/rotatePassword.md)
- [🛡️ Understand Security Model](/reference/security.md)
- [📚 Explore All Functions](/functions/)