# 🔐 Cryptonism &middot; [![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/sabkat-ahmed-rafi/cryptonism/blob/main/LICENSE)

**Frontend End-to-End Encryption Library**  
Secure your authentication flows and sensitive data with zero-knowledge architecture directly in the browser.

---

## ✨ Features

- 🔒 Easy-to-use frontend end-to-end encryption
- 🔑 Access decrypted `vaultKey` for custom use cases
- ⚡ Lightweight & framework-agnostic (React, Vue, Vanilla JS, etc.)
- 🧱 Built with TypeScript — includes types out of the box

---

## 📦 Installation

```bash
npm install cryptonism
```

## 📚 Documentation
Full documentation is available here: [View the Docs](https://your-library-url.com)

## Usage Example

### Encrypt An Account

```typescript
import { generateEncryptedKey } from 'cryptonism';

const result = await generateEncryptedKey({
  password: 'user-master-password'
});

if (result.success) {
  // Store these in your database
  const data = {
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
// Note: use same custom argonConfig for all functions
const result = await generateEncryptedKey({
  password: 'user-master-password',
  argonConfig: {
    time: 3,      // More iterations for higher security
    mem: 32000,  // 32MB memory usage
    hashLen: 32   // 32-byte output
  }
});

// The Default Argon2 Config
const defaultArgonConfig = {
  time: 3,
  mem: 65536,
  hashLen: 32
};

```

### Decrypt An Account

```typescript
import { decryptGeneratedKey } from 'cryptonism';

// Data from your database
const data = {
  salt: 'base64-salt-string',
  iv: 'base64-iv-string', 
  encryptedKey: 'base64-encrypted-key'
};

const result = await decryptGeneratedKey({
  salt: data.salt,
  iv: data.iv,
  encryptedKey: data.encryptedKey,
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

### Decrypt With Attempt Tracking

```typescript
const result = await decryptGeneratedKey({
  salt: data.salt,
  iv: data.iv,
  encryptedKey: data.encryptedKey,
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
  }
}
```

### Encrypt Each Secret Data

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

### Decrypt Each Secret

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


For advanced usage, configuration options, and troubleshooting tips, please refer to the [Full Documentation](#).