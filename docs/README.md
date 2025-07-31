# E2E Encryption Library

Cryptonism.js is a comprehensive frontend library providing secure encryption, decryption, and key management functionality using industry-standard cryptographic algorithms.

## Features

- **🔐 AES-GCM Encryption**: Authenticated encryption for maximum security
- **🔑 Argon2id Key Derivation**: Memory-hard password hashing resistant to attacks
- **🛡️ Recovery System**: Secure mnemonic-based key recovery
- **🔄 Password Rotation**: Safe password updates without data loss
- **📊 Attempt Tracking**: Built-in protection against brute force attacks
- **⚡ TypeScript Support**: Full type safety and IntelliSense support

## Quick Start

```typescript
import { generateEncryptedKey, decryptGeneratedKey } from 'cryptonism';

// 1. Generate a new encrypted key
const keyResult = await generateEncryptedKey({
  password: 'your-secure-password'
});

if (keyResult.success) {
  // Store these values securely
  const { encryptedKey, salt, iv, recoveryPhrase } = keyResult;

  const result = await decryptGeneratedKey({
    salt,
    iv,
    encryptedKey,
    password: 'user-secure-password'
  });

  const decryptedKey = result.decryptedKey;
  // Now you can use this key to encrypt/decrypt secrets
  
}
```

## Architecture Overview

The library follows a layered security approach:

1. **Password Layer**: User passwords are processed through Argon2id
2. **Key Layer**: Generated encryption keys are protected by derived passwords
3. **Data Layer**: Actual secrets are encrypted using AES-GCM with the protected keys
4. **Recovery Layer**: Mnemonic phrases provide secure key recovery options

## Security Guarantees

- **Confidentiality**: AES-GCM provides strong encryption
- **Integrity**: Built-in authentication prevents tampering
- **Forward Secrecy**: Password rotation doesn't compromise old data
- **Recovery**: Secure mnemonic-based key recovery system
- **Brute Force Protection**: Configurable attempt limiting

## Next Steps

- [📖 Read the Quick Start Guide](/quickstart.md)
- [🔧 Explore Configuration Options](/configuration.md)
- [📚 Browse Function Documentation](/functions/)
- [🛡️ Learn About Security](/reference/security.md)