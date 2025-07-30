# Security Reference

This document outlines the security model, best practices, and considerations for the encryption utilities library.

## Security Architecture

### Layered Security Model

The library implements a multi-layered security approach:

```
┌─────────────────────────────────────┐
│           User Password             │ ← User Authentication Layer
├─────────────────────────────────────┤
│         Argon2id Hashing           │ ← Key Derivation Layer  
├─────────────────────────────────────┤
│        AES-GCM Encryption          │ ← Data Encryption Layer
├─────────────────────────────────────┤
│       Recovery System              │ ← Backup Access Layer
└─────────────────────────────────────┘
```

### Cryptographic Primitives

| Component | Algorithm | Key Size | Security Level |
|-----------|-----------|----------|----------------|
| Password Hashing | Argon2id | 256-bit | High |
| Symmetric Encryption | AES-GCM | 256-bit | High |
| Random Generation | Crypto.getRandomValues() | - | High |
| Key Derivation | PBKDF2 (via Argon2) | 256-bit | High |

## Threat Model

### Protected Against

✅ **Password Attacks**
- Brute force attacks (Argon2id memory-hardness)
- Dictionary attacks (strong password requirements)
- Rainbow table attacks (unique salts)

✅ **Data Tampering**
- Modification attacks (AES-GCM authentication)
- Bit-flipping attacks (authenticated encryption)
- Replay attacks (unique IVs)

✅ **Key Compromise**
- Forward secrecy (password rotation)
- Key recovery (mnemonic backup system)
- Session hijacking (proper key management)

### Attack Vectors Considered

⚠️ **Partially Protected**
- Side-channel attacks (depends on implementation environment)
- Timing attacks (constant-time operations where possible)
- Memory dumps (keys cleared after use, but not guaranteed)

❌ **Not Protected Against**
- Physical access to unlocked devices
- Malware with system-level access
- Compromised browser/runtime environment
- Social engineering attacks
- Quantum computing attacks (future threat)

## Cryptographic Details

### Password Hashing (Argon2id)

```typescript
// Default configuration provides strong security
const defaultArgonConfig = {
  time: 3,      // 3 iterations
  mem: 65536,   // 64MB memory usage
  hashLen: 32   // 256-bit output
};
```

**Security Properties:**
- **Memory-hard**: Requires significant RAM, making parallel attacks expensive
- **Time-hard**: Configurable iteration count increases computation time
- **Side-channel resistant**: Designed to resist timing and cache attacks

**Recommended Configurations:**

| Environment | Time | Memory | Use Case |
|-------------|------|--------|----------|
| Web | 2-3 | 32-64MB | User-facing applications |


### Encryption (AES-GCM)

```typescript
// AES-256-GCM provides authenticated encryption
const algorithm = {
  name: 'AES-GCM',
  iv: crypto.getRandomValues(new Uint8Array(12)), // 96-bit IV
  tagLength: 128 // 128-bit authentication tag
};
```

**Security Properties:**
- **Confidentiality**: AES-256 encryption prevents data disclosure
- **Integrity**: GCM mode detects any data modification
- **Authenticity**: Authentication tag prevents forgery
- **Uniqueness**: Random IVs prevent pattern analysis

### Key Generation

```typescript
// Cryptographically secure random key generation
const key = crypto.getRandomValues(new Uint8Array(32));   // 256-bit key
const salt = crypto.getRandomValues(new Uint8Array(32));  // 256-bit salt
const iv = crypto.getRandomValues(new Uint8Array(12));    // 96-bit IV
```

**Security Properties:**
- **Entropy**: Uses system's cryptographically secure random number generator
- **Uniqueness**: Each key, salt, and IV is randomly generated
- **Independence**: No correlation between generated values

## Security Best Practices

### Password Security

#### Strong Password Requirements

```typescript
interface PasswordPolicy {
  minLength: number;        // Minimum 12 characters
  requireUppercase: boolean; // At least one A-Z
  requireLowercase: boolean; // At least one a-z
  requireNumbers: boolean;   // At least one 0-9
  requireSymbols: boolean;   // At least one special character
  preventCommon: boolean;    // Block common passwords
  preventPersonal: boolean;  // Block personal information
}

function validatePassword(password: string, policy: PasswordPolicy): boolean {
  if (password.length < policy.minLength) return false;
  if (policy.requireUppercase && !/[A-Z]/.test(password)) return false;
  if (policy.requireLowercase && !/[a-z]/.test(password)) return false;
  if (policy.requireNumbers && !/[0-9]/.test(password)) return false;
  if (policy.requireSymbols && !/[^A-Za-z0-9]/.test(password)) return false;
  
  // Additional checks for common/personal passwords
  return true;
}
```

#### Password Storage

```typescript
// ❌ NEVER store passwords
const user = {
  id: 'user-123',
  email: 'user@example.com',
  // password: 'never-store-this', // NEVER DO THIS
  
  // ✅ Store only encrypted vault data
  vault: {
    encryptedKey: 'base64-encrypted-key',
    salt: 'base64-salt',
    iv: 'base64-iv'
  }
};
```

## Security Recommendations

### For Developers

1. **Always use HTTPS** in production environments
2. **Implement proper session management** with secure cookies
3. **Use rate limiting** for all authentication endpoints
4. **Log security events** for monitoring and compliance
5. **Regularly update dependencies** to patch security vulnerabilities
6. **Implement proper error handling** without information disclosure
7. **Use Content Security Policy (CSP)** headers
8. **Validate all inputs** before processing

### For Users

1. **Use strong, unique passwords** for each account
2. **Store recovery phrases securely offline** (paper, hardware wallet)
3. **Enable two-factor authentication** where available
4. **Keep software updated** to latest versions
5. **Use trusted devices** for sensitive operations
6. **Be aware of phishing attempts**
7. **Report suspicious activity** immediately

### For Organizations

1. **Conduct regular security audits** and penetration testing
2. **Implement security monitoring** and alerting systems
3. **Train staff** on security best practices
4. **Maintain incident response procedures**
5. **Ensure compliance** with relevant regulations
6. **Use secure development practices** (SAST, DAST, code reviews)
7. **Implement defense in depth** strategies

## Next Steps

- [📚 Review Function Documentation](/functions/)
- [⚠️ Understand Error Handling](/reference/errors.md)
- [🔧 See Implementation Examples](/examples.md)