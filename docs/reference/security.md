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
| Mobile/Web | 2-3 | 32-64MB | User-facing applications |
| Server | 4-6 | 128-256MB | Backend processing |
| High Security | 8+ | 512MB+ | Maximum security requirements |

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
const masterKey = crypto.getRandomValues(new Uint8Array(32)); // 256-bit key
const salt = crypto.getRandomValues(new Uint8Array(32));      // 256-bit salt
const iv = crypto.getRandomValues(new Uint8Array(12));        // 96-bit IV
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

### Key Management

#### Key Lifecycle

```typescript
class SecureKeyManager {
  private keys = new Map<string, Uint8Array>();
  
  // Store key with expiration
  storeKey(userId: string, key: Uint8Array, ttlMs: number = 30 * 60 * 1000) {
    this.keys.set(userId, key);
    
    // Auto-expire keys
    setTimeout(() => {
      this.clearKey(userId);
    }, ttlMs);
  }
  
  // Securely clear key from memory
  clearKey(userId: string) {
    const key = this.keys.get(userId);
    if (key) {
      // Zero out the key data
      key.fill(0);
      this.keys.delete(userId);
    }
  }
  
  // Clear all keys on application shutdown
  clearAllKeys() {
    for (const [userId] of this.keys) {
      this.clearKey(userId);
    }
  }
}
```

#### Session Security

```typescript
interface SecureSession {
  userId: string;
  decryptedKey: Uint8Array;
  createdAt: Date;
  expiresAt: Date;
  ipAddress: string;
  userAgent: string;
}

class SessionManager {
  private sessions = new Map<string, SecureSession>();
  
  createSession(userId: string, decryptedKey: Uint8Array, request: Request): string {
    const sessionId = crypto.randomUUID();
    const now = new Date();
    
    this.sessions.set(sessionId, {
      userId,
      decryptedKey,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 30 * 60 * 1000), // 30 minutes
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown'
    });
    
    return sessionId;
  }
  
  validateSession(sessionId: string, request: Request): SecureSession | null {
    const session = this.sessions.get(sessionId);
    
    if (!session || session.expiresAt < new Date()) {
      this.clearSession(sessionId);
      return null;
    }
    
    // Optional: Validate IP and User-Agent for additional security
    const currentIP = request.headers.get('x-forwarded-for') || 'unknown';
    const currentUA = request.headers.get('user-agent') || 'unknown';
    
    if (session.ipAddress !== currentIP || session.userAgent !== currentUA) {
      this.clearSession(sessionId);
      return null;
    }
    
    return session;
  }
  
  clearSession(sessionId: string) {
    const session = this.sessions.get(sessionId);
    if (session) {
      // Zero out the key
      session.decryptedKey.fill(0);
      this.sessions.delete(sessionId);
    }
  }
}
```

### Data Protection

#### Secure Data Handling

```typescript
class SecureDataHandler {
  // Encrypt sensitive data before storage
  async storeSensitiveData(data: string, userKey: Uint8Array): Promise<void> {
    const result = await encryptSecret({
      secret: data,
      decryptedKey: userKey
    });
    
    if (result.success) {
      await this.saveToDatabase({
        encryptedSecret: result.encryptedSecret,
        iv: result.iv
      });
    }
    
    // Clear sensitive data from memory
    data = '';
  }
  
  // Retrieve and decrypt sensitive data
  async retrieveSensitiveData(recordId: string, userKey: Uint8Array): Promise<string | null> {
    const record = await this.getFromDatabase(recordId);
    if (!record) return null;
    
    const result = await decryptSecret({
      encryptedSecret: record.encryptedSecret,
      iv: record.iv,
      decryptedKey: userKey
    });
    
    return result.success ? result.decryptedSecret : null;
  }
}
```

#### Memory Security

```typescript
// Secure string handling
class SecureString {
  private data: Uint8Array;
  
  constructor(str: string) {
    this.data = new TextEncoder().encode(str);
  }
  
  toString(): string {
    return new TextDecoder().decode(this.data);
  }
  
  // Securely clear from memory
  clear(): void {
    this.data.fill(0);
  }
  
  // Auto-clear on garbage collection (best effort)
  finalize(): void {
    this.clear();
  }
}

// Usage
function handleSensitiveInput(input: string) {
  const secureInput = new SecureString(input);
  
  try {
    // Process the sensitive data
    processData(secureInput.toString());
  } finally {
    // Always clear sensitive data
    secureInput.clear();
    input = ''; // Clear original reference
  }
}
```

### Network Security

#### HTTPS Requirements

```typescript
// Enforce HTTPS in production
function enforceHTTPS(request: Request): void {
  if (process.env.NODE_ENV === 'production') {
    const protocol = request.headers.get('x-forwarded-proto') || 
                    new URL(request.url).protocol;
    
    if (protocol !== 'https:') {
      throw new Error('HTTPS required for cryptographic operations');
    }
  }
}
```

#### API Security

```typescript
// Rate limiting for sensitive operations
const rateLimiter = new Map<string, { count: number; resetTime: number }>();

function checkRateLimit(userId: string, operation: string, maxAttempts: number): boolean {
  const key = `${userId}:${operation}`;
  const now = Date.now();
  const windowMs = 60 * 60 * 1000; // 1 hour
  
  const current = rateLimiter.get(key);
  
  if (!current || current.resetTime < now) {
    rateLimiter.set(key, { count: 1, resetTime: now + windowMs });
    return true;
  }
  
  if (current.count >= maxAttempts) {
    return false;
  }
  
  current.count++;
  return true;
}

// Usage in API endpoints
app.post('/api/decrypt', async (req, res) => {
  const userId = req.user.id;
  
  if (!checkRateLimit(userId, 'decrypt', 100)) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  
  // Process request...
});
```

## Security Monitoring

### Audit Logging

```typescript
interface SecurityEvent {
  timestamp: Date;
  userId: string;
  eventType: 'login' | 'password_change' | 'recovery' | 'failed_attempt';
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details?: Record<string, any>;
}

class SecurityAuditor {
  async logEvent(event: SecurityEvent): Promise<void> {
    // Log to secure audit system
    await this.writeToAuditLog(event);
    
    // Alert on suspicious activity
    if (this.isSuspicious(event)) {
      await this.sendSecurityAlert(event);
    }
  }
  
  private isSuspicious(event: SecurityEvent): boolean {
    // Multiple failed attempts
    if (event.eventType === 'failed_attempt' && 
        this.getRecentFailures(event.userId) > 5) {
      return true;
    }
    
    // Login from new location
    if (event.eventType === 'login' && 
        this.isNewLocation(event.userId, event.ipAddress)) {
      return true;
    }
    
    return false;
  }
}
```

### Anomaly Detection

```typescript
class AnomalyDetector {
  async analyzeUserBehavior(userId: string, event: SecurityEvent): Promise<void> {
    const recentEvents = await this.getRecentEvents(userId, 24 * 60 * 60 * 1000);
    
    // Check for unusual patterns
    const anomalies = [
      this.detectUnusualTiming(recentEvents),
      this.detectUnusualLocation(recentEvents),
      this.detectUnusualFrequency(recentEvents)
    ].filter(Boolean);
    
    if (anomalies.length > 0) {
      await this.handleAnomalies(userId, anomalies);
    }
  }
  
  private async handleAnomalies(userId: string, anomalies: string[]): Promise<void> {
    // Log anomalies
    await this.logSecurityEvent({
      userId,
      eventType: 'anomaly_detected',
      details: { anomalies }
    });
    
    // Consider additional security measures
    await this.requireAdditionalAuthentication(userId);
  }
}
```

## Recovery Security

### Mnemonic Phrase Security

```typescript
// Secure mnemonic generation and validation
class MnemonicSecurity {
  static validatePhrase(phrase: string): boolean {
    const words = phrase.trim().toLowerCase().split(/\s+/);
    
    // Must be exactly 12 words
    if (words.length !== 12) return false;
    
    // Each word must be from BIP39 wordlist
    return words.every(word => BIP39_WORDLIST.includes(word));
  }
  
  static calculateEntropy(phrase: string): number {
    // 12 words from 2048-word list = 128 bits of entropy
    return 128;
  }
  
  static assessSecurity(phrase: string): 'weak' | 'strong' | 'very_strong' {
    if (!this.validatePhrase(phrase)) return 'weak';
    
    const entropy = this.calculateEntropy(phrase);
    if (entropy >= 128) return 'very_strong';
    if (entropy >= 96) return 'strong';
    return 'weak';
  }
}
```

### Recovery Process Security

```typescript
class SecureRecovery {
  async initiateRecovery(userId: string, request: Request): Promise<void> {
    // Rate limit recovery attempts
    if (!checkRateLimit(userId, 'recovery', 3)) {
      throw new Error('Too many recovery attempts');
    }
    
    // Log recovery initiation
    await this.logSecurityEvent({
      userId,
      eventType: 'recovery_initiated',
      ipAddress: this.getClientIP(request),
      userAgent: request.headers.get('user-agent')
    });
    
    // Optional: Send email notification
    await this.notifyRecoveryAttempt(userId);
  }
  
  async completeRecovery(userId: string, newPassword: string): Promise<void> {
    // Invalidate all existing sessions
    await this.invalidateAllSessions(userId);
    
    // Log successful recovery
    await this.logSecurityEvent({
      userId,
      eventType: 'recovery_completed',
      success: true
    });
    
    // Require password change on next login
    await this.setPasswordChangeRequired(userId);
  }
}
```

## Compliance and Standards

### Industry Standards

The library follows these security standards:

- **NIST SP 800-63B**: Digital Identity Guidelines for Authentication
- **OWASP**: Web Application Security Guidelines
- **RFC 9106**: Argon2 Password Hashing Specification
- **FIPS 140-2**: Cryptographic Module Validation

### Compliance Considerations

#### GDPR Compliance

```typescript
class GDPRCompliance {
  // Right to be forgotten
  async deleteUserData(userId: string): Promise<void> {
    // Delete encrypted data (keys become useless)
    await this.deleteUserVault(userId);
    await this.deleteUserSecrets(userId);
    
    // Clear audit logs (if legally permissible)
    await this.anonymizeAuditLogs(userId);
  }
  
  // Data portability
  async exportUserData(userId: string): Promise<any> {
    // Export only non-sensitive metadata
    return {
      userId,
      createdAt: await this.getUserCreationDate(userId),
      secretCount: await this.getUserSecretCount(userId),
      // Note: Encrypted data cannot be exported without user's password
    };
  }
}
```

## Security Testing

### Penetration Testing Checklist

- [ ] Password brute force resistance
- [ ] Timing attack resistance
- [ ] Memory dump analysis
- [ ] Network traffic analysis
- [ ] Session hijacking attempts
- [ ] CSRF protection
- [ ] XSS prevention
- [ ] SQL injection prevention

### Security Test Examples

```typescript
describe('Security Tests', () => {
  test('should resist timing attacks', async () => {
    const validPassword = 'correct-password';
    const invalidPassword = 'wrong-password';
    
    // Measure timing for valid password
    const start1 = performance.now();
    await decryptGeneratedKey({ password: validPassword, ...vaultData });
    const time1 = performance.now() - start1;
    
    // Measure timing for invalid password
    const start2 = performance.now();
    await decryptGeneratedKey({ password: invalidPassword, ...vaultData });
    const time2 = performance.now() - start2;
    
    // Times should be similar (within reasonable variance)
    const timeDifference = Math.abs(time1 - time2);
    expect(timeDifference).toBeLessThan(100); // 100ms tolerance
  });
  
  test('should prevent password enumeration', async () => {
    // Both valid and invalid users should take similar time
    const validUser = 'existing-user';
    const invalidUser = 'non-existent-user';
    
    const time1 = await measureLoginTime(validUser, 'wrong-password');
    const time2 = await measureLoginTime(invalidUser, 'any-password');
    
    const timeDifference = Math.abs(time1 - time2);
    expect(timeDifference).toBeLessThan(50);
  });
});
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