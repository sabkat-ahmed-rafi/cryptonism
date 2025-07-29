# Examples

This page provides comprehensive examples showing how to use the encryption utilities library in real-world scenarios.

## Complete User Registration Flow

### Backend Implementation

```typescript
import { generateEncryptedKey, encryptSecret } from '@your-org/encryption-utils';

interface UserRegistration {
  email: string;
  password: string;
  confirmPassword: string;
}

async function registerUser(userData: UserRegistration) {
  // 1. Validate input
  if (userData.password !== userData.confirmPassword) {
    throw new Error('Passwords do not match');
  }
  
  if (!isPasswordStrong(userData.password)) {
    throw new Error('Password does not meet security requirements');
  }
  
  // 2. Generate encrypted key system
  const keyResult = await generateEncryptedKey({
    password: userData.password,
    argonConfig: {
      time: 4,
      mem: 65536,
      hashLen: 32
    }
  });
  
  if (!keyResult.success) {
    throw new Error('Failed to generate encryption key');
  }
  
  // 3. Create user record
  const userId = crypto.randomUUID();
  const user = await createUser({
    id: userId,
    email: userData.email,
    createdAt: new Date()
  });
  
  // 4. Store vault data
  await createUserVault({
    userId: userId,
    encryptedKey: keyResult.encryptedKey,
    salt: keyResult.salt,
    iv: keyResult.iv,
    encryptedRecoveryKey: keyResult.encryptedRecoveryKey,
    recoverySalt: keyResult.recoverySalt,
    recoveryIV: keyResult.recoveryIV
  });
  
  // 5. Return success with recovery phrase (show only once!)
  return {
    success: true,
    userId: userId,
    recoveryPhrase: keyResult.recoveryPhrase,
    message: 'Account created successfully. Please save your recovery phrase!'
  };
}

function isPasswordStrong(password: string): boolean {
  return password.length >= 12 && 
         /[A-Z]/.test(password) && 
         /[a-z]/.test(password) && 
         /[0-9]/.test(password) && 
         /[^A-Za-z0-9]/.test(password);
}
```

### Frontend React Component

```typescript
import React, { useState } from 'react';

function RegistrationForm() {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [recoveryPhrase, setRecoveryPhrase] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });
      
      const result = await response.json();
      
      if (result.success) {
        setRecoveryPhrase(result.recoveryPhrase);
      } else {
        setError(result.error);
      }
    } catch (err) {
      setError('Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  if (recoveryPhrase) {
    return (
      <div className="recovery-display">
        <h2>✅ Account Created Successfully!</h2>
        <div className="recovery-phrase-container">
          <h3>🔑 Your Recovery Phrase</h3>
          <p className="warning">
            ⚠️ Write this down and store it safely. You'll need it to recover your account if you forget your password.
          </p>
          <div className="recovery-phrase">
            {recoveryPhrase}
          </div>
          <div className="recovery-actions">
            <button onClick={() => navigator.clipboard.writeText(recoveryPhrase)}>
              Copy to Clipboard
            </button>
            <button onClick={() => window.location.href = '/login'}>
              I've Saved It - Continue to Login
            </button>
          </div>
        </div>
      </div>
    );
  }
  
  return (
    <form onSubmit={handleSubmit}>
      <h2>Create Account</h2>
      
      <div>
        <label>Email:</label>
        <input
          type="email"
          value={formData.email}
          onChange={(e) => setFormData({...formData, email: e.target.value})}
          required
        />
      </div>
      
      <div>
        <label>Password:</label>
        <input
          type="password"
          value={formData.password}
          onChange={(e) => setFormData({...formData, password: e.target.value})}
          required
        />
        <small>At least 12 characters with mixed case, numbers, and symbols</small>
      </div>
      
      <div>
        <label>Confirm Password:</label>
        <input
          type="password"
          value={formData.confirmPassword}
          onChange={(e) => setFormData({...formData, confirmPassword: e.target.value})}
          required
        />
      </div>
      
      {error && <div className="error">{error}</div>}
      
      <button type="submit" disabled={loading}>
        {loading ? 'Creating Account...' : 'Create Account'}
      </button>
    </form>
  );
}
```

## User Login and Session Management

### Backend Session Handler

```typescript
import { decryptGeneratedKey } from '@your-org/encryption-utils';

interface LoginRequest {
  email: string;
  password: string;
}

class SessionManager {
  private sessions = new Map<string, {
    userId: string;
    decryptedKey: Uint8Array;
    expiresAt: Date;
  }>();
  
  async login(loginData: LoginRequest): Promise<{
    success: boolean;
    sessionToken?: string;
    error?: string;
  }> {
    try {
      // 1. Find user by email
      const user = await getUserByEmail(loginData.email);
      if (!user) {
        // Don't reveal if user exists
        await this.simulatePasswordCheck();
        return { success: false, error: 'Invalid credentials' };
      }
      
      // 2. Get user's vault
      const vault = await getUserVault(user.id);
      if (!vault) {
        return { success: false, error: 'Account setup incomplete' };
      }
      
      // 3. Attempt to decrypt key
      const unlockResult = await decryptGeneratedKey({
        salt: vault.salt,
        iv: vault.iv,
        encryptedKey: vault.encryptedKey,
        password: loginData.password,
        trackAttempts: {
          enable: true,
          id: user.id,
          maxAttempts: 5
        }
      });
      
      if (!unlockResult.success) {
        await this.logFailedLogin(user.id, unlockResult.attempts);
        
        if (unlockResult.attempts >= 5) {
          await this.lockAccount(user.id);
          return { success: false, error: 'Account locked due to too many failed attempts' };
        }
        
        return { 
          success: false, 
          error: `Invalid password. ${5 - unlockResult.attempts} attempts remaining.` 
        };
      }
      
      // 4. Create session
      const sessionToken = crypto.randomUUID();
      this.sessions.set(sessionToken, {
        userId: user.id,
        decryptedKey: unlockResult.decryptedKey,
        expiresAt: new Date(Date.now() + 30 * 60 * 1000) // 30 minutes
      });
      
      // 5. Log successful login
      await this.logSuccessfulLogin(user.id);
      
      return { success: true, sessionToken };
      
    } catch (error) {
      console.error('Login error:', error);
      return { success: false, error: 'Login failed' };
    }
  }
  
  getSession(sessionToken: string): { userId: string; decryptedKey: Uint8Array } | null {
    const session = this.sessions.get(sessionToken);
    
    if (!session || session.expiresAt < new Date()) {
      this.clearSession(sessionToken);
      return null;
    }
    
    return {
      userId: session.userId,
      decryptedKey: session.decryptedKey
    };
  }
  
  clearSession(sessionToken: string): void {
    const session = this.sessions.get(sessionToken);
    if (session) {
      // Zero out the key
      session.decryptedKey.fill(0);
      this.sessions.delete(sessionToken);
    }
  }
  
  private async simulatePasswordCheck(): Promise<void> {
    // Simulate Argon2 computation to prevent timing attacks
    await new Promise(resolve => setTimeout(resolve, 200));
  }
}
```

### Frontend Login Component

```typescript
import React, { useState, useContext } from 'react';

interface AuthContextType {
  sessionToken: string | null;
  login: (token: string) => void;
  logout: () => void;
}

const AuthContext = React.createContext<AuthContextType | null>(null);

function LoginForm() {
  const [credentials, setCredentials] = useState({ email: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const auth = useContext(AuthContext);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials)
      });
      
      const result = await response.json();
      
      if (result.success) {
        auth?.login(result.sessionToken);
        window.location.href = '/dashboard';
      } else {
        setError(result.error);
      }
    } catch (err) {
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <h2>Login</h2>
      
      <div>
        <label>Email:</label>
        <input
          type="email"
          value={credentials.email}
          onChange={(e) => setCredentials({...credentials, email: e.target.value})}
          required
        />
      </div>
      
      <div>
        <label>Password:</label>
        <input
          type="password"
          value={credentials.password}
          onChange={(e) => setCredentials({...credentials, password: e.target.value})}
          required
        />
      </div>
      
      {error && <div className="error">{error}</div>}
      
      <button type="submit" disabled={loading}>
        {loading ? 'Logging in...' : 'Login'}
      </button>
      
      <div className="login-links">
        <a href="/forgot-password">Forgot Password?</a>
        <a href="/register">Create Account</a>
      </div>
    </form>
  );
}
```

## Secret Management System

### Backend API

```typescript
import { encryptSecret, decryptSecret } from '@your-org/encryption-utils';

interface SecretData {
  name: string;
  secret: string;
  category?: string;
  notes?: string;
}

class SecretManager {
  async createSecret(
    sessionToken: string, 
    secretData: SecretData
  ): Promise<{ success: boolean; secretId?: string; error?: string }> {
    try {
      // 1. Validate session
      const session = sessionManager.getSession(sessionToken);
      if (!session) {
        return { success: false, error: 'Invalid session' };
      }
      
      // 2. Encrypt the secret
      const encryptResult = await encryptSecret({
        secret: secretData.secret,
        decryptedKey: session.decryptedKey
      });
      
      if (!encryptResult.success) {
        return { success: false, error: 'Failed to encrypt secret' };
      }
      
      // 3. Store encrypted secret
      const secretId = crypto.randomUUID();
      await this.saveSecret({
        id: secretId,
        userId: session.userId,
        name: secretData.name,
        category: secretData.category || 'general',
        notes: secretData.notes || '',
        encryptedSecret: encryptResult.encryptedSecret,
        iv: encryptResult.iv,
        createdAt: new Date()
      });
      
      return { success: true, secretId };
      
    } catch (error) {
      console.error('Create secret error:', error);
      return { success: false, error: 'Failed to create secret' };
    }
  }
  
  async getSecret(
    sessionToken: string, 
    secretId: string
  ): Promise<{ success: boolean; secret?: SecretData & { id: string }; error?: string }> {
    try {
      // 1. Validate session
      const session = sessionManager.getSession(sessionToken);
      if (!session) {
        return { success: false, error: 'Invalid session' };
      }
      
      // 2. Get encrypted secret from database
      const secretRecord = await this.getSecretRecord(secretId, session.userId);
      if (!secretRecord) {
        return { success: false, error: 'Secret not found' };
      }
      
      // 3. Decrypt the secret
      const decryptResult = await decryptSecret({
        encryptedSecret: secretRecord.encryptedSecret,
        iv: secretRecord.iv,
        decryptedKey: session.decryptedKey
      });
      
      if (!decryptResult.success) {
        return { success: false, error: 'Failed to decrypt secret' };
      }
      
      return {
        success: true,
        secret: {
          id: secretRecord.id,
          name: secretRecord.name,
          secret: decryptResult.decryptedSecret,
          category: secretRecord.category,
          notes: secretRecord.notes
        }
      };
      
    } catch (error) {
      console.error('Get secret error:', error);
      return { success: false, error: 'Failed to retrieve secret' };
    }
  }
  
  async listSecrets(sessionToken: string): Promise<{
    success: boolean;
    secrets?: Array<{ id: string; name: string; category: string; createdAt: Date }>;
    error?: string;
  }> {
    try {
      const session = sessionManager.getSession(sessionToken);
      if (!session) {
        return { success: false, error: 'Invalid session' };
      }
      
      // Return only metadata (no encrypted secrets)
      const secrets = await this.getSecretMetadata(session.userId);
      
      return { success: true, secrets };
      
    } catch (error) {
      console.error('List secrets error:', error);
      return { success: false, error: 'Failed to list secrets' };
    }
  }
}
```

### Frontend Secret Manager

```typescript
import React, { useState, useEffect } from 'react';

interface Secret {
  id: string;
  name: string;
  category: string;
  createdAt: Date;
}

interface SecretDetail extends Secret {
  secret: string;
  notes: string;
}

function SecretManager() {
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [selectedSecret, setSelectedSecret] = useState<SecretDetail | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [loading, setLoading] = useState(true);
  
  useEffect(() => {
    loadSecrets();
  }, []);
  
  const loadSecrets = async () => {
    try {
      const response = await fetch('/api/secrets', {
        headers: {
          'Authorization': `Bearer ${getSessionToken()}`
        }
      });
      
      const result = await response.json();
      if (result.success) {
        setSecrets(result.secrets);
      }
    } catch (error) {
      console.error('Failed to load secrets:', error);
    } finally {
      setLoading(false);
    }
  };
  
  const viewSecret = async (secretId: string) => {
    try {
      const response = await fetch(`/api/secrets/${secretId}`, {
        headers: {
          'Authorization': `Bearer ${getSessionToken()}`
        }
      });
      
      const result = await response.json();
      if (result.success) {
        setSelectedSecret(result.secret);
      }
    } catch (error) {
      console.error('Failed to load secret:', error);
    }
  };
  
  const createSecret = async (secretData: {
    name: string;
    secret: string;
    category: string;
    notes: string;
  }) => {
    try {
      const response = await fetch('/api/secrets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getSessionToken()}`
        },
        body: JSON.stringify(secretData)
      });
      
      const result = await response.json();
      if (result.success) {
        setShowCreateForm(false);
        loadSecrets(); // Refresh list
      }
    } catch (error) {
      console.error('Failed to create secret:', error);
    }
  };
  
  if (loading) {
    return <div>Loading secrets...</div>;
  }
  
  return (
    <div className="secret-manager">
      <div className="secret-list">
        <div className="list-header">
          <h2>Your Secrets</h2>
          <button onClick={() => setShowCreateForm(true)}>
            Add New Secret
          </button>
        </div>
        
        {secrets.map(secret => (
          <div 
            key={secret.id} 
            className="secret-item"
            onClick={() => viewSecret(secret.id)}
          >
            <h3>{secret.name}</h3>
            <span className="category">{secret.category}</span>
            <span className="date">{new Date(secret.createdAt).toLocaleDateString()}</span>
          </div>
        ))}
      </div>
      
      <div className="secret-detail">
        {selectedSecret ? (
          <SecretDetailView 
            secret={selectedSecret} 
            onClose={() => setSelectedSecret(null)}
          />
        ) : (
          <div className="no-selection">
            Select a secret to view details
          </div>
        )}
      </div>
      
      {showCreateForm && (
        <CreateSecretForm 
          onSubmit={createSecret}
          onCancel={() => setShowCreateForm(false)}
        />
      )}
    </div>
  );
}

function SecretDetailView({ 
  secret, 
  onClose 
}: { 
  secret: SecretDetail; 
  onClose: () => void; 
}) {
  const [showSecret, setShowSecret] = useState(false);
  
  const copyToClipboard = () => {
    navigator.clipboard.writeText(secret.secret);
    // Show toast notification
  };
  
  return (
    <div className="secret-detail-view">
      <div className="detail-header">
        <h2>{secret.name}</h2>
        <button onClick={onClose}>×</button>
      </div>
      
      <div className="detail-content">
        <div className="field">
          <label>Category:</label>
          <span>{secret.category}</span>
        </div>
        
        <div className="field">
          <label>Secret:</label>
          <div className="secret-field">
            {showSecret ? (
              <span className="secret-value">{secret.secret}</span>
            ) : (
              <span className="secret-hidden">••••••••••••</span>
            )}
            <button onClick={() => setShowSecret(!showSecret)}>
              {showSecret ? 'Hide' : 'Show'}
            </button>
            <button onClick={copyToClipboard}>Copy</button>
          </div>
        </div>
        
        {secret.notes && (
          <div className="field">
            <label>Notes:</label>
            <p>{secret.notes}</p>
          </div>
        )}
        
        <div className="field">
          <label>Created:</label>
          <span>{new Date(secret.createdAt).toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
}

function CreateSecretForm({ 
  onSubmit, 
  onCancel 
}: { 
  onSubmit: (data: any) => void; 
  onCancel: () => void; 
}) {
  const [formData, setFormData] = useState({
    name: '',
    secret: '',
    category: 'general',
    notes: ''
  });
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(formData);
  };
  
  return (
    <div className="modal-overlay">
      <div className="modal">
        <form onSubmit={handleSubmit}>
          <h2>Add New Secret</h2>
          
          <div>
            <label>Name:</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({...formData, name: e.target.value})}
              required
            />
          </div>
          
          <div>
            <label>Secret:</label>
            <textarea
              value={formData.secret}
              onChange={(e) => setFormData({...formData, secret: e.target.value})}
              required
            />
          </div>
          
          <div>
            <label>Category:</label>
            <select
              value={formData.category}
              onChange={(e) => setFormData({...formData, category: e.target.value})}
            >
              <option value="general">General</option>
              <option value="passwords">Passwords</option>
              <option value="api-keys">API Keys</option>
              <option value="certificates">Certificates</option>
            </select>
          </div>
          
          <div>
            <label>Notes:</label>
            <textarea
              value={formData.notes}
              onChange={(e) => setFormData({...formData, notes: e.target.value})}
            />
          </div>
          
          <div className="form-actions">
            <button type="submit">Create Secret</button>
            <button type="button" onClick={onCancel}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}
```

## Password Change Flow

### Backend Implementation

```typescript
import { rotatePassword } from '@your-org/encryption-utils';

async function changePassword(
  sessionToken: string,
  oldPassword: string,
  newPassword: string
): Promise<{ success: boolean; error?: string }> {
  try {
    // 1. Validate session
    const session = sessionManager.getSession(sessionToken);
    if (!session) {
      return { success: false, error: 'Invalid session' };
    }
    
    // 2. Validate new password
    if (!isPasswordStrong(newPassword)) {
      return { 
        success: false, 
        error: 'New password must be at least 12 characters with mixed case, numbers, and symbols' 
      };
    }
    
    // 3. Get current vault data
    const vault = await getUserVault(session.userId);
    if (!vault) {
      return { success: false, error: 'Vault not found' };
    }
    
    // 4. Rotate password
    const rotateResult = await rotatePassword({
      encryptedKey: vault.encryptedKey,
      salt: vault.salt,
      iv: vault.iv,
      oldPassword: oldPassword,
      newPassword: newPassword
    });
    
    if (!rotateResult.success) {
      return { success: false, error: 'Current password is incorrect' };
    }
    
    // 5. Update vault in database
    await updateUserVault(session.userId, {
      encryptedKey: rotateResult.encryptedKey,
      salt: rotateResult.salt,
      iv: rotateResult.iv,
      updatedAt: new Date()
    });
    
    // 6. Invalidate all other sessions (force re-login)
    await sessionManager.invalidateAllSessionsExcept(sessionToken, session.userId);
    
    // 7. Log security event
    await logSecurityEvent({
      userId: session.userId,
      eventType: 'password_changed',
      timestamp: new Date()
    });
    
    return { success: true };
    
  } catch (error) {
    console.error('Password change error:', error);
    return { success: false, error: 'Failed to change password' };
  }
}
```

### Frontend Password Change Form

```typescript
import React, { useState } from 'react';

function PasswordChangeForm() {
  const [passwords, setPasswords] = useState({
    current: '',
    new: '',
    confirm: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);
  
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    
    // Validate passwords match
    if (passwords.new !== passwords.confirm) {
      setError('New passwords do not match');
      setLoading(false);
      return;
    }
    
    try {
      const response = await fetch('/api/change-password', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${getSessionToken()}`
        },
        body: JSON.stringify({
          oldPassword: passwords.current,
          newPassword: passwords.new
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        setSuccess(true);
        setPasswords({ current: '', new: '', confirm: '' });
      } else {
        setError(result.error);
      }
    } catch (err) {
      setError('Failed to change password. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  if (success) {
    return (
      <div className="success-message">
        <h2>✅ Password Changed Successfully</h2>
        <p>Your password has been updated. All other sessions have been logged out for security.</p>
        <button onClick={() => setSuccess(false)}>Change Another Password</button>
      </div>
    );
  }
  
  return (
    <form onSubmit={handleSubmit}>
      <h2>Change Password</h2>
      
      <div>
        <label>Current Password:</label>
        <input
          type="password"
          value={passwords.current}
          onChange={(e) => setPasswords({...passwords, current: e.target.value})}
          required
        />
      </div>
      
      <div>
        <label>New Password:</label>
        <input
          type="password"
          value={passwords.new}
          onChange={(e) => setPasswords({...passwords, new: e.target.value})}
          required
        />
        <small>At least 12 characters with mixed case, numbers, and symbols</small>
      </div>
      
      <div>
        <label>Confirm New Password:</label>
        <input
          type="password"
          value={passwords.confirm}
          onChange={(e) => setPasswords({...passwords, confirm: e.target.value})}
          required
        />
      </div>
      
      {error && <div className="error">{error}</div>}
      
      <button type="submit" disabled={loading}>
        {loading ? 'Changing Password...' : 'Change Password'}
      </button>
    </form>
  );
}
```

## Account Recovery Flow

### Complete Recovery Implementation

```typescript
import { recoverEncryptedKey, rotatePasswordAfterRecovery } from '@your-org/encryption-utils';

async function recoverAccount(
  email: string,
  recoveryPhrase: string,
  newPassword: string
): Promise<{ success: boolean; error?: string }> {
  try {
    // 1. Find user by email
    const user = await getUserByEmail(email);
    if (!user) {
      // Don't reveal if user exists
      return { success: false, error: 'Invalid recovery information' };
    }
    
    // 2. Get recovery data
    const recoveryData = await getUserRecoveryData(user.id);
    if (!recoveryData) {
      return { success: false, error: 'No recovery data found' };
    }
    
    // 3. Validate recovery phrase format
    const words = recoveryPhrase.trim().split(/\s+/);
    if (words.length !== 12) {
      return { success: false, error: 'Recovery phrase must be exactly 12 words' };
    }
    
    // 4. Attempt key recovery
    const recoverResult = await recoverEncryptedKey({
      recoveryMnemonic: recoveryPhrase,
      encryptedRecoveryKey: recoveryData.encryptedRecoveryKey,
      recoverySalt: recoveryData.recoverySalt,
      recoveryIV: recoveryData.recoveryIV
    });
    
    if (!recoverResult.success) {
      await logFailedRecovery(user.id);
      return { success: false, error: 'Invalid recovery phrase' };
    }
    
    // 5. Set new password
    const rotateResult = await rotatePasswordAfterRecovery({
      recoveredDecryptedKey: recoverResult.decryptedKey,
      newPassword: newPassword
    });
    
    if (!rotateResult.success) {
      return { success: false, error: 'Failed to set new password' };
    }
    
    // 6. Update vault with new password
    await updateUserVault(user.id, {
      encryptedKey: rotateResult.encryptedKey,
      salt: rotateResult.salt,
      iv: rotateResult.iv,
      recoveredAt: new Date()
    });
    
    // 7. Invalidate all existing sessions
    await sessionManager.invalidateAllSessions(user.id);
    
    // 8. Log successful recovery
    await logSuccessfulRecovery(user.id);
    
    return { success: true };
    
  } catch (error) {
    console.error('Account recovery error:', error);
    return { success: false, error: 'Recovery failed' };
  }
}
```

### Frontend Recovery Component

```typescript
import React, { useState } from 'react';

function AccountRecovery() {
  const [step, setStep] = useState<'email' | 'recovery' | 'password' | 'success'>('email');
  const [email, setEmail] = useState('');
  const [recoveryPhrase, setRecoveryPhrase] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setStep('recovery');
  };
  
  const handleRecoverySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    
    if (!isPasswordStrong(newPassword)) {
      setError('Password must be at least 12 characters with mixed case, numbers, and symbols');
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch('/api/recover-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          recoveryPhrase: recoveryPhrase.trim(),
          newPassword
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        setStep('success');
      } else {
        setError(result.error);
      }
    } catch (err) {
      setError('Recovery failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };
  
  if (step === 'email') {
    return (
      <form onSubmit={handleEmailSubmit}>
        <h2>Account Recovery</h2>
        <p>Enter your email address to begin account recovery.</p>
        
        <div>
          <label>Email Address:</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        
        <button type="submit">Continue</button>
        <a href="/login">Back to Login</a>
      </form>
    );
  }
  
  if (step === 'recovery') {
    return (
      <form onSubmit={handleRecoverySubmit}>
        <h2>Enter Recovery Information</h2>
        
        <div>
          <label>Recovery Phrase (12 words):</label>
          <textarea
            value={recoveryPhrase}
            onChange={(e) => setRecoveryPhrase(e.target.value)}
            placeholder="Enter your 12-word recovery phrase..."
            rows={3}
            required
          />
          <small>Enter the 12-word phrase you saved when creating your account</small>
        </div>
        
        <div>
          <label>New Password:</label>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
          />
        </div>
        
        <div>
          <label>Confirm New Password:</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
          />
        </div>
        
        {error && <div className="error">{error}</div>}
        
        <button type="submit" disabled={loading}>
          {loading ? 'Recovering Account...' : 'Recover Account'}
        </button>
        
        <button type="button" onClick={() => setStep('email')}>
          Back
        </button>
      </form>
    );
  }
  
  if (step === 'success') {
    return (
      <div className="success-message">
        <h2>✅ Account Recovered Successfully!</h2>
        <p>Your account has been recovered and your new password has been set.</p>
        <p>You can now log in with your new password.</p>
        <button onClick={() => window.location.href = '/login'}>
          Go to Login
        </button>
      </div>
    );
  }
  
  return null;
}
```

## Database Schema Examples

### PostgreSQL Schema

```sql
-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- User vaults (encrypted key storage)
CREATE TABLE user_vaults (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  encrypted_key TEXT NOT NULL,
  salt TEXT NOT NULL,
  iv TEXT NOT NULL,
  encrypted_recovery_key TEXT NOT NULL,
  recovery_salt TEXT NOT NULL,
  recovery_iv TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  recovered_at TIMESTAMP
);

-- Encrypted secrets
CREATE TABLE user_secrets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  category VARCHAR(100) DEFAULT 'general',
  notes TEXT,
  encrypted_secret TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Security audit log
CREATE TABLE security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  event_type VARCHAR(50) NOT NULL,
  success BOOLEAN DEFAULT true,
  ip_address INET,
  user_agent TEXT,
  details JSONB,
  timestamp TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX idx_user_secrets_user_id ON user_secrets(user_id);
CREATE INDEX idx_user_secrets_category ON user_secrets(category);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_type ON security_events(event_type);
```

## Next Steps

- [📚 Explore Function Documentation](/functions/)
- [🛡️ Review Security Best Practices](/reference/security.md)
- [⚠️ Understand Error Handling](/reference/errors.md)
- [🔧 Learn About Configuration](/configuration.md)