# Configuration

Cryptonism library uses Argon2id for key derivation with configurable parameters to balance security and performance.

## Argon2 Configuration

### Default Configuration

```typescript
export const defaultArgonConfig = {
  time: 3,      // Number of iterations
  mem: 65536,   // Memory usage in KB (64MB)
  hashLen: 32   // Output hash length in bytes
};
```

### Custom Configuration

You can override these defaults for specific security requirements:

```typescript
import { generateEncryptedKey } from 'cryptonism';

const customConfig = {
  time: 5,        // More iterations = slower but more secure
  mem: 131072,    // More memory = harder to attack (128MB)
  hashLen: 32     // Keep at 32 for AES-256
};

const result = await generateEncryptedKey({
  password: 'user-password',
  argonConfig: customConfig
});
```

## Parameter Guidelines

### Time Parameter (Iterations)

| Value | Security Level | Use Case |
|-------|---------------|----------|
| 1-2   | Low | Development/Testing |
| 3-4   | Medium | Standard Applications |
| 5-10  | High | High-Security Applications |
| 10+   | Very High | Maximum Security (slow) |

### Memory Parameter (KB)

| Value | Memory | Security Level |
|-------|--------|---------------|
| 32768 | 32MB | Minimum |
| 65536 | 64MB | Standard |
| 131072 | 128MB | High |
| 262144 | 256MB | Maximum |

### Hash Length

- **32 bytes**: Standard for AES-256 (recommended)
- **16 bytes**: For AES-128 (not recommended)
- **64 bytes**: For additional security margin

## Performance Considerations

### Client-Side Performance

```typescript
// For web browsers - lighter config
const browserConfig = {
  time: 2,
  mem: 32768,  // 32MB
  hashLen: 32
};
```


## Environment-Specific Configs

### Development

```typescript
const devConfig = {
  time: 1,      // Fast for development
  mem: 16384,   // 16MB
  hashLen: 32
};
```

### Production

```typescript
const prodConfig = {
  time: 4,      // Balanced security/performance
  mem: 65536,   // 64MB
  hashLen: 32
};
```

### High-Security

```typescript
// But slow and cause performance issue
const highSecConfig = {
  time: 8,      // Maximum reasonable iterations
  mem: 262144,  // 256MB
  hashLen: 32
};
```

## Benchmarking

Test different configurations in your environment:

```typescript
async function benchmarkConfig(config) {
  const start = performance.now();
  
  await generateEncryptedKey({
    password: 'test-password',
    argonConfig: config
  });
  
  const end = performance.now();
  console.log(`Config took ${end - start}ms`);
}

// Test different configurations
await benchmarkConfig({ time: 2, mem: 32768, hashLen: 32 });
await benchmarkConfig({ time: 4, mem: 65536, hashLen: 32 });
await benchmarkConfig({ time: 6, mem: 131072, hashLen: 32 });
```

## Security vs Performance Trade-offs

| Priority | Time | Memory | Performance | Security |
|----------|------|--------|-------------|----------|
| Speed | 1-2 | 16-32MB | Fast | Lower |
| Balanced | 3-4 | 64MB | Medium | Standard |
| Security | 5-8 | 128-256MB | Slow | High |

## Recommendations

1. **Start with defaults** and adjust based on your needs
2. **Test performance** in your target environment
3. **Consider user experience** - don't make login too slow
4. **Use stronger configs** for high-value data
5. **Document your choices** for future reference

## Next Steps

- [🔐 Learn About Core Functions](/functions/)
- [🛡️ Understand Security Model](/reference/security.md)
- [📊 See Performance Examples](/examples.md)