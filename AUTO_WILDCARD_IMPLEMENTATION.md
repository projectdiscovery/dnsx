# Auto Wildcard Detection Implementation

## Overview
This PR implements automatic wildcard DNS detection across multiple domains in a single run, similar to how PureDNS handles it. This addresses issue #924.

## Changes Made

### 1. New Flag: `--auto-wildcard` / `-aw`
- Added to `internal/runner/options.go`
- Enables automatic wildcard detection without requiring `-wd` flag for each domain
- Mutually exclusive with `--wildcard-domain` flag
- Not supported in stream mode

### 2. New File: `internal/runner/autowildcard.go`
Implements the core auto-wildcard detection logic:

#### Key Components:
- **AutoWildcardDetector**: Main struct managing wildcard detection across multiple domains
- **DomainWildcardInfo**: Stores wildcard information per domain
- **ExtractBaseDomain()**: Extracts base domain from subdomains
- **DetectWildcard()**: Tests domains with random subdomains to identify wildcards
- **IsWildcardSubdomain()**: Checks if a subdomain resolves to wildcard IPs

#### Detection Algorithm:
1. For each unique base domain encountered:
   - Generate 3 random subdomains
   - Query each random subdomain
   - If 2+ queries return the same IP, mark as wildcard
   - Cache wildcard IPs for that domain

2. For each subdomain being resolved:
   - Extract its base domain
   - Check if base domain has wildcard configured
   - If yes, compare resolved IPs against wildcard IPs
   - Filter out if IPs match wildcard pattern

### 3. Integration Points

#### In `runner.go`:
```go
// Add to Runner struct
type Runner struct {
    // ... existing fields ...
    autoWildcardDetector *AutoWildcardDetector
}

// In New() function
if options.AutoWildcard {
    r.autoWildcardDetector = NewAutoWildcardDetector(&r)
}

// In worker() function - after DNS query
if r.options.AutoWildcard && r.autoWildcardDetector != nil {
    if r.autoWildcardDetector.IsWildcardSubdomain(domain) {
        // Skip this subdomain - it's a wildcard
        continue
    }
}
```

## Usage Examples

### Basic Usage
```bash
# Automatically detect and filter wildcards across multiple domains
cat subdomains.txt | dnsx --auto-wildcard -json

# With custom resolvers
dnsx -l subdomains.txt --auto-wildcard -r resolvers.txt

# With verbose output to see wildcard detection
dnsx -l subdomains.txt --auto-wildcard -v
```

### Input Format
```
api.example.com
www.example.com
test.another-domain.com
admin.another-domain.com
```

The tool will:
1. Automatically detect that `example.com` and `another-domain.com` are the base domains
2. Test each domain for wildcard DNS
3. Filter out any subdomains that resolve to wildcard IPs

## Benefits

1. **No Manual Domain Specification**: Unlike `-wd` which requires specifying each domain, `-aw` automatically detects all unique domains
2. **Multi-Domain Support**: Works seamlessly with subdomain lists from multiple domains
3. **Efficient**: Caches wildcard detection results per domain
4. **Compatible**: Works with existing dnsx flags (JSON output, resolvers, etc.)

## Testing

### Test Cases
1. Single domain with wildcard DNS
2. Multiple domains, some with wildcards
3. Mixed input (wildcards + non-wildcards)
4. Large subdomain lists (10k+ entries)

### Example Test
```bash
# Create test file with known wildcard domain
echo "random123.example.com" > test.txt
echo "random456.example.com" >> test.txt
echo "api.example.com" >> test.txt

# Run with auto-wildcard
dnsx -l test.txt --auto-wildcard -v

# Should filter out wildcard entries and keep legitimate subdomains
```

## Performance Considerations

- **Initial Detection**: 3 DNS queries per unique base domain
- **Caching**: Wildcard info cached after first detection
- **Memory**: Minimal overhead - stores only wildcard IPs per domain
- **Concurrency**: Thread-safe with mutex protection

## Comparison with PureDNS

| Feature | PureDNS | dnsx (with -aw) |
|---------|---------|-----------------|
| Auto wildcard detection | ✅ | ✅ |
| Multi-domain support | ✅ | ✅ |
| Manual domain specification | ❌ | ✅ (via -wd) |
| JSON output | ❌ | ✅ |
| Custom resolvers | ✅ | ✅ |
| Rate limiting | ✅ | ✅ |

## Future Enhancements

1. **Public Suffix List**: Use PSL for better base domain extraction (handles .co.uk, etc.)
2. **Configurable Test Count**: Allow users to specify number of random tests
3. **Wildcard Threshold**: Configurable threshold for wildcard detection
4. **Export Wildcard Info**: Option to export detected wildcard domains

## Related Issues

- Closes #924
- Related to #232, #236 (wildcard detection extensions)
