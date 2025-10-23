# zig-jks

Java KeyStore (JKS) encoder/decoder in pure Zig.

## Overview

Read and write JKS files (the keystore format used by Java). Fully compatible with Java's keytool and the JKS spec.

## Features

- Read/write JKS v1 and v2 files
- Private key entries and trusted certificates
- Sun's proprietary key encryption algorithm
- Configurable alias handling (case-sensitive, ordered)
- Password policies (minimum length, etc)
- Zero dependencies - just Zig stdlib
- Comprehensive test suite

## Requirements

- Zig 0.15.1 or later

## Installation

Add this to your `build.zig.zon`:

```zig
.dependencies = .{
    .jks = .{
        .url = "https://github.com/yourusername/zig-jks/archive/main.tar.gz",
        .hash = "...",
    },
},
```

And in your `build.zig`:

```zig
const jks = b.dependency("jks", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("jks", jks.module("jks"));
```

## Quick Start

### Creating a KeyStore

```zig
const std = @import("std");
const jks = @import("jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new keystore
    var keystore = jks.Jks.init(allocator);
    defer keystore.deinit();

    // Add a trusted certificate
    const cert = jks.Certificate{
        .type = "X.509",
        .content = certificate_der_bytes,
    };

    const entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = cert,
    };

    try keystore.setTrustedCertificateEntry("my-cert", entry);

    // Save to file
    const file = try std.fs.cwd().createFile("keystore.jks", .{});
    defer file.close();

    try keystore.store(file.writer().any(), "storepassword");
}
```

### Loading a KeyStore

```zig
const file = try std.fs.cwd().openFile("keystore.jks", .{});
defer file.close();

var keystore = jks.Jks.init(allocator);
defer keystore.deinit();

try keystore.load(file.reader().any(), "storepassword");

// Retrieve a certificate
const cert_entry = try keystore.getTrustedCertificateEntry("my-cert");
defer cert_entry.deinit(allocator);

std.debug.print("Certificate type: {s}\n", .{cert_entry.certificate.type});
```

### Working with Private Keys

```zig
// Add a private key entry
const chain = [_]jks.Certificate{cert};
const pk_entry = jks.PrivateKeyEntry{
    .creation_time = std.time.milliTimestamp(),
    .private_key = pkcs8_key_bytes,
    .certificate_chain = &chain,
};

try keystore.setPrivateKeyEntry("my-key", pk_entry, "keypassword");

// Retrieve and decrypt the private key
const retrieved = try keystore.getPrivateKeyEntry("my-key", "keypassword");
defer retrieved.deinit(allocator);

// Use the decrypted private key
std.debug.print("Private key size: {d} bytes\n", .{retrieved.private_key.len});
```

## Configuration Options

```zig
var keystore = jks.Jks.initWithOptions(allocator, .{
    .ordered = true,           // Sort aliases alphabetically
    .case_exact = false,       // Case-insensitive aliases (default)
    .min_password_len = 8,     // Minimum password length
});
defer keystore.deinit();
```

## API Reference

### Jks

- `init(allocator)` - Create a new keystore with default options
- `initWithOptions(allocator, options)` - Create with custom options
- `deinit()` - Free all resources
- `setPrivateKeyEntry(alias, entry, password)` - Add a private key entry
- `getPrivateKeyEntry(alias, password)` - Retrieve and decrypt a private key entry
- `setTrustedCertificateEntry(alias, entry)` - Add a trusted certificate
- `getTrustedCertificateEntry(alias)` - Retrieve a trusted certificate
- `isPrivateKeyEntry(alias)` - Check if entry is a private key
- `isTrustedCertificateEntry(alias)` - Check if entry is a trusted certificate
- `deleteEntry(alias)` - Remove an entry
- `aliases()` - Get list of all aliases
- `store(writer, password)` - Write keystore to a writer
- `load(reader, password)` - Read keystore from a reader

### Entry Types

- `Certificate` - X.509 or other certificate type
- `PrivateKeyEntry` - Private key with certificate chain
- `TrustedCertificateEntry` - Standalone trusted certificate

## Notes

- Private keys must be PKCS#8 encoded
- Passwords are zeroed after use
- Uses SHA-1 (JKS requirement, yeah it's legacy)
- Caller owns all returned data - remember to `deinit()`

## Examples

The `examples/` directory contains practical demonstrations:

- **01_create_keystore.zig** - Creating a keystore from scratch
- **02_inspect_keystore.zig** - Inspecting keystore contents
- **03_manage_entries.zig** - Managing entries (add/update/delete)
- **04_load_modify_save.zig** - Complete workflow example
- **05_working_with_passwords.zig** - Password handling and security

Run examples with:
```bash
zig build create     # Create a keystore
zig build inspect    # Inspect keystore contents
zig build manage     # Manage entries
zig build workflow   # Load/modify/save workflow
zig build passwords  # Password handling
```

## Test Data

The `testdata/` directory contains various JKS files for testing:

```bash
# Generate all test files
zig build generate-testdata
```

This creates keystores with:
- Empty keystore
- Single/multiple certificates
- Private keys with different passwords
- Mixed content
- Special alias formats
- Large keystores (50+ entries)
- Various password configurations

## Testing

Run the test suite:

```bash
zig build test
```

## Compatibility

Works with keystores from:
- `keytool` (Java's CLI tool)
- `java.security.KeyStore` API
- Any JKS-compatible tool

## License

This project is released under the MIT License. See LICENSE file for details.

## References

- [Java KeyStore Specification](https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement)
- [Original Go Implementation](https://github.com/pavlo-v-chernykh/keystore-go)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
