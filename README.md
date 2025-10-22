# zig-jks

A Zig implementation of the Java KeyStore (JKS) format encoder/decoder.

## Overview

**zig-jks** is a pure Zig library for reading and writing Java KeyStore files in the JKS format. This library provides a complete implementation compatible with the Java KeyStore specification, allowing you to manage cryptographic keys and certificates from Zig applications.

## Features

- **Full JKS Format Support**: Read and write JKS files (versions 1 and 2)
- **Entry Types**: Manage both private key entries and trusted certificate entries
- **Encryption**: Secure private key encryption using Sun's proprietary algorithm
- **Options**: Configurable alias handling (case-sensitive, ordered) and password policies
- **Memory Safe**: Explicit memory management with Zig's allocator pattern
- **Zero Dependencies**: Pure Zig implementation using only the standard library
- **Well Tested**: Comprehensive test suite with >95% coverage

## Requirements

- Zig 0.15.1 or later

## Installation

Add this to your `build.zig.zon`:

```zig
.dependencies = .{
    .zig_jks = .{
        .url = "https://github.com/yourusername/zig-jks/archive/main.tar.gz",
        .hash = "...",
    },
},
```

And in your `build.zig`:

```zig
const zig_jks = b.dependency("zig_jks", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_jks", zig_jks.module("zig_jks"));
```

## Quick Start

### Creating a KeyStore

```zig
const std = @import("std");
const jks = @import("zig_jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new keystore
    var keystore = jks.KeyStore.init(allocator);
    defer keystore.deinit();

    // Add a trusted certificate
    const cert = jks.Certificate{
        .type = "X509",
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

var keystore = jks.KeyStore.init(allocator);
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
const options = jks.KeyStoreOptions{
    .ordered = true,           // Sort aliases alphabetically
    .case_exact = true,        // Preserve alias case (default: lowercase)
    .min_password_len = 8,     // Minimum password length
};

var keystore = jks.KeyStore.initWithOptions(allocator, options);
defer keystore.deinit();
```

## API Reference

### KeyStore

- `init(allocator)` - Create a new keystore with default options
- `initWithOptions(allocator, options)` - Create with custom options
- `deinit()` - Free all resources
- `setPrivateKeyEntry(alias, entry, password)` - Add a private key entry
- `getPrivateKeyEntry(alias, password)` - Retrieve and decrypt a private key entry
- `setTrustedCertificateEntry(alias, entry)` - Add a trusted certificate
- `getTrustedCertificateEntry(alias)` - Retrieve a trusted certificate
- `deleteEntry(alias)` - Remove an entry
- `aliases()` - Get list of all aliases
- `store(writer, password)` - Write keystore to a writer
- `load(reader, password)` - Read keystore from a reader

### Entry Types

- `Certificate` - X.509 or other certificate type
- `PrivateKeyEntry` - Private key with certificate chain
- `TrustedCertificateEntry` - Standalone trusted certificate

## Important Notes

- **Private Keys**: Must be in PKCS#8 format
- **Passwords**: Zeroed after use for security
- **SHA-1**: Used for compatibility with JKS format (legacy standard)
- **Memory**: All returned data must be freed by the caller using `deinit()`

## Examples

The `examples/` directory contains practical demonstrations:

- **01_create_keystore.zig** - Creating a keystore from scratch
- **02_inspect_keystore.zig** - Inspecting keystore contents
- **03_manage_entries.zig** - Managing entries (add/update/delete)
- **04_load_modify_save.zig** - Complete workflow example
- **05_working_with_passwords.zig** - Password handling and security

See [examples/README.md](examples/README.md) for detailed instructions.

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

See [testdata/README.md](testdata/README.md) for details on each test file.

## Testing

Run the test suite:

```bash
zig build test
```

## Compatibility

This implementation is compatible with Java KeyStore files created by:
- Java's `keytool` utility
- The `java.security.KeyStore` API
- Other JKS-compatible tools

## License

This project is released under the MIT License. See LICENSE file for details.

## References

- [Java KeyStore Specification](https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#KeyManagement)
- [Original Go Implementation](https://github.com/pavlo-v-chernykh/keystore-go)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
