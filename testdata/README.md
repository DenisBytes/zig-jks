# Test Data

This directory contains various JKS (Java KeyStore) files for testing the zig-jks library.

## Test Files

### Basic Tests

- **empty.jks** - Empty keystore (no entries)
  - Password: `password`

- **single_cert.jks** - Single trusted certificate
  - Password: `password`
  - Entries: 1 trusted certificate (`mycert`)

- **multiple_certs.jks** - Multiple trusted certificates
  - Password: `password`
  - Entries: 3 trusted certificates (`rootca`, `intermediateca`, `trustanchor`)

### Private Key Tests

- **single_key.jks** - Single private key entry
  - Store password: `storepass`
  - Key password: `keypass`
  - Entries: 1 private key (`mykey`) with certificate chain

### Mixed Content Tests

- **mixed.jks** - Mixed entries (certificates + private keys)
  - Store password: `mixedpass`
  - Key passwords: `key1pass`, `key2pass`
  - Entries: 2 trusted certificates + 2 private keys

### Special Cases

- **special_aliases.jks** - Various alias formats
  - Password: `password`
  - Aliases: `my-cert`, `my_cert`, `my.cert`, `mycert123`, `UPPERCASE`, `MixedCase`
  - Tests alias handling with different characters and cases

- **large.jks** - Large keystore (50 entries)
  - Password: `password`
  - Entries: 50 trusted certificates (`cert000` through `cert049`)
  - Tests performance with many entries

### Password Variations

- **short_password.jks** - Short password
  - Password: `abc` (3 characters)

- **long_password.jks** - Long password
  - Password: `this_is_a_very_long_password_with_many_characters_123456789` (60+ characters)

- **special_password.jks** - Special characters in password
  - Password: `P@ssw0rd!#$%`

## Generating Test Files

To regenerate all test files:

```bash
zig build generate-testdata
```

This runs the `testdata/generate.zig` program which creates all test files programmatically using the zig-jks library.

## Using Test Files

These files can be used to:

1. **Verify compatibility** - Test loading/saving with Java's keytool
2. **Performance testing** - Benchmark with different file sizes
3. **Edge case testing** - Test password handling, alias formats, etc.
4. **Integration testing** - Verify round-trip encoding/decoding

### Example: Loading a Test File

```zig
const std = @import("std");
const jks = @import("zig_jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const file = try std.fs.cwd().openFile("testdata/single_cert.jks", .{});
    defer file.close();

    var keystore = jks.KeyStore.init(allocator);
    defer keystore.deinit();

    try keystore.load(file.reader().any(), "password");

    std.debug.print("Loaded {} entries\n", .{keystore.entries.count()});
}
```

## File Format

All files follow the JKS (Java KeyStore) format version 2:

- Big-endian encoding
- SHA-1 HMAC for integrity
- Proprietary encryption for private keys
- Compatible with Java's `keytool` and `java.security.KeyStore`

## Notes

- The certificate content in test files is minimal DER-encoded data, not real certificates
- Private keys are sample PKCS#8 structures, not actual cryptographic keys
- These files are for testing purposes only and should not be used in production
