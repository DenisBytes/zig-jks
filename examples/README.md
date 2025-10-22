# Examples

This directory contains practical examples demonstrating how to use the zig-jks library.

## Running Examples

Each example is a standalone Zig program. To compile and run an example:

```bash
# First, generate test data if needed
zig build generate-testdata

# Then compile and run any example
zig run examples/01_create_keystore.zig --dep zig_jks -Mroot=examples/01_create_keystore.zig -Mzig_jks=src/root.zig
```

Or you can add build steps to your `build.zig` to make it easier.

## Example List

### 01_create_keystore.zig
**Creating a KeyStore from Scratch**

Learn how to:
- Create a new KeyStore
- Add trusted certificate entries
- Add private key entries with certificate chains
- Save the keystore to a file

```bash
zig run examples/01_create_keystore.zig --dep zig_jks -Mroot=examples/01_create_keystore.zig -Mzig_jks=src/root.zig
```

Output: `my_keystore.jks`

---

### 02_inspect_keystore.zig
**Inspecting KeyStore Contents**

Learn how to:
- Load an existing keystore
- List all aliases
- Check entry types (private key vs trusted certificate)
- Retrieve and display entry information
- Format timestamps

```bash
zig run examples/02_inspect_keystore.zig --dep zig_jks -Mroot=examples/02_inspect_keystore.zig -Mzig_jks=src/root.zig
```

Requires: `testdata/mixed.jks`

---

### 03_manage_entries.zig
**Managing KeyStore Entries**

Learn how to:
- Add new entries
- Update existing entries
- Delete entries
- Use case-insensitive aliases
- Work with ordered aliases
- Check entry types

```bash
zig run examples/03_manage_entries.zig --dep zig_jks -Mroot=examples/03_manage_entries.zig -Mzig_jks=src/root.zig
```

---

### 04_load_modify_save.zig
**Load → Modify → Save Workflow**

Learn how to:
- Load an existing keystore
- Make modifications (add/update/delete)
- Save the modified keystore
- Verify changes by reloading

```bash
zig run examples/04_load_modify_save.zig --dep zig_jks -Mroot=examples/04_load_modify_save.zig -Mzig_jks=src/root.zig
```

Requires: `testdata/multiple_certs.jks`
Output: `modified_keystore.jks`

---

### 05_working_with_passwords.zig
**Password Handling and Security**

Learn how to:
- Use different passwords for store and keys
- Enforce minimum password length
- Handle authentication failures
- Follow password security best practices

```bash
zig run examples/05_working_with_passwords.zig --dep zig_jks -Mroot=examples/05_working_with_passwords.zig -Mzig_jks=src/root.zig
```

---

## Common Patterns

### Creating a KeyStore

```zig
const jks = @import("zig_jks");

var keystore = jks.KeyStore.init(allocator);
defer keystore.deinit();
```

### Adding a Certificate

```zig
const cert = jks.Certificate{
    .type = "X.509",
    .content = der_encoded_bytes,
};

const entry = jks.TrustedCertificateEntry{
    .creation_time = std.time.milliTimestamp(),
    .certificate = cert,
};

try keystore.setTrustedCertificateEntry("my-cert", entry);
```

### Adding a Private Key

```zig
const chain = [_]jks.Certificate{leaf_cert, intermediate_cert};

const entry = jks.PrivateKeyEntry{
    .creation_time = std.time.milliTimestamp(),
    .private_key = pkcs8_key_bytes,
    .certificate_chain = &chain,
};

try keystore.setPrivateKeyEntry("my-key", entry, "key-password");
```

### Saving to File

```zig
var buffer = std.ArrayList(u8).init(allocator);
defer buffer.deinit();

try keystore.store(buffer.writer().any(), "store-password");

try std.fs.cwd().writeFile(.{
    .sub_path = "keystore.jks",
    .data = buffer.items,
});
```

### Loading from File

```zig
const file = try std.fs.cwd().openFile("keystore.jks", .{});
defer file.close();

var keystore = jks.KeyStore.init(allocator);
defer keystore.deinit();

try keystore.load(file.reader().any(), "store-password");
```

## Testing with Java's keytool

After creating a keystore with these examples, you can verify it with Java's keytool:

```bash
# List all entries
keytool -list -keystore my_keystore.jks -storepass my-keystore-password

# List with detailed information
keytool -list -v -keystore my_keystore.jks -storepass my-keystore-password

# Export a certificate
keytool -exportcert -alias my-cert -keystore my_keystore.jks -storepass my-keystore-password -file cert.der
```

## Tips

1. **Memory Management**: Always use `defer` to ensure cleanup
   ```zig
   var keystore = jks.KeyStore.init(allocator);
   defer keystore.deinit();
   ```

2. **Error Handling**: Use Zig's error handling
   ```zig
   const entry = keystore.getTrustedCertificateEntry("alias") catch |err| {
       std.debug.print("Error: {}\n", .{err});
       return err;
   };
   defer entry.deinit(allocator);
   ```

3. **Password Security**: The library automatically zeros password buffers after use

4. **Testing**: Use the `testdata/` directory for test keystores

## See Also

- [Main README](../README.md) - Library documentation
- [testdata/](../testdata/) - Test keystore files
- [CLAUDE.md](../CLAUDE.md) - Development context

## Need Help?

If you need more examples or have questions:
1. Check the test files in `src/` for more usage patterns
2. Read the API documentation in source files
3. Open an issue on GitHub
