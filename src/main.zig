const std = @import("std");
const jks = @import("zig_jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("zig-jks: Java KeyStore library for Zig\n", .{});
    std.debug.print("=====================================\n\n", .{});

    // Create a new keystore
    var keystore = jks.KeyStore.init(allocator);
    defer keystore.deinit();

    std.debug.print("Creating a new KeyStore...\n", .{});

    // Create a sample certificate
    const cert_content = [_]u8{ 0x30, 0x82, 0x01, 0x02, 0x03, 0x04, 0x05 };
    const cert = jks.Certificate{
        .type = "X509",
        .content = &cert_content,
    };

    // Add a trusted certificate entry
    const cert_entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = cert,
    };

    try keystore.setTrustedCertificateEntry("my-trusted-cert", cert_entry);
    std.debug.print("  ✓ Added trusted certificate: 'my-trusted-cert'\n", .{});

    // Add a private key entry
    const pk_data = "sample_pkcs8_private_key_data_here";
    const chain = [_]jks.Certificate{cert};
    const pk_entry = jks.PrivateKeyEntry{
        .creation_time = std.time.milliTimestamp(),
        .private_key = pk_data,
        .certificate_chain = &chain,
    };

    try keystore.setPrivateKeyEntry("my-private-key", pk_entry, "keypassword123");
    std.debug.print("  ✓ Added private key entry: 'my-private-key'\n", .{});

    // Store to memory buffer
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try keystore.store(buffer.writer().any(), "storepass123");
    std.debug.print("\n  ✓ Keystore encoded: {} bytes\n", .{buffer.items.len});

    // Load from buffer into a new keystore
    var keystore2 = jks.KeyStore.init(allocator);
    defer keystore2.deinit();

    var stream = std.io.fixedBufferStream(buffer.items);
    try keystore2.load(stream.reader().any(), "storepass123");
    std.debug.print("  ✓ Keystore decoded successfully\n", .{});

    // List all aliases
    const alias_list = try keystore2.aliases();
    defer allocator.free(alias_list);

    std.debug.print("\nKeyStore contains {} entries:\n", .{alias_list.len});
    for (alias_list) |alias| {
        std.debug.print("  - {s}\n", .{alias});
    }

    // Retrieve and verify entries
    const retrieved_cert = try keystore2.getTrustedCertificateEntry("my-trusted-cert");
    defer retrieved_cert.deinit(allocator);
    std.debug.print("\n  ✓ Retrieved trusted certificate\n", .{});

    const retrieved_pk = try keystore2.getPrivateKeyEntry("my-private-key", "keypassword123");
    defer retrieved_pk.deinit(allocator);
    std.debug.print("  ✓ Retrieved and decrypted private key\n", .{});

    std.debug.print("\n✓ All operations completed successfully!\n", .{});
    std.debug.print("\nRun 'zig build test' to execute the full test suite.\n", .{});
}
