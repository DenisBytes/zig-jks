// Create a new JKS keystore and add some entries

const std = @import("std");
const jks = @import("jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Creating a new JKS keystore...\n\n", .{});

    var keystore = jks.Jks.init(allocator);
    defer keystore.deinit();

    std.debug.print("1. Adding a trusted certificate\n", .{});

    const cert_content = [_]u8{ 0x30, 0x82, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    const certificate = jks.Certificate{
        .type = "X.509",
        .content = &cert_content,
    };

    const cert_entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = certificate,
    };

    try keystore.setTrustedCertificateEntry("my-root-ca", cert_entry);
    std.debug.print("   ✓ Added trusted certificate: 'my-root-ca'\n\n", .{});

    std.debug.print("2. Adding a private key entry\n", .{});

    const private_key_data = "-----BEGIN PRIVATE KEY----- ... sample ... -----END PRIVATE KEY-----";

    const leaf_cert = jks.Certificate{
        .type = "X.509",
        .content = &cert_content,
    };

    const chain = [_]jks.Certificate{leaf_cert};

    const key_entry = jks.PrivateKeyEntry{
        .creation_time = std.time.milliTimestamp(),
        .private_key = private_key_data,
        .certificate_chain = &chain,
    };

    const key_password = "my-secure-key-password";
    try keystore.setPrivateKeyEntry("my-signing-key", key_entry, key_password);
    std.debug.print("   ✓ Added private key: 'my-signing-key'\n\n", .{});

    try keystore.setTrustedCertificateEntry("my-intermediate-ca", cert_entry);
    std.debug.print("   ✓ Added trusted certificate: 'my-intermediate-ca'\n\n", .{});

    std.debug.print("3. Saving keystore to file\n", .{});

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const store_password = "my-keystore-password";
    try keystore.store(buffer.writer().any(), store_password);

    try std.fs.cwd().writeFile(.{
        .sub_path = "my_keystore.jks",
        .data = buffer.items,
    });

    std.debug.print("   ✓ Saved to 'my_keystore.jks' ({} bytes)\n", .{buffer.items.len});
    std.debug.print("   Store password: {s}\n", .{store_password});
    std.debug.print("   Key password: {s}\n\n", .{key_password});

    std.debug.print("✓ JKS Keystore created successfully!\n", .{});
    std.debug.print("\nYou can now load this keystore with:\n", .{});
    std.debug.print("  keytool -list -keystore my_keystore.jks\n", .{});
}
