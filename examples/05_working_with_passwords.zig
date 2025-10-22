/// Example: Working with passwords
/// This example demonstrates password handling, security, and best practices

const std = @import("std");
const jks = @import("zig_jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Working with Passwords\n\n", .{});

    // Example 1: Using different passwords for store and keys
    std.debug.print("1. Store password vs Key passwords\n", .{});

    var keystore = jks.KeyStore.init(allocator);
    defer keystore.deinit();

    const cert_content = [_]u8{ 0x30, 0x82, 0x01 };
    const cert = jks.Certificate{
        .type = "X.509",
        .content = &cert_content,
    };

    const chain = [_]jks.Certificate{cert};

    // Add private keys with different passwords
    const key1 = jks.PrivateKeyEntry{
        .creation_time = std.time.milliTimestamp(),
        .private_key = "key1_data",
        .certificate_chain = &chain,
    };

    const key2 = jks.PrivateKeyEntry{
        .creation_time = std.time.milliTimestamp(),
        .private_key = "key2_data",
        .certificate_chain = &chain,
    };

    try keystore.setPrivateKeyEntry("key1", key1, "key1-password");
    try keystore.setPrivateKeyEntry("key2", key2, "key2-password");

    std.debug.print("   ✓ Each private key has its own password\n", .{});
    std.debug.print("   ✓ The keystore itself has a separate store password\n\n", .{});

    // Save with store password
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    const store_password = "store-password";
    try keystore.store(buffer.writer().any(), store_password);

    std.debug.print("   Store password: '{s}'\n", .{store_password});
    std.debug.print("   Key 1 password: 'key1-password'\n", .{});
    std.debug.print("   Key 2 password: 'key2-password'\n\n", .{});

    // Example 2: Minimum password length enforcement
    std.debug.print("2. Enforcing minimum password length\n", .{});

    var secure_keystore = jks.KeyStore.initWithOptions(allocator, .{
        .min_password_len = 12,  // Require at least 12 characters
    });
    defer secure_keystore.deinit();

    // This will fail - password too short
    const weak_password = "weak";
    const result1 = secure_keystore.setPrivateKeyEntry("key", key1, weak_password);

    if (result1) |_| {
        std.debug.print("   Unexpected: weak password accepted\n", .{});
    } else |err| {
        std.debug.print("   ✓ Rejected password '{s}' ({} chars): {}\n", .{
            weak_password,
            weak_password.len,
            err,
        });
    }

    // This will succeed
    const strong_password = "MySecurePassword123!";
    try secure_keystore.setPrivateKeyEntry("key", key1, strong_password);
    std.debug.print("   ✓ Accepted password '{s}' ({} chars)\n\n", .{
        strong_password,
        strong_password.len,
    });

    // Example 3: Wrong password handling
    std.debug.print("3. Handling wrong passwords\n", .{});

    try std.fs.cwd().writeFile(.{
        .sub_path = "password_test.jks",
        .data = buffer.items,
    });

    var test_keystore = jks.KeyStore.init(allocator);
    defer test_keystore.deinit();

    const test_file = try std.fs.cwd().openFile("password_test.jks", .{});
    defer test_file.close();

    try test_keystore.load(test_file.reader().any(), store_password);

    // Try with wrong key password
    const wrong_result = test_keystore.getPrivateKeyEntry("key1", "wrong-password");
    if (wrong_result) |retrieved| {
        retrieved.deinit(allocator);
        std.debug.print("   Unexpected: wrong password accepted\n", .{});
    } else |err| {
        std.debug.print("   ✓ Rejected wrong key password: {}\n", .{err});
    }

    // Try with correct password
    const correct_result = try test_keystore.getPrivateKeyEntry("key1", "key1-password");
    defer correct_result.deinit(allocator);
    std.debug.print("   ✓ Accepted correct key password\n\n", .{});

    // Example 4: Password security best practices
    std.debug.print("4. Password security best practices\n", .{});
    std.debug.print("   ✓ Use different passwords for store and individual keys\n", .{});
    std.debug.print("   ✓ Enforce minimum password length (12+ characters)\n", .{});
    std.debug.print("   ✓ Use strong passwords with mixed case, numbers, symbols\n", .{});
    std.debug.print("   ✓ Never hardcode passwords in production code\n", .{});
    std.debug.print("   ✓ Clear password buffers after use (library does this automatically)\n\n", .{});

    std.debug.print("✓ Password handling complete\n", .{});

    // Cleanup
    std.fs.cwd().deleteFile("password_test.jks") catch {};
}
