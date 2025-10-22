const std = @import("std");
const jks = @import("zig_jks");

/// Helper to write keystore to file
fn writeKeystore(ks: *jks.KeyStore, allocator: std.mem.Allocator, path: []const u8, password: []const u8) !void {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try ks.store(buffer.writer().any(), password);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = buffer.items });
}

/// Generate various test JKS files for testing
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Generating test JKS files...\n", .{});

    // Sample certificate content (minimal DER-encoded certificate structure)
    const cert_der = [_]u8{
        0x30, 0x82, 0x02, 0x92, 0x30, 0x82, 0x01, 0x7a, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x09, 0x00, 0xd0, 0x4e, 0x4e, 0xf5, 0xa6, 0x42, 0x15, 0x1b,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    };

    // Sample PKCS8 private key structure
    const pkcs8_key = [_]u8{
        0x30, 0x82, 0x01, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
        0x01, 0x3e, 0x30, 0x82, 0x01, 0x3a, 0x02, 0x01, 0x00, 0x02, 0x41, 0x00,
    };

    // Test Case 1: Empty keystore
    try generateEmptyKeystore(allocator);

    // Test Case 2: Single trusted certificate
    try generateSingleCertificate(allocator, &cert_der);

    // Test Case 3: Multiple trusted certificates
    try generateMultipleCertificates(allocator, &cert_der);

    // Test Case 4: Single private key entry
    try generateSinglePrivateKey(allocator, &cert_der, &pkcs8_key);

    // Test Case 5: Mixed entries (certificates and private keys)
    try generateMixedEntries(allocator, &cert_der, &pkcs8_key);

    // Test Case 6: With special characters in aliases
    try generateSpecialAliases(allocator, &cert_der);

    // Test Case 7: Large keystore (many entries)
    try generateLargeKeystore(allocator, &cert_der);

    // Test Case 8: Different password scenarios
    try generatePasswordVariations(allocator, &cert_der, &pkcs8_key);

    std.debug.print("\n✓ All test files generated successfully!\n", .{});
}

fn generateEmptyKeystore(allocator: std.mem.Allocator) !void {
    var ks = jks.KeyStore.init(allocator);
    defer ks.deinit();

    try writeKeystore(&ks, allocator, "testdata/empty.jks", "password");
    std.debug.print("  ✓ empty.jks - Empty keystore\n", .{});
}

fn generateSingleCertificate(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.KeyStore.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000, // 2024-01-01 00:00:00 UTC
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("mycert", entry);
    try writeKeystore(&ks, allocator, "testdata/single_cert.jks", "password");
    std.debug.print("  ✓ single_cert.jks - One trusted certificate\n", .{});
}

fn generateMultipleCertificates(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.KeyStore.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const aliases = [_][]const u8{ "rootca", "intermediateca", "trustanchor" };
    const times = [_]i64{ 1704067200000, 1704153600000, 1704240000000 };

    for (aliases, times) |alias, time| {
        const entry = jks.TrustedCertificateEntry{
            .creation_time = time,
            .certificate = cert,
        };
        try ks.setTrustedCertificateEntry(alias, entry);
    }

    try writeKeystore(&ks, allocator, "testdata/multiple_certs.jks", "password");
    std.debug.print("  ✓ multiple_certs.jks - Three trusted certificates\n", .{});
}

fn generateSinglePrivateKey(allocator: std.mem.Allocator, cert_der: []const u8, key: []const u8) !void {
    var ks = jks.KeyStore.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const chain = [_]jks.Certificate{cert};
    const entry = jks.PrivateKeyEntry{
        .creation_time = 1704067200000,
        .private_key = key,
        .certificate_chain = &chain,
    };

    try ks.setPrivateKeyEntry("mykey", entry, "keypass");

    try writeKeystore(&ks, allocator, "testdata/single_key.jks", "storepass");
    std.debug.print("  ✓ single_key.jks - One private key (store: 'storepass', key: 'keypass')\n", .{});
}

fn generateMixedEntries(allocator: std.mem.Allocator, cert_der: []const u8, key: []const u8) !void {
    var ks = jks.KeyStore.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    // Add trusted certificates
    const cert_entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000,
        .certificate = cert,
    };
    try ks.setTrustedCertificateEntry("trusted1", cert_entry);
    try ks.setTrustedCertificateEntry("trusted2", cert_entry);

    // Add private keys
    const chain = [_]jks.Certificate{cert};
    const key_entry = jks.PrivateKeyEntry{
        .creation_time = 1704153600000,
        .private_key = key,
        .certificate_chain = &chain,
    };
    try ks.setPrivateKeyEntry("privatekey1", key_entry, "key1pass");
    try ks.setPrivateKeyEntry("privatekey2", key_entry, "key2pass");

    try writeKeystore(&ks, allocator, "testdata/mixed.jks", "mixedpass");
    std.debug.print("  ✓ mixed.jks - Mixed entries (store: 'mixedpass')\n", .{});
}

fn generateSpecialAliases(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.KeyStore.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000,
        .certificate = cert,
    };

    // Various alias formats
    const aliases = [_][]const u8{
        "my-cert",
        "my_cert",
        "my.cert",
        "mycert123",
        "UPPERCASE",
        "MixedCase",
    };

    for (aliases) |alias| {
        try ks.setTrustedCertificateEntry(alias, entry);
    }

    try writeKeystore(&ks, allocator, "testdata/special_aliases.jks", "password");
    std.debug.print("  ✓ special_aliases.jks - Various alias formats\n", .{});
}

fn generateLargeKeystore(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.KeyStore.initWithOptions(allocator, .{ .ordered = true });
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000,
        .certificate = cert,
    };

    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const alias = try std.fmt.allocPrint(allocator, "cert{d:0>3}", .{i});
        defer allocator.free(alias);
        try ks.setTrustedCertificateEntry(alias, entry);
    }

    try writeKeystore(&ks, allocator, "testdata/large.jks", "password");
    std.debug.print("  ✓ large.jks - 50 certificates\n", .{});
}

fn generatePasswordVariations(allocator: std.mem.Allocator, cert_der: []const u8, _: []const u8) !void {
    // Short password
    {
        var ks = jks.KeyStore.init(allocator);
        defer ks.deinit();

        const cert = jks.Certificate{
            .type = "X.509",
            .content = cert_der,
        };

        const entry = jks.TrustedCertificateEntry{
            .creation_time = 1704067200000,
            .certificate = cert,
        };

        try ks.setTrustedCertificateEntry("cert", entry);

        try writeKeystore(&ks, allocator, "testdata/short_password.jks", "abc");
        std.debug.print("  ✓ short_password.jks - Password: 'abc'\n", .{});
    }

    // Long password
    {
        var ks = jks.KeyStore.init(allocator);
        defer ks.deinit();

        const cert = jks.Certificate{
            .type = "X.509",
            .content = cert_der,
        };

        const entry = jks.TrustedCertificateEntry{
            .creation_time = 1704067200000,
            .certificate = cert,
        };

        try ks.setTrustedCertificateEntry("cert", entry);

        try writeKeystore(&ks, allocator, "testdata/long_password.jks", "this_is_a_very_long_password_with_many_characters_123456789");
        std.debug.print("  ✓ long_password.jks - Password: 'this_is_a_very_long_password...'\n", .{});
    }

    // Special characters in password
    {
        var ks = jks.KeyStore.init(allocator);
        defer ks.deinit();

        const cert = jks.Certificate{
            .type = "X.509",
            .content = cert_der,
        };

        const entry = jks.TrustedCertificateEntry{
            .creation_time = 1704067200000,
            .certificate = cert,
        };

        try ks.setTrustedCertificateEntry("cert", entry);

        try writeKeystore(&ks, allocator, "testdata/special_password.jks", "P@ssw0rd!#$%");
        std.debug.print("  ✓ special_password.jks - Password: 'P@ssw0rd!#$%'\n", .{});
    }
}
