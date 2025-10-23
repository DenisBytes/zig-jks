const std = @import("std");
const jks = @import("jks");

fn writeKeystore(ks: *jks.Jks, allocator: std.mem.Allocator, path: []const u8, password: []const u8) !void {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try ks.store(buffer.writer().any(), password);
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = buffer.items });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Generating test JKS files...\n", .{});

    const cert_der = [_]u8{
        0x30, 0x82, 0x02, 0x92, 0x30, 0x82, 0x01, 0x7a, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x09, 0x00, 0xd0, 0x4e, 0x4e, 0xf5, 0xa6, 0x42, 0x15, 0x1b,
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    };

    const pkcs8_key = [_]u8{
        0x30, 0x82, 0x01, 0x54, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
        0x01, 0x3e, 0x30, 0x82, 0x01, 0x3a, 0x02, 0x01, 0x00, 0x02, 0x41, 0x00,
    };

    try generateEmptyKeystore(allocator);
    try generateSingleCertificate(allocator, &cert_der);
    try generateMultipleCertificates(allocator, &cert_der);
    try generateSinglePrivateKey(allocator, &cert_der, &pkcs8_key);
    try generateMixedEntries(allocator, &cert_der, &pkcs8_key);
    try generateSpecialAliases(allocator, &cert_der);
    try generateLargeKeystore(allocator, &cert_der);
    try generatePasswordVariations(allocator, &cert_der, &pkcs8_key);

    std.debug.print("\n✓ All test files generated successfully!\n", .{});
}

fn generateEmptyKeystore(allocator: std.mem.Allocator) !void {
    var ks = jks.Jks.init(allocator);
    defer ks.deinit();

    try writeKeystore(&ks, allocator, "testdata/empty.jks", "password");
    std.debug.print("  ✓ empty.jks\n", .{});
}

fn generateSingleCertificate(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.Jks.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000,
        .certificate = cert,
    };

    try ks.setTrustedCertificateEntry("mycert", entry);
    try writeKeystore(&ks, allocator, "testdata/single_cert.jks", "password");
    std.debug.print("  ✓ single_cert.jks\n", .{});
}

fn generateMultipleCertificates(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.Jks.init(allocator);
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
    std.debug.print("  ✓ multiple_certs.jks\n", .{});
}

fn generateSinglePrivateKey(allocator: std.mem.Allocator, cert_der: []const u8, key: []const u8) !void {
    var ks = jks.Jks.init(allocator);
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
    std.debug.print("  ✓ single_key.jks\n", .{});
}

fn generateMixedEntries(allocator: std.mem.Allocator, cert_der: []const u8, key: []const u8) !void {
    var ks = jks.Jks.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const cert_entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000,
        .certificate = cert,
    };
    try ks.setTrustedCertificateEntry("trusted1", cert_entry);
    try ks.setTrustedCertificateEntry("trusted2", cert_entry);

    const chain = [_]jks.Certificate{cert};
    const key_entry = jks.PrivateKeyEntry{
        .creation_time = 1704153600000,
        .private_key = key,
        .certificate_chain = &chain,
    };
    try ks.setPrivateKeyEntry("privatekey1", key_entry, "key1pass");
    try ks.setPrivateKeyEntry("privatekey2", key_entry, "key2pass");

    try writeKeystore(&ks, allocator, "testdata/mixed.jks", "mixedpass");
    std.debug.print("  ✓ mixed.jks\n", .{});
}

fn generateSpecialAliases(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.Jks.init(allocator);
    defer ks.deinit();

    const cert = jks.Certificate{
        .type = "X.509",
        .content = cert_der,
    };

    const entry = jks.TrustedCertificateEntry{
        .creation_time = 1704067200000,
        .certificate = cert,
    };

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
    std.debug.print("  ✓ special_aliases.jks\n", .{});
}

fn generateLargeKeystore(allocator: std.mem.Allocator, cert_der: []const u8) !void {
    var ks = jks.Jks.initWithOptions(allocator, .{ .ordered = true });
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
    std.debug.print("  ✓ large.jks\n", .{});
}

fn generatePasswordVariations(allocator: std.mem.Allocator, cert_der: []const u8, _: []const u8) !void {
    {
        var ks = jks.Jks.init(allocator);
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
        std.debug.print("  ✓ short_password.jks\n", .{});
    }

    {
        var ks = jks.Jks.init(allocator);
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
        std.debug.print("  ✓ long_password.jks\n", .{});
    }

    {
        var ks = jks.Jks.init(allocator);
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
        std.debug.print("  ✓ special_password.jks\n", .{});
    }
}
