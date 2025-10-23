// Add, update, and delete keystore entries

const std = @import("std");
const jks = @import("jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Managing JKS keystore Entries...\n\n", .{});

    // Create a keystore with ordered aliases
    var keystore = jks.Jks.initWithOptions(allocator, .{
        .ordered = true,  // Keep aliases sorted
        .case_exact = false,  // Case-insensitive aliases
    });
    defer keystore.deinit();

    const cert_content = [_]u8{ 0x30, 0x82, 0x01, 0x02, 0x03 };
    const cert = jks.Certificate{
        .type = "X.509",
        .content = &cert_content,
    };

    // Example 1: Adding entries
    std.debug.print("1. Adding entries\n", .{});

    const cert_entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = cert,
    };

    try keystore.setTrustedCertificateEntry("cert-alpha", cert_entry);
    try keystore.setTrustedCertificateEntry("cert-beta", cert_entry);
    try keystore.setTrustedCertificateEntry("cert-gamma", cert_entry);

    var alias_list = try keystore.aliases();
    std.debug.print("   Entries:", .{});
    for (alias_list) |alias| {
        std.debug.print(" {s}", .{alias});
    }
    std.debug.print("\n\n", .{});
    allocator.free(alias_list);

    // Example 2: Updating an entry
    std.debug.print("2. Updating an entry\n", .{});

    const updated_entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = cert,
    };

    // Setting with same alias updates the entry
    try keystore.setTrustedCertificateEntry("cert-beta", updated_entry);
    std.debug.print("   Updated 'cert-beta'\n\n", .{});

    // Example 3: Case-insensitive access
    std.debug.print("3. Case-insensitive alias access\n", .{});

    // These all refer to the same entry
    const exists1 = try keystore.isTrustedCertificateEntry("cert-alpha");
    const exists2 = try keystore.isTrustedCertificateEntry("CERT-ALPHA");
    const exists3 = try keystore.isTrustedCertificateEntry("Cert-Alpha");

    std.debug.print("   'cert-alpha' exists: {}\n", .{exists1});
    std.debug.print("   'CERT-ALPHA' exists: {}\n", .{exists2});
    std.debug.print("   'Cert-Alpha' exists: {}\n\n", .{exists3});

    // Example 4: Deleting entries
    std.debug.print("4. Deleting entries\n", .{});

    try keystore.deleteEntry("cert-beta");
    std.debug.print("   Deleted 'cert-beta'\n", .{});

    alias_list = try keystore.aliases();
    std.debug.print("   Remaining entries:", .{});
    for (alias_list) |alias| {
        std.debug.print(" {s}", .{alias});
    }
    std.debug.print("\n\n", .{});
    allocator.free(alias_list);

    // Example 5: Adding a private key
    std.debug.print("5. Adding a private key\n", .{});

    const chain = [_]jks.Certificate{cert};
    const key_entry = jks.PrivateKeyEntry{
        .creation_time = std.time.milliTimestamp(),
        .private_key = "sample_private_key_data",
        .certificate_chain = &chain,
    };

    try keystore.setPrivateKeyEntry("my-key", key_entry, "keypassword");
    std.debug.print("   Added private key 'my-key'\n\n", .{});

    // Example 6: Checking entry types
    std.debug.print("6. Checking entry types\n", .{});

    alias_list = try keystore.aliases();
    defer allocator.free(alias_list);

    for (alias_list) |alias| {
        const is_key = try keystore.isPrivateKeyEntry(alias);
        const is_cert = try keystore.isTrustedCertificateEntry(alias);

        std.debug.print("   '{s}': ", .{alias});
        if (is_key) {
            std.debug.print("Private Key\n", .{});
        } else if (is_cert) {
            std.debug.print("Trusted Certificate\n", .{});
        }
    }

    std.debug.print("\n✓ Entry management complete\n", .{});
}
