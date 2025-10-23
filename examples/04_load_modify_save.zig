// Load an existing keystore, make changes, and save it back

const std = @import("std");
const jks = @import("jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Load → Modify → Save Workflow\n\n", .{});

    // Step 1: Load existing keystore
    std.debug.print("1. Loading existing keystore\n", .{});

    const input_file = std.fs.cwd().openFile("testdata/multiple_certs.jks", .{}) catch |err| {
        std.debug.print("Error: Could not open testdata/multiple_certs.jks\n", .{});
        std.debug.print("Please run 'zig build generate-testdata' first.\n", .{});
        return err;
    };
    defer input_file.close();

    var keystore = jks.Jks.init(allocator);
    defer keystore.deinit();

    const password = "password";
    try keystore.load(input_file.reader().any(), password);

    var alias_list = try keystore.aliases();
    std.debug.print("   Loaded {} entries: {s}\n\n", .{ alias_list.len, alias_list });
    allocator.free(alias_list);

    // Step 2: Make modifications
    std.debug.print("2. Making modifications\n", .{});

    // Add a new certificate
    const new_cert_content = [_]u8{ 0x30, 0x82, 0x03, 0x04, 0x05, 0x06 };
    const new_cert = jks.Certificate{
        .type = "X.509",
        .content = &new_cert_content,
    };

    const new_entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = new_cert,
    };

    try keystore.setTrustedCertificateEntry("newcert", new_entry);
    std.debug.print("   ✓ Added 'newcert'\n", .{});

    // Delete an existing entry
    try keystore.deleteEntry("rootca");
    std.debug.print("   ✓ Deleted 'rootca'\n", .{});

    // Update an existing entry
    const updated_entry = jks.TrustedCertificateEntry{
        .creation_time = std.time.milliTimestamp(),
        .certificate = new_cert,
    };
    try keystore.setTrustedCertificateEntry("intermediateca", updated_entry);
    std.debug.print("   ✓ Updated 'intermediateca'\n\n", .{});

    // Show current state
    alias_list = try keystore.aliases();
    std.debug.print("   Current entries: {s}\n\n", .{alias_list});
    allocator.free(alias_list);

    // Step 3: Save the modified keystore
    std.debug.print("3. Saving modified keystore\n", .{});

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try keystore.store(buffer.writer().any(), password);

    try std.fs.cwd().writeFile(.{
        .sub_path = "modified_keystore.jks",
        .data = buffer.items,
    });

    std.debug.print("   ✓ Saved to 'modified_keystore.jks' ({} bytes)\n\n", .{buffer.items.len});

    // Step 4: Verify by reloading
    std.debug.print("4. Verifying by reloading\n", .{});

    var verify_keystore = jks.Jks.init(allocator);
    defer verify_keystore.deinit();

    const verify_file = try std.fs.cwd().openFile("modified_keystore.jks", .{});
    defer verify_file.close();

    try verify_keystore.load(verify_file.reader().any(), password);

    alias_list = try verify_keystore.aliases();
    defer allocator.free(alias_list);

    std.debug.print("   ✓ Reloaded {} entries: {s}\n\n", .{ alias_list.len, alias_list });

    std.debug.print("✓ Workflow complete!\n", .{});
    std.debug.print("\nYou can inspect the modified keystore with:\n", .{});
    std.debug.print("  keytool -list -keystore modified_keystore.jks -storepass password\n", .{});
}
