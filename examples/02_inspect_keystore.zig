/// Example: Inspecting KeyStore contents
/// This example demonstrates how to load and inspect a keystore

const std = @import("std");
const jks = @import("zig_jks");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Check if testdata file exists
    const file = std.fs.cwd().openFile("testdata/mixed.jks", .{}) catch |err| {
        std.debug.print("Error: Could not open testdata/mixed.jks\n", .{});
        std.debug.print("Please run 'zig build generate-testdata' first.\n", .{});
        return err;
    };
    defer file.close();

    std.debug.print("Inspecting KeyStore...\n\n", .{});

    // Load the keystore
    var keystore = jks.KeyStore.init(allocator);
    defer keystore.deinit();

    const password = "mixedpass";
    try keystore.load(file.reader().any(), password);

    std.debug.print("✓ Loaded keystore successfully\n\n", .{});

    // Get all aliases
    const alias_list = try keystore.aliases();
    defer allocator.free(alias_list);

    std.debug.print("KeyStore contains {} entries:\n\n", .{alias_list.len});

    // Inspect each entry
    for (alias_list, 1..) |alias, i| {
        std.debug.print("Entry {}: {s}\n", .{ i, alias });

        // Check what type of entry it is
        const is_private_key = try keystore.isPrivateKeyEntry(alias);
        const is_trusted_cert = try keystore.isTrustedCertificateEntry(alias);

        if (is_private_key) {
            std.debug.print("  Type: Private Key Entry\n", .{});

            // Note: We need the key password to decrypt the private key
            // For this example, we know the password
            const key_password = blk: {
                if (std.mem.eql(u8, alias, "privatekey1")) break :blk "key1pass";
                if (std.mem.eql(u8, alias, "privatekey2")) break :blk "key2pass";
                break :blk "unknown";
            };

            if (!std.mem.eql(u8, key_password, "unknown")) {
                const entry = try keystore.getPrivateKeyEntry(alias, key_password);
                defer entry.deinit(allocator);

                const date = std.time.epoch.EpochSeconds{ .secs = @intCast(@divFloor(entry.creation_time, 1000)) };
                const day_seconds = date.getDaySeconds();

                std.debug.print("  Created: {}-{:0>2}-{:0>2} {:0>2}:{:0>2}:{:0>2} UTC\n", .{
                    date.getEpochDay().calculateYearDay().year,
                    date.getEpochDay().calculateMonthDay().month.numeric(),
                    date.getEpochDay().calculateMonthDay().day_index + 1,
                    day_seconds.getHoursIntoDay(),
                    day_seconds.getMinutesIntoHour(),
                    day_seconds.getSecondsIntoMinute(),
                });
                std.debug.print("  Private key size: {} bytes\n", .{entry.private_key.len});
                std.debug.print("  Certificate chain length: {}\n", .{entry.certificate_chain.len});

                for (entry.certificate_chain, 0..) |cert, j| {
                    std.debug.print("    Certificate {}: {} ({} bytes)\n", .{
                        j + 1,
                        cert.type,
                        cert.content.len,
                    });
                }
            }
        } else if (is_trusted_cert) {
            std.debug.print("  Type: Trusted Certificate\n", .{});

            const entry = try keystore.getTrustedCertificateEntry(alias);
            defer entry.deinit(allocator);

            const date = std.time.epoch.EpochSeconds{ .secs = @intCast(@divFloor(entry.creation_time, 1000)) };
            const day_seconds = date.getDaySeconds();

            std.debug.print("  Created: {}-{:0>2}-{:0>2} {:0>2}:{:0>2}:{:0>2} UTC\n", .{
                date.getEpochDay().calculateYearDay().year,
                date.getEpochDay().calculateMonthDay().month.numeric(),
                date.getEpochDay().calculateMonthDay().day_index + 1,
                day_seconds.getHoursIntoDay(),
                day_seconds.getMinutesIntoHour(),
                day_seconds.getSecondsIntoMinute(),
            });
            std.debug.print("  Certificate type: {s}\n", .{entry.certificate.type});
            std.debug.print("  Certificate size: {} bytes\n", .{entry.certificate.content.len});
        }

        std.debug.print("\n", .{});
    }

    std.debug.print("✓ Inspection complete\n", .{});
}
