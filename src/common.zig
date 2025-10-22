const std = @import("std");
const testing = std.testing;

/// Magic number identifying a JKS file
pub const magic: u32 = 0xfeedfeed;

/// JKS format version 1
pub const version_01: u32 = 1;

/// JKS format version 2 (supports explicit certificate types)
pub const version_02: u32 = 2;

/// Tag identifying a private key entry
pub const private_key_tag: u32 = 1;

/// Tag identifying a trusted certificate entry
pub const trusted_certificate_tag: u32 = 2;

/// Salt used in the keystore digest calculation
pub const whitener_message = "Mighty Aphrodite";

/// Byte order used in JKS format (big-endian)
pub const byte_order = std.builtin.Endian.big;

/// Convert password bytes to JKS format.
/// Each byte becomes two bytes: [0x00, byte].
/// Caller owns the returned slice and must free it.
pub fn passwordBytes(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, password.len * 2);
    errdefer allocator.free(result);

    for (password, 0..) |b, i| {
        result[i * 2] = 0;
        result[i * 2 + 1] = b;
    }

    return result;
}

/// Zero out a byte buffer for security purposes.
/// This is used to clear sensitive data like passwords from memory.
pub fn zeroing(buf: []u8) void {
    @memset(buf, 0);
}

test "passwordBytes converts correctly" {
    const input = "test";
    const result = try passwordBytes(testing.allocator, input);
    defer testing.allocator.free(result);

    const expected = [_]u8{ 0, 't', 0, 'e', 0, 's', 0, 't' };
    try testing.expectEqualSlices(u8, &expected, result);
}

test "passwordBytes with empty input" {
    const input = "";
    const result = try passwordBytes(testing.allocator, input);
    defer testing.allocator.free(result);

    try testing.expectEqual(@as(usize, 0), result.len);
}

test "passwordBytes with single byte" {
    const input = "a";
    const result = try passwordBytes(testing.allocator, input);
    defer testing.allocator.free(result);

    const expected = [_]u8{ 0, 'a' };
    try testing.expectEqualSlices(u8, &expected, result);
}

test "zeroing clears buffer" {
    var buf = [_]u8{ 1, 2, 3, 4, 5 };
    zeroing(&buf);

    for (buf) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

test "zeroing with empty buffer" {
    var buf = [_]u8{};
    zeroing(&buf);
    try testing.expectEqual(@as(usize, 0), buf.len);
}
