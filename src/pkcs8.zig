//! PKCS#8 private key encoding/decoding (RFC 5208, RFC 5958)

const std = @import("std");
pub const Error = error{
    InvalidPkcs8Format,
    UnsupportedAlgorithm,
    InvalidKeyData,
};
pub fn validate(data: []const u8) bool {
    if (data.len < 2) return false;
    return data[0] == 0x30;
}

test "pkcs8: validate recognizes SEQUENCE tag" {
    const valid = [_]u8{ 0x30, 0x82, 0x01, 0x00 };
    try std.testing.expect(validate(&valid));

    const invalid = [_]u8{ 0x04, 0x08 };
    try std.testing.expect(!validate(&invalid));

    const empty: []const u8 = &[_]u8{};
    try std.testing.expect(!validate(empty));
}
