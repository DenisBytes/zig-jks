const std = @import("std");
const testing = std.testing;
const common = @import("common.zig");
const types = @import("types.zig");

const Error = types.Error;
const Certificate = types.Certificate;
const PrivateKeyEntry = types.PrivateKeyEntry;
const TrustedCertificateEntry = types.TrustedCertificateEntry;

/// Encoder wraps a writer and hash for encoding JKS format.
pub const Encoder = struct {
    writer: std.io.AnyWriter,
    hash: std.crypto.hash.Sha1,

    pub fn init(writer: std.io.AnyWriter) Encoder {
        return .{
            .writer = writer,
            .hash = std.crypto.hash.Sha1.init(.{}),
        };
    }

    /// Write a u16 in big-endian format
    pub fn writeU16(self: *Encoder, value: u16) !void {
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, value, common.byte_order);
        try self.writeBytes(&buf);
    }

    /// Write a u32 in big-endian format
    pub fn writeU32(self: *Encoder, value: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, common.byte_order);
        try self.writeBytes(&buf);
    }

    /// Write a u64 in big-endian format
    pub fn writeU64(self: *Encoder, value: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, common.byte_order);
        try self.writeBytes(&buf);
    }

    /// Write bytes to both the writer and hash
    pub fn writeBytes(self: *Encoder, bytes: []const u8) !void {
        try self.writer.writeAll(bytes);
        self.hash.update(bytes);
    }

    /// Write a string with length prefix (u16 length)
    pub fn writeString(self: *Encoder, value: []const u8) !void {
        if (value.len > std.math.maxInt(u16)) {
            return Error.StringTooLong;
        }

        try self.writeU16(@intCast(value.len));
        try self.writeBytes(value);
    }

    /// Write a certificate
    pub fn writeCertificate(self: *Encoder, cert: Certificate) !void {
        try self.writeString(cert.type);

        if (cert.content.len > std.math.maxInt(u32)) {
            return Error.DataTooLong;
        }

        try self.writeU32(@intCast(cert.content.len));
        try self.writeBytes(cert.content);
    }

    /// Write a private key entry
    pub fn writePrivateKeyEntry(self: *Encoder, alias: []const u8, entry: PrivateKeyEntry) !void {
        try self.writeU32(common.private_key_tag);
        try self.writeString(alias);
        try self.writeU64(@intCast(entry.creation_time));

        if (entry.private_key.len > std.math.maxInt(u32)) {
            return Error.DataTooLong;
        }

        try self.writeU32(@intCast(entry.private_key.len));
        try self.writeBytes(entry.private_key);

        if (entry.certificate_chain.len > std.math.maxInt(u32)) {
            return Error.DataTooLong;
        }

        try self.writeU32(@intCast(entry.certificate_chain.len));

        for (entry.certificate_chain) |cert| {
            try self.writeCertificate(cert);
        }
    }

    /// Write a trusted certificate entry
    pub fn writeTrustedCertificateEntry(self: *Encoder, alias: []const u8, entry: TrustedCertificateEntry) !void {
        try self.writeU32(common.trusted_certificate_tag);
        try self.writeString(alias);
        try self.writeU64(@intCast(entry.creation_time));
        try self.writeCertificate(entry.certificate);
    }

    /// Get the final hash digest
    pub fn finalize(self: *Encoder) [std.crypto.hash.Sha1.digest_length]u8 {
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        self.hash.final(&digest);
        return digest;
    }
};

// Tests

test "Encoder.writeU16 big-endian" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());
    try encoder.writeU16(0x1234);

    const expected = [_]u8{ 0x12, 0x34 };
    try testing.expectEqualSlices(u8, &expected, buf.items);
}

test "Encoder.writeU32 big-endian" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());
    try encoder.writeU32(0x12345678);

    const expected = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    try testing.expectEqualSlices(u8, &expected, buf.items);
}

test "Encoder.writeU64 big-endian" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());
    try encoder.writeU64(0x123456789ABCDEF0);

    const expected = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    try testing.expectEqualSlices(u8, &expected, buf.items);
}

test "Encoder.writeString with length prefix" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());
    try encoder.writeString("test");

    const expected = [_]u8{ 0x00, 0x04, 't', 'e', 's', 't' };
    try testing.expectEqualSlices(u8, &expected, buf.items);
}

test "Encoder.writeString empty string" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());
    try encoder.writeString("");

    const expected = [_]u8{ 0x00, 0x00 };
    try testing.expectEqualSlices(u8, &expected, buf.items);
}

test "Encoder.writeCertificate" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());

    const cert = Certificate{
        .type = "X509",
        .content = &[_]u8{ 0x30, 0x82, 0x01 },
    };

    try encoder.writeCertificate(cert);

    // Expected: length(4) + "X509" + length(3) + content
    const expected = [_]u8{
        0x00, 0x04, 'X', '5', '0', '9', // type
        0x00, 0x00, 0x00, 0x03, // content length
        0x30, 0x82, 0x01, // content
    };
    try testing.expectEqualSlices(u8, &expected, buf.items);
}

test "Encoder hash is updated" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    var encoder = Encoder.init(buf.writer().any());
    try encoder.writeBytes("test");

    const digest = encoder.finalize();

    // Verify the hash was actually computed (non-zero)
    var all_zero = true;
    for (digest) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try testing.expect(!all_zero);
}
