const std = @import("std");
const testing = std.testing;
const common = @import("common.zig");
const types = @import("types.zig");

const Error = types.Error;
const Certificate = types.Certificate;
const PrivateKeyEntry = types.PrivateKeyEntry;
const TrustedCertificateEntry = types.TrustedCertificateEntry;

const default_certificate_type = "X509";

/// Decoder wraps a reader and hash for decoding JKS format.
pub const Decoder = struct {
    allocator: std.mem.Allocator,
    reader: std.io.AnyReader,
    hash: std.crypto.hash.Sha1,

    pub fn init(allocator: std.mem.Allocator, reader: std.io.AnyReader) Decoder {
        return .{
            .allocator = allocator,
            .reader = reader,
            .hash = std.crypto.hash.Sha1.init(.{}),
        };
    }

    /// Read a u16 in big-endian format
    pub fn readU16(self: *Decoder) !u16 {
        const bytes = try self.readBytes(2);
        defer self.allocator.free(bytes);
        return std.mem.readInt(u16, bytes[0..2], common.byte_order);
    }

    /// Read a u32 in big-endian format
    pub fn readU32(self: *Decoder) !u32 {
        const bytes = try self.readBytes(4);
        defer self.allocator.free(bytes);
        return std.mem.readInt(u32, bytes[0..4], common.byte_order);
    }

    /// Read a u64 in big-endian format
    pub fn readU64(self: *Decoder) !u64 {
        const bytes = try self.readBytes(8);
        defer self.allocator.free(bytes);
        return std.mem.readInt(u64, bytes[0..8], common.byte_order);
    }

    /// Read exact number of bytes, update hash, and return owned slice
    pub fn readBytes(self: *Decoder, num: usize) ![]u8 {
        const buf = try self.allocator.alloc(u8, num);
        errdefer self.allocator.free(buf);

        try self.reader.readNoEof(buf);
        self.hash.update(buf);

        return buf;
    }

    /// Read a string with length prefix (u16 length). Caller owns returned slice.
    pub fn readString(self: *Decoder) ![]u8 {
        const len = try self.readU16();
        return try self.readBytes(len);
    }

    /// Read a certificate. Caller owns returned certificate and must call deinit.
    pub fn readCertificate(self: *Decoder, version: u32) !Certificate {
        const cert_type = switch (version) {
            common.version_01 => blk: {
                // Version 1 always uses X509
                break :blk try self.allocator.dupe(u8, default_certificate_type);
            },
            common.version_02 => try self.readString(),
            else => return Error.InvalidVersion,
        };
        errdefer self.allocator.free(cert_type);

        const len = try self.readU32();
        const content = try self.readBytes(len);
        errdefer self.allocator.free(content);

        return Certificate{
            .type = cert_type,
            .content = content,
        };
    }

    /// Read a private key entry. Caller owns returned entry and must call deinit.
    pub fn readPrivateKeyEntry(self: *Decoder, version: u32) !PrivateKeyEntry {
        const creation_time = try self.readU64();

        const pk_len = try self.readU32();
        const private_key = try self.readBytes(pk_len);
        errdefer self.allocator.free(private_key);

        const cert_num = try self.readU32();
        const chain = try self.allocator.alloc(Certificate, cert_num);
        errdefer {
            for (chain) |cert| {
                cert.deinit(self.allocator);
            }
            self.allocator.free(chain);
        }

        for (chain) |*cert| {
            cert.* = try self.readCertificate(version);
        }

        return PrivateKeyEntry{
            .creation_time = @intCast(creation_time),
            .private_key = private_key,
            .certificate_chain = chain,
        };
    }

    /// Read a trusted certificate entry. Caller owns returned entry and must call deinit.
    pub fn readTrustedCertificateEntry(self: *Decoder, version: u32) !TrustedCertificateEntry {
        const creation_time = try self.readU64();
        const certificate = try self.readCertificate(version);

        return TrustedCertificateEntry{
            .creation_time = @intCast(creation_time),
            .certificate = certificate,
        };
    }

    /// Read an entry (tag + alias + entry data). Caller owns returned alias and entry.
    pub fn readEntry(self: *Decoder, version: u32) !struct { alias: []u8, entry: types.Entry } {
        const tag = try self.readU32();
        const alias = try self.readString();
        errdefer self.allocator.free(alias);

        const entry = switch (tag) {
            common.private_key_tag => blk: {
                const pke = try self.readPrivateKeyEntry(version);
                break :blk types.Entry{ .private_key = pke };
            },
            common.trusted_certificate_tag => blk: {
                const tce = try self.readTrustedCertificateEntry(version);
                break :blk types.Entry{ .trusted_certificate = tce };
            },
            else => return Error.UnknownEntryTag,
        };

        return .{ .alias = alias, .entry = entry };
    }

    /// Get the final hash digest
    pub fn finalize(self: *Decoder) [std.crypto.hash.Sha1.digest_length]u8 {
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        self.hash.final(&digest);
        return digest;
    }
};

// Tests

test "Decoder.readU16 big-endian" {
    const data = [_]u8{ 0x12, 0x34 };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const value = try decoder.readU16();

    try testing.expectEqual(@as(u16, 0x1234), value);
}

test "Decoder.readU32 big-endian" {
    const data = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const value = try decoder.readU32();

    try testing.expectEqual(@as(u32, 0x12345678), value);
}

test "Decoder.readU64 big-endian" {
    const data = [_]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const value = try decoder.readU64();

    try testing.expectEqual(@as(u64, 0x123456789ABCDEF0), value);
}

test "Decoder.readString with length prefix" {
    const data = [_]u8{ 0x00, 0x04, 't', 'e', 's', 't' };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const value = try decoder.readString();
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("test", value);
}

test "Decoder.readString empty string" {
    const data = [_]u8{ 0x00, 0x00 };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const value = try decoder.readString();
    defer testing.allocator.free(value);

    try testing.expectEqualStrings("", value);
}

test "Decoder.readCertificate version 2" {
    const data = [_]u8{
        0x00, 0x04, 'X', '5', '0', '9', // type
        0x00, 0x00, 0x00, 0x03, // content length
        0x30, 0x82, 0x01, // content
    };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const cert = try decoder.readCertificate(common.version_02);
    defer cert.deinit(testing.allocator);

    try testing.expectEqualStrings("X509", cert.type);
    const expected_content = [_]u8{ 0x30, 0x82, 0x01 };
    try testing.expectEqualSlices(u8, &expected_content, cert.content);
}

test "Decoder.readCertificate version 1 default type" {
    const data = [_]u8{
        0x00, 0x00, 0x00, 0x03, // content length
        0x30, 0x82, 0x01, // content
    };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const cert = try decoder.readCertificate(common.version_01);
    defer cert.deinit(testing.allocator);

    try testing.expectEqualStrings("X509", cert.type);
    const expected_content = [_]u8{ 0x30, 0x82, 0x01 };
    try testing.expectEqualSlices(u8, &expected_content, cert.content);
}

test "Decoder hash is updated" {
    const data = [_]u8{ 't', 'e', 's', 't' };
    var stream = std.io.fixedBufferStream(&data);

    var decoder = Decoder.init(testing.allocator, stream.reader().any());
    const bytes = try decoder.readBytes(4);
    defer testing.allocator.free(bytes);

    const digest = decoder.finalize();

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
