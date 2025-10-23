const std = @import("std");

const byte_order = std.builtin.Endian.big;
const default_certificate_type = "X509";

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

    pub fn readU16(self: *Decoder) !u16 {
        const bytes = try self.readBytes(2);
        defer self.allocator.free(bytes);
        return std.mem.readInt(u16, bytes[0..2], byte_order);
    }

    pub fn readU32(self: *Decoder) !u32 {
        const bytes = try self.readBytes(4);
        defer self.allocator.free(bytes);
        return std.mem.readInt(u32, bytes[0..4], byte_order);
    }

    pub fn readU64(self: *Decoder) !u64 {
        const bytes = try self.readBytes(8);
        defer self.allocator.free(bytes);
        return std.mem.readInt(u64, bytes[0..8], byte_order);
    }

    pub fn readBytes(self: *Decoder, num: usize) ![]u8 {
        const buf = try self.allocator.alloc(u8, num);
        errdefer self.allocator.free(buf);

        try self.reader.readNoEof(buf);
        self.hash.update(buf);

        return buf;
    }

    pub fn readString(self: *Decoder) ![]u8 {
        const len = try self.readU16();
        return try self.readBytes(len);
    }

    pub fn readCertificate(self: *Decoder, version: u32) !struct { cert_type: []u8, content: []u8 } {
        const cert_type = switch (version) {
            1 => try self.allocator.dupe(u8, default_certificate_type),
            2 => try self.readString(),
            else => return error.InvalidVersion,
        };
        errdefer self.allocator.free(cert_type);

        const len = try self.readU32();
        const content = try self.readBytes(len);

        return .{ .cert_type = cert_type, .content = content };
    }

    pub fn finalize(self: *Decoder) [std.crypto.hash.Sha1.digest_length]u8 {
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        self.hash.final(&digest);
        return digest;
    }
};
