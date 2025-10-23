const std = @import("std");

const byte_order = std.builtin.Endian.big;

pub const Encoder = struct {
    writer: std.io.AnyWriter,
    hash: std.crypto.hash.Sha1,

    pub fn init(writer: std.io.AnyWriter) Encoder {
        return .{
            .writer = writer,
            .hash = std.crypto.hash.Sha1.init(.{}),
        };
    }

    pub fn writeU16(self: *Encoder, value: u16) !void {
        var buf: [2]u8 = undefined;
        std.mem.writeInt(u16, &buf, value, byte_order);
        try self.writeBytes(&buf);
    }

    pub fn writeU32(self: *Encoder, value: u32) !void {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, value, byte_order);
        try self.writeBytes(&buf);
    }

    pub fn writeU64(self: *Encoder, value: u64) !void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, value, byte_order);
        try self.writeBytes(&buf);
    }

    pub fn writeBytes(self: *Encoder, bytes: []const u8) !void {
        try self.writer.writeAll(bytes);
        self.hash.update(bytes);
    }

    pub fn writeString(self: *Encoder, value: []const u8) !void {
        if (value.len > std.math.maxInt(u16)) {
            return error.StringTooLong;
        }

        try self.writeU16(@intCast(value.len));
        try self.writeBytes(value);
    }

    pub fn writeCertificate(self: *Encoder, cert_type: []const u8, cert_content: []const u8, version: u32) !void {
        if (version == 2) {
            try self.writeString(cert_type);
        }

        if (cert_content.len > std.math.maxInt(u32)) {
            return error.DataTooLong;
        }

        try self.writeU32(@intCast(cert_content.len));
        try self.writeBytes(cert_content);
    }

    pub fn finalize(self: *Encoder) [std.crypto.hash.Sha1.digest_length]u8 {
        var digest: [std.crypto.hash.Sha1.digest_length]u8 = undefined;
        self.hash.final(&digest);
        return digest;
    }
};
